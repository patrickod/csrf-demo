package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	safe "csrf/fixed"
	csrf "csrf/vulnerable"
)

var (
	//go:embed static/*
	staticFS  embed.FS
	templates = template.Must(template.New("templates").ParseFS(staticFS, "static/*.html"))

	// CLI flags
	domain      = flag.String("domain", "csrf.patrickod.com", "domain to use for the demo (bind it, target.$DOMAIN, and attack.$DOMAIN to localhost with /etc/hosts)")
	listen      = flag.String("listen", ":443", "address to listen on")
	tlsCertFile = flag.String("tls-cert", "", "path to TLS certificate file")
	tlsKeyFile  = flag.String("tls-key", "", "path to TLS key file")
	dev         = flag.Bool("dev", false, "load assets from disk instead of embedded FS")
)

func main() {
	flag.Parse()

	ln := createListener()
	log.Printf("listening on %s", ln.Addr())

	// create handlers for the target, safe, and trusted origins with different CSRF configurations
	h := targetOriginHandler()

	// vulnerable origin with current gorilla/csrf
	vulnerableOrigin := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(h)

	// safe origin with patched gorilla/csrf
	safeOrigin := safe.Protect([]byte("32-byte-long-auth-key"), safe.Secure(true))(h)

	// safe origin with patched gorilla/csrf that allows cross-origin requests
	// from our attacker host
	trustedCrossOrigin := safe.Protect(
		[]byte("32-byte-long-auth-key"),
		safe.Secure(true),
		safe.TrustedOrigins([]string{fmt.Sprintf("attack.%s", *domain)}),
	)(h)

	// attackServer serves the CSRF form with scraped CSRF token values from the target
	as := newAttackServer(*domain)

	router := createRouter(vulnerableOrigin, safeOrigin, trustedCrossOrigin, as)
	if err := http.Serve(ln, router); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func createListener() net.Listener {
	var ln net.Listener
	var err error
	if *tlsCertFile != "" && *tlsKeyFile != "" {
		crt, err := tls.LoadX509KeyPair(*tlsCertFile, *tlsKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		config := &tls.Config{Certificates: []tls.Certificate{crt}}
		ln, err = tls.Listen("tcp", *listen, config)
		if err != nil {
			log.Fatalf("failed to create listener %v", err)
		}
	} else {
		ln, err = net.Listen("tcp", ":8080")
		if err != nil {
			log.Fatalf("failed to create listener %v", err)
		}
	}
	return ln

}

func createRouter(vulnerableOrigin, safeOrigin, trustedCrossOrigin http.Handler, as *attackServer) http.Handler {
	// route requests to their appropriate origin handler based on the sudomain.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// attack origin hosting CSRF form
		case strings.HasPrefix(r.Host, "attack."):
			as.ServeHTTP(w, r)
		// safe origin with patched gorilla/csrf
		case strings.HasPrefix(r.Host, "safe."):
			safeOrigin.ServeHTTP(w, r)
		// safe origin with patched gorilla/csrf that permits cross-origin requests
		case strings.HasPrefix(r.Host, "trusted."):
			trustedCrossOrigin.ServeHTTP(w, r)
		// target origin with vulnerable gorilla/csrf
		case strings.HasPrefix(r.Host, "target."):
			vulnerableOrigin.ServeHTTP(w, r)
		default:
			as.ServeHTTP(w, r)
		}
	})
}

func serveTargetHome(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		csrf.TemplateTag: csrf.TemplateField(r),
		"CSRFToken":      csrf.Token(r),
		"Domain":         *domain,
		"Today":          time.Now().Format("2006-01-02"),
		"SafeOrigin":     strings.HasPrefix(r.Host, "safe."),
	}
	w.Header().Set("Content-Type", "text/html")

	b := bytes.NewBuffer(nil)
	if err := templates.ExecuteTemplate(b, "target.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
		return
	}
}

// serveParams exports the CSRF token and the encoded token to the attacker origin.
// in reality an attacker would scrape the target to obtain these values
func serveParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"token": csrf.Token(r),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func targetOriginHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /params.json", serveParams)
	mux.HandleFunc("POST /submit", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "SUCCESSFUL POST REQUEST")
	})
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("GET /", serveTargetHome)
	return mux
}
