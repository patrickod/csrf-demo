package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"html/template"
	"io"
	"log"
	"net/http"

	_ "embed"

	"github.com/gorilla/csrf"
)

var (
	//go:embed attacker.html
	attackerTemplateBytes []byte
	attackerTemplate      = template.Must(template.New("attacker").Parse(string(attackerTemplateBytes)))

	//go:embed target.html
	targetTemplateBytes []byte
	targetTemplate      = template.Must(template.New("target").Parse(string(targetTemplateBytes)))

	//go:embed inject.js
	injectJSTemplateBytes []byte
	injectJSTemplate      = template.Must(template.New("inject.js").Parse(string(injectJSTemplateBytes)))

	// CLI flags
	domain      = flag.String("domain", "example.test", "domain to use for the demo (bind it, target.$DOMAIN, and bad.$DOMAIN to localhost with /etc/hosts)")
	tlsCertFile = flag.String("tls-cert", "", "path to TLS certificate file")
	tlsKeyFile  = flag.String("tls-key", "", "path to TLS key file")
)

func main() {
	flag.Parse()
	if *tlsCertFile == "" || *tlsKeyFile == "" {
		log.Fatal("both -tls-cert and -tls-key must be provided")
	}

	crt, err := tls.LoadX509KeyPair(*tlsCertFile, *tlsKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{crt}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", ln.Addr())

	primaryOrigin := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(http.HandlerFunc(primaryOriginHandler))

	attackerOriginMux := http.NewServeMux()
	attackerOriginMux.HandleFunc("/", attackerOriginHandler)

	if err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "bad."+*domain {
			attackerOriginMux.ServeHTTP(w, r)
		} else {
			primaryOrigin.ServeHTTP(w, r)
		}
	})); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func serveTargetHome(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		csrf.TemplateTag: csrf.TemplateField(r),
		"CSRFToken":      csrf.Token(r),
	}
	w.Header().Set("Content-Type", "text/html")

	b := bytes.NewBuffer(nil)
	if err := targetTemplate.Execute(b, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
		return
	}
}

func serveInjectJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	b := bytes.NewBuffer(nil)

	if err := injectJSTemplate.Execute(b, map[string]any{
		"Domain": *domain,
		"Token":  csrf.Token(r),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func primaryOriginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		switch r.URL.Path {
		case "/":
			serveTargetHome(w, r)
		case "/inject.js":
			serveInjectJS(w, r)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	case "POST":
		if r.URL.Path == "/submit" {
			io.WriteString(w, "SUCCESSFUL POST REQUEST")
			return
		}
		http.Error(w, "invalid POST request", http.StatusBadRequest)
	}
}

func attackerOriginHandler(w http.ResponseWriter, r *http.Request) {
	// template the attacker page
	w.Header().Set("Content-Type", "text/html")
	data := map[string]any{
		"Domain": *domain,
		"Token":  "attacker-controlled",
	}
	b := bytes.NewBuffer(nil)
	if err := attackerTemplate.Execute(b, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
		return
	}
}
