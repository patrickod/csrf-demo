package main

import (
	"bytes"
	"context"
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

	safe "github.com/gorilla/csrf"
	csrf "github.com/gorilla/csrf/vulnerable"
	"tailscale.com/tsweb"

	// prometheus varz metrics export
	_ "tailscale.com/tsweb/promvarz"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	debug       = flag.Bool("debug", false, "enable debug HTTP interface on :8081")
)

var (
	inFlightGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_in_flight_requests",
		Help: "A gauge of requests currently being served by the wrapped handler.",
	})
	counter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "A counter for requests to the wrapped handler.",
		},
		[]string{"domain", "code", "method"},
	)
	duration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: []float64{.25, .5, 1, 2.5, 5, 10},
		},
		[]string{"domain", "method"},
	)
)

func main() {
	flag.Parse()

	ln := createListener()
	log.Printf("listening on %s", ln.Addr())

	if *debug {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDebugServer(ctx)
	}

	// create handlers for the target, safe, and trusted origins with different CSRF configurations
	h := targetOriginHandler()

	// vulnerable origin with current gorilla/csrf
	vulnerableOrigin := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(h)
	vulnerableOriginWrapped := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(
			duration.MustCurryWith(prometheus.Labels{"domain": "target"}),
			promhttp.InstrumentHandlerCounter(
				counter.MustCurryWith(prometheus.Labels{"domain": "target"}),
				vulnerableOrigin,
			),
		))

	// safe origin with patched gorilla/csrf
	safeOrigin := safe.Protect([]byte("32-byte-long-auth-key"), safe.Secure(true))(h)
	safeOriginWrapped := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(
			duration.MustCurryWith(prometheus.Labels{"domain": "safe"}),
			promhttp.InstrumentHandlerCounter(
				counter.MustCurryWith(prometheus.Labels{"domain": "safe"}),
				safeOrigin,
			),
		))

	// safe origin with patched gorilla/csrf that allows cross-origin requests
	// from our attacker host
	trustedCrossOrigin := safe.Protect(
		[]byte("32-byte-long-auth-key"),
		safe.Secure(true),
		safe.TrustedOrigins([]string{fmt.Sprintf("attack.%s", *domain)}),
	)(h)
	trustedCrossOriginWrapped := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(
			duration.MustCurryWith(prometheus.Labels{"domain": "trusted"}),
			promhttp.InstrumentHandlerCounter(
				counter.MustCurryWith(prometheus.Labels{"domain": "trusted"}),
				trustedCrossOrigin,
			),
		))

	// attackServer serves the CSRF form with scraped CSRF token values from the target
	as := newAttackServer(*domain)
	attackServerWrapped := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(
			duration.MustCurryWith(prometheus.Labels{"domain": "attack"}),
			promhttp.InstrumentHandlerCounter(
				counter.MustCurryWith(prometheus.Labels{"domain": "attack"}),
				as,
			),
		))

	router := createRouter(
		vulnerableOriginWrapped,
		safeOriginWrapped,
		trustedCrossOriginWrapped,
		attackServerWrapped,
	)

	// instrument router with prometheus metrics

	if err := http.Serve(ln, router); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func runDebugServer(ctx context.Context) {
	mux := http.NewServeMux()
	tsweb.Debugger(mux)
	ln, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("failed to create listener %v", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		if err := http.Serve(ln, mux); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
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

func createRouter(vulnerableOrigin, safeOrigin, trustedCrossOrigin, attackServer http.Handler) http.Handler {
	// route requests to their appropriate origin handler based on the sudomain.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subdomain := strings.Split(r.Host, ".")[0]
		switch subdomain {
		// attack origin hosting CSRF form
		case "attack":
			attackServer.ServeHTTP(w, r)
		// safe origin with patched gorilla/csrf
		case "safe":
			safeOrigin.ServeHTTP(w, r)
		// safe origin with patched gorilla/csrf that permits cross-origin requests
		case "trusted":
			trustedCrossOrigin.ServeHTTP(w, r)
		// target origin with vulnerable gorilla/csrf
		case "target":
			vulnerableOrigin.ServeHTTP(w, r)
		default:
			attackServer.ServeHTTP(w, r)
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
