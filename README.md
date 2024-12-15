# gorilla/csrf CSRF demo

## what

this repository contains a demonstration CSRF attack exploiting a vulnerability in gorilla/csrf based on broken referer checking.

 This vulnerability allows an attacker who has gained XSS on a subdomain or top level domain to perform authenticated form submissions against gorilla/csrf protected targets that share the same top level domain.

 This bug has existed in gorilla/csrf since its initial release in 2015.

 ## how and why

 gorilla/csrf examines the contents of `r.URL.Scheme` to determine whether a request is being served over HTTPS and only runs the `Referer` check if this is the case. However, per the Go `net/http#Request` documentation, these values are never set for "server" requests, and so this check never executes.
 ```
	// URL specifies either the URI being requested (for server
	// requests) or the URL to access (for client requests).
	//
	// For server requests, the URL is parsed from the URI
	// supplied on the Request-Line as stored in RequestURI.  For
	// most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)
	//
	// For client requests, the URL's Host specifies the server to
	// connect to, while the Request's Host field optionally
	// specifies the Host header value to send in the HTTP
	// request.
	URL *url.URL
  ```

  Even more unfortunate, these values _are_ populated when constructing
  `http.Request` objects with `http.NewRequest` passing full URLs as happens in the
  library's test suite. This means that the unit tests are in effect "cheating"
  as they have access to information in the `r.URL` struct that will never be
  available to a production application.

## instructions to replicate demo

1. install `mkcert`
2. use `mkcert` to create a certificate for the `*.example.test` domain
3. point each of the following domains to localhost in `/etc/hosts` or similar.
  - `attack.example.test`
  - `safe.example.test`
  - `target.example.test`
  - `trusted.example.test`
4. run `sudo go run main.go -tls-cert=YOUR_CERT_FILE -tls-key=YOUR_KEY_FILE -domain=example.test`
5. navigate to `https://target.example.test` & use the forms to make requests to `https://attack.example.test` and `https://safe.example.test`
