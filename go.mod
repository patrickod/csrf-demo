module github.com/patrickod/csrf-demo

go 1.23.1

require (
	csrf/vulnerable v0.0.0-00010101000000-000000000000
	csrf/fixed v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.32.0
)

require github.com/gorilla/securecookie v1.1.2 // indirect

replace csrf/vulnerable => github.com/gorilla/csrf v1.7.2

replace csrf/fixed => github.com/gorilla/csrf v1.7.3-0.20250123201450-9dd6af1f6d30
