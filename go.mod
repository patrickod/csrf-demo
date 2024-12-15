module github.com/patrickod/csrf-demo

go 1.23.1

require (
	csrf/fixed v0.0.0-00010101000000-000000000000
	csrf/vulnerable v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.32.0
)

require github.com/gorilla/securecookie v1.1.2 // indirect

replace csrf/vulnerable => ./src/vulnerable

replace csrf/fixed => ./src/fixed
