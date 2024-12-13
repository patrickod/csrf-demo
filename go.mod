module github.com/patrickod/csrf-demo

go 1.23.1

require (
	github.com/gorilla/csrf v1.7.2
	github.com/gorilla/securecookie v1.1.2 // indirect
)

replace github.com/gorilla/csrf => ../csrf
