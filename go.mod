module github.com/patrickod/csrf-demo

go 1.24.1

replace github.com/gorilla/csrf/vulnerable => github.com/gorilla/csrf v1.7.2

require (
	github.com/gorilla/csrf v1.7.3-0.20250123201450-9dd6af1f6d30
	github.com/gorilla/csrf/vulnerable v0.0.0-00010101000000-000000000000
	github.com/prometheus/client_golang v1.21.1
	golang.org/x/net v0.38.0
	tailscale.com v1.82.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20250223041408-d3c622f1b874 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	google.golang.org/protobuf v1.36.1 // indirect
)
