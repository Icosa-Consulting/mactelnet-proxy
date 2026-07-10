module mactelnet-proxy

go 1.25.0

// Pinned to a version with no open Go vulnerability advisories per
// pkg.go.dev/vuln. govulncheck (run from the Makefile) re-validates this
// on every CI build.
require golang.org/x/crypto v0.52.0

require golang.org/x/sys v0.45.0 // indirect
