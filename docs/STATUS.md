# Project Status

Living tracker for milestones and known gaps. Update as work lands.

## Milestones

### M1 — Repo skeleton + MNDP discovery (in progress)

Goal: a working `mndp -t SECONDS -j` CLI that prints discovered
MikroTiks as JSON. Smallest meaningful slice.

- [x] Repo layout, Go module, license, build/Make
- [x] systemd unit + Dockerfile (scratch base)
- [x] Stub package shells with public surface declared
- [x] Clone upstream into `_upstream/MAC-Telnet` (`make upstream`)
- [x] Port MNDP TLV parser from upstream `mndp.c` — `internal/mndp/parser.go`
- [x] Port MNDP UDP listener + interface binding —
      `internal/mndp/{conn.go,discover.go}`. Binds 0.0.0.0:5678 with
      SO_REUSEADDR + SO_BROADCAST, fires the 4-byte SOLICIT, dedupes by
      MAC, returns a sorted slice on timeout/ctx-done.
- [x] Wire `mactelnet-proxy mndp …` subcommand —
      `cmd/mactelnet-proxy/mndp.go`, with `-t` / `-i` / `-j` flags.
      Human table mirrors upstream's bold-header layout; `-j` emits JSON.
- [x] Unit tests with packet fixtures — `parser_test.go` synthesizes
      wire-format datagrams (header + TLV records) via a `buildPacket`
      helper and exercises the parser end-to-end. Real captured pcaps
      from a live device would be a stronger fixture; that's a follow-up.
- [x] Smoke test against a real MikroTik — verified 2026-04-29: MNDP
      discovers live devices on the LAN end-to-end.
- [ ] CI: `go test`, `go vet`, `govulncheck`

### M2 — MAC-Telnet protocol port (in progress)

Goal: an interactive PTY session against a known MikroTik MAC.

- [x] Port `protocol.c` packet types + framing — `internal/mactelnet/protocol.go`
- [x] Port MD5 challenge-response auth — `internal/mactelnet/auth.go`
- [x] Port EC-SRP (mtwei) auth — `internal/mactelnet/mtwei.go` (**unverified
      against a live device**; curve constants and internal roundtrip pass
      but bit-exact equivalence with upstream OpenSSL output needs a
      captured handshake or live RouterOS to confirm)
- [x] Port term-type / size negotiation in the auth handshake
      (TERM_TYPE/TERM_WIDTH/TERM_HEIGHT control records, little-endian dims)
- [x] Port sequence/ACK/retransmit logic — `internal/mactelnet/seq.go` +
      `sendDataAndWaitAck` in session.go
- [x] Port keepalive — empty ACK every 10 s, matching upstream
      (mactelnet.c:862). The `encodePing` PING/PONG packet builder is in
      `protocol.go` for completeness but upstream's runtime uses ACK as
      its keepalive, not PING/PONG, and we mirror that.
- [x] Port mid-session terminal resize — `Session.Resize(cols, rows)`
- [x] Session state machine end-to-end — `Open()` runs SESSIONSTART →
      auth (EC-SRP or MD5) → END_AUTH; `Session` is `io.ReadWriteCloser`
      backed by a single rx-loop goroutine plus a keepalive ticker.
- [ ] Parity tests against pcaps captured from upstream `mactelnet`
- [x] `mactelnet-proxy mactelnet -u USER MAC` subcommand wired
      (smoke-test: stdio piped through; cooked-mode TTY only — raw mode
      and proper interactive shell ergonomics are a follow-up)
- [x] Smoke test against a real RouterOS device — verified 2026-04-29:
      EC-SRP auth completes against RouterOS, terminal data flows
      bidirectionally, keepalive ACKs hold the session. Required two
      fixes uncovered during the test; see CHANGELOG entry for the
      same date.

### M3 — SSH server + integration (in progress)

Goal: NetCFG can connect to the proxy and run sessions end-to-end.

- [x] `golang.org/x/crypto/ssh` server, key-auth only —
      `internal/sshserver/server.go`
- [x] `authorized_keys` reload on SIGHUP —
      `Server.ReloadAuthorizedKeys()` wired from main.go
- [x] Auto-generate ED25519 host key on first run —
      `loadOrCreateHostKey` in `keys.go`
- [x] Route exec requests to the right engine — `splitCmd` +
      `dispatchExec` in `exec.go`; `mactelnet` and `mndp` subcommands
      hosted in-process (no fork)
- [x] PTY allocation + size-change forwarding — `pty-req` captures
      cols/rows for the session, `window-change` forwards via a buffered
      channel into `Session.Resize`
- [ ] End-to-end test against a NetCFG dev instance

## Decisions log

- **Language**: Go 1.25+, `CGO_ENABLED=0`, single static binary.
  (Bumped from 1.22 when x/crypto v0.50.0 required 1.25.)
- **License**: GPL-2.0 (inherited via port from upstream).
- **Auth**: SSH public-key only, no passwords.
- **Linux only**: Windows / macOS proxies not in scope.
- **Privileges**: `CAP_NET_RAW` ambient capability via systemd; never setuid.
- **External deps**: stdlib + `golang.org/x/crypto` (and its indirect
  `golang.org/x/sys`). Pinned, govulncheck'd.
- **Final Docker base**: `scratch` (empty), ~10 MB image.
- **EC-SRP curve math**: hand-rolled affine point ops on `math/big`.
  `crypto/elliptic.CurveParams` assumes `a = -3 mod p` and panics on the
  Weierstrass-form Curve25519 coefficients upstream uses.
- **Direction handling**: replaced upstream's `mt_direction_fromserver`
  global with an explicit `direction` argument on encode/decode helpers.
  Keeps the client/server byte-position swap at the call site.
