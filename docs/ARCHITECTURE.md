# Architecture

A walkthrough of how `mactelnet-proxy` is shaped, intended for
contributors and operators who need to reason about the daemon
beyond what the README covers. The README is the operator surface
(install, configure, run); this file is what's *underneath* that.

## Component layout

Single Go module, single binary, no plugins.

```
src/
├── cmd/mactelnet-proxy/        # binary entry, subcommand dispatch
│   ├── main.go                 # root parser; dispatches `serve` (default),
│   │                           #   `mactelnet`, `mndp`, `version`
│   ├── mactelnet.go            # standalone-mode mactelnet (no SSH server)
│   └── mndp.go                 # standalone-mode mndp
└── internal/
    ├── sshserver/              # frontend — accepts SSH, runs `exec` requests
    │   ├── server.go           # listener, handshake, per-conn dispatch
    │   ├── exec.go             # exec parsing, password prompt, subcommand routing
    │   ├── ifaces.go           # `ifaces` SSH-exec implementation
    │   └── keys.go             # host-key load-or-generate
    ├── mactelnet/              # backend — speaks MAC-Telnet to MikroTiks
    │   ├── conn.go             # PF_PACKET raw L2 send + UDP/20561 receive
    │   ├── protocol.go         # outer header, control-record framing
    │   ├── auth.go             # PASSSALT / EC-SRP / MD5 handshake
    │   ├── mtwei.go            # EC-SRP on Curve25519 in Weierstrass form
    │   ├── seq.go              # stop-and-wait retransmit schedule
    │   ├── session.go          # session state machine (Open/Read/Write/Close)
    │   └── loop.go             # rxLoop — single demux goroutine per session
    └── mndp/                   # backend — MNDP discovery on UDP/5678
        ├── conn.go             # SO_REUSEADDR/REUSEPORT bound to 0.0.0.0:5678
        ├── discover.go         # solicit + listen + dedup → []Neighbor
        ├── parser.go           # TLV parser, big-endian except TIMESTAMP
        └── types.go            # Neighbor record shape
```

Total Go: ~4,100 lines across 20 files. No third-party deps beyond
stdlib + `golang.org/x/crypto`.

## Process model

`serve` is the long-running mode used in production; `mactelnet` and
`mndp` exist as standalone CLIs for one-shot debugging without
running an SSH server. Only `serve` is wired into the systemd unit.

The systemd unit runs the daemon as `root` with
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE` and the full
hardening kit (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectControlGroups`, `RestrictAddressFamilies`,
`RestrictNamespaces`, `MemoryDenyWriteExecute`, `LockPersonality`,
`SystemCallFilter=@system-service ~@privileged @resources`). The
optional VRF drop-in widens the bounding set with
`CAP_NET_ADMIN CAP_SYS_ADMIN` and relaxes `~@privileged` /
`ProtectControlGroups` for `ip vrf exec`'s bpf+cgroup setup.

## Data flow

The interesting path is an SSH-fronted MAC-Telnet session:

```
external client ─SSH/TCP/22─→ sshserver.Server.handleConn
                                   │
                                   │ key auth via authPublicKey
                                   ▼
                               handleSession
                                   │
                                   │ "exec mactelnet -u admin MAC"
                                   ▼
                               dispatchExec ─→ execMactelnet
                                                │
                                                │ password prompt (or -p)
                                                ▼
                                         mactelnet.Open
                                                │
                                ┌───────────────┴───────────────┐
                                ▼                               ▼
                       conn.openRecv                   conn.openRawSender
                       UDP/20561 listener              PF_PACKET / SOCK_RAW
                       (kernel demux)                  (user-built Eth+IP+UDP)
                                                                │
                                                                ▼
                                                       MikroTik on L2
```

The reverse path (device → proxy) lands on `recvConn` and is consumed
by `rxLoop`, which demuxes by packet type (ACK / DATA / END_AUTH /
PONG) and routes payloads to `rxPipe` (terminal data) or `controlCh`
(handshake state machine).

`mndp` and `ifaces` follow the same SSH-frontend → `dispatchExec` →
package-call shape; both return JSON or text directly to the SSH
channel and exit.

## MAC-Telnet wire format

The proxy speaks MAC-Telnet identically to RouterOS's own
`/tool mac-telnet` — verified by pcap comparison against a CCR2116
on every byte of the Ethernet, IP, UDP, and outer MAC-Telnet headers.

**Send path** uses `PF_PACKET / SOCK_RAW` directly, **not**
`AF_INET / SOCK_RAW + IP_HDRINCL`. Reason: under `IP_HDRINCL`, Linux
silently rewrites the IP source from `0.0.0.0` to the egress
interface IP, which RouterOS rejects ([`internal/mactelnet/conn.go`
header comment](../src/internal/mactelnet/conn.go) has the long form).

User-space builds the full frame:

| Layer | Source | Destination |
|---|---|---|
| Ethernet | the proxy's iface MAC | the *target's* MAC (not broadcast — switches with broadcast suppression silently drop ff:ff:ff:ff:ff:ff) |
| IP | `0.0.0.0`, `TOS=0x00`, no DF | `255.255.255.255` |
| UDP | port 20561 | port 20561 |

`buildFrame` in `internal/mactelnet/conn.go` produces this layout
byte-for-byte against `interfaces.c:net_send_udp` upstream. The
checksums (IP + UDP) are computed in user space; the kernel doesn't
fix them up under `PF_PACKET`.

**Receive path** is a regular `*net.UDPConn` bound to `0.0.0.0:20561`
with `SO_REUSEADDR` + `SO_REUSEPORT`. Binding to the interface's
specific IPv4 (an earlier design) caused the kernel to filter
RouterOS's replies addressed to the limited broadcast — replies were
silently dropped before reaching `rxLoop`, surfacing as
`peer not responding` retransmit exhausts. Binding to `0.0.0.0`
matches upstream and resolves it.

## Outer header & control records

Each MAC-Telnet UDP datagram carries a fixed 22-byte outer header
(version, ptype, source/dest MACs, session id, client type, counter)
followed by zero or more control records (TLV-ish: 4-byte type,
2-byte length, payload). Encoding details are in
`internal/mactelnet/protocol.go` with byte-offset-annotated comments.

`ptype` values used:

| ptype | Direction | Meaning |
|---|---|---|
| 0x01 SESSION_START | client | open / re-open a session |
| 0x02 DATA | both | carries control records or terminal data |
| 0x03 ACK | both | counter advance |
| 0x04 END_AUTH | server | close session (auth fail or peer END) |
| 0x05 PING | client | keepalive, every 10 s |
| 0x06 PONG | server | keepalive ACK |

Stop-and-wait reliability: every DATA carries a 32-bit byte-offset
counter; the receiver replies with an ACK whose counter equals
(sender's counter + payload length). Retransmit ramps via the table
in `internal/mactelnet/seq.go` — the upstream exponential ramp
followed by 1 s entries until the configured budget
(`MACTELNET_PROXY_AUTH_TIMEOUT` / `_DATA_TIMEOUT`) is consumed.

## Authentication

Two flavors are negotiated by reply length to `PASSSALT`:

- **EC-SRP** (modern RouterOS): Curve25519 in Weierstrass form,
  `internal/mactelnet/mtwei.go`. The proxy sends a 33-byte client
  pubkey, the server replies with 33 bytes pubkey + 16 bytes salt,
  the proxy derives the shared key via `mtwei_id_xy` and emits a
  32-byte verifier in `PASSWORD`.
- **MD5** (legacy): server replies with a 16-byte challenge salt;
  proxy emits 17 bytes (1-byte zero pad + MD5(salt || password) — see
  `auth.go` for the byte ordering).

Either way, on success the server emits `END_AUTH` (which is the
"auth complete" signal here, despite the misleading name — the
session continues and only sends another `END_AUTH` if it tears
down). The session then enters terminal mode and `Read`/`Write` on
the `Session` proxy stdio to/from the SSH channel.

## SSH frontend

Implemented on `golang.org/x/crypto/ssh`. Highlights:

- **Auth:** public-key only. `authPublicKey` compares the incoming
  key's marshaled bytes against the parsed `authorized_keys`. No
  per-key principals — possession of any matching key authorizes
  any of the three exec commands.
- **Authorized-keys reload:** `ReloadAuthorizedKeys` is wired to
  SIGHUP via `systemctl reload mactelnet-proxy`. Hot — no in-flight
  session is interrupted.
- **PTY/winch:** the SSH-side `pty-req` is parsed for cols/rows;
  `window-change` requests update a `winChange` channel that the
  session goroutine forwards to `Session.Resize`. Coalescing is
  fine — terminal resizes are idempotent.
- **Host key:** loaded from `<KEYS_DIR>/mactel_ed25519_key`,
  auto-generated on first start (`internal/sshserver/keys.go`). The
  filename was renamed in 0.1.8 from `ssh_host_ed25519_key` to avoid
  confusion with the host's own sshd key in operators' file listings.

## MNDP

UDP/5678 broadcast. The proxy sends an empty SOLICIT to
`255.255.255.255:5678` and listens for inbound announcements; the
listener also picks up unsolicited periodic broadcasts that
RouterOS sends at ~1/min.

`internal/mndp/parser.go` parses the TLV stream — most fields are
big-endian, except `TIMESTAMP` (uptime, seconds) which is
little-endian per the RouterOS encoder. The parser is tolerant of
unknown attribute types (skips them).

`Discover` dedups by source MAC (`map[[6]byte]Neighbor`) and returns
a slice once the listen window expires.

## Concurrency

- **One goroutine per SSH connection** in `Server.handleConn`,
  spawned per `Accept`.
- **One goroutine per SSH session** within a connection in
  `handleSession` (most clients open one session per connection).
- **One goroutine per MAC-Telnet session** for the rx demux
  (`rxLoop`), plus the transient retransmit waiter inside
  `sendDataAndWaitAck`.
- **One goroutine for window-change events** so the session loop can
  read them non-blockingly.

No shared mutable state across sessions — each `mactelnet.Session`
owns its sockets, counters, and channels. The signal handler
(`SIGTERM`/`SIGINT`/`SIGHUP`) lives in `cmd/mactelnet-proxy/main.go`
and cancels the root `context.Context` for graceful shutdown.

## Configuration

Resolution precedence: **CLI flag > env var > built-in default**.
Each flag in `runServe` falls back to its `MACTELNET_PROXY_*` env via
the helpers `envOr`, `envDurationOr`, `envBoolOr`.

| Flag | Env | Default |
|---|---|---|
| `-listen` | `MACTELNET_PROXY_LISTEN` | `0.0.0.0:22` (the systemd unit overrides to `:222`) |
| `-keys-dir` | `MACTELNET_PROXY_KEYS_DIR` | `/etc/mactelnet-proxy` |
| `-host-key` | `MACTELNET_PROXY_HOST_KEY` | `<keys-dir>/mactel_ed25519_key` |
| `-authorized-keys` | `MACTELNET_PROXY_AUTHORIZED_KEYS` | `<keys-dir>/authorized_keys` |
| `-interface` | `MACTELNET_PROXY_INTERFACE` | (empty, required for any L2 traffic) |
| `-auth-timeout` | `MACTELNET_PROXY_AUTH_TIMEOUT` | `10s` |
| `-data-timeout` | `MACTELNET_PROXY_DATA_TIMEOUT` | `0` (= upstream's exact ~2.4s ramp) |
| `-debug` | `MACTELNET_PROXY_DEBUG` | off |

Booleans accept `0`/`false`/`no`/`off` (case-insensitive) as off;
durations are `time.ParseDuration`. Invalid values warn to stderr
and fall back to default — the daemon never refuses to boot for a
malformed env var.

## Hardening

Defense-in-depth list, in roughly increasing-blast-radius order:

1. **Read-only filesystem** outside `<KEYS_DIR>` — `ProtectSystem=strict`
   + `ReadWritePaths=/etc/mactelnet-proxy` (auto-extended if you
   override `KEYS_DIR`).
2. **No /home, no /tmp leak** — `ProtectHome`, `PrivateTmp`.
3. **No /dev** — `PrivateDevices=yes`. AF_PACKET works without it.
4. **No /proc/sys writes** — `ProtectKernelTunables=yes`.
5. **No module load** — `ProtectKernelModules=yes`.
6. **Cgroup ro** — `ProtectControlGroups=yes` (relaxed by the VRF
   drop-in only).
7. **Address family allowlist** —
   `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX`.
8. **Namespace deny** — `RestrictNamespaces=yes`.
9. **WX memory deny** — `MemoryDenyWriteExecute=yes`. Notable because
   it would block BPF JIT, but the daemon doesn't load BPF; only
   `ip vrf exec` would, and that runs out-of-process.
10. **Syscall filter** — `@system-service` allow, `~@privileged
    @resources` deny.
11. **Capability bounding** — root, but bounded to
    `CAP_NET_RAW CAP_NET_BIND_SERVICE`. The optional VRF drop-in
    extends to add `CAP_NET_ADMIN CAP_SYS_ADMIN` (only when
    installed).

## Testing & verification

- **Unit tests:** `seq_test.go` (retransmit schedule), `parser_test.go`
  (MNDP TLV parser). `make test` runs them.
- **Vulnerability scan:** `make vulncheck` runs
  [`govulncheck`](https://go.dev/security/vuln) against the official
  Go vuln DB. Wired into CI.
- **Pcap parity:** the wire-format claims ("byte-identical to
  RouterOS") were verified against a CCR2116 doing
  `/tool mac-telnet` to the same target on the same VLAN. There's
  no automated harness for this — re-do it manually if anything in
  `conn.go` / `protocol.go` changes meaningfully.
- **End-to-end smoke:** described in
  [docs/STATUS.md](STATUS.md) — full SSH auth → exec → EC-SRP →
  terminal mode against a live RouterOS device.

## Out-of-tree pieces

Worth knowing about even though they're not in the Go source:

- **systemd unit** —
  [`debian/mactelnet-proxy.service`](../debian/mactelnet-proxy.service)
  (package install) and
  [`deploy/systemd/mactelnet-proxy.service`](../deploy/systemd/mactelnet-proxy.service)
  (manual install, `/usr/local/bin` ExecStart). Two files because the
  binary path differs between the two install styles.
- **VRF drop-in** —
  [`deploy/systemd/mactelnet-proxy.service.d/vrf.conf`](../deploy/systemd/mactelnet-proxy.service.d/vrf.conf).
  Shipped as an example via `dh_installexamples`.
- **Debian packaging** —
  [`debian/`](../debian/) at project root. Cross-arch builds via
  `dpkg-buildpackage --host-arch=…`; the GOARCH/GOARM mapping is
  in `debian/rules`.
- **Docker** — three per-arch Dockerfiles in
  [`deploy/docker/`](../deploy/docker/). Alpine final stage so
  busybox tooling is available; `CGO_ENABLED=0` so we don't actually
  link against musl.

## See also

- [README](../README.md) — operator-focused install / configure / run.
- [CHANGELOG](CHANGELOG.md) — what shipped in each release.
- [STATUS](STATUS.md) — milestone tracking.
- [Wiki](https://github.com/icosa-consulting/mactelnet-proxy/wiki) —
  deployment recipes, troubleshooting, SSH CLI usage, NetCFG
  integration.
