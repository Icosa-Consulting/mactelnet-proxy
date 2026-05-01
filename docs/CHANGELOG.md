# Changelog

All notable code changes to `mactelnet-proxy` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow SemVer. Per-tag summaries also live in
[`debian/changelog`](../debian/changelog).

## Unreleased

## [0.1.9] – 2026-05-01

### Changed
- Generalize deployment-specific defaults so the project ships
  vendor-neutral. Dockerfiles' `MACTELNET_PROXY_KEYS_DIR` default
  moved from `/config/auth` (a VyOS-flavored path) to
  `/etc/mactelnet-proxy` so it matches the systemd unit and the
  binary's compiled-in default. Comment examples for
  `MACTELNET_PROXY_INTERFACE` switched from `bond0`/`bond0.3006` to
  `eth0`/`eth1`. Debian-package deploys are unaffected — the systemd
  unit pins `MACTELNET_PROXY_KEYS_DIR=/etc/mactelnet-proxy` explicitly.

### Docs
- README rewritten to match the actual binary/package shape: `.deb`
  install flow, `MACTELNET_PROXY_*` env-var configuration table,
  current single-dash flag style, root-by-default service, alpine
  (not distroless) Docker base, optional VRF drop-in.

## [0.1.8] – 2026-05-01

### Changed
- Default keys dir rebased: `/etc/netcfg-mactelnet-proxy` →
  `/etc/mactelnet-proxy`. Matches what `postinst` has always created
  and what the systemd unit sets via `MACTELNET_PROXY_KEYS_DIR`, so
  no migration needed for package-installed deployments.
- Default host-key filename renamed: `ssh_host_ed25519_key` →
  `mactel_ed25519_key`. In-place upgrades auto-generate a fresh key
  under the new name on first start (new SSH host fingerprint).
  Operators wanting the existing fingerprint preserved should `mv`
  the old file to the new name. (`src/cmd/mactelnet-proxy/main.go`)

## [0.1.7] – 2026-05-01

### Changed
- Service runs as root/root (the systemd default) instead of a
  dedicated `mactelnet` user. The daemon needs `CAP_NET_RAW` +
  `PF_PACKET` regardless, and `User=mactelnet` was tripping DAC on
  operator-owned key paths (e.g. `/config/auth` on VyOS) without
  actually shrinking the privilege surface.
  `CapabilityBoundingSet` + `Protect*` / `Restrict*` /
  `SystemCallFilter` still meaningfully constrain the root daemon.
- `postinst` no longer creates the `mactelnet` user/group; `postrm`
  no longer deletes them. `/etc/mactelnet-proxy` is now installed
  `root:root 0700` (was `mactelnet:mactelnet 0750`).
- VRF drop-in (`vrf.conf`) simplified: no `User=` override needed,
  dropped `AmbientCapabilities` (no-op for root). Still expands the
  bounding set, relaxes `SystemCallFilter`, and sets
  `ProtectControlGroups=no` for `ip vrf exec`'s cgroup mkdir.
  (`debian/mactelnet-proxy.service`,
  `deploy/systemd/mactelnet-proxy.service`,
  `debian/postinst`, `debian/postrm`,
  `deploy/systemd/mactelnet-proxy.service.d/vrf.conf`)

## [0.1.6] – 2026-05-01

### Fixed
- VRF drop-in now sets `ProtectControlGroups=no`. Without it the base
  unit's `ProtectControlGroups=yes` makes `/sys/fs/cgroup` read-only
  for the service, and `ip vrf exec` fails when it tries to `mkdir`
  a sub-cgroup for its eBPF program:
  > `mkdir failed for /sys/fs/cgroup/system.slice/mactelnet-proxy.service/vrf: Read-only file system`
  > `Failed to setup vrf cgroup2 directory`
  Override that one knob in the drop-in; the rest of the unit's
  hardening (`ProtectSystem=strict`, `ProtectKernelTunables`, etc.)
  still applies. (`deploy/systemd/mactelnet-proxy.service.d/vrf.conf`)

## [0.1.5] – 2026-05-01

### Added
- Optional systemd drop-in example for running the proxy inside a
  Linux VRF via `ip vrf exec ${VRF}`. Shipped at
  `/usr/share/doc/mactelnet-proxy/examples/vrf.conf` so operators
  copy it into `/etc/systemd/system/mactelnet-proxy.service.d/`,
  edit `VRF=`, and reload. Drop-in extends `CapabilityBoundingSet`
  with `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` and relaxes
  `SystemCallFilter`'s `~@privileged` deny so `ip(8)` can call
  `bpf(2)`/`mount(2)`. (`deploy/systemd/mactelnet-proxy.service.d/vrf.conf`,
  `debian/mactelnet-proxy.examples`)

### Fixed
- Drop literal `#DEBHELPER#` from `postinst`/`prerm` comments.
  debhelper does naive text substitution on the token wherever it
  appears, including inside comments — 0.1.4's
  `# (#DEBHELPER#) handles ...` expanded into multi-line shell
  inside the comment, leaving stray `) handles ...` parsed as broken
  shell. `dpkg -i mactelnet-proxy_0.1.4_amd64.deb` failed with
  `syntax error near unexpected token \`)'`. Comments now reference
  "DEBHELPER" without the surrounding hashes; the actual token at
  the substitution point is preserved. (`debian/postinst`,
  `debian/prerm`)

## [0.1.0] – pre-release through 0.1.4

The initial pre-release work landed on 2026-05-01 as a rapid
sequence of tags `0.1.0` → `0.1.4`; the items below collectively
describe that work. Per-tag splits are in
[`debian/changelog`](../debian/changelog):

- `0.1.0` initial pre-release: MNDP discovery + TLV parser, MAC-Telnet
  protocol with EC-SRP/MD5 auth + terminal-size negotiation +
  sequence/ACK retransmit + keepalive, embedded SSH server, raw L2
  send via `PF_PACKET` with `src=0.0.0.0`, configurable retransmit
  budgets.
- `0.1.1` `ifaces` SSH-exec subcommand.
- `0.1.2` L2 destination = target MAC (not broadcast).
- `0.1.3` env-var driven systemd unit; IP header byte-identical to
  RouterOS `/tool mac-telnet` (TOS=0x00, no DF).
- `0.1.4` env vars prefixed `MACTELNET_PROXY_*`; `ExecStart` and
  Docker `ENTRYPOINT` collapsed to single exec-form lines.

### Changed

- **Binary reads configuration env vars directly** via `os.Getenv()`,
  replacing the shell-form `ExecStart=/bin/sh -c 'exec ...
  ${VAR:+-flag "$VAR"}'` kludge in the systemd unit and the matching
  shell-form `ENTRYPOINT` in the Dockerfiles. Each CLI flag now falls
  back to a `MACTELNET_PROXY_*` env var with the same semantics:
  CLI > env > built-in default.
  - `MACTELNET_PROXY_LISTEN`, `_KEYS_DIR`, `_AUTHORIZED_KEYS`,
    `_HOST_KEY`, `_INTERFACE`, `_AUTH_TIMEOUT`, `_DATA_TIMEOUT`,
    `_DEBUG`.
  - systemd unit shrinks to `ExecStart=/usr/bin/mactelnet-proxy serve`
    (one line).
  - Dockerfiles shrink to `ENTRYPOINT ["/usr/local/bin/mactelnet-proxy",
    "serve"]` (exec-form, PID 1 is the proxy itself, signals reach
    it directly).
  - `/etc/default/mactelnet-proxy` env file uses the new prefixed
    names.
  - Boolean env vars accept `0`, `false`, `no`, `off` (case-insensitive)
    as off; anything else non-empty is on. Duration vars accept
    Go's `time.ParseDuration` syntax (`10s`, `2m`, `100ms`); invalid
    values warn to stderr and fall back to default.
  (`src/cmd/mactelnet-proxy/main.go`,
  `deploy/systemd/mactelnet-proxy.service`,
  `deploy/systemd/mactelnet-proxy.env.example`,
  `debian/mactelnet-proxy.service`,
  `deploy/docker/Dockerfile.{amd64,arm64,armhf}`)

- **Go source moved under `src/`** for cleaner separation between
  application code and packaging/deploy material at the project root.
  `cmd/`, `internal/`, `go.mod`, `go.sum` all live in `src/` now.
  Builds use `go build -C src ...` to keep the module rooted there;
  Makefile, `debian/rules`, and the three Dockerfiles updated. No
  effect on runtime, imports, or wire format — pure restructure.

### Build & Deploy

- **Debian source-package layout** under `debian/` at project root,
  buildable with `dpkg-buildpackage` (no debhelper add-on dependency
  beyond the standard `debhelper-compat=13`). `debian/rules` maps
  `DEB_HOST_ARCH` → Go `GOARCH`/`GOARM` so cross-arch builds work
  natively without a C cross-toolchain. The package installs:
  - `/usr/bin/mactelnet-proxy` (the binary)
  - `/usr/lib/systemd/system/mactelnet-proxy.service` (with `/usr/bin/`
    `ExecStart`, separate from the `/usr/local/bin/` source unit kept
    in `deploy/systemd/` for manual installs)
  - `/etc/default/mactelnet-proxy` (env-var overrides, marked as
    a conffile)
  - `/etc/mactelnet-proxy/` (empty placeholder; `postinst` chowns to
    `mactelnet:mactelnet 0750`)
  postinst creates the `mactelnet` system user/group, prerm/postrm
  handle stop and purge cleanup, dh_installsystemd auto-handles the
  systemd lifecycle but with `--no-start` so the package install
  doesn't try to bring up a not-yet-configured proxy.
  Convenience wrappers in the Makefile: `make deb-amd64`,
  `deb-arm64`, `deb-armhf`, `deb-all` — all call `dpkg-buildpackage
  --host-arch=…` and stash the artifact in `dist/`.
- **systemd unit accepts environment-variable overrides** via
  `EnvironmentFile=-/etc/default/netcfg-mactelnet-proxy` (Debian/Ubuntu)
  and `EnvironmentFile=-/etc/sysconfig/netcfg-mactelnet-proxy`
  (RHEL/Fedora) — same env-var vocabulary the Docker images already
  use (`LISTEN`, `KEYS_DIR`, `MNDP_IFACE`, `AUTH_TIMEOUT`,
  `DATA_TIMEOUT`, `DEBUG`). `ExecStart` is shell-form so `${VAR:+…}`
  can omit optional flags entirely when their var is empty; `exec`
  replaces the shell with the proxy so signals reach it directly.
  Default `LISTEN` bumped to `0.0.0.0:222` to avoid stomping on
  system sshd. `ExecReload=/bin/kill -HUP $MAINPID` enables
  `systemctl reload` for live `authorized_keys` updates.
  `AmbientCapabilities` extended with `CAP_NET_BIND_SERVICE` so the
  unit handles privileged ports if `LISTEN` is overridden below 1024.
  (`deploy/systemd/netcfg-mactelnet-proxy.service`,
  `deploy/systemd/netcfg-mactelnet-proxy.env.example`)

### Fixed

- **IP header now matches RouterOS's own `/tool mac-telnet` byte for
  byte**: `TOS=0x00` (was `0x10` per upstream `interfaces.c`) and IP
  flags field cleared (no DF, was `0x4000`). Pcap-verified against a
  CCR2116 doing mac-telnet to the same target — every byte of our
  Ethernet + IP + UDP + MAC-Telnet header is now identical to what
  the router emits. Behavioural difference is small (TOS rarely
  inspected, DF only matters for fragmentation which never happens at
  this size), but removes the only remaining wire-level delta from
  the trusted reference flow. (`internal/mactelnet/conn.go`)

- **L2 destination is now the target's MAC, not the broadcast MAC.**
  `buildFrame` (renamed from `buildBroadcastFrame`) and
  `rawSender.Send` now take a `dstMAC [6]byte` and put it into the
  Ethernet header + the AF_PACKET `sockaddr_ll.Addr`. The IP layer
  stays `0.0.0.0 → 255.255.255.255`. Matches upstream
  `interfaces.c:net_send_udp` exactly. Pcap comparison against the
  working `/tool mac-telnet` flow on a CCR2116 confirmed our prior
  L2-broadcast variant differed at the Ethernet layer; this is the
  fix for "router-direct mac-telnet works, proxy-via-veth doesn't"
  on networks where intermediate L2 paths apply broadcast suppression
  / hardware-MAC-rule filtering. (`internal/mactelnet/conn.go`,
  `internal/mactelnet/session.go`, `internal/mactelnet/loop.go`)

- **Send path now uses `PF_PACKET / SOCK_RAW`** instead of
  `AF_INET / SOCK_RAW + IP_HDRINCL`. Linux silently rewrites the IP
  source under `IP_HDRINCL` to the egress-interface IP, producing
  `<ifaceIP> > 255.255.255.255` on the wire — RouterOS mac-server
  expects `0.0.0.0 > 255.255.255.255` (verified against device pcap).
  The new path builds the full Ethernet + IP + UDP frame in user
  space, matches upstream `interfaces.c:net_send_udp` byte-for-byte,
  and lets src=0.0.0.0 actually appear on the wire. The receive
  socket continues to be a regular UDP listener bound to
  `0.0.0.0:20561`. Wire effect: directed broadcast replaced with
  limited broadcast and `0.0.0.0` source. (`internal/mactelnet/conn.go`,
  `internal/mactelnet/session.go`, `internal/mactelnet/loop.go`)
- **`resolveInterface` no longer requires the interface to have an
  IPv4 address.** The L2-raw send path bypasses IP routing entirely
  and the receive socket binds to `0.0.0.0`, so vlan/veth/bond children
  with no IPv4 of their own (e.g. a container veth attached to a
  RouterOS bridge) work fine as long as they have a usable hardware
  address. (`internal/mactelnet/conn.go`)
- **Password prompt now times out after 30 s.** A client that opens
  the SSH channel and never sends a password no longer pins the proxy
  in a blocking `ReadByte` forever; `execMactelnet` returns 1, the
  channel closes cleanly, and NetCFG's `_closeConn` fires.
  (`internal/sshserver/exec.go`)
- **MAC-Telnet inbound replies were silently dropped** when the device
  addressed them to the limited broadcast (`255.255.255.255`). The
  receive socket bound to the interface's specific IPv4 only delivers
  datagrams whose destination matches that IP, so RouterOS replies were
  filtered by the kernel before reaching `rxLoop`. Surfaced as
  `auth init: retransmit exhausted, peer not responding` even though
  the device was answering. `openUDP` now binds to `0.0.0.0`, mirroring
  upstream `mactelnet.c:776–784`. (`internal/mactelnet/conn.go`)

### Added

- **New SSH-exec subcommand: `ifaces`** that lists the proxy host's
  network interfaces with name, ifindex, MAC, MTU, flags, and IPv4/v6
  addresses — handy for picking the right `-i IFACE` value before
  invoking `mactelnet`. Supports `-j` for JSON output and `-i NAME`
  to filter to a single interface. (`internal/sshserver/ifaces.go`,
  `internal/sshserver/exec.go`)
- **Configurable retransmit budgets** via two new `serve` flags:
  - `-auth-timeout` (default `10s`) — total budget for the
    pre-`END_AUTH` handshake. Generous so a slow EC-SRP / sleepy
    MikroTik / single dropped reply doesn't trip
    `peer not responding` on otherwise-working sessions.
  - `-data-timeout` (default `0` = upstream's exact ramp, ~2.4s) —
    budget for in-session DATA packets, kept tight so a dropped
    keystroke doesn't visibly stall.

  Internally `mactelnet.Configure(authBudget, dataBudget)` rebuilds
  two schedules: the upstream exponential ramp first, then 1 s entries
  appended until the budget is consumed. `sendDataAndWaitAck` picks
  `authSchedule` or `dataSchedule` based on `terminalMode`.
  (`cmd/mactelnet-proxy/main.go`, `internal/mactelnet/seq.go`,
  `internal/mactelnet/session.go`, `internal/mactelnet/seq_test.go`)
- **AF_PACKET sendto error logging.** First failure emits a WARN
  with errno + ifindex + frame size; subsequent repeats are DEBUG
  to avoid flooding when an interface is down for a sustained
  period. Surfaces EPERM in restricted runtimes (containers without
  `CAP_NET_RAW`) without needing `-debug`.
  (`internal/mactelnet/conn.go`)
- **Startup confirms `-debug` activation.** The `starting` info line
  now carries `debug=true|false`, and a `level=DEBUG msg="debug
  logging enabled"` line follows when the flag is set — quick visible
  proof the runtime parsed it.
  (`cmd/mactelnet-proxy/main.go`)
- `-debug` flag on `serve` that drops the slog handler to
  `LevelDebug`. Enables packet-level rx logging without a rebuild.
  (`cmd/mactelnet-proxy/main.go`)
- Password-flow logging in `execMactelnet`:
  `prompting for password on stdin` /
  `password received via prompt` /
  `password supplied via -p flag` (length only, never the value).
  Pinpoints which side of the SSH channel is stuck when a session
  fails before auth. (`internal/sshserver/exec.go`)
- Receive-loop packet logging (`mactelnet: rx datagram` with the
  source endpoint, length, and a 32-byte hex preview), plus matching
  drop reasons (`rx dropped (short)`, `rx dropped (bad header)`,
  `rx dropped (session-key mismatch)`). All `slog.Debug`, gated on
  `-debug`. (`internal/mactelnet/loop.go`)

### Build & Deploy

- **Dockerfiles switched from `scratch` to `alpine:3.20`** so
  `ENTRYPOINT` can be shell-form and expand `ENV` vars into flags
  at run time. `scratch` had no shell so `${VAR}` substitution
  wasn't possible. Three per-arch Dockerfiles (`Dockerfile.amd64`,
  `Dockerfile.arm64`, `Dockerfile.armhf`) with `--platform=$BUILDPLATFORM`
  on the build stage for cross-compile via Go (no qemu round-trip).
  (`deploy/docker/Dockerfile.{amd64,arm64,armhf}`)
- **Env-var driven configuration** with `KEYS_DIR`, `LISTEN`,
  `MNDP_IFACE`, `AUTH_TIMEOUT`, `DATA_TIMEOUT`, `DEBUG`. Optional
  flags emit only when their var is non-empty (`${VAR:+-flag "$VAR"}`),
  so an empty value doesn't pass an empty arg.
  (`deploy/docker/Dockerfile.*`)
- **`# check=skip=SecretsUsedInArgOrEnv`** on each Dockerfile to
  silence the buildkit linter false-positive that flags
  `AUTH_TIMEOUT` (any var name containing `AUTH`) as a secret.
- **`GO_VERSION` bumped to 1.25** to match `go.mod`'s `go 1.25.0`
  directive (older `golang:1.22-alpine` images failed `go mod
  download` with `go.mod requires go >= 1.25.0`).

### Verified

- Full mac-telnet session against a live RouterOS device on a
  vlan-filtered switch bridge: SSH auth → `exec mactelnet -u admin
  MAC` → in-channel password prompt → EC-SRP handshake → terminal
  mode with bidirectional ANSI/VT data and 10 s keepalive ACKs.
  Closes the M2 smoke-test gap recorded in STATUS.md.
- **Wire-byte-identical to upstream** verified via pcap comparison
  against `/tool mac-telnet` on a CCR2116: same Ethernet src=our
  iface MAC / dst=ff:ff:ff:ff:ff:ff, IP src=0.0.0.0 / dst=255.255.255.255,
  UDP src/dst = 20561, MAC-Telnet outer header layout per
  `protocol.h:147` retransmit ramp.
