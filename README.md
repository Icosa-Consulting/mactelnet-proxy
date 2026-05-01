# mactelnet-proxy

A small SSH server that runs **MAC-Telnet** sessions and **MNDP** discovery
on behalf of a remote NetCFG instance. Deploy on a Linux box that shares a
Layer-2 broadcast domain with your MikroTik fleet; NetCFG reaches it over
SSH using key authentication and `exec's` a session.

## A bit of history

MAC-Telnet is a MikroTik invention from the mid-2000s, and its
original use case was almost embarrassingly simple: you mistyped an
IP address in a router config and locked yourself out, and you needed
a way back in that didn't depend on the IP layer. The answer was a
UDP-broadcast protocol that addresses the target device by its MAC,
so any host on the same Layer-2 segment can reach it. No address
required, no truck roll.

It's a beautiful little tool until you grow past one switch closet.
MAC-Telnet doesn't traverse routers — broadcast dies at L3. So if
your MikroTik fleet is at twenty remote sites and your NOC sits in
one office, the official tool can't reach any of them. The community
had a partial fix for years:
[`haakonnessjoen/MAC-Telnet`](https://github.com/haakonnessjoen/MAC-Telnet)
is a C client that runs on Linux instead of inside RouterOS — but it
inherits the same on-segment constraint. To use it remotely you SSH
to a box that _is_ on the right segment, then run it from there.

This proxy is that pattern made permanent. One small Go binary on
each L2 segment, fronting an SSH server. Your tooling — NetCFG, an
operator's shell, a script — connects over SSH and `exec`s
`mactelnet -u admin AA:BB:CC:DD:EE:FF`; the daemon translates that
into a real MAC-Telnet session against the device on the wire and
pipes the terminal back. EC-SRP/MD5 auth, retransmit budgets, MNDP
discovery, terminal-mode I/O — everything the upstream client does,
but reachable from wherever your management plane lives.

The unglamorous half of the work was the wire format. RouterOS is
unforgiving: if your IP source isn't `0.0.0.0`, or your TOS byte
isn't `0x00`, or your Ethernet destination is the broadcast MAC
instead of the device's actual one, the router answers with silence
and you spend a week wondering why. This implementation is
byte-identical to RouterOS's own `/tool mac-telnet` on every layer,
verified by pcap comparison against a CCR2116. Anything less ships
something that works in the lab until the first switch with
broadcast suppression eats the frame.

## Status

Work in progress. See [docs/STATUS.md](docs/STATUS.md) for milestone
tracking and [docs/CHANGELOG.md](docs/CHANGELOG.md) for release
notes. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) walks through how
the daemon is shaped (component layout, data flow, wire format, auth,
hardening) for contributors and operators who need to reason past
the install/configure surface.

## Install

The primary deploy is a Debian package:

```sh
sudo dpkg -i mactelnet-proxy_<version>_<arch>.deb
sudoedit /etc/default/mactelnet-proxy   # set MACTELNET_PROXY_INTERFACE
sudo systemctl start mactelnet-proxy
```

The package installs the binary at `/usr/bin/mactelnet-proxy`, the
systemd unit, an environment-file template, and creates an empty keys
dir at `/etc/mactelnet-proxy/` (root-owned, mode 0700). The unit ships
disabled-but-enabled-on-install with `--no-start` — the proxy can't do
anything useful until you point `MACTELNET_PROXY_INTERFACE` at the
L2-facing NIC.

## Configure

Configuration is via environment variables. Edit
`/etc/default/mactelnet-proxy` (Debian/Ubuntu) or
`/etc/sysconfig/mactelnet-proxy` (RHEL-family) — the unit reads either
path automatically.

| Variable                          | Default                         | Notes                                                                                                                                                     |
| --------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MACTELNET_PROXY_INTERFACE`       | _(empty)_                       | **Required** for MAC-Telnet/MNDP traffic. Pick the interface on the same broadcast domain as your MikroTiks (often a VLAN sub-interface, e.g. `eth0.20`). |
| `MACTELNET_PROXY_LISTEN`          | `0.0.0.0:222`                   | Address:port the SSH server binds to.                                                                                                                     |
| `MACTELNET_PROXY_KEYS_DIR`        | `/etc/mactelnet-proxy`          | Holds the host key and `authorized_keys` (auto-generated on first run).                                                                                   |
| `MACTELNET_PROXY_AUTH_TIMEOUT`    | `10s`                           | Retransmit budget for the pre-END_AUTH handshake. Bump on flaky links.                                                                                    |
| `MACTELNET_PROXY_DATA_TIMEOUT`    | _(upstream default ~2.4s)_      | Retransmit budget for in-session DATA packets.                                                                                                            |
| `MACTELNET_PROXY_DEBUG`           | _(off)_                         | Any non-empty value (except `0`/`false`/`no`/`off`) enables verbose packet-level logging.                                                                 |
| `MACTELNET_PROXY_HOST_KEY`        | `<keys-dir>/mactel_ed25519_key` | Override only if the key lives outside `KEYS_DIR`.                                                                                                        |
| `MACTELNET_PROXY_AUTHORIZED_KEYS` | `<keys-dir>/authorized_keys`    | Override only if the file lives outside `KEYS_DIR`.                                                                                                       |

CLI flags (`-listen`, `-keys-dir`, `-interface`, …) take precedence over
env vars; env vars take precedence over built-in defaults.

## Run inside a VRF

For switch/router platforms where the management interface lives in a
dedicated routing table (VyOS, FRR, Cumulus), the package ships an
optional drop-in at
`/usr/share/doc/mactelnet-proxy/examples/vrf.conf` that wraps `ExecStart`
in `ip vrf exec ${VRF}`:

```sh
sudo install -D -m 0644 \
    /usr/share/doc/mactelnet-proxy/examples/vrf.conf \
    /etc/systemd/system/mactelnet-proxy.service.d/vrf.conf
sudoedit /etc/systemd/system/mactelnet-proxy.service.d/vrf.conf   # set VRF=
sudo systemctl daemon-reload
sudo systemctl restart mactelnet-proxy
```

The drop-in expands `CapabilityBoundingSet` and relaxes
`SystemCallFilter`/`ProtectControlGroups` just enough for `ip vrf exec`'s
bpf/cgroup setup; the rest of the unit's hardening still applies.

## Build from source

```sh
make build           # static binary in ./bin/mactelnet-proxy-linux-<arch>
make test            # go test ./...
make vulncheck       # govulncheck against the official Go vuln DB
make deb             # .deb for the host arch → dist/
make deb-all         # .debs for amd64, arm64, armhf
make docker          # alpine-based image for the host arch
make docker-all      # amd64, arm64, armhf images
```

Cross-compile the bare binary by overriding `GOARCH`:

```sh
GOARCH=arm64  make build      # → bin/mactelnet-proxy-linux-arm64
GOARCH=arm    make build      # → bin/mactelnet-proxy-linux-arm (32-bit)
```

For .deb cross-builds use the package toolchain directly:

```sh
make deb-arm64
make deb-armhf
```

## Subcommands

The single binary exposes:

- `serve` (default) — run the embedded SSH server. This is the systemd
  unit's `ExecStart`.
- `mactelnet -u USER MAC` — open one MAC-Telnet session on stdio (used
  via SSH `exec`).
- `mndp [-t SECONDS] [-j]` — run MNDP discovery and print
  newline-separated or JSON neighbor records (also via SSH `exec`).
- `version` — print version and exit.

Argument shape mirrors the upstream `mactelnet` / `mndp` CLIs so existing
tooling can be pointed at this proxy with minimal changes.

## Authentication

SSH only. Public-key authentication only — `authorized_keys` style. No
password auth, no host-key prompts. NetCFG generates a key pair on first
use and the operator pastes the public key into the proxy's
`authorized_keys` file. Same key model as a Linux box you'd `ssh` into.

Send `SIGHUP` (or `systemctl reload mactelnet-proxy`) to pick up new
keys appended to `authorized_keys` without restarting the daemon.

## Capabilities and hardening

The proxy needs `CAP_NET_RAW` (AF_PACKET / SOCK_RAW for MAC-Telnet
outbound, broadcast UDP/20561 listener) and `CAP_NET_BIND_SERVICE`
(privileged-port LISTEN if you drop below 1024). The systemd unit runs
as root/root with `CapabilityBoundingSet` capping the process to those
two caps, plus the standard hardening kit:
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`,
`RestrictAddressFamilies` (AF_INET/INET6/NETLINK/PACKET/UNIX),
`RestrictNamespaces`, `MemoryDenyWriteExecute`, and a
`SystemCallFilter` that allows `@system-service` minus
`@privileged @resources`.

## License

GPL-2.0. This codebase is a Go port of
[`haakonnessjoen/MAC-Telnet`](https://github.com/haakonnessjoen/MAC-Telnet)
(also GPL-2.0). See [`LICENSE`](LICENSE) for the full text and
[`NOTICE`](NOTICE) for upstream attribution.

## Security

- Only stdlib + `golang.org/x/crypto` (Go team), pinned to a version
  with no open advisories per pkg.go.dev/vuln.
- `make vulncheck` runs [govulncheck](https://go.dev/security/vuln) and
  is wired into CI.
- The proxy's keypair never leaves the box; NetCFG holds only the
  public key.
