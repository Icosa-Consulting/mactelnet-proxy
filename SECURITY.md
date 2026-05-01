# Security Policy

## Supported versions

`mactelnet-proxy` is in active pre-release development. Only the
latest published tag receives security fixes; prior tags are
historical only.

| Version  | Status            |
|----------|-------------------|
| 0.1.x    | latest minor — supported |
| < 0.1.0  | unsupported       |

Once the project reaches 1.0 the support window will widen; until
then, upgrade to the latest tag to pick up fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security bugs.**

Use GitHub's **[Private Vulnerability Reporting](https://github.com/icosa-consulting/mactelnet-proxy/security/advisories/new)**
flow (Security tab → "Report a vulnerability"). This creates a
private advisory that only the maintainers and the reporter can see,
and lets us coordinate a fix and a public disclosure together.

What to include in the report:

- A description of the vulnerability and its impact.
- The version (`mactelnet-proxy version`) and platform you observed
  it on.
- A minimal reproduction or proof-of-concept, if you have one.
- Any suggested fix or mitigation, if you've identified one.

What to expect:

- An acknowledgment within 7 days (best effort — this is a small
  project).
- A status update within 30 days, including a fix timeline if the
  report is accepted.
- A coordinated disclosure: we cut a fix release, then publish the
  advisory together. Reporters are credited unless they ask to
  remain anonymous.

## Threat model

The proxy is intended to sit between an untrusted-network SSH
client and a trusted Layer-2 broadcast domain that contains MikroTik
devices.

What the proxy trusts:

- Anyone in possession of a private key whose public half is in
  `<KEYS_DIR>/authorized_keys` is treated as authorized to issue
  any of the three exec commands (`mactelnet`, `mndp`, `ifaces`)
  against any device on the L2 segment. There is no per-key
  authorization beyond the SSH layer.
- The L2 segment itself: MAC-Telnet is a clear-text-over-broadcast
  protocol, so anyone with read access on the segment can
  observe sessions. The proxy doesn't add transport encryption to
  MAC-Telnet — that's a property of the protocol, not a project
  decision.
- The RouterOS device's identity is verified only by MAC address
  (the protocol gives us no stronger handle).

What the proxy does **not** trust:

- The network on the SSH side: SSH host-key auth is the only
  endpoint identity check; clients should pin the proxy's host
  key fingerprint (see the
  [SSH CLI Usage wiki page](https://github.com/icosa-consulting/mactelnet-proxy/wiki/SSH-CLI-Usage)).
- Filesystem state outside `KEYS_DIR`: `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices`, and a confined
  `ReadWritePaths=/etc/mactelnet-proxy` keep the daemon from
  writing anywhere unexpected.
- Capabilities beyond `CAP_NET_RAW` + `CAP_NET_BIND_SERVICE`:
  `CapabilityBoundingSet` enforces this even though the unit runs
  as root. The optional VRF drop-in widens the bounding set to
  `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` — applies only when that
  drop-in is installed.

## Out of scope

The following are not considered vulnerabilities for this project:

- **MAC-Telnet protocol weaknesses inherited from upstream RouterOS.**
  This proxy is wire-compatible with `/tool mac-telnet`; protocol-
  level issues (clear-text-over-broadcast, MD5/EC-SRP design choices)
  are upstream concerns. Report them to MikroTik.
- **Misconfiguration that exposes a key with broader scope than
  intended** (e.g. pasting a key into `authorized_keys` whose holder
  shouldn't have proxy access). The proxy honors what's in the file;
  managing that file is operator responsibility.
- **Denial-of-service via SSH connection flooding.** The proxy
  doesn't currently rate-limit; reverse-proxy or firewall it if you
  need that. We may revisit once the project stabilizes.
- **Anything reachable only by an attacker who already has root on
  the proxy host.** If they're on the box, the daemon's hardening
  isn't the boundary.

## Dependencies and known-vulnerability scanning

`make vulncheck` runs
[`govulncheck`](https://go.dev/security/vuln) against the official Go
vulnerability database for every build. The dependency surface is
small on purpose — only Go stdlib + `golang.org/x/crypto`.
