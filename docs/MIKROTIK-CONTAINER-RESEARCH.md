# MikroTik RouterOS Container — Deep Dive

Research compiled 2026-05-02 against RouterOS 7.22 stable / 7.23rc2 testing,
with live-hardware verification on RouterOS 7.21.4 / RB5009 finalized
2026-05-02. The single best community resource is the [Container Limitations
wiki](https://tangentsoft.com/mikrotik/wiki?name=Container+Limitations) on
tangentsoft.com — most of this report cross-references it.

## TL;DR — verified on hardware

Live-hardware tests on **RB5009 (arm64) running RouterOS 7.21.4** with the
proxy running in a stock RouterOS container, confirmed:

- ✅ **AF_PACKET / SOCK_RAW works** — the `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))`
  call succeeds and sent frames make it onto the bridge. This was the
  big-unknown blocker pre-test; it isn't.
- ✅ **NETLINK_ROUTE works** — `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`
  succeeds, so route-table lookups for source-IP selection work.
- ✅ **MNDP works** — plain UDP/5678 broadcast send/receive succeeds.
- ✅ **mac-telnet client works end-to-end** to a target on the *same* L2
  segment as the container's veth (auth, session, terminal I/O all clean).
- ✅ **`docker save` → `/container/add file=` works directly** for single-stage
  Alpine arm64 images. No skopeo conversion needed in this configuration.
- ⚠ **Bridges with `vlan-filtering=yes`** require code-side 802.1Q support in
  the proxy. RouterOS has no Linux VLAN sub-interface mechanism, so the
  kernel can neither auto-tag outbound frames nor auto-strip inbound tags
  for a regular UDP socket. The proxy gained `--vlan` (commit pending) for
  this reason; see §2l for the why.

What we still haven't tested:
- Other architectures (only arm64 was exercised).
- Other RouterOS versions (only 7.21.4).
- Other devices (only RB5009).
- arm32v5 EN7562CT chips remain a no-go because the proxy's `armhf`
  Dockerfile builds with `GOARM=7`, not v5.

## 1. Feature scope & current state

- **Introduced:** RouterOS v7.4beta. Stable since the 7.x series.
- **Status:** Stable but explicitly disabled by default. Enabling requires *physical access* to the device — not just admin-over-network — to flip the flag.
- **Package size:** `container.npk` is **0.18 MiB** (Docker Engine is 422 MiB, for reference). It is "custom development written in-house by MikroTik, not a copy of Docker Engine."
- **Architectures supported:** **arm, arm64, x86 only.** No MIPS, PowerPC, or TILE.
  - ARM-based MikroTik devices fall in two camps: arm64 (RB5009, CCR2004, etc.) and arm32. Among arm32, devices with the **EN7562CT CPU** (hEX Refresh, hEX S Refresh, hAP ax S) are **arm32v5** — a "seriously old tech" architecture with very few base images available.
- **License level:** No specific level called out in the docs; the `container` package is just an additional `.npk`.
- **Storage requirement:** External disk recommended at "≥100 MB/s sequential, ≥10K random IOPS." Internal NAND is **explicitly discouraged** for container volumes — wear concerns plus speed.
- **RAM warning for remote pulls:** "Using remote-image functionality requires a lot of free space in main memory; 16 MB SPI flash boards may use pre-built images on USB or other disk media."

Sources: [MikroTik docs — Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container), [Container Limitations wiki](https://tangentsoft.com/mikrotik/wiki?name=Container+Limitations).

## 2. Quirks vs. standard Docker / OCI

### 2a. Image format / pull source

- Pull uses `/container/add remote-image=…`. Default registry is `https://lscr.io/`; can be reset with `/container/config/set registry-url=…`.
- **Single registry login only** (one `username/password` pair globally, not per-image).
- **No local image cache.** Pull happens at `add` time; if you delete the container you lose the image. Pulling the same image to instantiate two containers downloads it twice.
- **No `docker push` / `docker tag` / `docker history`.**
- **OCI tarball compatibility is fragile** in the general case. Default `docker save` produces a layout MikroTik won't import in many configurations; the community workaround is `skopeo copy docker-archive:in.tar docker-archive:out.tar`, which produces a "more complicated internal structure" RouterOS accepts ([forum thread](https://forum.mikrotik.com/t/docker-built-containers-wont-work-on-mikrotik/180943)). **However**, our live test on arm64 with a single-stage Alpine image built via `docker buildx build --platform linux/arm64 --output=type=docker` imported cleanly via `/container/add file=…` *without* any skopeo step. The tarball-format failures appear concentrated on multi-arch manifests, multi-stage builds saved with the OCI exporter, or arm32 targets — single-platform single-stage arm64 just works.
- **No multi-arch manifest support.** You must hand-pick the right-arch tag yourself.
- **No image build on device.** No `buildx`, no `Dockerfile` runner. You build off-device, save, skopeo-convert, upload via `/file`, then `/container/add file=…`.

### 2b. Networking model

The RouterOS networking model is fundamentally different from Docker's:

- All container networking goes through **`/interface/veth/add`** — a virtual ethernet pair. The veth has its own IP and MAC.
- The veth must be plugged into either:
  1. **A bridge with NAT** (default in the docs). RouterOS NATs container traffic. EXPOSE'd ports require manual `dstnat` rules.
  2. **An isolated bridge** for container-to-container only.
  3. **The LAN bridge directly** (bridged-VETH). Container appears as a regular L2 host on the LAN. ([Bridged VETH wiki](https://tangentsoft.com/mikrotik/wiki?name=Bridged+Container+VETH))
- There is **no `--network=host`** equivalent. The closest is bridged-VETH, but the container still has its own MAC and goes through veth, not the physical interface directly.
- **WiFi incompatible with bridged-VETH** — the extra MAC over a single wireless link "confuses access points, causing performance degradation."
- **Hardware offload disabled** when a software interface (veth) joins a bridge. Acceptable on router-class hardware, painful on switch-class.
- Performance regression reports: ["Adding veth slows internet"](https://forum.mikrotik.com/viewtopic.php?t=196518) — adding a veth interface for a container can degrade throughput even when the container is stopped.

### 2c. Volume mounts / persistence

- `/container/mounts/add list=NAME src=disk1/foo dst=/data` then `/container/add mountlists=NAME …`.
- **Bind mounts only.** No named volumes, no volume drivers.
- **Pre-7.20 you could only mount entire directories.** 7.20+ adds single-file mounts.
- **File ownership becomes "root" on ext4 host volumes.** Workaround: format the disk as exFAT (`/disk/format-drive file-system=exfat`).
- If the `src` directory doesn't exist, MikroTik populates it on first run from whatever was at `dst` in the image — a useful but surprising behaviour.

### 2d. Init / PID 1 / signals / restart

- Containers run with the image's `ENTRYPOINT` as PID 1. No `--init` flag.
- **Restart policy is new.** Pre-7.23β you had to script `start-on-boot=yes` plus a polling watchdog. RouterOS 7.23β+ adds a real `restart-policy` parameter.
- **No `docker restart`.** You stop, then start, manually. No grace-period kill (`docker kill` vs `docker stop`).
- 7.22 added healthcheck-* parameters for in-container health checks.

### 2e. Capabilities (NET_RAW / NET_ADMIN)

The documentation is thin, but live testing on RouterOS 7.21.4 / RB5009
gave us concrete answers:

- The tangentsoft wiki notes containers run "as a nerfed `root` user" — meaning user-namespaced, not actual host-root.
- There is **no documented way to grant or restrict Linux capabilities per container.** No `--cap-add`, no seccomp, no AppArmor toggles.
- ✅ **NET_RAW / AF_PACKET works.** Confirmed via strace: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))` succeeds, and frames sent through it actually reach targets on the bridged-VETH path. The "nerfed root" appears to retain `CAP_NET_RAW` by default (or RouterOS just doesn't drop it). This was the biggest unknown pre-test; it's now a confirmed-working primitive.
- ✅ **NETLINK_ROUTE works.** `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` and `bind(...)` both succeed, so the proxy's source-IP selection (which queries the routing table) functions normally.
- ❓ **CAP_NET_ADMIN remains untested.** We don't need it for the mactelnet-proxy path, but anything that wants to create/modify interfaces (e.g., `ip link add ... type vlan`) probably can't. RouterOS isn't going to let containers touch the host's interface set, and there's no kernel sub-interface mechanism RouterOS exposes — see §2l.

The implication for any project considering RouterOS-container deployment: the standard "set up Linux VLAN sub-interfaces and use them as L2 endpoints" pattern doesn't work, but raw L2 access from userspace **is** available, so apps that want to construct frames themselves (instead of relying on kernel VLAN handling) can do so.

### 2f. Multicast / broadcast

- Forum threads exist but they're about RouterOS proper (PIM-SM, IGMP), not specifically about containers ([sample 1](https://forum.mikrotik.com/t/multicast-problems/263004)).
- ✅ **UDP broadcast confirmed working** in live testing — MNDP's `setsockopt(SO_BROADCAST, 1)` plus `bind(0.0.0.0:5678)` plus broadcast send all succeed, and broadcast frames cross the bridged-VETH path in both directions.
- The bridged-VETH model puts the container's veth on the same broadcast domain as the LAN, so broadcast and multicast propagate as expected. Combined with the §2e finding that AF_PACKET works, raw L2 use cases (MNDP listener, custom protocols, packet sniffers) are viable inside the container.

### 2g. IPv6

- Not specifically called out as broken, but the docs mostly use v4 examples. No reports of v6 inside containers being missing.

### 2h. Logging

- **Container topic isn't enabled in default logging.** You have to add it: `/container/add … logging=yes` plus `/system/logging add topics=container action=…`.
- **stdout vs stderr is not distinguished.** RouterOS doesn't surface that distinction anywhere.
- **Logs go to volatile RAM by default** (to spare flash). Survives reboot only if you set up disk logging.
- 7.20 adds `/container/log` — a per-container ring buffer of the last 100 messages held in memory.
- "No `docker logs --follow`" — closest is `/container/print follow*`.

### 2i. USB / device passthrough

- Pre-7.20: only via mounts or pre-existing kernel drivers.
- 7.20+: `/system/hardware` lists mappable devices, passable via `device=…` on `/container/add`.
- 7.23β+: USB audio devices added.
- **No GPU passthrough** even on x86. RouterOS doesn't ship GPU drivers.

### 2j. DNS

- Containers see whatever DNS is configured on the host (via DHCP on the veth or static). No special quirks.

### 2k. Memory limits & OOM

- Pre-7.20: `ram-high=…` was **global** across all containers.
- 7.20+: per-container limits.
- 7.21+: CPU-subset (`--cpuset-cpus`) equivalent.
- **Still missing:** `--cpu-quota`, `--cpu-shares`, `--pids-limit`, `--ulimit`, `/dev/shm` size, FD limits, IOPS caps.

### 2l. Bridge VLAN-filtering and the container netns interface restriction

This one isn't documented anywhere we found and bit us during testing —
it's the single most surprising RouterOS-specific quirk for L2-aware
container apps:

- RouterOS bridges support `vlan-filtering=yes` for proper 802.1Q
  segmentation. A bridge port can have a `pvid=N` (incoming-untagged
  classification) and per-VLAN `tagged`/`untagged` membership lists.
- When a container's veth is a bridge port with `pvid=N` and the rest
  of the bridge configuration delivers traffic on VLAN N to the veth
  tagged (e.g. via the VLAN egress configuration of other ports), the
  container sees 802.1Q-tagged Ethernet frames on its veth.
- On a normal Linux host this is solved with `ip link add link veth1
  name veth1.N type vlan id N` — the kernel creates a sub-interface
  that auto-strips/tags VLAN traffic, and userspace just opens regular
  UDP sockets on it. RouterOS itself supports VLAN sub-interfaces on
  veths in the *host* (RouterOS) network namespace.
- **The container's network namespace only accepts veth-type
  interfaces.** RouterOS will not move a VLAN sub-interface, a bridge,
  or a physical interface into the container's netns; only the
  container-end of a veth pair lives in there. So even if you create
  a `veth1.20` on the RouterOS side, you can't expose it to the
  process inside the container — the container only sees its own
  veth endpoint.
- **The only working pattern is application-side 802.1Q.** The
  container app must build outbound Ethernet frames with an inserted
  4-byte 802.1Q tag (TPID 0x8100, TCI=PCP|DEI|VID), and on receive it
  must read raw frames from AF_PACKET and parse the tag itself. UDP
  sockets won't work because the kernel inside the container never
  sees an inner UDP datagram — its EtherType filter sees 0x8100 and
  demuxes the frame as "VLAN", which goes nowhere without a
  sub-interface inside the namespace.
- For mactelnet-proxy specifically this drove the addition of the
  `--vlan` flag (and `MACTELNET_PROXY_VLAN` env), which makes the
  proxy emit and consume 802.1Q-tagged frames natively.

If you're evaluating a different containerized app for RouterOS and it
needs to live on a vlan-filtered bridge, ask early whether the app has
its own 802.1Q implementation. If not, you'll either rebuild the bridge
without VLAN filtering, or add tagging support to the app yourself.

## 3. Broken-or-missing features that work fine in regular Docker

Subset (not exhaustive) of the [tangentsoft missing-commands matrix](https://tangentsoft.com/mikrotik/wiki?name=Container+Limitations):

| Docker feature | Status on RouterOS |
|---|---|
| `docker build` | Unavailable. Build off-device. |
| `docker compose` | Partially supported via `/app` (RouterOS 7.22+); subset of the spec, custom-implemented. |
| `docker exec -it` | RouterOS 7.20+ via `/container/shell`; 7.21+ via `/container/run`. Multi-step, not a one-liner. |
| `docker attach` | Unavailable. RouterOS terminal model can't expose pty/termios that way. |
| `docker logs --follow` | Workaround via logging config. |
| `docker cp` | Unavailable. Mount a volume + use `/file`. |
| `docker pull` (separate from run) | Unavailable. Pull is bound to `add`. |
| `docker push` | Unavailable (no image cache). |
| `docker tag` | Unavailable (rebuild required). |
| `docker history` | Unavailable. |
| `docker stats` / `top` | Partial. |
| `docker network create` | Unavailable. Use RouterOS networking. |
| `docker secret` | Unavailable. Use envs or bind-mounted files. |
| Health checks | RouterOS 7.22+ adds `healthcheck-*` parameters. |
| `--restart` policy | RouterOS 7.23β+ only. |
| `--rm` (auto-cleanup) | Unavailable. |
| `--user` / `--group-add` | Unavailable. |
| `--cap-add` / `--cap-drop` | Unavailable. |
| Seccomp / AppArmor profiles | Unavailable. |
| Multi-arch `manifest` lists | Unavailable. Pick the right arch tag yourself. |
| Image signing / provenance verification | Unavailable. |
| Swarm / k8s / k3s | Out of scope by design. |

## 4. Community sentiment

From the tangentsoft "Containers Are Not VMs" wiki and forum reading:

- **The dominant tone is "use sparingly, for narrow purposes."** The community framing is "don't expect this to replace a Docker host."
- **Common pain point #1:** image-format incompatibility ([forum](https://forum.mikrotik.com/t/docker-built-containers-wont-work-on-mikrotik/180943)). Newcomers expect `docker save | upload | done`; reality involves skopeo and head-scratching.
- **Common pain point #2:** non-descriptive errors. *"container latest:latest exited, status: 255"* without further context. Typical for users of [metube and openspeedtest](https://forum.mikrotik.com/t/why-do-only-some-containers-work-on-mikrotik/264728).
- **Common pain point #3:** networking. *"Why does Mikrotik always use VETH in a bridge?"* ([forum](https://forum.mikrotik.com/t/why-does-mikrotik-always-use-veth-in-a-bridge/168334)) — the model works but isn't intuitive coming from Docker.
- **Common pain point #4:** resource exhaustion on small devices. fail2ban alone uses ~half of a 128 MiB device's flash.
- **Common pain point #5:** no good update flow. Pre-7.22 had no `repull`; the workaround was delete-and-recreate, which destroyed the running container's state.
- **Production usage:** mostly hobbyist / homelab / Pi-hole + AdGuard / Wireguard. Production network operators deploy services on dedicated Linux hosts adjacent to the MikroTik, not inside it.
- **The "you'll regret this" warning:** running anything that wants to phone home / pull updates / log heavily / have a real init system. RouterOS containers are best as "single-binary microservices that read-only their config from envs."

## 5. Known workarounds

(Inline with each limitation above; the consolidated set:)

- **Image format problems** → skopeo conversion (general); not needed for single-stage Alpine arm64 images saved with `docker buildx build --platform linux/arm64 --output=type=docker`.
- **NET_RAW / AF_PACKET access** → just works on tested config (RouterOS 7.21.4 / RB5009). No `--cap-add` flag needed because RouterOS doesn't drop CAP_NET_RAW from the container's effective set.
- **Bridge with `vlan-filtering=yes`** → application-side 802.1Q tagging. Build/parse the tag in the app; you can't ask the kernel inside the container to do it. See §2l.
- **No `docker run` one-liner** → multi-line script: env list, mount list, add, run.
- **No image cache** → pre-pull via off-device build, save, upload as tarball.
- **No restart policy pre-7.23** → `start-on-boot=yes` plus a polling script that detects exited state and restarts.
- **No health checks pre-7.22** → external `/fetch` polling with stop/start remediation.
- **No multi-container** → single container with multi-process supervisor (s6, runit) inside; community frowns on this but people do it.
- **Slow internal storage** → external USB/NVMe.
- **Wrong file ownership on bind mounts** → exFAT-format the disk.

## 6. Roadmap / promised features

The pattern is clear from the version history: each minor release adds 1–3 container features. The MikroTik changelog is the authoritative source.

Recently shipped (per [v7.22 announcement](https://forum.mikrotik.com/t/v7-22-stable-is-released/269092)):
- 7.20: per-container RAM limits, single-file mounts, `/container/log` ring buffer, `interactive`/`tty` flags.
- 7.21: `/container/run`, `--cpuset-cpus` equivalent, `docker exec`-style flow.
- 7.22 (current stable, 2026-Q1): healthcheck-* parameters, `/app` compose-file subset, `/container/repull`.
- 7.23 (testing rc2 as of 2026-04-23): `restart-policy` parameter, USB audio passthrough.

What's still on community wishlists but not committed:
- `docker build` on device (probably never — explicit design choice).
- Multi-arch manifest auto-selection.
- `--cap-add` / `--cap-drop`.
- True host networking (`--network=host`).
- Local image cache.
- `docker compose` parity beyond the current subset.

MikroTik don't publish a public roadmap document; commitments come via release notes and MUM presentations. None of the wishlist items have been publicly promised in those venues to my knowledge.

## 7. Specific to mactelnet-proxy

Your requirements vs RouterOS container reality (verified on RB5009 / 7.21.4):

| Requirement | Verdict |
|---|---|
| Raw L2 socket on a physical interface (MNDP, mactelnet) | ✅ **Works.** `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))` succeeds, and frames sent through it reach targets on the same L2 segment. The container's `eth0` is the veth endpoint, which the bridge wires onto the LAN. CAP_NET_RAW is in the effective set; we did not have to do anything special to get it. |
| TCP port 222 (embedded SSH server) | ✅ Works. EXPOSE is ignored, so add `dstnat` for inbound and a firewall rule for the listening side. |
| Persistent storage for SSH host key + authorized_keys | ✅ Works. One-line bind mount; recommend external USB and exFAT to avoid the root-ownership issue. |
| IPv4 broadcast send/receive (MNDP) | ✅ Works. UDP/5678 with `SO_BROADCAST` confirmed via strace and end-to-end MNDP discovery on the bridged-VETH path. |
| Outbound UDP to fleet on same L2 segment | ✅ Works. |
| Inbound UDP from those devices | ✅ Works (no inbound NAT needed in bridged-VETH mode). |
| Bridge with `vlan-filtering=yes` and `pvid=N` on the veth | ⚠ Requires the proxy to do its own 802.1Q tagging. Use `--vlan N` (or `MACTELNET_PROXY_VLAN=N`). RouterOS won't pass a VLAN sub-interface into the container's netns — only veths can live there — so the kernel can't auto-tag/strip for plain UDP sockets. See §2l. |
| Where it can still choke | (1) WiFi-only deployments — the bridged-VETH model breaks on wireless links. Hardware fleets are wired so this is fine for the proxy's typical placement. (2) The device must be arm64 or x86; arm32v5 (EN7562CT) is a no-go because the proxy's existing armhf Dockerfile uses ARMv7 (`GOARM=7`), not v5. (3) Reaching downstream devices across L3 hops — that's a mac-telnet protocol limitation, not a RouterOS one (mac-telnet is L2-only by design). Run a separate proxy on each L2 segment that contains MikroTik devices. |
| Smallest device it could run on | Proxy ~15 MB + Alpine ~5 MB ≈ 20 MB image; with diagnostic tools added (~8 MB) ≈ 28 MB. Add log buffers + SSH key dir → 30-40 MB persistent storage. **A RB5009 (arm64, 1 GB RAM, eMMC + USB) is comfortable** — that's where we tested. A hAP ac3 (arm, 256 MiB flash/RAM) might work with USB storage but the bridged-VETH softpath is a measurable hit on its softswitch. Anything smaller and you'd want to run the proxy on a separate Pi/x86 box and point NetCFG at it over the network. |

### Recommendation

The RouterOS container is a **supported deployment target** for the proxy
on RB5009-class arm64 hardware running 7.21.4 or later. Production
checklist:

1. Build with `docker buildx build --platform linux/arm64
   --output=type=docker -t mactelnet-proxy:vX.Y .` then `docker save
   mactelnet-proxy:vX.Y -o proxy.tar`. No skopeo step needed for
   single-stage Alpine arm64.
2. Upload to the device: `/file/print` to confirm space, then SCP/FTP
   the tarball to `disk1/proxy.tar`.
3. Create the veth and add it to the LAN bridge (or whichever bridge
   carries the MikroTik fleet). Set the appropriate `pvid=` if the
   bridge is vlan-filtered.
4. Mount lists for the keys directory (`/etc/mactelnet-proxy` →
   `disk1/proxy/keys`) — exFAT-format the disk to avoid the root-owned
   files quirk.
5. Env vars: `MACTELNET_PROXY_LISTEN=0.0.0.0:222`,
   `MACTELNET_PROXY_INTERFACE=eth0` (the container's view of the veth),
   and `MACTELNET_PROXY_VLAN=N` if the bridge is vlan-filtered. Add
   `MACTELNET_PROXY_DEBUG=1` for the first run.
6. Add and start: `/container/add file=disk1/proxy.tar interface-list=…
   envlist=… mountlists=…`.
7. Open RouterOS port-forward for SSH (`/ip/firewall/nat add chain=dstnat
   protocol=tcp dst-port=222 action=dst-nat to-addresses=<veth-ip>`).
8. Try MNDP discovery and a mactelnet to a known device on the bridge
   from a NetCFG box pointed at the proxy.

For deployments outside that envelope (other RouterOS versions, other
device classes, x86), strace inside the container at first run is the
fastest way to surface anything unexpected — `/container/shell <name>`
plus `strace -fe socket,bind,setsockopt /usr/local/bin/mactelnet-proxy
…` was the workflow that confirmed each layer during initial bring-up.

---

## Sources

Primary:
- [MikroTik docs — Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)
- [MikroTik docs — Containerized App management](https://help.mikrotik.com/docs/spaces/ROS/pages/343244823/Containerized+App+management)
- [tangentsoft — Container Limitations](https://tangentsoft.com/mikrotik/wiki?name=Container+Limitations)
- [tangentsoft — Bridged Container VETH](https://tangentsoft.com/mikrotik/wiki?name=Bridged+Container+VETH)
- [tangentsoft — Containers Are Not VMs](https://tangentsoft.com/mikrotik/wiki?name=Containers+Are+Not+VMs)
- [tangentsoft — Musings on Docker](https://tangentsoft.com/mikrotik/wiki?name=Musings+on+Docker)

Forum threads referenced:
- [Docker built containers won't work on Mikrotik](https://forum.mikrotik.com/t/docker-built-containers-wont-work-on-mikrotik/180943)
- [Why do only some containers work on Mikrotik?](https://forum.mikrotik.com/t/why-do-only-some-containers-work-on-mikrotik/264728)
- [Why does Mikrotik always use VETH in a bridge?](https://forum.mikrotik.com/t/why-does-mikrotik-always-use-veth-in-a-bridge/168334)
- [Adding veth slows internet](https://forum.mikrotik.com/viewtopic.php?t=196518)
- [Cannot ping from console VETH interface in containers bridge](https://forum.mikrotik.com/t/cannot-ping-from-console-veth-interface-in-containers-bridge/178730)
- [Container "could not acquire interface" in v7.20.2](https://forum.mikrotik.com/t/container-couldnot-acquire-interface-in-v7-20-2/265948)
- [Multiple VETH per container](https://forum.mikrotik.com/t/multiple-veth-per-container/164471)
- [Recommend Mikrotik for running Container](https://forum.mikrotik.com/t/recommend-mikrotik-for-running-container/176689)
- [Container — import docker compose file feature?](https://forum.mikrotik.com/t/container-import-docker-compose-file-feature/169807)
- [V7.22 stable release](https://forum.mikrotik.com/t/v7-22-stable-is-released/269092)
