// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Net helpers for the MAC-Telnet client.
//
// Two sockets per session:
//
//   recvConn  — *net.UDPConn bound to 0.0.0.0:20561, SO_REUSEADDR/PORT
//               so multiple sessions on the host can share the well-known
//               port. Receives the device's broadcast replies.
//
//   rawSender — SOCK_RAW + IP_HDRINCL socket. We hand-build the full
//               IP+UDP header so we can put src=0.0.0.0 / dst=255.255.255.255
//               on the wire — the upstream-compatible address pair that
//               RouterOS mac-server expects (and replies to). A regular
//               UDP socket can't do this; the kernel always fills the
//               source IP from the bound socket.
//
// CAP_NET_RAW is required for SOCK_RAW + SO_BINDTODEVICE; the proxy's
// systemd unit / Dockerfile already grants it.

// soReusePort is the SOL_SOCKET option for SO_REUSEPORT on Linux. The Go
// stdlib doesn't export it; the value is stable (Linux 3.9+, value 15).
const soReusePort = 15

// resolveInterface looks up the local interface by name and returns its
// *net.Interface (for ifindex + hardware address). Empty name is an
// error — auto-discovery (the upstream `find_interface` dance that
// sends SESSIONSTART on every interface and picks the one that answers)
// is intentionally not ported.
//
// We do NOT require the interface to have an IPv4 address. The L2-raw
// send path (PF_PACKET) doesn't go through the IP routing layer, the
// IP header carries src=0.0.0.0 anyway, and the receive socket is bound
// to 0.0.0.0 — so a vlan/veth/bond child with no IPv4 of its own works
// fine as long as it has a usable hardware address.
func resolveInterface(name string) (*net.Interface, error) {
	if name == "" {
		return nil, fmt.Errorf("mactelnet: interface name required")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("mactelnet: interface %q: %w", name, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("mactelnet: interface %q has no usable hardware address", name)
	}
	return iface, nil
}

// rxConn is the read side of one MAC-Telnet session. Two implementations:
//
//   *udpRxConn   — wraps net.UDPConn, used when vlanID == 0. The kernel's
//                  IP/UDP demux delivers payload-only bytes; cheapest path
//                  and untouched by the VLAN refactor.
//   *rawReceiver — wraps an AF_PACKET fd bound to a single interface, used
//                  when vlanID > 0. Reads full Ethernet frames, parses the
//                  802.1Q tag, filters by the configured VLAN ID, then
//                  parses IP+UDP and returns the UDP payload — the same
//                  bytes the UDP path would have returned.
//
// rxLoop only sees this interface; the rest of the protocol code is
// unchanged regardless of which receiver is in use.
type rxConn interface {
	Read(buf []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// openSockets opens the receive socket and the raw L2 send socket for
// one MAC-Telnet session. iface supplies both the Linux ifindex (egress
// selector) and the source MAC put into the Ethernet header. vlanID > 0
// switches the receive path from net.UDPConn to AF_PACKET so 802.1Q
// tags can be parsed/filtered by the proxy itself.
func openSockets(iface *net.Interface, vlanID uint16) (rxConn, *rawSender, error) {
	var (
		recv rxConn
		err  error
	)
	if vlanID != 0 {
		recv, err = openRawReceiver(iface, vlanID)
	} else {
		recv, err = openRecv()
	}
	if err != nil {
		return nil, nil, err
	}
	sender, err := openRawSender(iface, vlanID)
	if err != nil {
		recv.Close()
		return nil, nil, err
	}
	return recv, sender, nil
}

// openRecv binds a UDP/20561 listener on 0.0.0.0 with
// SO_REUSEADDR/SO_REUSEPORT so multiple in-process sessions can share
// the well-known port. The receive side accepts any destination IP
// (including 255.255.255.255) because INADDR_ANY doesn't filter on dst.
func openRecv() (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if sockErr == nil {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", udpPort))
	if err != nil {
		return nil, fmt.Errorf("mactelnet: bind UDP/%d: %w", udpPort, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("mactelnet: expected *net.UDPConn, got %T", pc)
	}
	return conn, nil
}

// rawSender wraps a PF_PACKET / SOCK_RAW socket used to emit MAC-Telnet
// datagrams with a hand-built Ethernet + IP + UDP frame. We go this
// deep (rather than AF_INET + SOCK_RAW + IP_HDRINCL) because Linux
// rewrites the IP source address to the egress-interface IP under
// IP_HDRINCL — that produces `<ifaceIP> > 255.255.255.255` on the wire,
// while RouterOS mac-server expects `0.0.0.0 > 255.255.255.255`. With
// AF_PACKET the kernel does not touch our bytes; the frame goes out
// exactly as built.
//
// L2 destination is the target's MAC (L2 unicast), not the broadcast
// MAC — verified against upstream `interfaces.c:net_send_udp` and
// against pcap traces of the working `/tool mac-telnet` flow on a
// CCR2116. Some L2 paths (broadcast suppression, hardware-MAC-rule
// filtering on CRS-class switches) drop broadcast UDP/20561 frames
// while passing unicast frames addressed to a known host.
type rawSender struct {
	fd      int
	ifindex int
	srcMAC  [6]byte
	ipID    uint16

	// vlanID is the 802.1Q VLAN identifier (1–4094) inserted into every
	// outbound Ethernet frame. Zero means "no tag" — the frame leaves
	// the wire as a plain Ethernet/IP frame, identical to the pre-VLAN
	// behaviour. Non-zero adds a 4-byte 802.1Q header (TPID 0x8100 +
	// TCI=vlanID) between the source MAC and the original EtherType.
	//
	// Used in deployments where the proxy's interface (typically a
	// veth into a RouterOS bridge with vlan-filtering or
	// frame-types=admit-only-vlan-tagged) requires tagged frames at
	// the link layer; the kernel won't tag for us because RouterOS has
	// no Linux VLAN sub-interfaces and we can't synthesize one inside
	// the container without CAP_NET_ADMIN.
	vlanID uint16

	// sendErrCount counts non-nil sendto() returns. We log the first
	// failure at WARN (so EPERM in a restricted runtime becomes visible
	// without a debug flag) and every Nth thereafter at DEBUG to avoid
	// flooding when an interface is down for a sustained period.
	sendErrCount atomic.Uint64
}

// htons converts u16 to network byte order without pulling in net.
func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0xff }

// ethPIP is ETH_P_IP (0x0800) — the Ethertype for IPv4. Using a literal
// here avoids depending on golang.org/x/sys/unix for one constant.
const ethPIP = 0x0800

// ethP8021Q is the TPID (Tag Protocol Identifier) for 802.1Q VLAN tags
// (0x8100). When a frame is tagged, this 16-bit value sits where the
// EtherType normally would, followed by a 16-bit TCI and then the real
// EtherType. We don't use Q-in-Q (0x88a8) — single tag is enough for
// the RouterOS bridge use case.
const ethP8021Q = 0x8100

// openRawSender opens a PF_PACKET / SOCK_RAW socket scoped to one
// interface. The protocol filter is ETH_P_IP because we only emit IPv4
// frames; receive of broadcast replies stays on the regular UDP socket.
//
// vlanID, if non-zero, is the 802.1Q VLAN identifier inserted into
// every outbound frame; zero means untagged (legacy behaviour).
func openRawSender(iface *net.Interface, vlanID uint16) (*rawSender, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPIP)))
	if err != nil {
		return nil, fmt.Errorf("mactelnet: AF_PACKET SOCK_RAW: %w", err)
	}
	r := &rawSender{fd: fd, ifindex: iface.Index, vlanID: vlanID}
	copy(r.srcMAC[:], iface.HardwareAddr)
	return r, nil
}

// Send wraps payload in an Ethernet + IP + UDP frame and emits it
// straight onto the wire. Addresses are fixed except for the L2 dst:
//
//	Ethernet: src = our iface MAC, dst = the supplied target MAC
//	IP:       src = 0.0.0.0,       dst = 255.255.255.255
//	UDP:      src port = dst port = 20561
//
// L2-unicast (dst = target MAC) matches upstream
// `interfaces.c:net_send_udp`. Bridges along the path then forward via
// their MAC table directly to the target's port — broadcast suppression,
// storm-control, and loop-protection rules that drop L2-broadcast
// frames still let unicasts addressed to a known host through.
//
// Errors from the underlying Sendto are returned and logged. Common
// failure modes worth recognising in the log:
//   - EPERM:    the runtime didn't grant CAP_NET_RAW (e.g. RouterOS
//               container, unprivileged user, restrictive seccomp).
//   - ENETDOWN: chosen interface is admin-down at the moment.
//   - ENXIO:    interface ifindex no longer exists (renamed/removed).
func (r *rawSender) Send(payload []byte, dstMAC [6]byte) error {
	r.ipID++ // monotonically-increasing IP ID per upstream convention
	pkt := buildFrame(r.srcMAC, dstMAC, r.vlanID, r.ipID, payload)
	// SockaddrLinklayer.Protocol is the *outer* EtherType the kernel
	// uses to dispatch the frame; tagged frames present 0x8100 to the
	// wire, untagged frames present 0x0800.
	outerEth := uint16(ethPIP)
	if r.vlanID != 0 {
		outerEth = ethP8021Q
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(outerEth),
		Ifindex:  r.ifindex,
		Halen:    6,
	}
	copy(addr.Addr[:6], dstMAC[:])

	if err := syscall.Sendto(r.fd, pkt, 0, addr); err != nil {
		n := r.sendErrCount.Add(1)
		switch n {
		case 1:
			slog.Warn("mactelnet: AF_PACKET sendto failed",
				"err", err, "ifindex", r.ifindex, "len", len(pkt))
		default:
			slog.Debug("mactelnet: AF_PACKET sendto failed (repeat)",
				"err", err, "count", n)
		}
		return err
	}
	return nil
}

// Close releases the raw socket fd.
func (r *rawSender) Close() error {
	return syscall.Close(r.fd)
}

// rawReceiver is the AF_PACKET-based read side used when the proxy is
// configured with a non-zero VLAN ID. RouterOS doesn't expose Linux VLAN
// sub-interfaces, so the kernel never strips the 802.1Q tag from frames
// arriving on our veth — a regular UDP/20561 socket would never see the
// inner UDP datagrams. We therefore read full Ethernet frames, parse the
// 802.1Q tag, filter by VID, then parse IP+UDP and return the UDP
// payload (which is what the rest of the rxLoop expects).
type rawReceiver struct {
	fd        int
	vlanID    uint16
	srcMAC    [6]byte // our own MAC — used to drop frames we sent
	closeOnce sync.Once
	closed    atomic.Bool
}

// openRawReceiver opens a PF_PACKET / SOCK_RAW socket bound to iface.
// We bind to ETH_P_ALL (passes both 0x8100 tagged and 0x0800 untagged
// frames to userspace) and filter by VLAN ID + dst MAC + UDP port in
// software — the BPF gain isn't worth the engine here on a low-traffic
// veth.
func openRawReceiver(iface *net.Interface, vlanID uint16) (*rawReceiver, error) {
	const ethPALL = 0x0003 // ETH_P_ALL — see linux/if_ether.h
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPALL)))
	if err != nil {
		return nil, fmt.Errorf("mactelnet: AF_PACKET SOCK_RAW (recv): %w", err)
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("mactelnet: bind AF_PACKET to %s: %w", iface.Name, err)
	}
	r := &rawReceiver{fd: fd, vlanID: vlanID}
	copy(r.srcMAC[:], iface.HardwareAddr)
	return r, nil
}

// Read fills buf with the UDP payload of the next mac-telnet frame
// arriving on the bound interface. Frames not matching our VLAN, not
// addressed to our MAC (ignoring our own outbound copies), or not a
// UDP datagram on port udpPort are silently dropped and the loop
// continues until either a real frame matches, the read deadline
// fires, or the socket is closed.
//
// Behaviour mirrors net.UDPConn.Read for the caller: returns (n, nil)
// on a delivered payload; (0, os.ErrDeadlineExceeded) when the recv
// timeout fires; (0, net.ErrClosed) after Close().
func (r *rawReceiver) Read(buf []byte) (int, error) {
	frame := make([]byte, 2048)
	for {
		if r.closed.Load() {
			return 0, net.ErrClosed
		}
		n, _, err := syscall.Recvfrom(r.fd, frame, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return 0, os.ErrDeadlineExceeded
			}
			if r.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		if n < 14 {
			continue // runt frame
		}
		// Drop our own outbound frames — AF_PACKET on the bound
		// interface receives both directions of traffic by default.
		var srcMAC [6]byte
		copy(srcMAC[:], frame[6:12])
		if srcMAC == r.srcMAC {
			continue
		}
		// Only accept frames addressed to us (unicast) or broadcast.
		var dstMAC [6]byte
		copy(dstMAC[:], frame[0:6])
		if dstMAC != r.srcMAC && dstMAC != [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
			continue
		}

		off := 14
		etherType := binary.BigEndian.Uint16(frame[12:14])
		// 802.1Q tagged: TPID + TCI + inner EtherType. We require the
		// VID to match the configured VLAN — anything else is somebody
		// else's tagged traffic.
		if etherType == ethP8021Q {
			if n < off+4 {
				continue
			}
			tci := binary.BigEndian.Uint16(frame[off : off+2])
			if tci&0x0fff != r.vlanID {
				continue
			}
			etherType = binary.BigEndian.Uint16(frame[off+2 : off+4])
			off += 4
		} else {
			// Untagged frame on a VLAN-aware receiver — drop. RouterOS
			// bridges with frame-types=admit-only-vlan-tagged on the
			// veth port shouldn't deliver any here, but be defensive.
			continue
		}
		if etherType != ethPIP {
			continue
		}

		// Minimal IP header parse: must be IPv4, at least 20 bytes,
		// protocol == UDP. We don't validate the IP checksum — the
		// kernel already did that for normal traffic, and tagged-frame
		// receivers (us) will at worst process a corrupt frame whose
		// UDP/MAC-Telnet layer also fails its own validation.
		if n < off+20 {
			continue
		}
		ipHdr := frame[off:]
		if ipHdr[0]>>4 != 4 {
			continue
		}
		ihl := int(ipHdr[0]&0x0f) * 4
		if ihl < 20 || n < off+ihl {
			continue
		}
		if ipHdr[9] != 17 { // protocol = UDP
			continue
		}
		udpOff := off + ihl
		if n < udpOff+8 {
			continue
		}
		udp := frame[udpOff:]
		dstPort := binary.BigEndian.Uint16(udp[2:4])
		if dstPort != udpPort {
			continue
		}
		udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
		if udpLen < 8 || udpOff+udpLen > n {
			continue
		}
		payload := frame[udpOff+8 : udpOff+udpLen]
		copied := copy(buf, payload)
		return copied, nil
	}
}

// SetReadDeadline configures SO_RCVTIMEO on the raw fd. The rxLoop sets
// a short deadline (~500ms) so it can periodically check ctx without
// blocking forever in Recvfrom. A zero time clears the timeout.
func (r *rawReceiver) SetReadDeadline(t time.Time) error {
	var tv syscall.Timeval
	if t.IsZero() {
		tv = syscall.Timeval{}
	} else {
		d := time.Until(t)
		if d < 0 {
			d = time.Microsecond
		}
		tv = syscall.NsecToTimeval(d.Nanoseconds())
	}
	return syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// Close releases the raw fd. Idempotent and safe from any goroutine.
func (r *rawReceiver) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		err = syscall.Close(r.fd)
	})
	return err
}

// buildFrame lays out the Ethernet + (optional 802.1Q tag) + IP + UDP
// header followed by the MAC-Telnet payload. L2 dst is the supplied
// target MAC (L2 unicast — see Send for the rationale); IP dst stays
// 255.255.255.255 to match upstream's RouterOS-tested wire format.
// IP and UDP checksums are computed here because PF_PACKET emits the
// bytes verbatim — the kernel never touches them.
//
// vlanID > 0 inserts a 4-byte 802.1Q tag (TPID 0x8100, TCI = vlanID
// with PCP=0, DEI=0) between the source MAC and the EtherType. The
// resulting frame is 4 bytes longer; offsets to IP/UDP shift accordingly.
func buildFrame(srcMAC, dstMAC [6]byte, vlanID, ipID uint16, payload []byte) []byte {
	const ethLen = 14
	const dot1qLen = 4
	const ipLen = 20
	const udpLen = 8

	tagLen := 0
	if vlanID != 0 {
		tagLen = dot1qLen
	}
	total := ethLen + tagLen + ipLen + udpLen + len(payload)
	pkt := make([]byte, total)

	// Ethernet header (14 bytes): dst, src, EtherType-or-TPID
	copy(pkt[0:6], dstMAC[:])
	copy(pkt[6:12], srcMAC[:])
	if vlanID != 0 {
		binary.BigEndian.PutUint16(pkt[12:14], ethP8021Q)
		// 802.1Q TCI: PCP (3) | DEI (1) | VID (12). PCP/DEI both 0;
		// VID occupies the low 12 bits. Mask vlanID to be safe even
		// though valid VIDs are 1–4094.
		binary.BigEndian.PutUint16(pkt[14:16], vlanID&0x0fff)
		binary.BigEndian.PutUint16(pkt[16:18], ethPIP)
	} else {
		binary.BigEndian.PutUint16(pkt[12:14], ethPIP)
	}

	// IP header (20 bytes, no options) — offset shifts by tagLen.
	//
	// TOS=0x00 and flags=0 (no DF) match RouterOS's own /tool mac-telnet
	// wire format, verified against pcap. Upstream mactelnet-client uses
	// TOS=0x10 + DF, but RouterOS itself doesn't — and "looks like the
	// router doing it" is the safer pattern for traversing intermediate
	// MikroTik switches with hardware-MAC-rule filtering.
	ipOff := ethLen + tagLen
	ip := pkt[ipOff:]
	ip[0] = 0x45                                            // version=4, IHL=5
	ip[1] = 0x00                                            // TOS
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen+udpLen+len(payload)))
	binary.BigEndian.PutUint16(ip[4:6], ipID)               // ID
	binary.BigEndian.PutUint16(ip[6:8], 0)                  // flags=0 (no DF), frag=0
	ip[8] = 64                                              // TTL
	ip[9] = 17                                              // protocol = UDP
	// ip[10:12] checksum filled below
	// ip[12:16] src IP = 0.0.0.0 (already zero)
	ip[16], ip[17], ip[18], ip[19] = 0xff, 0xff, 0xff, 0xff // dst IP
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:ipLen]))

	// UDP header (8 bytes) — offset = ipOff + 20
	udp := pkt[ipOff+ipLen:]
	binary.BigEndian.PutUint16(udp[0:2], udpPort)                    // src port
	binary.BigEndian.PutUint16(udp[2:4], udpPort)                    // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload))) // UDP length
	// udp[6:8] checksum = 0 (legal on IPv4 — receivers don't require it)

	copy(pkt[ipOff+ipLen+udpLen:], payload)
	return pkt
}

// internetChecksum is the standard 16-bit one's-complement sum used
// by IP, UDP, and TCP headers. b must have even length for IP-header
// use; if not, the trailing odd byte is treated as the high half of a
// final word.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseMAC parses a "aa:bb:cc:dd:ee:ff" string into a fixed-size array.
// Only EUI-48 (6-byte) addresses are accepted.
func parseMAC(s string) ([6]byte, error) {
	var out [6]byte
	hw, err := net.ParseMAC(s)
	if err != nil {
		return out, fmt.Errorf("mactelnet: parse MAC %q: %w", s, err)
	}
	if len(hw) != 6 {
		return out, fmt.Errorf("mactelnet: MAC %q is %d bytes, want 6", s, len(hw))
	}
	copy(out[:], hw)
	return out, nil
}
