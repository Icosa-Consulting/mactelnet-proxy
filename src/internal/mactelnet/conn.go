// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
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

// openSockets opens the receive UDP socket and the raw L2 send socket
// for one MAC-Telnet session. iface supplies both the Linux ifindex
// (egress selector) and the source MAC put into the Ethernet header.
func openSockets(iface *net.Interface) (*net.UDPConn, *rawSender, error) {
	recv, err := openRecv()
	if err != nil {
		return nil, nil, err
	}
	sender, err := openRawSender(iface)
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

// openRawSender opens a PF_PACKET / SOCK_RAW socket scoped to one
// interface. The protocol filter is ETH_P_IP because we only emit IPv4
// frames; receive of broadcast replies stays on the regular UDP socket.
func openRawSender(iface *net.Interface) (*rawSender, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPIP)))
	if err != nil {
		return nil, fmt.Errorf("mactelnet: AF_PACKET SOCK_RAW: %w", err)
	}
	r := &rawSender{fd: fd, ifindex: iface.Index}
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
	pkt := buildFrame(r.srcMAC, dstMAC, r.ipID, payload)
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
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

// buildFrame lays out the 14-byte Ethernet + 20-byte IP + 8-byte UDP
// header followed by the MAC-Telnet payload. L2 dst is the supplied
// target MAC (L2 unicast — see Send for the rationale); IP dst stays
// 255.255.255.255 to match upstream's RouterOS-tested wire format.
// IP and UDP checksums are computed here because PF_PACKET emits the
// bytes verbatim — the kernel never touches them.
func buildFrame(srcMAC, dstMAC [6]byte, ipID uint16, payload []byte) []byte {
	const ethLen = 14
	const ipLen = 20
	const udpLen = 8
	total := ethLen + ipLen + udpLen + len(payload)
	pkt := make([]byte, total)

	// Ethernet header (14 bytes)
	copy(pkt[0:6], dstMAC[:])
	copy(pkt[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(pkt[12:14], ethPIP)

	// IP header (20 bytes, no options) — offset 14
	//
	// TOS=0x00 and flags=0 (no DF) match RouterOS's own /tool mac-telnet
	// wire format, verified against pcap. Upstream mactelnet-client uses
	// TOS=0x10 + DF, but RouterOS itself doesn't — and "looks like the
	// router doing it" is the safer pattern for traversing intermediate
	// MikroTik switches with hardware-MAC-rule filtering.
	ip := pkt[14:]
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

	// UDP header (8 bytes) — offset 14 + 20 = 34
	udp := pkt[34:]
	binary.BigEndian.PutUint16(udp[0:2], udpPort)                    // src port
	binary.BigEndian.PutUint16(udp[2:4], udpPort)                    // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload))) // UDP length
	// udp[6:8] checksum = 0 (legal on IPv4 — receivers don't require it)

	copy(pkt[42:], payload)
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
