// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mndp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

// Discover listens for MNDP announcement packets on UDP/5678 for the
// supplied duration and returns one Neighbor entry per unique MAC seen.
// On startup it sends a 4-byte SOLICIT packet to the broadcast address
// to prompt nearby MikroTiks to announce immediately, rather than
// waiting for their next 60-second tick.
//
// `iface` selects the egress interface for the SOLICIT only — the
// listener always binds to 0.0.0.0:5678 and accepts announcements on
// any interface. Empty iface falls back to limited broadcast and lets
// the kernel pick egress via the default route.
//
// `timeout` is the listen window. The function returns when the timeout
// elapses or ctx is canceled, whichever comes first. Partial results
// gathered before cancellation are returned with a nil error — an empty
// slice is a legitimate "quiet segment" outcome, distinct from a
// listener error.
func Discover(ctx context.Context, iface string, timeout time.Duration) ([]Neighbor, error) {
	conn, err := openListener()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Best-effort SOLICIT. Devices announce on their own every 60 s, so
	// even a failed SOLICIT just means slower discovery — not a hard
	// error.
	if bcast, berr := resolveBroadcast(iface); berr == nil {
		_, _ = conn.WriteToUDP([]byte{0, 0, 0, 0}, bcast)
	}

	deadline := time.Now().Add(timeout)
	seen := make(map[[6]byte]Neighbor)
	buf := make([]byte, maxPacketBuf)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return collectNeighbors(seen), nil
		default:
		}

		// Short read deadline so we re-check ctx and the overall deadline
		// on a regular cadence even when the segment is silent.
		readDeadline := time.Now().Add(500 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		_ = conn.SetReadDeadline(readDeadline)

		n, src, rerr := conn.ReadFromUDP(buf)
		if errors.Is(rerr, os.ErrDeadlineExceeded) {
			continue
		}
		if rerr != nil {
			return collectNeighbors(seen), fmt.Errorf("mndp: read: %w", rerr)
		}

		pkt, perr := ParsePacket(buf[:n])
		if perr != nil {
			continue
		}
		// Skip announcements that didn't carry an ADDRESS TLV — without
		// a MAC there's no way to dedupe and we'd never connect to it.
		if pkt.MAC == ([6]byte{}) {
			continue
		}
		seen[pkt.MAC] = packetToNeighbor(pkt, src, time.Now())
	}

	return collectNeighbors(seen), nil
}

// maxPacketBuf bounds inbound MNDP datagrams. Real announcements fit in
// well under 500 bytes; 1500 covers everything the protocol can carry
// (matches upstream's MT_PACKET_LEN).
const maxPacketBuf = 1500

// packetToNeighbor projects the wire-form Packet plus its UDP source
// address into the operator-facing Neighbor type.
func packetToNeighbor(pkt *Packet, src *net.UDPAddr, now time.Time) Neighbor {
	n := Neighbor{
		MAC:        formatMAC(pkt.MAC),
		Identity:   pkt.Identity,
		Platform:   pkt.Platform,
		Version:    pkt.Version,
		Board:      pkt.Hardware,
		SoftwareID: pkt.SoftID,
		Iface:      pkt.Iface,
		Uptime:     pkt.Uptime,
		SeenAt:     now,
	}
	if src != nil && src.IP != nil {
		if ip4 := src.IP.To4(); ip4 != nil {
			n.IPv4 = ip4.String()
		} else {
			n.IPv6 = src.IP.String()
		}
	}
	return n
}

// formatMAC renders a 6-byte MAC as the canonical xx:xx:xx:xx:xx:xx form
// upstream uses (lowercase). Lowercase is also what `ether_ntoa_z` in
// mndp.c emits — keeping that for parity makes side-by-side diffs easier.
func formatMAC(b [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// collectNeighbors materializes the dedup map as a slice sorted by MAC
// for stable output.
func collectNeighbors(seen map[[6]byte]Neighbor) []Neighbor {
	out := make([]Neighbor, 0, len(seen))
	for _, n := range seen {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}
