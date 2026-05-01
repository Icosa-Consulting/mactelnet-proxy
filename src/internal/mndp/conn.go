// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mndp

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// MNDP transport — UDP/5678 listener and broadcast helpers, ported from
// _upstream/MAC-Telnet/src/mndp.c.
//
// Bind layout:
//
//   - Listener: 0.0.0.0:5678 with SO_REUSEADDR (multiple discoverers can
//     coexist) and SO_BROADCAST (so the same socket can fire the SOLICIT
//     announcement-request packet).
//   - SOLICIT destination: the iface's directed broadcast if specified
//     (e.g. 192.168.1.255), or 255.255.255.255 limited broadcast otherwise
//     — in which case the kernel routes via the default-route iface.
//
// MNDP devices announce every MT_MNDP_BROADCAST_INTERVAL (60 s) on their
// own, so the SOLICIT is purely a "tell me now" prompt to shorten the
// discovery window. Failure to send it is non-fatal.

const mndpPort = 5678 // MT_MNDP_PORT

// openListener binds a UDP socket to all interfaces on the MNDP port,
// with SO_REUSEADDR + SO_BROADCAST set up via the ListenConfig.Control
// hook (so they apply before bind, not just after).
func openListener() (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var ctlErr error
			cerr := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
					ctlErr = fmt.Errorf("SO_REUSEADDR: %w", e)
					return
				}
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); e != nil {
					ctlErr = fmt.Errorf("SO_BROADCAST: %w", e)
					return
				}
			})
			if cerr != nil {
				return cerr
			}
			return ctlErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", mndpPort))
	if err != nil {
		return nil, fmt.Errorf("mndp: bind UDP/%d: %w", mndpPort, err)
	}
	return pc.(*net.UDPConn), nil
}

// resolveBroadcast picks the destination for the SOLICIT packet. If
// iface is empty, returns the IPv4 limited-broadcast 255.255.255.255 and
// the kernel's default-route iface picks the egress. Otherwise, returns
// the directed broadcast for the iface's first IPv4 address.
func resolveBroadcast(iface string) (*net.UDPAddr, error) {
	if iface == "" {
		return &net.UDPAddr{IP: net.IPv4bcast, Port: mndpPort}, nil
	}
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("mndp: interface %q: %w", iface, err)
	}
	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("mndp: addrs for %q: %w", iface, err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		bcastIP := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			bcastIP[i] = ip4[i] | ^ipnet.Mask[i]
		}
		return &net.UDPAddr{IP: bcastIP, Port: mndpPort}, nil
	}
	return nil, fmt.Errorf("mndp: interface %q has no IPv4 address", iface)
}
