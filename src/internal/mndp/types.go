// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

// Package mndp implements MikroTik Neighbor Discovery Protocol — the
// broadcast announcement protocol every RouterOS device speaks on UDP/5678.
// Listening for ~30 seconds on the local broadcast domain is enough to
// enumerate every reachable device.
//
// This file declares the data types only; the wire-format parser and the
// UDP listener live alongside in this package and are populated as part
// of M1 of the milestone plan (see ../../docs/STATUS.md).
package mndp

import "time"

// Neighbor is a single discovered MikroTik device. Field names mirror the
// MNDP TLV codes used by upstream so a side-by-side read of mndp.c stays
// straightforward when porting.
type Neighbor struct {
	MAC        string        `json:"mac"`               // 6-byte MAC formatted xx:xx:xx:xx:xx:xx
	Identity   string        `json:"identity,omitempty"`// device hostname / "Identity" in WinBox
	Platform   string        `json:"platform,omitempty"`// usually "MikroTik"
	Version    string        `json:"version,omitempty"` // RouterOS version string
	Board      string        `json:"board,omitempty"`   // board model — "CCR2004-1G-12S+2XS" etc.
	SoftwareID string        `json:"software_id,omitempty"`
	Iface      string        `json:"iface,omitempty"`   // source interface name on the announcing device
	IPv4       string        `json:"ipv4,omitempty"`    // first management IPv4 if announced
	IPv6       string        `json:"ipv6,omitempty"`    // first management IPv6 if announced
	Uptime     time.Duration `json:"uptime,omitempty"`  // remote uptime at the moment of announcement
	SeenAt     time.Time     `json:"seen_at"`           // when WE received the announcement
}
