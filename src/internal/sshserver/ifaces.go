// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package sshserver

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// execIfaces enumerates the host's network interfaces and writes a
// summary to the SSH channel. Useful for an operator to pick the right
// `-i IFACE` value for a subsequent `mactelnet` exec without needing
// shell access on the proxy host.
//
// Usage: ifaces [-j] [-i NAME]
//
//	-j        emit JSON instead of the human-readable table
//	-i NAME   filter to a single interface by name
func (s *Server) execIfaces(args []string, ch ssh.Channel) int {
	fs := flag.NewFlagSet("ifaces", flag.ContinueOnError)
	fs.SetOutput(ch.Stderr())

	asJSON := fs.Bool("j", false, "emit results as JSON")
	only := fs.String("i", "", "only show this interface")

	fs.Usage = func() {
		fmt.Fprintln(ch.Stderr(), "usage: ifaces [-j] [-i NAME]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	all, err := net.Interfaces()
	if err != nil {
		s.logger.Warn("ifaces: enumerate failed", "err", err)
		fmt.Fprintf(ch.Stderr(), "ifaces: %v\n", err)
		return 1
	}

	out := make([]ifaceInfo, 0, len(all))
	for _, iface := range all {
		if *only != "" && iface.Name != *only {
			continue
		}
		out = append(out, summarize(iface))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })

	if *only != "" && len(out) == 0 {
		fmt.Fprintf(ch.Stderr(), "ifaces: interface %q not found\n", *only)
		return 1
	}

	s.logger.Info("ifaces listing", "count", len(out), "filter", *only, "json", *asJSON)

	if *asJSON {
		enc := json.NewEncoder(ch)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(ch.Stderr(), "ifaces: encode: %v\n", err)
			return 1
		}
		return 0
	}

	writeIfaceTable(ch, out)
	return 0
}

// ifaceInfo is the per-interface payload emitted by `ifaces -j` and
// rendered into the human table for `ifaces`.
type ifaceInfo struct {
	Name   string   `json:"name"`
	Index  int      `json:"index"`
	MAC    string   `json:"mac,omitempty"`
	MTU    int      `json:"mtu"`
	Flags  string   `json:"flags"`
	Kind   string   `json:"kind,omitempty"`   // ether, vlan, bond, bridge, veth, loopback, …
	Parent string   `json:"parent,omitempty"` // VLAN sub-iface: parent device
	VID    int      `json:"vid,omitempty"`    // VLAN sub-iface: 802.1Q VID
	Master string   `json:"master,omitempty"` // bond/bridge master, when enslaved
	Oper   string   `json:"oper,omitempty"`   // up, down, no-carrier, dormant, …
	IPv4   []string `json:"ipv4,omitempty"`
	IPv6   []string `json:"ipv6,omitempty"`
}

func summarize(iface net.Interface) ifaceInfo {
	info := ifaceInfo{
		Name:   iface.Name,
		Index:  iface.Index,
		MTU:    iface.MTU,
		Flags:  iface.Flags.String(),
		Kind:   readKind(iface),
		Master: readMaster(iface.Name),
		Oper:   readOper(iface.Name),
	}
	if len(iface.HardwareAddr) > 0 {
		info.MAC = iface.HardwareAddr.String()
	}
	if info.Kind == "vlan" {
		info.Parent, info.VID = readVLAN(iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return info
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		s := ipnet.String()
		if ipnet.IP.To4() != nil {
			info.IPv4 = append(info.IPv4, s)
		} else {
			info.IPv6 = append(info.IPv6, s)
		}
	}
	return info
}

// readSysNet returns the trimmed contents of /sys/class/net/<name>/<file>,
// or "" if the file isn't there. Callers treat "" as "unknown" — the
// fields are sysfs-only on Linux, and we don't want a missing path to
// fail the listing on a more exotic platform.
func readSysNet(name, file string) string {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readKind classifies an interface as ether/vlan/bond/bridge/veth/etc.
// The DEVTYPE line in /sys/class/net/<name>/uevent is the canonical
// answer when it's present (vlan, bond, bridge, veth, vxlan, …);
// regular Ethernet NICs and IPoIB-style links don't have a DEVTYPE,
// so we infer from net.Flags + the wireless sysfs node.
func readKind(iface net.Interface) string {
	if iface.Flags&net.FlagLoopback != 0 {
		return "loopback"
	}
	uevent := readSysNet(iface.Name, "uevent")
	for _, line := range strings.Split(uevent, "\n") {
		if v, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
			return v
		}
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", iface.Name, "wireless")); err == nil {
		return "wireless"
	}
	if iface.Flags&net.FlagPointToPoint != 0 {
		return "ptp"
	}
	return "ether"
}

// readMaster returns the bond/bridge this interface is enslaved to, if
// any. /sys/class/net/<name>/master is a symlink to ../<master> when
// enslaved; absent otherwise.
func readMaster(name string) string {
	target, err := os.Readlink(filepath.Join("/sys/class/net", name, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// readVLAN reads /proc/net/vlan/<name> and extracts the parent device
// and VID for an 802.1Q VLAN sub-interface. Returns ("", 0) if the
// file isn't present (e.g. it's not a VLAN).
//
// The first non-empty line is "<name>  VID: <id>  REORDER_HDR: …"
// and a later "Device: <parent>" line names the parent device.
func readVLAN(name string) (string, int) {
	b, err := os.ReadFile(filepath.Join("/proc/net/vlan", name))
	if err != nil {
		return "", 0
	}
	var parent string
	var vid int
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "VID:" && i+1 < len(fields) {
				if v, err := strconv.Atoi(fields[i+1]); err == nil && vid == 0 {
					vid = v
				}
			}
		}
		if strings.HasPrefix(strings.TrimSpace(line), "Device:") {
			parent = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Device:"))
		}
	}
	return parent, vid
}

// readOper returns operstate adjusted with the carrier sysfs flag so
// "up but cable unplugged" surfaces as "no-carrier" instead of the
// less specific "up". Possible values: up, down, no-carrier, dormant,
// lowerlayerdown, unknown, "".
func readOper(name string) string {
	op := readSysNet(name, "operstate")
	carrier := readSysNet(name, "carrier")
	if op == "up" && carrier == "0" {
		return "no-carrier"
	}
	return op
}

// writeIfaceTable emits a pleasantly-aligned, no-color summary. We
// don't know the SSH client's terminal width, so columns are compact
// rather than padded to fixed widths — long IP/IPv6 lists wrap onto
// continuation rows.
func writeIfaceTable(w ssh.Channel, rows []ifaceInfo) {
	// Compute column widths from data so a single-interface filter
	// doesn't get stuck with a wide-fleet column layout.
	nameW, macW, mtuW := len("NAME"), len("MAC"), len("MTU")
	for _, r := range rows {
		if n := len(r.Name); n > nameW {
			nameW = n
		}
		if n := len(r.MAC); n > macW {
			macW = n
		}
		if n := len(fmt.Sprintf("%d", r.MTU)); n > mtuW {
			mtuW = n
		}
	}

	header := fmt.Sprintf("%-*s  %3s  %-*s  %*s  %s",
		nameW, "NAME", "IDX", macW, "MAC", mtuW, "MTU", "FLAGS / ADDRS")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)))
	for _, r := range rows {
		mac := r.MAC
		if mac == "" {
			mac = "-"
		}
		fmt.Fprintf(w, "%-*s  %3d  %-*s  %*d  %s\n",
			nameW, r.Name, r.Index, macW, mac, mtuW, r.MTU, r.Flags)
		if meta := metaLine(r); meta != "" {
			fmt.Fprintf(w, "%-*s        %-*s  %*s    %s\n",
				nameW, "", macW, "", mtuW, "", meta)
		}
		for _, ip := range r.IPv4 {
			fmt.Fprintf(w, "%-*s        %-*s  %*s    %s\n",
				nameW, "", macW, "", mtuW, "", ip)
		}
		for _, ip := range r.IPv6 {
			fmt.Fprintf(w, "%-*s        %-*s  %*s    %s\n",
				nameW, "", macW, "", mtuW, "", ip)
		}
	}
}

// metaLine assembles a single space-separated `kind=… parent=… vid=…
// master=… oper=…` summary, omitting fields that aren't relevant for
// this interface. Returns "" if there's nothing to show.
func metaLine(r ifaceInfo) string {
	var parts []string
	if r.Kind != "" {
		parts = append(parts, "kind="+r.Kind)
	}
	if r.Parent != "" {
		parts = append(parts, "parent="+r.Parent)
	}
	if r.VID != 0 {
		parts = append(parts, fmt.Sprintf("vid=%d", r.VID))
	}
	if r.Master != "" {
		parts = append(parts, "master="+r.Master)
	}
	if r.Oper != "" {
		parts = append(parts, "oper="+r.Oper)
	}
	return strings.Join(parts, "  ")
}
