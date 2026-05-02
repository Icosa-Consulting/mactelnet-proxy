// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package mactelnet

import (
	"encoding/binary"
	"testing"
)

// TestBuildFrameUntagged is a regression check on the original (no-VLAN)
// frame layout. Offsets must stay where the rest of the protocol code
// expects them: Ethernet 14, IP 20, UDP 8 = first payload byte at 42.
func TestBuildFrameUntagged(t *testing.T) {
	src := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	dst := [6]byte{0x4c, 0x65, 0x57, 0xd1, 0x0e, 0x30}
	payload := []byte("hello mactelnet")

	pkt := buildFrame(src, dst, 0, 0xabcd, payload)

	wantLen := 14 + 20 + 8 + len(payload)
	if len(pkt) != wantLen {
		t.Fatalf("frame length: got %d, want %d", len(pkt), wantLen)
	}
	if [6]byte(pkt[0:6]) != dst {
		t.Errorf("dst MAC: got %x, want %x", pkt[0:6], dst)
	}
	if [6]byte(pkt[6:12]) != src {
		t.Errorf("src MAC: got %x, want %x", pkt[6:12], src)
	}
	if et := binary.BigEndian.Uint16(pkt[12:14]); et != ethPIP {
		t.Errorf("ethertype: got 0x%04x, want 0x%04x (IPv4)", et, ethPIP)
	}
	// IP version + IHL byte is the first byte after Ethernet (offset 14).
	if pkt[14] != 0x45 {
		t.Errorf("ip[0]: got 0x%02x, want 0x45 (v=4 IHL=5)", pkt[14])
	}
	// UDP src+dst port both 20561 — after Ethernet(14)+IP(20).
	if sp := binary.BigEndian.Uint16(pkt[34:36]); sp != udpPort {
		t.Errorf("udp src port: got %d, want %d", sp, udpPort)
	}
	if dp := binary.BigEndian.Uint16(pkt[36:38]); dp != udpPort {
		t.Errorf("udp dst port: got %d, want %d", dp, udpPort)
	}
	if got := string(pkt[42:]); got != string(payload) {
		t.Errorf("payload: got %q, want %q", got, string(payload))
	}
}

// TestBuildFrameTagged exercises the 802.1Q insertion path. The 4-byte
// tag must sit between src MAC and the original EtherType, with PCP=0
// DEI=0 and the VID in the low 12 bits of the TCI. IP/UDP offsets shift
// accordingly so the IP and UDP parsers are still aligned.
func TestBuildFrameTagged(t *testing.T) {
	src := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	dst := [6]byte{0x4c, 0x65, 0x57, 0xd1, 0x0e, 0x30}
	payload := []byte("hello vlan")
	const vid = 20

	pkt := buildFrame(src, dst, vid, 0xabcd, payload)

	wantLen := 14 + 4 + 20 + 8 + len(payload)
	if len(pkt) != wantLen {
		t.Fatalf("tagged frame length: got %d, want %d", len(pkt), wantLen)
	}
	// Ethernet header still ends at offset 12; the byte after src MAC
	// should be the 802.1Q TPID, not the original EtherType.
	if tpid := binary.BigEndian.Uint16(pkt[12:14]); tpid != ethP8021Q {
		t.Errorf("TPID: got 0x%04x, want 0x%04x (802.1Q)", tpid, ethP8021Q)
	}
	tci := binary.BigEndian.Uint16(pkt[14:16])
	if got := tci & 0x0fff; got != vid {
		t.Errorf("VID in TCI: got %d, want %d", got, vid)
	}
	if pcp := tci >> 13; pcp != 0 {
		t.Errorf("PCP in TCI: got %d, want 0 (best-effort)", pcp)
	}
	if dei := (tci >> 12) & 1; dei != 0 {
		t.Errorf("DEI bit in TCI: got %d, want 0", dei)
	}
	// Inner EtherType comes right after the TCI.
	if et := binary.BigEndian.Uint16(pkt[16:18]); et != ethPIP {
		t.Errorf("inner ethertype: got 0x%04x, want 0x%04x (IPv4)", et, ethPIP)
	}
	// IP v4 + IHL=5 should now be at offset 18 instead of 14.
	if pkt[18] != 0x45 {
		t.Errorf("ip[0] after tag: got 0x%02x, want 0x45", pkt[18])
	}
	// UDP src/dst port at offset 18 + 20 = 38.
	if sp := binary.BigEndian.Uint16(pkt[38:40]); sp != udpPort {
		t.Errorf("udp src port (tagged): got %d, want %d", sp, udpPort)
	}
	// Payload starts at 18 + 20 + 8 = 46.
	if got := string(pkt[46:]); got != string(payload) {
		t.Errorf("payload (tagged): got %q, want %q", got, string(payload))
	}
}

// TestBuildFrameVidMaskedTo12Bits guards against a future change that
// might widen vlanID handling and accidentally let bits ≥4096 leak into
// the PCP/DEI fields. Even if a caller passes vid=0x1014, only the low
// 12 bits should appear in the VID field.
func TestBuildFrameVidMaskedTo12Bits(t *testing.T) {
	src := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	dst := [6]byte{0x4c, 0x65, 0x57, 0xd1, 0x0e, 0x30}

	pkt := buildFrame(src, dst, 0x1014, 1, []byte("x"))
	tci := binary.BigEndian.Uint16(pkt[14:16])
	if got := tci & 0x0fff; got != 0x014 {
		t.Errorf("VID mask: got 0x%03x, want 0x014", got)
	}
	if (tci >> 13) != 0 {
		t.Errorf("PCP must remain 0 even when high bits in vid are set; got TCI 0x%04x", tci)
	}
}
