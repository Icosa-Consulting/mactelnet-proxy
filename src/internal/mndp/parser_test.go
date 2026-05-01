// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package mndp

import (
	"encoding/binary"
	"testing"
	"time"
)

// tlv is a single attribute record used by buildPacket below.
type tlv struct {
	typ uint16
	val []byte
}

// buildPacket assembles a wire-form MNDP datagram: 4-byte header + TLV
// records. Mirrors what upstream's mndp_init_packet + mndp_add_attribute
// would emit, so feeding the result through ParsePacket exercises the
// real wire format.
func buildPacket(t *testing.T, version, ttl uint8, cksum uint16, tlvs []tlv) []byte {
	t.Helper()
	out := []byte{version, ttl, byte(cksum >> 8), byte(cksum)}
	hdr := make([]byte, 4)
	for _, r := range tlvs {
		binary.BigEndian.PutUint16(hdr[0:2], r.typ)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(r.val)))
		out = append(out, hdr...)
		out = append(out, r.val...)
	}
	return out
}

func TestParsePacketShortBuffer(t *testing.T) {
	if _, err := ParsePacket(make([]byte, 17)); err != ErrShortPacket {
		t.Errorf("got %v, want ErrShortPacket", err)
	}
}

func TestParsePacketRealistic(t *testing.T) {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	var uptime [4]byte
	binary.LittleEndian.PutUint32(uptime[:], 7200) // 2 hours

	raw := buildPacket(t, 1, 64, 0xdead, []tlv{
		{attrAddress, mac},
		{attrIdentity, []byte("router1")},
		{attrPlatform, []byte("MikroTik")},
		{attrVersion, []byte("7.10.2")},
		{attrTimestamp, uptime[:]},
		{attrHardware, []byte("RB750Gr3")},
		{attrSoftID, []byte("ABC1-DEF2")},
		{attrIfname, []byte("ether1")},
	})

	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.HeaderVersion != 1 {
		t.Errorf("HeaderVersion: %d, want 1", pkt.HeaderVersion)
	}
	if pkt.TTL != 64 {
		t.Errorf("TTL: %d, want 64", pkt.TTL)
	}
	if pkt.Checksum != 0xdead {
		t.Errorf("Checksum: %#x, want 0xdead", pkt.Checksum)
	}
	want := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if pkt.MAC != want {
		t.Errorf("MAC: %x, want %x", pkt.MAC, want)
	}
	if pkt.Identity != "router1" {
		t.Errorf("Identity: %q", pkt.Identity)
	}
	if pkt.Platform != "MikroTik" {
		t.Errorf("Platform: %q", pkt.Platform)
	}
	if pkt.Version != "7.10.2" {
		t.Errorf("Version: %q", pkt.Version)
	}
	if pkt.Uptime != 2*time.Hour {
		t.Errorf("Uptime: %v, want 2h", pkt.Uptime)
	}
	if pkt.Hardware != "RB750Gr3" {
		t.Errorf("Hardware: %q", pkt.Hardware)
	}
	if pkt.SoftID != "ABC1-DEF2" {
		t.Errorf("SoftID: %q", pkt.SoftID)
	}
	if pkt.Iface != "ether1" {
		t.Errorf("Iface: %q", pkt.Iface)
	}
}

func TestParsePacketUnknownTLVSkipped(t *testing.T) {
	// Real MNDP packets sometimes carry attribute types we don't model.
	// Parser must walk past them without losing later known TLVs.
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	raw := buildPacket(t, 1, 64, 0, []tlv{
		{0x0099, []byte("unknown-attr")},
		{attrAddress, mac},
		{0x00ff, []byte{0xde, 0xad, 0xbe, 0xef}},
		{attrIdentity, []byte("router")},
	})
	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.MAC != ([6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("MAC lost across unknown TLVs: %x", pkt.MAC)
	}
	if pkt.Identity != "router" {
		t.Errorf("Identity lost across unknown TLVs: %q", pkt.Identity)
	}
}

func TestParsePacketTruncatedTLVStops(t *testing.T) {
	// Header + valid ADDRESS + a TLV claiming length=99 with only 2
	// bytes following. Parser should retain the address but drop the
	// rest silently (matches upstream's best-effort behavior).
	raw := []byte{
		1, 64, 0, 0, // header
		0, 1, 0, 6, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // ADDRESS
		0, 5, 0, 99, 'h', 'i', // truncated IDENTITY
	}
	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.MAC != ([6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("MAC should still be parsed, got %x", pkt.MAC)
	}
	if pkt.Identity != "" {
		t.Errorf("truncated Identity should not be set, got %q", pkt.Identity)
	}
}

func TestParsePacketUptimeIsLittleEndian(t *testing.T) {
	// The MNDP spec is big-endian everywhere except TIMESTAMP, which is
	// transmitted little-endian. Encode 1 LE — if we accidentally decoded
	// as big-endian, we'd see ~16 million seconds instead of 1.
	var uptime [4]byte
	binary.LittleEndian.PutUint32(uptime[:], 1)
	raw := buildPacket(t, 1, 64, 0, []tlv{
		{attrAddress, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		{attrTimestamp, uptime[:]},
	})
	pkt, _ := ParsePacket(raw)
	if pkt.Uptime != time.Second {
		t.Errorf("Uptime: %v, want 1s", pkt.Uptime)
	}
}

func TestParsePacketShortAddressIgnored(t *testing.T) {
	// ADDRESS TLV with len < 6 should be skipped, not crash. The full
	// datagram must still clear the 18-byte minimum, so pad Identity.
	raw := buildPacket(t, 1, 64, 0, []tlv{
		{attrAddress, []byte{0x01, 0x02, 0x03}},
		{attrIdentity, []byte("router-x")},
	})
	pkt, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.MAC != ([6]byte{}) {
		t.Errorf("MAC should remain zero on short ADDRESS, got %x", pkt.MAC)
	}
	if pkt.Identity != "router-x" {
		t.Errorf("identity after short address should still be parsed: %q", pkt.Identity)
	}
}
