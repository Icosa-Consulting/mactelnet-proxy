// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mndp

import (
	"encoding/binary"
	"errors"
	"time"
)

// MNDP wire format — ported from _upstream/MAC-Telnet/src/protocol.c:parse_mndp
// and the type codes in src/protocol.h:enum mt_mndp_attrtype.
//
// Datagram layout:
//
//	u8  version
//	u8  ttl
//	u16 checksum   (big-endian; upstream never validates it, neither do we)
//	repeated TLV records:
//	    u16 type     (big-endian)
//	    u16 length   (big-endian)
//	    N   value
//
// Note: the TIMESTAMP attribute (uptime, seconds) is encoded **little-endian**
// even though every other multibyte field in the protocol is big-endian. This
// is documented as suspicious in upstream protocol.c with the comment
// "Seems like ping uptime is transmitted as little endian?" — it is, and we
// have to honor it.

const (
	headerLen        = 4
	minPacketLen     = 18  // matches upstream's `if (packet_len < 18)` floor
	mndpMaxStringLen = 128 // MT_MNDP_MAX_STRING_SIZE
)

// MNDP attribute type codes — mirror `enum mt_mndp_attrtype` in protocol.h.
const (
	attrAddress   uint16 = 0x0001
	attrIdentity  uint16 = 0x0005
	attrVersion   uint16 = 0x0007
	attrPlatform  uint16 = 0x0008
	attrTimestamp uint16 = 0x000a // remote uptime, little-endian u32 seconds
	attrSoftID    uint16 = 0x000b
	attrHardware  uint16 = 0x000c
	attrIfname    uint16 = 0x0010
)

// ErrShortPacket is returned when the buffer is below the 18-byte floor
// upstream uses to reject obvious garbage.
var ErrShortPacket = errors.New("mndp: packet shorter than minimum")

// Packet is the decoded form of one MNDP datagram. Field semantics mirror
// upstream's `struct mt_mndp_info` in protocol.h. Attributes that weren't
// present in the announcement remain at their zero value.
//
// The source IP is intentionally absent: it is not carried as a TLV; it
// comes from the UDP source address and is added by the listener when it
// converts a Packet into a Neighbor.
type Packet struct {
	HeaderVersion uint8  // upstream mt_mndp_hdr.version
	TTL           uint8  // upstream mt_mndp_hdr.ttl
	Checksum      uint16 // upstream mt_mndp_hdr.cksum (unverified)

	MAC      [6]byte       // attr 0x0001
	Identity string        // attr 0x0005
	Version  string        // attr 0x0007 — RouterOS version
	Platform string        // attr 0x0008
	Uptime   time.Duration // attr 0x000a — little-endian u32 seconds
	SoftID   string        // attr 0x000b
	Hardware string        // attr 0x000c
	Iface    string        // attr 0x0010 — announcing device's iface name
}

// ParsePacket decodes one MNDP datagram.
//
// Returns ErrShortPacket if the buffer is below the minimum length. Truncated
// or unrecognized TLVs in the body are skipped silently and the packet is
// returned with whatever was successfully parsed — this matches upstream's
// best-effort behavior in protocol.c, and avoids losing announcements that
// happen to carry attribute types we don't model yet.
func ParsePacket(buf []byte) (*Packet, error) {
	if len(buf) < minPacketLen {
		return nil, ErrShortPacket
	}

	pkt := &Packet{
		HeaderVersion: buf[0],
		TTL:           buf[1],
		Checksum:      binary.BigEndian.Uint16(buf[2:4]),
	}

	p := buf[headerLen:]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p[0:2])
		ln := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if ln > len(p) {
			break
		}
		val := p[:ln]
		p = p[ln:]

		switch typ {
		case attrAddress:
			if len(val) >= 6 {
				copy(pkt.MAC[:], val[:6])
			}
		case attrIdentity:
			pkt.Identity = clipString(val)
		case attrVersion:
			pkt.Version = clipString(val)
		case attrPlatform:
			pkt.Platform = clipString(val)
		case attrTimestamp:
			if len(val) >= 4 {
				secs := binary.LittleEndian.Uint32(val[:4])
				pkt.Uptime = time.Duration(secs) * time.Second
			}
		case attrSoftID:
			pkt.SoftID = clipString(val)
		case attrHardware:
			pkt.Hardware = clipString(val)
		case attrIfname:
			pkt.Iface = clipString(val)
		}
	}
	return pkt, nil
}

// clipString applies upstream's MT_MNDP_MAX_STRING_SIZE-1 cap. Wire strings
// are not null-terminated; the cap is purely a defense against a malformed
// length field.
func clipString(b []byte) string {
	if len(b) >= mndpMaxStringLen {
		b = b[:mndpMaxStringLen-1]
	}
	return string(b)
}
