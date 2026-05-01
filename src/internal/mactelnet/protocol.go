// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"encoding/binary"
	"errors"
)

// MAC-Telnet wire protocol — framing primitives only.
//
// Ported from _upstream/MAC-Telnet/src/protocol.{h,c}. This file covers the
// outer 22-byte UDP header, control-packet records, and the PING/PONG
// 18-byte header. Auth (MD5 challenge), sequence/ACK retransmit, keepalive,
// and term-type negotiation live in separate files in this package.
//
// Outer header (client→server):
//
//	0:   u8   version  (always 1)
//	1:   u8   ptype
//	2-7: [6]  src MAC
//	8-13:[6]  dst MAC
//	14-15:u16 session key (big-endian)
//	16-17:[2] client-type magic {0x00, 0x15}
//	18-21:u32 counter (big-endian)
//
// Server→client swaps the session-key (16-17) and client-type (14-15)
// fields. Upstream toggles this via the `mt_direction_fromserver` global —
// here we pass an explicit direction.
//
// Control records inside a DATA payload (9-byte header + body):
//
//	0-3: [4]  magic {0x56, 0x34, 0x12, 0xff}
//	4:   u8   cptype
//	5-8: u32  length (big-endian)
//	9..: [N]  body
//
// PING/PONG packets are 18 bytes: outer header truncated to drop the
// counter, with bytes 14-17 zeroed (no seskey, no client-type magic).

const (
	// udpPort is the well-known MAC-Telnet UDP port.
	udpPort = 20561

	// headerLen is the full outer header for SESSIONSTART/DATA/ACK/END.
	headerLen = 22

	// pingHeaderLen is the trimmed header used for PING/PONG.
	pingHeaderLen = 18

	// cpHeaderLen is the control-record header preceding each control body.
	cpHeaderLen = 9

	// maxPacket is the upstream MT_PACKET_LEN — single-datagram cap.
	maxPacket = 1500

	// protocolVersion is the constant byte 0 of every outer header.
	protocolVersion = 1
)

// pType — outer packet type (byte 1 of the header).
type pType uint8

const (
	pTypeSessionStart pType = 0
	pTypeData         pType = 1
	pTypeAck          pType = 2
	pTypePing         pType = 4
	pTypePong         pType = 5
	pTypeEnd          pType = 255
)

// cpType — control-record type (byte 4 of the control header). Values
// match `enum mt_cptype` in protocol.h. cpTypePlainData (-1) is synthetic:
// it is not a wire value but is used by the parser to surface raw terminal
// bytes that fall outside the magic-prefixed records.
type cpType int8

const (
	cpTypeBeginAuth   cpType = 0
	cpTypePassSalt    cpType = 1
	cpTypePassword    cpType = 2
	cpTypeUsername    cpType = 3
	cpTypeTermType    cpType = 4
	cpTypeTermWidth   cpType = 5
	cpTypeTermHeight  cpType = 6
	cpTypePacketError cpType = 7
	cpTypeEndAuth     cpType = 9
	cpTypePlainData   cpType = -1
)

// Wire constants. Sizes are fixed by the protocol.
var (
	cpMagic    = [4]byte{0x56, 0x34, 0x12, 0xff}
	clientType = [2]byte{0x00, 0x15}
)

// direction names which side originates the packet. Encoding and decoding
// take it explicitly so the client/server layout swap stays at the call
// site, not behind a package-global flag.
type direction uint8

const (
	dirToServer direction = iota // client→server
	dirToClient                  // server→client
)

// header is the parsed/serializable form of the 22-byte outer header.
// Counter and SessionKey are exposed in host byte order; the encode/decode
// helpers handle wire-order conversion.
type header struct {
	Version    uint8
	PType      pType
	SrcAddr    [6]byte
	DstAddr    [6]byte
	SessionKey uint16
	Counter    uint32
}

// Errors returned by decode helpers.
var (
	errShortHeader  = errors.New("mactelnet: packet shorter than outer header")
	errShortControl = errors.New("mactelnet: truncated control record")
	errBadMagic     = errors.New("mactelnet: control record missing magic")
)

// encode serializes h into buf and returns the number of bytes written
// (always headerLen). Caller must size buf to at least headerLen.
func (h header) encode(buf []byte, dir direction) int {
	_ = buf[headerLen-1] // bounds-check hoist
	buf[0] = protocolVersion
	buf[1] = byte(h.PType)
	copy(buf[2:8], h.SrcAddr[:])
	copy(buf[8:14], h.DstAddr[:])

	seskeyOff, ctypeOff := 14, 16
	if dir == dirToClient {
		seskeyOff, ctypeOff = 16, 14
	}
	binary.BigEndian.PutUint16(buf[seskeyOff:seskeyOff+2], h.SessionKey)
	copy(buf[ctypeOff:ctypeOff+2], clientType[:])

	binary.BigEndian.PutUint32(buf[18:22], h.Counter)
	return headerLen
}

// decodeHeader reads a 22-byte outer header from buf and returns it along
// with the remaining payload slice (buf[22:]).
func decodeHeader(buf []byte, dir direction) (header, []byte, error) {
	if len(buf) < headerLen {
		return header{}, nil, errShortHeader
	}
	var h header
	h.Version = buf[0]
	h.PType = pType(buf[1])
	copy(h.SrcAddr[:], buf[2:8])
	copy(h.DstAddr[:], buf[8:14])

	seskeyOff := 14
	if dir == dirToClient {
		seskeyOff = 16
	}
	h.SessionKey = binary.BigEndian.Uint16(buf[seskeyOff : seskeyOff+2])
	h.Counter = binary.BigEndian.Uint32(buf[18:22])
	return h, buf[headerLen:], nil
}

// encodePing writes an 18-byte PING (or PONG) header and returns the
// number of bytes written. PING/PONG carry no session key, client-type
// magic, or counter — bytes 14-17 are zero and the counter is omitted.
func encodePing(buf []byte, srcMAC, dstMAC [6]byte, isPong bool) int {
	_ = buf[pingHeaderLen-1]
	buf[0] = protocolVersion
	if isPong {
		buf[1] = byte(pTypePong)
	} else {
		buf[1] = byte(pTypePing)
	}
	copy(buf[2:8], srcMAC[:])
	copy(buf[8:14], dstMAC[:])
	for i := 14; i < pingHeaderLen; i++ {
		buf[i] = 0
	}
	return pingHeaderLen
}

// encodeControl appends one control record to buf and returns the number
// of bytes written. The buffer must already contain the outer header at
// positions 0..headerLen and any prior control records; pass the slice
// from the current write offset onward.
//
// For cpTypePlainData the magic header and length are omitted and only
// the raw body is written — this matches upstream's add_control_packet
// behavior, which uses PLAINDATA to splat un-framed terminal bytes.
func encodeControl(buf []byte, ct cpType, body []byte) (int, error) {
	if ct == cpTypePlainData {
		if len(body) > len(buf) {
			return 0, errShortControl
		}
		return copy(buf, body), nil
	}
	need := cpHeaderLen + len(body)
	if need > len(buf) {
		return 0, errShortControl
	}
	copy(buf[0:4], cpMagic[:])
	buf[4] = byte(ct)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(body)))
	copy(buf[cpHeaderLen:], body)
	return need, nil
}

// controlRecord is one decoded entry from iterateControl.
type controlRecord struct {
	CPType cpType
	Body   []byte // alias into the caller's buffer; do not retain past the call
}

// iterateControl walks the payload following an outer DATA header and
// yields control records via fn. Records with the magic prefix are decoded
// as control packets; any trailing bytes that don't carry the magic are
// surfaced as a single cpTypePlainData record covering the remainder. This
// mirrors upstream's parse_control_packet, which switches to PLAINDATA on
// magic mismatch and consumes the rest of the buffer.
//
// Iteration stops if fn returns false, on a truncated length field, or
// when payload is exhausted.
func iterateControl(payload []byte, fn func(controlRecord) bool) error {
	for len(payload) > 0 {
		if len(payload) < cpHeaderLen || string(payload[0:4]) != string(cpMagic[:]) {
			fn(controlRecord{CPType: cpTypePlainData, Body: payload})
			return nil
		}
		ct := cpType(int8(payload[4]))
		ln := binary.BigEndian.Uint32(payload[5:9])
		body := payload[cpHeaderLen:]
		if uint32(len(body)) < ln {
			// truncated body — clamp to available, surface, and stop.
			// upstream does the same: cpkthdr->length = remainder.
			ln = uint32(len(body))
		}
		if !fn(controlRecord{CPType: ct, Body: body[:ln]}) {
			return nil
		}
		payload = body[ln:]
	}
	return nil
}
