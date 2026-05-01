// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Auth flow — ported from _upstream/MAC-Telnet/src/mactelnet.c (send_auth,
// handle_packet) and protocol.h.
//
// 1. Client sends DATA with control records:
//      BEGINAUTH (empty)
//      PASSSALT  (username || \0 || client EC-SRP pubkey, 33 bytes)  [EC-SRP only]
//
// 2. Server replies with PASSSALT carrying either:
//      16 bytes — legacy MD5 challenge salt
//      49 bytes — 33-byte server EC-SRP pubkey followed by 16-byte salt
//
// 3. Client sends DATA with:
//      PASSWORD    (17 bytes for MD5, 32 bytes for EC-SRP)
//      USERNAME    (login string)
//      TERM_TYPE   (TERM env value, e.g. "xterm-256color")
//      TERM_WIDTH  (u16 little-endian)
//      TERM_HEIGHT (u16 little-endian)
//
// 4. Server replies with END_AUTH on success; PLAINDATA terminal traffic
//    flows from then on.

type authMode uint8

const (
	authModeMD5   authMode = 1
	authModeECSRP authMode = 2
)

const (
	md5SaltLen        = 16
	ecsrpSaltLen      = 49 // 33-byte server pubkey + 16-byte salt
	ecsrpPubkeyLen    = 33 // 32-byte x + 1-byte y-parity
	md5ResponseLen    = 17 // leading 0x00 + 16-byte MD5
	ecsrpResponseLen  = 32
	mtweiValidatorLen = 32
)

// detectAuthMode picks MD5 or EC-SRP from the PASSSALT body length the
// server sent in step 2 above.
func detectAuthMode(passSaltBody []byte) (authMode, error) {
	switch len(passSaltBody) {
	case md5SaltLen:
		return authModeMD5, nil
	case ecsrpSaltLen:
		return authModeECSRP, nil
	default:
		return 0, fmt.Errorf("mactelnet: PASSSALT length %d is neither MD5 (16) nor EC-SRP (49)", len(passSaltBody))
	}
}

// computeMD5Response builds the 17-byte legacy challenge response:
// 0x00 || MD5(0x00 || password || salt). The leading zero byte is part of
// the wire format, not a hash artifact — RouterOS expects to read 17 bytes
// where byte 0 is always zero.
func computeMD5Response(password string, salt []byte) [md5ResponseLen]byte {
	var out [md5ResponseLen]byte
	h := md5.New()
	h.Write([]byte{0x00})
	h.Write([]byte(password))
	h.Write(salt)
	out[0] = 0
	copy(out[1:], h.Sum(nil))
	return out
}

// mtweiID computes the SRP validator: SHA256(salt || SHA256(username || ":" || password)).
// 32-byte output. Matches mtwei_id in mtwei.c.
func mtweiID(username, password string, salt []byte) [mtweiValidatorLen]byte {
	inner := sha256.New()
	inner.Write([]byte(username))
	inner.Write([]byte{':'})
	inner.Write([]byte(password))
	innerSum := inner.Sum(nil)

	outer := sha256.New()
	outer.Write(salt)
	outer.Write(innerSum)

	var out [mtweiValidatorLen]byte
	copy(out[:], outer.Sum(nil))
	return out
}

// buildAuthInit writes the control-record sequence for the first DATA
// packet of the auth flow (step 1 above) into buf and returns the bytes
// written. clientPub is required — we always advertise EC-SRP capability
// by sending our pubkey, and let the server downgrade to MD5 by replying
// with a 16-byte salt instead of the full 49-byte payload.
func buildAuthInit(buf []byte, username string, clientPub *[ecsrpPubkeyLen]byte) (int, error) {
	n, err := encodeControl(buf, cpTypeBeginAuth, nil)
	if err != nil {
		return 0, err
	}

	body := make([]byte, 0, len(username)+1+ecsrpPubkeyLen)
	body = append(body, []byte(username)...)
	body = append(body, 0)
	body = append(body, clientPub[:]...)

	m, err := encodeControl(buf[n:], cpTypePassSalt, body)
	if err != nil {
		return 0, err
	}
	return n + m, nil
}

// buildAuthFinish writes the control records for the second client DATA
// packet (step 3 above): PASSWORD, USERNAME, TERM_TYPE, TERM_WIDTH,
// TERM_HEIGHT. Terminal dimensions are u16 LITTLE-endian — every other
// multibyte field in the protocol is big-endian, but RouterOS reads term
// size as little-endian (see mactelnet.c:295 `htole16`).
func buildAuthFinish(buf []byte, response, username, termType []byte, cols, rows uint16) (int, error) {
	n, err := encodeControl(buf, cpTypePassword, response)
	if err != nil {
		return 0, err
	}
	m, err := encodeControl(buf[n:], cpTypeUsername, username)
	if err != nil {
		return 0, err
	}
	n += m
	m, err = encodeControl(buf[n:], cpTypeTermType, termType)
	if err != nil {
		return 0, err
	}
	n += m

	var dim [2]byte
	binary.LittleEndian.PutUint16(dim[:], cols)
	m, err = encodeControl(buf[n:], cpTypeTermWidth, dim[:])
	if err != nil {
		return 0, err
	}
	n += m

	binary.LittleEndian.PutUint16(dim[:], rows)
	m, err = encodeControl(buf[n:], cpTypeTermHeight, dim[:])
	if err != nil {
		return 0, err
	}
	n += m

	return n, nil
}
