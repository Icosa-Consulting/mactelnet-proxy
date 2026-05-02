// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

// rxLoop is the single goroutine that reads from the UDP socket and
// demuxes inbound packets. It runs from session start until ctx is
// canceled or the socket is closed.
//
// Per-ptype handling, mirroring upstream's handle_packet:
//
//   - ACK:  forward the counter to ackCh (best-effort; drop if no listener).
//   - DATA: synthesize and send the matching ACK back, then walk control
//     records. PLAINDATA goes to rxPipe in terminal mode (dropped before).
//     Any other control record (PASSSALT, END_AUTH, …) is forwarded to
//     controlCh for the handshake driver or future consumers.
//   - END:  trigger session shutdown.
//
// Other ptypes (including the SESSIONSTART reply the device may emit when
// it sees our initial broadcast) are silently dropped — upstream logs them
// as "Unhandled" but otherwise ignores them, and so do we.
func (s *Session) rxLoop() {
	defer close(s.done)
	defer s.rxPipeW.Close()

	buf := make([]byte, maxPacket)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Short read deadline so we re-check ctx periodically. Closing
		// the conn from Close() also unblocks Read via ErrClosed.
		_ = s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		n, err := s.conn.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			s.fail(err)
			return
		}
		previewLen := n
		if previewLen > 32 {
			previewLen = 32
		}
		slog.Debug("mactelnet: rx datagram",
			"len", n, "head", hex.EncodeToString(buf[:previewLen]))
		if n < headerLen {
			slog.Debug("mactelnet: rx dropped (short)", "len", n)
			continue
		}

		h, payload, derr := decodeHeader(buf[:n], dirToClient)
		if derr != nil {
			slog.Debug("mactelnet: rx dropped (bad header)", "err", derr)
			continue
		}
		if h.SessionKey != s.sessionKey {
			slog.Debug("mactelnet: rx dropped (session-key mismatch)",
				"got", h.SessionKey, "want", s.sessionKey,
				"ptype", h.PType)
			continue
		}

		switch h.PType {
		case pTypeAck:
			// Best-effort: if nobody is currently waiting for an ACK
			// (e.g., this is a duplicate or a keepalive ack), drop it.
			select {
			case s.ackCh <- h.Counter:
			default:
			}

		case pTypeData:
			s.processInboundData(h, payload)

		case pTypeEnd:
			s.fail(io.EOF)
			return
		}
	}
}

// processInboundData ACKs a server DATA packet, deduplicates by counter,
// and dispatches each control record to either the rxPipe (PLAINDATA in
// terminal mode) or controlCh (everything else, for the handshake driver).
func (s *Session) processInboundData(h header, payload []byte) {
	plen := uint32(len(payload))

	// Always ACK, even if we're going to drop the packet as a duplicate —
	// the peer needs to see the ACK to retire its retransmit queue.
	ack := header{
		PType:      pTypeAck,
		SrcAddr:    s.srcMAC,
		DstAddr:    s.dstMAC,
		SessionKey: s.sessionKey,
		Counter:    ackCounterFor(h.Counter, plen),
	}
	var ackBuf [headerLen]byte
	ack.encode(ackBuf[:], dirToServer)

	s.sendMu.Lock()
	_ = s.sender.Send(ackBuf[:], s.dstMAC)
	s.sendMu.Unlock()

	if !s.counters.acceptIncoming(h.Counter) {
		return
	}

	_ = iterateControl(payload, func(rec controlRecord) bool {
		switch rec.CPType {
		case cpTypePlainData:
			if s.terminalMode.Load() {
				// rxPipeW.Write blocks if the consumer isn't reading,
				// which is the right backpressure: stalls the demux
				// instead of buffering unboundedly.
				_, _ = s.rxPipeW.Write(rec.Body)
			}
			// Pre-terminal-mode PLAINDATA has no use case — drop it.

		default:
			body := make([]byte, len(rec.Body))
			copy(body, rec.Body)
			select {
			case s.controlCh <- controlPacket{cpt: rec.CPType, body: body}:
			case <-s.ctx.Done():
				return false
			}
		}
		return true
	})
}

// keepaliveLoop sends an empty ACK (at the current outgoing counter)
// every keepaliveInterval. This matches upstream's mactelnet.c:862
// behavior — a no-op ACK is enough to keep NAT/firewall mappings open
// and to detect a vanished peer (which surfaces as ICMP "port
// unreachable" or similar on the next read).
//
// Upstream sends only on 10s of *inactivity*; we send unconditionally
// every 10s. The cost (one 22-byte datagram on a working session) is
// negligible and the simpler timer avoids the inactivity-tracking knob.
func (s *Session) keepaliveLoop() {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if s.closed.Load() {
				return
			}
			ack := header{
				PType:      pTypeAck,
				SrcAddr:    s.srcMAC,
				DstAddr:    s.dstMAC,
				SessionKey: s.sessionKey,
				Counter:    s.counters.out,
			}
			var buf [headerLen]byte
			ack.encode(buf[:], dirToServer)

			s.sendMu.Lock()
			_ = s.sender.Send(buf[:], s.dstMAC)
			s.sendMu.Unlock()
		}
	}
}
