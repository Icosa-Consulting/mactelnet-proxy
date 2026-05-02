// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

// Package mactelnet implements the MAC-Telnet client wire protocol — a
// connection-oriented protocol over UDP/20561 with EC-SRP (or legacy MD5)
// challenge-response auth, sequence-and-ACK retransmission, and per-
// session keepalive.
//
// Public surface is small: callers Open a Session, treat it as an
// io.ReadWriteCloser for terminal traffic, and Resize when their TTY
// changes size. The byte streams are raw — VT escape sequences and other
// terminal control characters pass through untouched.
package mactelnet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunables. These pick reasonable defaults for the proxy use case; the
// protocol itself doesn't dictate any of them.
const (
	// keepaliveInterval matches upstream mactelnet.c:860 — 10 seconds.
	keepaliveInterval = 10 * time.Second

	// authPhaseTimeout caps the entire SESSIONSTART → END_AUTH dance.
	// Generous on purpose: a slow MikroTik plus a CPU-pinned EC-SRP
	// handshake can take a few seconds end to end.
	authPhaseTimeout = 30 * time.Second

	// defaultTermType is sent in the auth handshake's TERM_TYPE record
	// when the caller doesn't override it. RouterOS recognizes the
	// common terminfo names; xterm-256color is a safe modern default.
	defaultTermType = "xterm-256color"
)

// ErrAuthFailed is returned by Open when the server rejects credentials
// or the handshake otherwise fails to reach END_AUTH.
var ErrAuthFailed = errors.New("mactelnet: authentication failed")

// ErrRetransmitExhausted is returned when no ACK arrives within the full
// retransmit_intervals schedule — treated as a peer-timeout.
var ErrRetransmitExhausted = errors.New("mactelnet: retransmit exhausted, peer not responding")

// controlPacket is one inbound control record (anything except PLAINDATA),
// forwarded by the rx loop to the handshake driver via Session.controlCh.
type controlPacket struct {
	cpt  cpType
	body []byte // owned copy
}

// Session is one in-flight MAC-Telnet session. Read returns terminal
// output from the device; Write sends terminal input. Read and Write may
// be called concurrently from different goroutines; multiple concurrent
// Writes are serialized internally.
type Session struct {
	// conn is the receive socket. For untagged sessions it's a
	// *net.UDPConn bound to 0.0.0.0:20561; for VLAN-tagged sessions
	// it's a *rawReceiver wrapping AF_PACKET — both implementations
	// satisfy the rxConn interface and the rest of the protocol code
	// is agnostic to which is in use.
	conn   rxConn
	sender *rawSender

	srcMAC     [6]byte
	dstMAC     [6]byte
	sessionKey uint16

	counters counters

	// sendMu serializes raw socket writes — taken by all four senders
	// (handshake, Write, Resize, keepalive, rx-loop ack-back).
	sendMu sync.Mutex

	// dataMu serializes outbound DATA-with-ACK-wait sequences. Without
	// it, two concurrent calls would race on ackCh.
	dataMu sync.Mutex

	// ackCh delivers inbound ACK counters from the rx loop. Buffered so
	// stray (duplicate, keepalive) ACKs don't block the rx loop.
	ackCh chan uint32

	// controlCh delivers inbound non-PLAINDATA control records.
	controlCh chan controlPacket

	// rxPipeR/W carries inbound PLAINDATA. Writes block when the consumer
	// isn't reading — that's the desired backpressure.
	rxPipeR *io.PipeReader
	rxPipeW *io.PipeWriter

	// terminalMode flips to true after END_AUTH. Before then, PLAINDATA
	// is dropped (no consumer); after, it's pumped to rxPipeW.
	terminalMode atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	done   chan struct{}
	errVal atomic.Value // last error, sticky
}

// Open establishes a MAC-Telnet session to the given target MAC over the
// supplied interface. iface is the local interface name (e.g. "eth0");
// auto-discovery is not supported. cols/rows are the initial terminal
// dimensions; pass zeros if unknown.
//
// vlanID, if non-zero, makes the proxy emit and accept 802.1Q-tagged
// frames with that VID. Required when the proxy interface sits on a
// RouterOS bridge configured for vlan-filtering / tagged-only access
// (RouterOS has no Linux VLAN sub-interface concept, so the kernel
// can't tag for us — the proxy has to do it itself). Zero means
// untagged, the historical behaviour.
//
// On success the returned Session is ready for terminal traffic via
// Read/Write. On failure all resources are released before returning.
func Open(ctx context.Context, iface, mac, username, password string,
	cols, rows, vlanID uint16,
) (*Session, error) {
	dst, err := parseMAC(mac)
	if err != nil {
		return nil, err
	}
	netIface, err := resolveInterface(iface)
	if err != nil {
		return nil, err
	}

	conn, sender, err := openSockets(netIface, vlanID)
	if err != nil {
		return nil, err
	}

	var skBytes [2]byte
	if _, err := rand.Read(skBytes[:]); err != nil {
		conn.Close()
		sender.Close()
		return nil, fmt.Errorf("mactelnet: rand: %w", err)
	}

	s := &Session{
		conn:       conn,
		sender:     sender,
		dstMAC:     dst,
		sessionKey: binary.BigEndian.Uint16(skBytes[:]),
		ackCh:      make(chan uint32, 8),
		controlCh:  make(chan controlPacket, 16),
		done:       make(chan struct{}),
	}
	copy(s.srcMAC[:], netIface.HardwareAddr)
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.rxPipeR, s.rxPipeW = io.Pipe()

	go s.rxLoop()

	if err := s.handshake(username, password, cols, rows); err != nil {
		s.Close()
		return nil, err
	}

	go s.keepaliveLoop()
	return s, nil
}

// Read blocks until terminal output bytes are available from the peer,
// or the session is closed. Implements io.Reader.
func (s *Session) Read(p []byte) (int, error) {
	return s.rxPipeR.Read(p)
}

// Write sends p as one or more PLAINDATA control records inside a DATA
// packet, waits for the peer's ACK (with retransmit), and returns once
// the bytes are confirmed received.
//
// Concurrent Writes from different goroutines are serialized.
func (s *Session) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p)+cpHeaderLen > maxPacket-headerLen {
		// Avoid building an oversized datagram. Caller should chunk.
		return 0, fmt.Errorf("mactelnet: write too large (%d bytes)", len(p))
	}

	payloadBuf := make([]byte, cpHeaderLen+len(p))
	n, err := encodeControl(payloadBuf, cpTypePlainData, p)
	if err != nil {
		return 0, err
	}
	if err := s.sendDataAndWaitAck(payloadBuf[:n]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Resize informs the peer of a new terminal size mid-session. Sends a
// DATA packet carrying TERM_WIDTH and TERM_HEIGHT control records.
func (s *Session) Resize(cols, rows uint16) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	payloadBuf := make([]byte, 2*(cpHeaderLen+2))
	var dim [2]byte

	binary.LittleEndian.PutUint16(dim[:], cols)
	n, err := encodeControl(payloadBuf, cpTypeTermWidth, dim[:])
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(dim[:], rows)
	m, err := encodeControl(payloadBuf[n:], cpTypeTermHeight, dim[:])
	if err != nil {
		return err
	}
	return s.sendDataAndWaitAck(payloadBuf[:n+m])
}

// Close tears down the session: best-effort END to the peer, then closes
// the socket and pipes. Idempotent.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Best-effort END. Any error here is moot — we're tearing down.
	end := header{
		PType:      pTypeEnd,
		SrcAddr:    s.srcMAC,
		DstAddr:    s.dstMAC,
		SessionKey: s.sessionKey,
	}
	var buf [headerLen]byte
	end.encode(buf[:], dirToServer)
	s.sendMu.Lock()
	_ = s.sender.Send(buf[:], s.dstMAC)
	s.sendMu.Unlock()

	s.cancel()
	_ = s.conn.Close()
	_ = s.sender.Close()
	_ = s.rxPipeW.Close()
	_ = s.rxPipeR.Close()

	<-s.done
	return nil
}

// fail records a session-level error and triggers shutdown. Called by
// the rx loop on socket errors or peer-initiated END.
func (s *Session) fail(err error) {
	if err != nil {
		s.errVal.CompareAndSwap(nil, err)
	}
	if s.closed.CompareAndSwap(false, true) {
		s.cancel()
		_ = s.conn.Close()
		_ = s.sender.Close()
		_ = s.rxPipeW.Close()
	}
}

// handshake runs SESSIONSTART → BEGINAUTH/PASSSALT → PASSSALT (in) →
// PASSWORD/USERNAME/TERM_* → END_AUTH (in). Blocks until either END_AUTH
// arrives (success) or the auth-phase timeout/ctx fires.
func (s *Session) handshake(username, password string, cols, rows uint16) error {
	hCtx, cancel := context.WithTimeout(s.ctx, authPhaseTimeout)
	defer cancel()

	if err := s.sendSessionStart(); err != nil {
		return fmt.Errorf("send SESSIONSTART: %w", err)
	}

	mtwei := newMtweiState()
	priv, clientPub, err := mtwei.keygen(rand.Reader, nil)
	if err != nil {
		return fmt.Errorf("EC-SRP keygen: %w", err)
	}

	payloadBuf := make([]byte, maxPacket-headerLen)

	n, err := buildAuthInit(payloadBuf, username, &clientPub)
	if err != nil {
		return fmt.Errorf("build auth init: %w", err)
	}
	if err := s.sendDataAndWaitAck(payloadBuf[:n]); err != nil {
		return fmt.Errorf("auth init: %w", err)
	}

	saltCp, err := s.awaitControl(hCtx, cpTypePassSalt)
	if err != nil {
		return fmt.Errorf("await PASSSALT: %w", err)
	}

	var response []byte
	switch len(saltCp.body) {
	case md5SaltLen:
		r := computeMD5Response(password, saltCp.body)
		response = r[:]
	case ecsrpSaltLen:
		var serverKey [ecsrpPubkeyLen]byte
		copy(serverKey[:], saltCp.body[:ecsrpPubkeyLen])
		salt := saltCp.body[ecsrpPubkeyLen:]
		validator := mtweiID(username, password, salt)
		r, err := mtwei.docrypto(priv, &serverKey, &clientPub, validator)
		if err != nil {
			return fmt.Errorf("EC-SRP docrypto: %w", err)
		}
		response = r[:]
	default:
		return fmt.Errorf("%w: PASSSALT length %d", ErrAuthFailed, len(saltCp.body))
	}

	n, err = buildAuthFinish(payloadBuf, response,
		[]byte(username), []byte(defaultTermType), cols, rows)
	if err != nil {
		return fmt.Errorf("build auth finish: %w", err)
	}
	if err := s.sendDataAndWaitAck(payloadBuf[:n]); err != nil {
		return fmt.Errorf("auth finish: %w", err)
	}

	if _, err := s.awaitControl(hCtx, cpTypeEndAuth); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}

	s.terminalMode.Store(true)
	return nil
}

// sendSessionStart fires the initial SESSIONSTART. No retransmit, no
// wait — the device will start replying at its own pace and the rx loop
// picks up subsequent frames as they arrive.
func (s *Session) sendSessionStart() error {
	h := header{
		PType:      pTypeSessionStart,
		SrcAddr:    s.srcMAC,
		DstAddr:    s.dstMAC,
		SessionKey: s.sessionKey,
	}
	var buf [headerLen]byte
	h.encode(buf[:], dirToServer)

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sender.Send(buf[:], s.dstMAC)
}

// sendDataAndWaitAck builds and transmits a DATA packet carrying payload,
// then drives the retransmit_intervals schedule waiting for the matching
// ACK. Returns nil on ACK, ErrRetransmitExhausted on timeout, or ctx.Err()
// on cancellation.
func (s *Session) sendDataAndWaitAck(payload []byte) error {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()

	// Drain any stale ACKs left in the channel from prior sends. After
	// taking dataMu we're the sole consumer, so post-drain the channel
	// holds only ACKs that arrive *after* our send.
	for {
		select {
		case <-s.ackCh:
		default:
			goto build
		}
	}
build:

	plen := uint32(len(payload))
	seq := s.counters.reserveOut(plen)
	wantAck := ackCounterFor(seq, plen)

	pkt := make([]byte, headerLen+len(payload))
	h := header{
		PType:      pTypeData,
		SrcAddr:    s.srcMAC,
		DstAddr:    s.dstMAC,
		SessionKey: s.sessionKey,
		Counter:    seq,
	}
	h.encode(pkt, dirToServer)
	copy(pkt[headerLen:], payload)

	send := func() error {
		s.sendMu.Lock()
		defer s.sendMu.Unlock()
		return s.sender.Send(pkt, s.dstMAC)
	}

	if err := send(); err != nil {
		return err
	}
	// Pick the appropriate retransmit schedule. Pre-END_AUTH packets use
	// the longer authSchedule (slow EC-SRP / sleepy MikroTik tolerated);
	// post-handshake terminal traffic uses the tighter dataSchedule so a
	// dropped keystroke doesn't visibly stall the session.
	schedule := dataSchedule
	if !s.terminalMode.Load() {
		schedule = authSchedule
	}
	for attempt := 0; attempt < len(schedule); attempt++ {
		err := s.waitForAck(wantAck, schedule[attempt])
		if err == nil {
			return nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err := send(); err != nil {
			return err
		}
	}
	return ErrRetransmitExhausted
}

// waitForAck blocks until either an ACK with counter == want arrives, the
// duration elapses, or ctx is canceled. Other ACKs (stale, keepalive) are
// silently consumed and ignored.
func (s *Session) waitForAck(want uint32, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errAckTimeout
		}
		t := time.NewTimer(remaining)
		select {
		case got := <-s.ackCh:
			t.Stop()
			if got == want {
				return nil
			}
			// non-matching ACK; keep waiting until deadline
		case <-t.C:
			return errAckTimeout
		case <-s.ctx.Done():
			t.Stop()
			return s.ctx.Err()
		}
	}
}

// awaitControl blocks until a control record of the requested type
// arrives, ctx is canceled, or hCtx (the handshake-phase deadline) fires.
// Records of other types received in the meantime are silently dropped —
// during the handshake we don't expect any others.
func (s *Session) awaitControl(hCtx context.Context, want cpType) (controlPacket, error) {
	for {
		select {
		case cp := <-s.controlCh:
			if cp.cpt == want {
				return cp, nil
			}
		case <-hCtx.Done():
			return controlPacket{}, hCtx.Err()
		case <-s.ctx.Done():
			return controlPacket{}, s.ctx.Err()
		}
	}
}

// errAckTimeout is the internal sentinel used by waitForAck. It's
// distinct from context errors so the retransmit loop can tell "deadline
// for this attempt" apart from "session canceled".
var errAckTimeout = errors.New("mactelnet: ack timeout (retransmit)")
