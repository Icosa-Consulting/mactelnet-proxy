// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import "time"

// Sequencing & retransmit primitives — port of the counter and timer logic
// in _upstream/MAC-Telnet/src/mactelnet.c (`send_udp`, `handle_packet`)
// and the schedule table in protocol.h:147.
//
// MAC-Telnet runs a simple stop-and-wait reliability layer on top of UDP:
// every DATA packet carries a 32-bit byte-offset counter; the receiver
// returns an ACK whose counter equals (sender's counter + payload length);
// the sender retransmits on a fixed exponential-ish schedule until ACKed
// or the schedule is exhausted (treated as session timeout).
//
// The retransmit *driver* lives next to the session state machine, where
// it can share the read loop that already services inbound packets while
// we wait for our own ACK.

// upstreamRamp is the exact retransmit schedule from upstream
// `protocol.h:147` (values in milliseconds). Sum is ~2.37 s. We use it
// as the natural fast-path ramp; longer schedules are built by appending
// 1-second entries on top of this base — see buildRetransmitSchedule.
var upstreamRamp = [...]time.Duration{
	15 * time.Millisecond,
	20 * time.Millisecond,
	30 * time.Millisecond,
	50 * time.Millisecond,
	90 * time.Millisecond,
	170 * time.Millisecond,
	330 * time.Millisecond,
	660 * time.Millisecond,
	1000 * time.Millisecond,
}

// authSchedule and dataSchedule are the schedules used during the
// pre-terminal handshake and after END_AUTH respectively. Splitting them
// lets us be patient during EC-SRP / SESSIONSTART (one-shot, slow CPUs
// or busy MikroTiks survive a couple seconds of churn) without slowing
// per-keystroke retransmits inside the session (where slow feels broken).
//
// Defaults: dataSchedule mirrors upstream (~2.37 s, what the protocol
// has shipped with for years); authSchedule extends the upstream ramp
// to a 10 s total budget. Operators can override both via Configure.
var (
	authSchedule = buildRetransmitSchedule(10 * time.Second)
	dataSchedule = buildRetransmitSchedule(0) // 0 ⇒ upstream ramp as-is
)

// Configure rebuilds the retransmit schedules with the given total
// budgets. A zero or negative budget falls back to the upstream ramp.
// Call once at startup before any Session is opened; the package vars
// are not goroutine-safe under concurrent updates.
func Configure(authBudget, dataBudget time.Duration) {
	authSchedule = buildRetransmitSchedule(authBudget)
	dataSchedule = buildRetransmitSchedule(dataBudget)
}

// buildRetransmitSchedule produces a retransmit interval slice whose
// total wait sums to roughly `budget`. The schedule starts with the
// upstream ramp (15 ms doubling-ish to 1 s) — that gives fast retries
// for the common dropped-packet case — and pads with 1 s entries until
// the budget is consumed. A budget shorter than the natural ramp
// truncates the prefix; budget=0 returns the ramp as-is.
func buildRetransmitSchedule(budget time.Duration) []time.Duration {
	if budget <= 0 {
		out := make([]time.Duration, len(upstreamRamp))
		copy(out, upstreamRamp[:])
		return out
	}
	out := make([]time.Duration, 0, len(upstreamRamp)+8)
	var sum time.Duration
	for _, iv := range upstreamRamp {
		if sum+iv > budget {
			break
		}
		out = append(out, iv)
		sum += iv
	}
	for sum+time.Second <= budget {
		out = append(out, time.Second)
		sum += time.Second
	}
	if rem := budget - sum; rem > 0 {
		out = append(out, rem)
	}
	return out
}

// counters tracks the per-session running byte counters in both directions.
//
// `out` is the total number of payload bytes the client has sent; the
// counter placed on the wire for a new DATA packet is `out` *before* the
// payload is added, then `out` advances by the payload length. The peer
// ACK echoes the post-bump value.
//
// `in` is the highest accepted incoming counter. The wire counter is u32;
// upstream tracks it in a `long` initialized to -1 to distinguish "never
// seen" from a legitimate counter of 0 — we use a separate `inSeen` bool.
type counters struct {
	out    uint32
	in     uint32
	inSeen bool
}

// reserveOut allocates `n` counter bytes for an outgoing DATA payload.
// Returns the counter value to put on the wire (the value *before* the
// bump). Mirrors upstream's
//
//	counter = outcounter; outcounter += plen;
func (c *counters) reserveOut(n uint32) uint32 {
	seq := c.out
	c.out += n
	return seq
}

// acceptIncoming returns true if `seq` should be processed as a new DATA
// packet's counter, and updates the high-water mark accordingly. Mirrors
// upstream's
//
//	if (counter > incounter || (incounter - counter) > 65535)
//
// — the second clause accepts packets whose counter has wrapped past
// UINT32_MAX, which can happen on a long-lived session.
//
// 65535 is upstream's chosen wrap threshold: any backwards jump larger
// than 64 KiB is treated as a wrap rather than as a stale retransmit.
// Anything inside that window is treated as a duplicate and dropped.
func (c *counters) acceptIncoming(seq uint32) bool {
	if !c.inSeen {
		c.inSeen = true
		c.in = seq
		return true
	}
	if seq > c.in {
		c.in = seq
		return true
	}
	if c.in-seq > 65535 {
		c.in = seq
		return true
	}
	return false
}

// ackCounterFor computes the counter to put on the ACK we send back for
// an inbound DATA packet of `payloadLen` bytes that carried wire counter
// `inboundSeq`. Matches upstream
//
//	pkthdr.counter + (data_len - MT_HEADER_LEN)
//
// — i.e., one past the last byte of the payload, in the peer's outgoing
// stream.
func ackCounterFor(inboundSeq uint32, payloadLen uint32) uint32 {
	return inboundSeq + payloadLen
}
