// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package mactelnet

import (
	"testing"
	"time"
)

func TestCountersReserveOut(t *testing.T) {
	var c counters
	if got := c.reserveOut(10); got != 0 {
		t.Errorf("first reserveOut: got %d, want 0", got)
	}
	if got := c.reserveOut(5); got != 10 {
		t.Errorf("second reserveOut: got %d, want 10", got)
	}
	if c.out != 15 {
		t.Errorf("out: got %d, want 15", c.out)
	}
}

func TestAcceptIncomingFirstAlwaysAccepted(t *testing.T) {
	// Even a counter of 0 must be accepted on first sight — the initial
	// "unseen" state is distinct from a legitimate 0.
	var c counters
	if !c.acceptIncoming(0) {
		t.Fatal("first acceptIncoming(0) was rejected")
	}
	if !c.inSeen || c.in != 0 {
		t.Fatalf("state after first accept: inSeen=%v in=%d", c.inSeen, c.in)
	}
}

func TestAcceptIncomingForwardProgress(t *testing.T) {
	var c counters
	c.acceptIncoming(100)
	if !c.acceptIncoming(150) {
		t.Fatal("forward 150 was rejected")
	}
	if c.in != 150 {
		t.Errorf("in: got %d, want 150", c.in)
	}
}

func TestAcceptIncomingDuplicateRejected(t *testing.T) {
	var c counters
	c.acceptIncoming(100)
	if c.acceptIncoming(100) {
		t.Error("duplicate counter 100 was accepted")
	}
	if c.acceptIncoming(50) {
		t.Error("older counter 50 (within 65535 window) was accepted")
	}
	if c.in != 100 {
		t.Errorf("in mutated by rejected packets: got %d, want 100", c.in)
	}
}

func TestAcceptIncomingWrap(t *testing.T) {
	// Highest accepted counter close to UINT32_MAX, then a small new
	// counter — the gap exceeds 65535 so it's treated as wrap, not as
	// a stale retransmit.
	var c counters
	near := uint32(0xFFFFFFF0)
	c.acceptIncoming(near)
	if !c.acceptIncoming(10) {
		t.Fatalf("wrap: counter 10 after %#x was rejected", near)
	}
	if c.in != 10 {
		t.Errorf("in after wrap: got %#x, want 10", c.in)
	}
}

func TestAcceptIncomingNotWrapWithinWindow(t *testing.T) {
	// A backwards jump inside the 65535 window is a duplicate, not a wrap.
	var c counters
	c.acceptIncoming(70000)
	if c.acceptIncoming(20000) {
		t.Error("backwards jump 70000→20000 (gap 50000, < 65535) accepted as wrap")
	}
}

func TestAckCounterFor(t *testing.T) {
	if got := ackCounterFor(1000, 50); got != 1050 {
		t.Errorf("ackCounterFor(1000, 50): got %d, want 1050", got)
	}
	// Wrap case: should overflow naturally as u32.
	if got := ackCounterFor(0xFFFFFFFE, 5); got != 3 {
		t.Errorf("ackCounterFor wrap: got %d, want 3", got)
	}
}

func TestUpstreamRampShape(t *testing.T) {
	// Sanity-check the upstream-mirrored ramp matches protocol.h:147.
	want := []int{15, 20, 30, 50, 90, 170, 330, 660, 1000}
	if len(upstreamRamp) != len(want) {
		t.Fatalf("length: got %d, want %d", len(upstreamRamp), len(want))
	}
	for i, ms := range want {
		if got := upstreamRamp[i].Milliseconds(); got != int64(ms) {
			t.Errorf("interval[%d]: got %dms, want %dms", i, got, ms)
		}
	}
}

func TestBuildRetransmitSchedule(t *testing.T) {
	// budget=0 ⇒ upstream ramp verbatim.
	got := buildRetransmitSchedule(0)
	if len(got) != len(upstreamRamp) {
		t.Errorf("budget=0 length: got %d, want %d", len(got), len(upstreamRamp))
	}

	// budget=10s ⇒ ramp prefix that fits, then 1s pads up to budget.
	got = buildRetransmitSchedule(10 * time.Second)
	var sum time.Duration
	for _, d := range got {
		sum += d
	}
	if sum != 10*time.Second {
		t.Errorf("budget=10s sum: got %v, want %v", sum, 10*time.Second)
	}

	// budget shorter than ramp ⇒ truncated prefix, no overshoot.
	got = buildRetransmitSchedule(100 * time.Millisecond)
	sum = 0
	for _, d := range got {
		sum += d
	}
	if sum > 100*time.Millisecond {
		t.Errorf("short budget overshoot: sum=%v want ≤100ms", sum)
	}
}
