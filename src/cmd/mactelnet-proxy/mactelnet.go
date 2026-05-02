// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"mactelnet-proxy/internal/mactelnet"
)

// runMactelnet implements the `mactelnet-proxy mactelnet` subcommand.
// Opens a single session, pumps stdin → device and device → stdout.
//
// Smoke-test mode: the local TTY stays in cooked (line-buffered) mode.
// You'll need to press Enter to send each line, and arrow keys / Tab /
// Ctrl+C won't behave like an interactive shell. That's fine for
// confirming the auth handshake and basic command exchange work end-to-
// end against a real MikroTik. Raw-mode polish is a separate task.
func runMactelnet(args []string) int {
	fs := flag.NewFlagSet("mactelnet", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	user := fs.String("u", "", "username (required)")
	iface := fs.String("i", "", "network interface to bind, e.g. eth0 (required)")
	pass := fs.String("p", "", "password (or set MACTELNET_PASSWORD)")
	vlanID := fs.Uint("vlan", 0,
		"802.1Q VLAN ID (1–4094) to tag emitted frames with; 0 = untagged. "+
			"Required when running inside a RouterOS container whose veth "+
			"sits on a vlan-filtered bridge — RouterOS has no kernel VLAN "+
			"sub-interfaces, so the proxy must tag itself.")

	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintln(w, "usage: mactelnet-proxy mactelnet -u USER -i IFACE [-p PASS] MAC")
		fmt.Fprintln(w)
		fs.PrintDefaults()
		fmt.Fprintln(w)
		fmt.Fprintln(w, "If -p is omitted, the MACTELNET_PASSWORD environment variable is used.")
		fmt.Fprintln(w, "MAC is the colon-separated EUI-48 address of the target MikroTik.")
		fmt.Fprintln(w, "Note: stdin is line-buffered (no raw TTY support yet).")
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *user == "" || *iface == "" || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if *vlanID > 4094 {
		fmt.Fprintln(os.Stderr, "mactelnet-proxy: -vlan must be in 1..4094 (or 0 for untagged)")
		return 2
	}

	mac := fs.Arg(0)
	password := *pass
	if password == "" {
		password = os.Getenv("MACTELNET_PASSWORD")
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "mactelnet-proxy: password required (use -p or MACTELNET_PASSWORD)")
		return 2
	}

	cols, rows := getTermSize(int(os.Stdin.Fd()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sess, err := mactelnet.Open(ctx, *iface, mac, *user, password, cols, rows, uint16(*vlanID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "mactelnet-proxy: open: %v\n", err)
		return 1
	}
	defer sess.Close()

	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	defer signal.Stop(winchCh)
	go func() {
		for range winchCh {
			c, r := getTermSize(int(os.Stdin.Fd()))
			_ = sess.Resize(c, r)
		}
	}()

	// stdin → session and session → stdout run concurrently. We exit on
	// whichever returns first (typically the session→stdout side, when
	// the device closes the session). The stdin pump may stay blocked
	// in os.Stdin.Read until the process exits — acceptable for a CLI
	// smoke-test tool.
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(sess, os.Stdin); errCh <- err }()
	go func() { _, err := io.Copy(os.Stdout, sess); errCh <- err }()

	select {
	case <-ctx.Done():
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			fmt.Fprintf(os.Stderr, "mactelnet-proxy: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "Connection closed.")
		return 0
	}
}

// getTermSize returns the terminal size for fd. Returns (0, 0) if fd is
// not a TTY or the ioctl fails — the protocol accepts zero dims and the
// device picks defaults in that case.
func getTermSize(fd int) (cols, rows uint16) {
	type winsize struct {
		Row, Col, Xpix, Ypix uint16
	}
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0, 0
	}
	return ws.Col, ws.Row
}
