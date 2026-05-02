// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package sshserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"mactelnet-proxy/internal/mactelnet"
	"mactelnet-proxy/internal/mndp"
)

// SSH wire-format payload structs. ssh.Marshal/Unmarshal handle the
// length-prefixed string and big-endian uint32 layout per RFC 4254.

type ptyReqMsg struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type winChangeMsg struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

type execMsg struct {
	Command string
}

func parsePTYReq(payload []byte) (term string, cols, rows uint32, ok bool) {
	var m ptyReqMsg
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return "", 0, 0, false
	}
	return m.Term, m.Cols, m.Rows, true
}

func parseWinChange(payload []byte) (cols, rows uint32, ok bool) {
	var m winChangeMsg
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return 0, 0, false
	}
	return m.Cols, m.Rows, true
}

func parseExec(payload []byte) (string, bool) {
	var m execMsg
	if err := ssh.Unmarshal(payload, &m); err != nil {
		return "", false
	}
	return m.Command, true
}

// splitCmd parses an SSH-exec command string into argv-like tokens.
// Whitespace separates args; single or double quotes group a substring
// as one arg (POSIX-shell style — only the matching quote character
// closes the run, so 'a"b' and "a'b" both pass through unchanged). No
// backslash escapes — operators won't need them for the shapes we expect
// (usernames, MACs, iface names, RouterOS paths like
// "/system/identity/print"). Unclosed quotes are an error.
func splitCmd(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var quoteCh rune // 0 when not inside a quoted run
	hasContent := false

	for _, r := range s {
		switch {
		case quoteCh != 0:
			if r == quoteCh {
				quoteCh = 0
			} else {
				cur.WriteRune(r)
			}
			hasContent = true
		case r == '"' || r == '\'':
			quoteCh = r
			hasContent = true
		case unicode.IsSpace(r):
			if hasContent {
				args = append(args, cur.String())
				cur.Reset()
				hasContent = false
			}
		default:
			cur.WriteRune(r)
			hasContent = true
		}
	}
	if quoteCh != 0 {
		return nil, errors.New("unclosed quote")
	}
	if hasContent {
		args = append(args, cur.String())
	}
	return args, nil
}

// dispatchExec parses the command and runs the matching engine. Returns
// the exit code to send back via "exit-status".
func (s *Server) dispatchExec(
	ctx context.Context,
	cmdline string,
	ch ssh.Channel,
	cols, rows uint32,
	winchCh <-chan winChange,
) int {
	s.logger.Info("exec received", "cmd", cmdline)
	args, err := splitCmd(cmdline)
	if err != nil {
		s.logger.Warn("exec rejected: bad command", "cmd", cmdline, "err", err)
		fmt.Fprintf(ch.Stderr(), "mactelnet-proxy: bad command: %v\n", err)
		return 2
	}
	if len(args) == 0 {
		s.logger.Warn("exec rejected: empty command")
		fmt.Fprintln(ch.Stderr(), "mactelnet-proxy: empty command")
		return 2
	}

	switch args[0] {
	case "mactelnet":
		code := s.execMactelnet(ctx, args[1:], ch, cols, rows, winchCh)
		s.logger.Info("exec finished", "cmd", "mactelnet", "code", code)
		return code
	case "mndp":
		code := s.execMndp(ctx, args[1:], ch)
		s.logger.Info("exec finished", "cmd", "mndp", "code", code)
		return code
	case "ifaces":
		code := s.execIfaces(args[1:], ch)
		s.logger.Info("exec finished", "cmd", "ifaces", "code", code)
		return code
	default:
		s.logger.Warn("exec rejected: unknown command", "cmd", args[0])
		fmt.Fprintf(ch.Stderr(), "mactelnet-proxy: unknown command %q\n", args[0])
		return 127
	}
}

// execMactelnet runs `mactelnet -u USER [-p PASS] [-i IFACE] MAC` over
// the SSH channel. Stdio on ch carries the terminal traffic; ch.Stderr()
// is for our wrapper's diagnostics. Window-change events from the
// request loop are forwarded to Session.Resize.
//
// If -p is omitted, the function emits "Password: " on the channel and
// reads one CRLF-terminated line from stdin before opening the session.
// That mirrors upstream mactelnet's stdin-prompt convention so that
// NetCFG's existing sniff-stdout-for-prompt-then-inject behavior works
// unchanged, and so the password never sits on the SSH exec command line.
func (s *Server) execMactelnet(
	ctx context.Context,
	args []string,
	ch ssh.Channel,
	cols, rows uint32,
	winchCh <-chan winChange,
) int {
	fs := flag.NewFlagSet("mactelnet", flag.ContinueOnError)
	fs.SetOutput(ch.Stderr())

	user := fs.String("u", "", "username (required)")
	pass := fs.String("p", "", "password (prompted on stdin if omitted)")
	iface := fs.String("i", s.cfg.Iface, "L2-facing interface (defaults to server config)")
	vlanID := fs.Uint("vlan", uint(s.cfg.VlanID),
		"802.1Q VLAN ID (1–4094) for emitted frames; 0 = untagged "+
			"(defaults to server config)")

	fs.Usage = func() {
		fmt.Fprintln(ch.Stderr(), "usage: mactelnet -u USER [-p PASS] [-i IFACE] [-vlan VID] MAC")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		s.logger.Warn("mactelnet: flag parse failed", "err", err)
		return 2
	}
	if *user == "" || *iface == "" || fs.NArg() != 1 {
		s.logger.Warn("mactelnet: missing required arg",
			"user_set", *user != "", "iface_set", *iface != "", "positional", fs.NArg())
		fs.Usage()
		return 2
	}
	if *vlanID > 4094 {
		s.logger.Warn("mactelnet: invalid -vlan value", "vlan", *vlanID)
		fmt.Fprintln(ch.Stderr(), "mactelnet: -vlan must be in 1..4094 (or 0 for untagged)")
		return 2
	}

	mac := fs.Arg(0)
	s.logger.Info("mactelnet starting",
		"iface", *iface, "user", *user, "mac", mac,
		"have_pass_flag", *pass != "", "cols", cols, "rows", rows)

	// Wrap ch in a bufio.Reader so we can both read a CRLF-terminated
	// password line *and* keep any post-password bytes (e.g. the user's
	// first keystrokes) for the io.Copy that follows. Without this we'd
	// drop any byte that arrived in the same packet as the password.
	chReader := bufio.NewReader(ch)

	password := *pass
	if password == "" {
		s.logger.Info("mactelnet: prompting for password on stdin")
		var err error
		// Bound the prompt read so a client that opens the channel and
		// never sends a password doesn't pin us forever. The blocking
		// ReadByte() in readPasswordPrompt has no deadline; we wrap it
		// in a goroutine and select against a timer + the session ctx
		// so a stalled client surfaces as a clean exit-status back to
		// the SSH side instead of an infinite hang.
		password, err = readPasswordPromptWithTimeout(ctx, ch, chReader, passwordPromptTimeout)
		if err != nil {
			s.logger.Warn("mactelnet: password prompt read failed", "err", err)
			fmt.Fprintf(ch.Stderr(), "mactelnet: read password: %v\n", err)
			return 1
		}
		s.logger.Info("mactelnet: password received via prompt", "len", len(password))
	} else {
		s.logger.Info("mactelnet: password supplied via -p flag", "len", len(password))
	}

	sess, err := mactelnet.Open(ctx, *iface, mac, *user, password, uint16(cols), uint16(rows), uint16(*vlanID))
	if err != nil {
		s.logger.Warn("mactelnet: open failed",
			"iface", *iface, "user", *user, "mac", mac, "err", err)
		fmt.Fprintf(ch.Stderr(), "mactelnet: %v\n", err)
		return 1
	}
	defer sess.Close()
	s.logger.Info("mactelnet session open", "iface", *iface, "mac", mac)

	resizeDone := make(chan struct{})
	go func() {
		defer close(resizeDone)
		for {
			select {
			case <-ctx.Done():
				return
			case w, ok := <-winchCh:
				if !ok {
					return
				}
				_ = sess.Resize(uint16(w.cols), uint16(w.rows))
			}
		}
	}()

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(sess, chReader); errCh <- err }()
	go func() { _, err := io.Copy(ch, sess); errCh <- err }()

	var rc int
	select {
	case <-ctx.Done():
		rc = 0
	case err := <-errCh:
		if err != nil &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, io.ErrClosedPipe) {
			fmt.Fprintf(ch.Stderr(), "mactelnet: %v\n", err)
			rc = 1
		}
	}
	return rc
}

// passwordPromptTimeout caps how long we'll wait for the SSH client to
// send a password after we've written the "Password: " prompt. NetCFG's
// auto-injection happens within milliseconds; a manual CLI user gets
// 30 s of patience. After that we give up so the channel can close
// cleanly and the client side sees the disconnect — without this the
// goroutine sits in a blocking ReadByte forever and the SSH session
// stays open until the client itself times out.
const passwordPromptTimeout = 30 * time.Second

// readPasswordPromptWithTimeout runs readPasswordPrompt in a goroutine
// and selects against a timeout / context cancellation. The underlying
// blocking ReadByte() can't be canceled directly, but when execMactelnet
// returns, sshserver closes the channel — that unblocks ReadByte with
// an error and the goroutine exits without leaking.
func readPasswordPromptWithTimeout(
	ctx context.Context, w io.Writer, r *bufio.Reader, d time.Duration,
) (string, error) {
	type result struct {
		pwd string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		pwd, err := readPasswordPrompt(w, r)
		resCh <- result{pwd, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r := <-resCh:
		return r.pwd, r.err
	case <-timer.C:
		return "", fmt.Errorf("timeout after %s waiting for password", d)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// readPasswordPrompt emits "Password: " on the channel and reads one
// CRLF-terminated line of input. The line ending may be "\r", "\n", or
// "\r\n" — we eagerly absorb a trailing \n so the io.Copy that follows
// doesn't see a phantom newline as the first byte of the session.
//
// Backspace (0x08) and DEL (0x7f) edit the buffer so a human typing at
// the prompt directly behaves sanely. Echo is intentionally suppressed:
// SSH clients invoking this without a local PTY won't echo anyway, and
// suppressing echo on our side means a remote CLI user (with a cooked
// local terminal) is no worse off than they would be with `getpass`.
func readPasswordPrompt(w io.Writer, r *bufio.Reader) (string, error) {
	if _, err := fmt.Fprint(w, "Password: "); err != nil {
		return "", err
	}
	const maxLen = 256
	var sb strings.Builder
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch c {
		case '\r', '\n':
			// Absorb a trailing \n if it's already buffered. Don't issue a
			// fresh underlying read just to look for one — that would block
			// indefinitely on a client that sent only \r.
			if c == '\r' && r.Buffered() > 0 {
				if peeked, perr := r.Peek(1); perr == nil && peeked[0] == '\n' {
					_, _ = r.ReadByte()
				}
			}
			// Visual newline so a direct CLI user sees their Enter.
			_, _ = fmt.Fprint(w, "\r\n")
			return sb.String(), nil
		case 0x08, 0x7f:
			if sb.Len() > 0 {
				s := sb.String()
				sb.Reset()
				sb.WriteString(s[:len(s)-1])
			}
		default:
			if c < 0x20 {
				continue // ignore other control bytes
			}
			if sb.Len() >= maxLen {
				return "", errors.New("password exceeds maximum length")
			}
			sb.WriteByte(c)
		}
	}
}

// execMndp runs `mndp [-t SECONDS] [-i IFACE] [-j]` over the SSH channel.
// Output goes to ch (table or JSON); the "Searching..." prelude and any
// error messages go to ch.Stderr().
func (s *Server) execMndp(ctx context.Context, args []string, ch ssh.Channel) int {
	fs := flag.NewFlagSet("mndp", flag.ContinueOnError)
	fs.SetOutput(ch.Stderr())

	timeout := fs.Int("t", 5, "listen seconds")
	iface := fs.String("i", s.cfg.Iface, "egress interface for the SOLICIT")
	asJSON := fs.Bool("j", false, "emit results as JSON")

	fs.Usage = func() {
		fmt.Fprintln(ch.Stderr(), "usage: mndp [-t SECONDS] [-i IFACE] [-j]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		s.logger.Warn("mndp: flag parse failed", "err", err)
		return 2
	}
	if *timeout <= 0 {
		s.logger.Warn("mndp: invalid timeout", "timeout", *timeout)
		fmt.Fprintln(ch.Stderr(), "mndp: -t must be positive")
		return 2
	}

	if !*asJSON {
		fmt.Fprintln(ch.Stderr(), "Searching for MAC-Telnet devices... Abort with CTRL+C.")
	}
	s.logger.Info("mndp starting",
		"iface", *iface, "timeoutSec", *timeout, "json", *asJSON)

	neighbors, err := mndp.Discover(ctx, *iface, time.Duration(*timeout)*time.Second)
	if err != nil {
		s.logger.Warn("mndp: discover failed", "iface", *iface, "err", err)
		fmt.Fprintf(ch.Stderr(), "mndp: %v\n", err)
		return 1
	}
	s.logger.Info("mndp completed", "iface", *iface, "count", len(neighbors))

	if *asJSON {
		enc := json.NewEncoder(ch)
		enc.SetIndent("", "  ")
		if err := enc.Encode(neighbors); err != nil {
			fmt.Fprintf(ch.Stderr(), "mndp: encode: %v\n", err)
			return 1
		}
		return 0
	}

	// Plain table — no ANSI bold, since we don't know the SSH client's
	// terminal capabilities.
	fmt.Fprintf(ch, "\n%-15s %-17s %s\n", "IP", "MAC-Address",
		"Identity (platform version hardware) uptime")
	for _, n := range neighbors {
		fmt.Fprintf(ch, "%-15s %-17s %s", n.IPv4, n.MAC, n.Identity)
		if n.Platform != "" {
			fmt.Fprintf(ch, " (%s %s %s)", n.Platform, n.Version, n.Board)
		}
		if n.Uptime > 0 {
			secs := int(n.Uptime.Seconds())
			fmt.Fprintf(ch, "  up %d days %d hours", secs/86400, (secs%86400)/3600)
		}
		if n.SoftwareID != "" {
			fmt.Fprintf(ch, "  %s", n.SoftwareID)
		}
		if n.Iface != "" {
			fmt.Fprintf(ch, " %s", n.Iface)
		}
		fmt.Fprintln(ch)
	}
	return 0
}
