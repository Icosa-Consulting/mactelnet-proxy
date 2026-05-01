// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

// Package sshserver embeds an SSH server (golang.org/x/crypto/ssh) that
// authenticates by public key only and routes the requested `exec`
// command to either the mactelnet or mndp engine. There is no
// interactive shell channel — every accepted session must be an `exec`
// of a known subcommand.
package sshserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Tunables.
const (
	// handshakeTimeout caps how long we'll wait for the SSH key exchange
	// to complete on a freshly-accepted connection. A hung client past
	// this gets the socket closed.
	handshakeTimeout = 30 * time.Second
)

// Config carries everything Server needs to come up. ListenAddr,
// HostKeyPath, and AuthorizedKeys are required; Iface is the default
// L2-facing interface the mactelnet engine will bind to when the exec
// request doesn't override it; Logger is optional (defaults to
// slog.Default()).
type Config struct {
	ListenAddr     string
	HostKeyPath    string
	AuthorizedKeys string
	Iface          string
	Logger         *slog.Logger
}

// Server is an instance of the embedded SSH frontend. After New, call
// Serve to run the accept loop, and ReloadAuthorizedKeys whenever the
// authorized_keys file changes (typically wired to SIGHUP by the caller).
type Server struct {
	cfg     Config
	logger  *slog.Logger
	sshConf *ssh.ServerConfig

	keysMu sync.RWMutex
	keys   []ssh.PublicKey
}

// Run is a convenience wrapper around New + Serve for callers that don't
// need the SIGHUP-reload hook.
func Run(ctx context.Context, cfg Config) error {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	return s.Serve(ctx)
}

// New loads the host key (generating one on first run if missing) and
// the authorized_keys file, configures pubkey-only auth, and returns a
// ready-to-Serve Server.
func New(cfg Config) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, logger: logger}

	signer, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	if err := s.reload(); err != nil {
		return nil, fmt.Errorf("authorized_keys: %w", err)
	}

	s.sshConf = &ssh.ServerConfig{
		PublicKeyCallback: s.authPublicKey,
		ServerVersion:     "SSH-2.0-mactelnet-proxy",
	}
	s.sshConf.AddHostKey(signer)
	return s, nil
}

// ReloadAuthorizedKeys re-reads the authorized_keys file. Existing
// connections keep their already-checked auth; new connections see the
// updated set.
func (s *Server) ReloadAuthorizedKeys() error {
	return s.reload()
}

func (s *Server) reload() error {
	keys, err := loadAuthorizedKeys(s.cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	s.keysMu.Lock()
	s.keys = keys
	s.keysMu.Unlock()
	s.logger.Info("authorized_keys loaded",
		"path", s.cfg.AuthorizedKeys, "count", len(keys))
	return nil
}

func (s *Server) authPublicKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	if !keyMatch(key, s.keys) {
		return nil, fmt.Errorf("ssh: unauthorized key for user %q", meta.User())
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"pubkey-fp": ssh.FingerprintSHA256(key),
		},
	}, nil
}

// Serve accepts connections until ctx is canceled. Each accepted
// connection runs in its own goroutine.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.logger.Info("ssh server listening", "addr", s.cfg.ListenAddr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Warn("accept failed", "err", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr()
	s.logger.Info("tcp accepted", "remote", remote)

	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(raw, s.sshConf)
	if err != nil {
		s.logger.Info("ssh handshake failed", "remote", remote, "err", err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer sshConn.Close()

	fp := ""
	if sshConn.Permissions != nil {
		fp = sshConn.Permissions.Extensions["pubkey-fp"]
	}
	s.logger.Info("ssh connection",
		"remote", remote, "user", sshConn.User(), "fp", fp)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels accepted")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			s.logger.Warn("channel accept failed", "err", err)
			continue
		}
		go s.handleSession(ctx, ch, chReqs)
	}
}

// winChange carries a window-change event from the request loop into the
// running exec. Buffered channel; if the runner isn't draining, drops on
// the floor (sane: terminal resizes can be coalesced).
type winChange struct {
	cols, rows uint32
}

// handleSession owns one SSH session channel. It dispatches `pty-req`,
// `window-change`, and `exec` requests; rejects everything else; runs
// the exec in a goroutine while still servicing window-change events;
// sends `exit-status` and closes the channel when the exec returns.
//
// Per RFC 4254 a session channel can carry only one shell/exec/subsystem;
// we enforce that with execStarted.
func (s *Server) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		ptyCols, ptyRows uint32
		execStarted      bool
	)
	execDone := make(chan int, 1)
	winchCh := make(chan winChange, 4)

	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				cancel()
				if execStarted {
					<-execDone
				}
				return
			}
			s.handleReq(sessCtx, ch, req, &ptyCols, &ptyRows, &execStarted, execDone, winchCh)

		case code := <-execDone:
			sendExitStatus(ch, code)
			return
		}
	}
}

func (s *Server) handleReq(
	ctx context.Context,
	ch ssh.Channel,
	req *ssh.Request,
	ptyCols, ptyRows *uint32,
	execStarted *bool,
	execDone chan<- int,
	winchCh chan winChange,
) {
	switch req.Type {
	case "pty-req":
		_, cols, rows, ok := parsePTYReq(req.Payload)
		if ok {
			*ptyCols, *ptyRows = cols, rows
		}
		_ = req.Reply(ok, nil)

	case "window-change":
		cols, rows, ok := parseWinChange(req.Payload)
		if ok {
			select {
			case winchCh <- winChange{cols, rows}:
			default:
			}
		}
		_ = req.Reply(ok, nil)

	case "exec":
		cmdline, ok := parseExec(req.Payload)
		_ = req.Reply(ok, nil)
		if !ok || *execStarted {
			return
		}
		*execStarted = true
		go func() {
			code := s.dispatchExec(ctx, cmdline, ch, *ptyCols, *ptyRows, winchCh)
			execDone <- code
		}()

	default:
		_ = req.Reply(false, nil)
	}
}

// sendExitStatus emits the SSH "exit-status" channel request that tells
// the client what code the exec exited with.
func sendExitStatus(ch ssh.Channel, code int) {
	type exitStatusMsg struct{ Status uint32 }
	payload := ssh.Marshal(exitStatusMsg{Status: uint32(code)})
	_, _ = ch.SendRequest("exit-status", false, payload)
}
