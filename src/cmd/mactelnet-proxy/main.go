// SPDX-License-Identifier: GPL-2.0-only
//
// mactelnet-proxy — entrypoint.
//
// Subcommand layout (the default with no subcommand is `serve`):
//
//	mactelnet-proxy serve [-listen ADDR] [-keys-dir DIR]
//	                      [-host-key PATH] [-authorized-keys PATH] ...
//	    Run the SSH server. -keys-dir is the folder both the host key and
//	    authorized_keys are read from by default; the per-file flags only
//	    need to be set when overriding one of them individually.
//
//	mactelnet-proxy mactelnet -u USER -i IFACE [-p PASS] MAC
//	    Open a single MAC-Telnet session to MAC and pipe terminal traffic
//	    to/from stdin/stdout. Smoke-test path; bypasses the SSH layer.
//
//	mactelnet-proxy mndp [-t SECONDS] [-j]
//	    Run MNDP discovery. Stubbed until M1's listener lands.
//
// Copyright (C) 2026 Icosa Consulting Inc.  Derivative work of MAC-Telnet
// (https://github.com/haakonnessjoen/MAC-Telnet) by Håkon Nessjøen.
// Licensed under GPL-2.0; see LICENSE.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mactelnet-proxy/internal/mactelnet"
	"mactelnet-proxy/internal/sshserver"
)

const (
	defaultKeysDir            = "/etc/mactelnet-proxy"
	defaultHostKeyName        = "mactel_ed25519_key"
	defaultAuthorizedKeysName = "authorized_keys"
)

// Build-time injected via -ldflags '-X main.version=...'
var version = "dev"

func main() {
	args := os.Args[1:]

	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "", "serve":
		os.Exit(runServe(args))
	case "mactelnet":
		os.Exit(runMactelnet(args))
	case "mndp":
		os.Exit(runMndp(args))
	case "version":
		fmt.Println("mactelnet-proxy", version)
	case "help", "-h", "--help":
		printRootUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "mactelnet-proxy: unknown subcommand %q\n\n", sub)
		printRootUsage(os.Stderr)
		os.Exit(2)
	}
}

func printRootUsage(w *os.File) {
	fmt.Fprintln(w, "usage: mactelnet-proxy [serve|mactelnet|mndp|version|help] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  serve      run the embedded SSH server (default)")
	fmt.Fprintln(w, "  mactelnet  open one MAC-Telnet session and pipe stdio")
	fmt.Fprintln(w, "  mndp       run MNDP discovery and print neighbors")
	fmt.Fprintln(w, "  version    print version and exit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run `mactelnet-proxy <subcommand> -h` for subcommand-specific flags.")
}

// runServe boots the SSH server. Each flag falls back to an
// environment variable so deploy surfaces (systemd EnvironmentFile,
// Docker `-e`, container schedulers) can configure the proxy without
// constructing a command line — `ExecStart=/usr/bin/mactelnet-proxy
// serve` is enough. Precedence: CLI flag > env var > built-in default.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen",
		envOr("MACTELNET_PROXY_LISTEN", "0.0.0.0:22"),
		"address:port for the embedded SSH server (env: MACTELNET_PROXY_LISTEN)")
	keysDir := fs.String("keys-dir",
		envOr("MACTELNET_PROXY_KEYS_DIR", defaultKeysDir),
		"directory holding the host key and authorized_keys file (env: MACTELNET_PROXY_KEYS_DIR)")
	authKeys := fs.String("authorized-keys",
		envOr("MACTELNET_PROXY_AUTHORIZED_KEYS", ""),
		"path to authorized_keys file (env: MACTELNET_PROXY_AUTHORIZED_KEYS; default: <keys-dir>/"+defaultAuthorizedKeysName+")")
	hostKey := fs.String("host-key",
		envOr("MACTELNET_PROXY_HOST_KEY", ""),
		"path to the SSH host private key, auto-generated on first run if missing (env: MACTELNET_PROXY_HOST_KEY; default: <keys-dir>/"+defaultHostKeyName+")")
	iface := fs.String("interface",
		envOr("MACTELNET_PROXY_INTERFACE", ""),
		"network interface to bind for L2 traffic, empty = system default (env: MACTELNET_PROXY_INTERFACE)")
	authTimeout := fs.Duration("auth-timeout",
		envDurationOr("MACTELNET_PROXY_AUTH_TIMEOUT", 10*time.Second),
		"total retransmit budget for the pre-END_AUTH MAC-Telnet handshake, e.g. 10s; 0 = upstream default ~2.4s (env: MACTELNET_PROXY_AUTH_TIMEOUT)")
	dataTimeout := fs.Duration("data-timeout",
		envDurationOr("MACTELNET_PROXY_DATA_TIMEOUT", 0),
		"total retransmit budget for in-session DATA packets, e.g. 2s; 0 = upstream default ~2.4s (env: MACTELNET_PROXY_DATA_TIMEOUT)")
	debug := fs.Bool("debug",
		envBoolOr("MACTELNET_PROXY_DEBUG", false),
		"verbose packet-level logging (env: MACTELNET_PROXY_DEBUG)")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("mactelnet-proxy", version)
		return 0
	}

	if *hostKey == "" {
		*hostKey = filepath.Join(*keysDir, defaultHostKeyName)
	}
	if *authKeys == "" {
		*authKeys = filepath.Join(*keysDir, defaultAuthorizedKeysName)
	}
	mactelnet.Configure(*authTimeout, *dataTimeout)

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting",
		"version", version,
		"listen", *listen,
		"keys_dir", *keysDir,
		"authorized_keys", *authKeys,
		"host_key", *hostKey,
		"interface", *iface,
		"auth_timeout", *authTimeout,
		"data_timeout", *dataTimeout,
		"debug", *debug)
	// Visibly confirm the slog level — only emits when -debug is on.
	logger.Debug("debug logging enabled")

	server, err := sshserver.New(sshserver.Config{
		ListenAddr:     *listen,
		HostKeyPath:    *hostKey,
		AuthorizedKeys: *authKeys,
		Iface:          *iface,
		Logger:         logger,
	})
	if err != nil {
		logger.Error("ssh server init failed", "err", err)
		return 1
	}

	// SIGHUP → reload authorized_keys (live updates without a restart).
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				if err := server.ReloadAuthorizedKeys(); err != nil {
					logger.Error("authorized_keys reload failed", "err", err)
				}
			}
		}
	}()

	if err := server.Serve(ctx); err != nil {
		logger.Error("ssh serve", "err", err)
		return 1
	}
	logger.Info("shutdown signal received, exiting")
	return 0
}

// envOr reads name from the environment and returns its value when
// set+non-empty; otherwise it returns fallback. Used to back CLI flag
// defaults so deploy surfaces (systemd EnvironmentFile, Docker `-e`)
// can configure the proxy without command-line plumbing. CLI flags
// always win over env vars because flag.Parse runs after we've fed
// these values in as defaults.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envDurationOr parses os.Getenv(name) as a time.Duration. Returns
// fallback on unset/empty/unparseable; emits a warning to stderr on
// parse failure so a misconfigured value doesn't silently fall back
// to a default that masks the operator's intent.
func envDurationOr(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"mactelnet-proxy: ignoring invalid duration in %s=%q (%v); using default %s\n",
			name, v, err, fallback)
		return fallback
	}
	return d
}

// envBoolOr returns false for the canonical "off" values
// ("0", "false", "no", "off" — case-insensitive) and true for any
// other non-empty value. Empty/unset returns fallback. Permissive on
// purpose: an operator who writes DEBUG=yes or DEBUG=1 expects it to
// turn on.
func envBoolOr(name string, fallback bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

