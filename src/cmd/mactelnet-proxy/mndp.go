// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mactelnet-proxy/internal/mndp"
)

// runMndp implements `mactelnet-proxy mndp`. Listens for the configured
// duration and emits results either as a human-readable table (matching
// upstream's `mndp` CLI shape) or as JSON when -j is passed.
func runMndp(args []string) int {
	fs := flag.NewFlagSet("mndp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	timeout := fs.Int("t", 5, "listen for SECONDS (matches upstream MT_MNDP_TIMEOUT)")
	iface := fs.String("i", "", "egress interface for the SOLICIT broadcast (optional)")
	asJSON := fs.Bool("j", false, "emit results as JSON instead of a human table")

	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintln(w, "usage: mactelnet-proxy mndp [-t SECONDS] [-i IFACE] [-j]")
		fmt.Fprintln(w)
		fs.PrintDefaults()
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Listens on UDP/5678 and prompts nearby MikroTiks to announce.")
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "mactelnet-proxy: -t must be positive")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !*asJSON {
		fmt.Fprintln(os.Stderr, "Searching for MAC-Telnet devices... Abort with CTRL+C.")
	}

	neighbors, err := mndp.Discover(ctx, *iface, time.Duration(*timeout)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mactelnet-proxy: %v\n", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(neighbors); err != nil {
			fmt.Fprintf(os.Stderr, "mactelnet-proxy: encode: %v\n", err)
			return 1
		}
		return 0
	}

	printTable(neighbors)
	return 0
}

// printTable mirrors upstream mndp.c's bold-header tabular output so
// operator muscle-memory carries over.
func printTable(neighbors []mndp.Neighbor) {
	fmt.Printf("\n\033[1m%-15s %-17s %s\033[m\n", "IP", "MAC-Address",
		"Identity (platform version hardware) uptime")
	for _, n := range neighbors {
		fmt.Printf("%-15s %-17s %s", n.IPv4, n.MAC, n.Identity)
		if n.Platform != "" {
			fmt.Printf(" (%s %s %s)", n.Platform, n.Version, n.Board)
		}
		if n.Uptime > 0 {
			secs := int(n.Uptime.Seconds())
			fmt.Printf("  up %d days %d hours", secs/86400, (secs%86400)/3600)
		}
		if n.SoftwareID != "" {
			fmt.Printf("  %s", n.SoftwareID)
		}
		if n.Iface != "" {
			fmt.Printf(" %s", n.Iface)
		}
		fmt.Println()
	}
}
