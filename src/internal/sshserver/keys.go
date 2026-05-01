// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.

package sshserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// loadOrCreateHostKey reads an OpenSSH-format private key from path.
// If the file is missing, generates an ED25519 key, writes it with 0600,
// and returns the signer for the new key. Subsequent boots reuse the
// same key so SSH clients don't see a new fingerprint each restart.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generateHostKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read host key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse host key %q: %w", path, err)
	}
	return signer, nil
}

func generateHostKey(path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %q: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write host key %q: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return signer, nil
}

// loadAuthorizedKeys parses an OpenSSH-format authorized_keys file.
// Comments and blank lines are skipped. Malformed lines are skipped
// silently (matching sshd) — callers should grep their logs to spot
// typos rather than have the whole reload fail on one bad line.
//
// If the file is missing, an empty stub is created (0600) so the server
// can come up on a fresh deploy without operator pre-staging. No keys
// will authenticate until an admin appends to it.
func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %q: %w", filepath.Dir(path), err)
		}
		stub := []byte("# mactelnet-proxy authorized_keys\n" +
			"# Append OpenSSH public keys (one per line) to grant access.\n")
		if err := os.WriteFile(path, stub, 0o600); err != nil {
			return nil, fmt.Errorf("create authorized_keys %q: %w", path, err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read authorized_keys %q: %w", path, err)
	}
	var keys []ssh.PublicKey
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// keyMatch is true if offered matches any key in keys, by marshaled wire
// representation.
func keyMatch(offered ssh.PublicKey, keys []ssh.PublicKey) bool {
	om := offered.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), om) {
			return true
		}
	}
	return false
}
