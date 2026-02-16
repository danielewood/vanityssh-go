package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewWireKeyBuf(t *testing.T) {
	t.Parallel()

	buf := newWireKeyBuf()

	if len(buf) != wireKeyLen {
		t.Errorf("newWireKeyBuf() length = %d, want %d", len(buf), wireKeyLen)
	}

	// Algorithm name length: big-endian uint32(11)
	if buf[3] != 11 {
		t.Errorf("algo name length byte = %d, want 11", buf[3])
	}

	// Algorithm name
	algoName := string(buf[4:15])
	if algoName != "ssh-ed25519" {
		t.Errorf("algo name = %q, want %q", algoName, "ssh-ed25519")
	}

	// Public key length: big-endian uint32(32)
	if buf[18] != 32 {
		t.Errorf("key length byte = %d, want 32", buf[18])
	}
}

func TestGetFingerprint(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	fp := getFingerprint(sshPub)

	if fp == "" {
		t.Error("getFingerprint() returned empty string")
	}

	// SHA256 (32 bytes) base64-encoded = 44 chars
	if len(fp) != 44 {
		t.Errorf("getFingerprint() length = %d, want 44", len(fp))
	}
}

func TestGetAuthorizedKey(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	authKey := getAuthorizedKey(sshPub)

	if authKey == "" {
		t.Error("getAuthorizedKey() returned empty string")
	}

	if !strings.HasPrefix(authKey, "ssh-ed25519 ") {
		t.Errorf("getAuthorizedKey() = %q, want prefix %q", authKey, "ssh-ed25519 ")
	}
}

func TestFindKeysMatchesPublicKey(t *testing.T) {
	t.Parallel()
	ResetCounters()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Match any ssh-ed25519 key (every key matches)
	re := regexp.MustCompile(`ssh-ed25519`)
	results := make(chan Result, 1)

	go func() {
		_ = FindKeys(ctx, Options{Regex: re}, results)
	}()

	select {
	case r := <-results:
		cancel()
		if len(r.PrivateKeyPEM) == 0 {
			t.Error("PrivateKeyPEM is empty")
		}
		if !strings.HasPrefix(r.AuthorizedKey, "ssh-ed25519 ") {
			t.Errorf("AuthorizedKey = %q, want prefix %q", r.AuthorizedKey, "ssh-ed25519 ")
		}
		if r.Fingerprint == "" {
			t.Error("Fingerprint is empty")
		}
		if len(r.Fingerprint) != 44 {
			t.Errorf("Fingerprint length = %d, want 44", len(r.Fingerprint))
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for match")
	}
}

func TestFindKeysMatchesFingerprint(t *testing.T) {
	t.Parallel()
	ResetCounters()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Match any fingerprint
	re := regexp.MustCompile(`.`)
	results := make(chan Result, 1)

	go func() {
		_ = FindKeys(ctx, Options{Regex: re, Fingerprint: true}, results)
	}()

	select {
	case r := <-results:
		cancel()
		if r.Fingerprint == "" {
			t.Error("Fingerprint is empty")
		}
		if len(r.PrivateKeyPEM) == 0 {
			t.Error("PrivateKeyPEM is empty")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for match")
	}
}

func TestFindKeysCancellation(t *testing.T) {
	t.Parallel()
	ResetCounters()

	// Impossible pattern — will never match
	re := regexp.MustCompile(`^IMPOSSIBLE_PATTERN_THAT_NEVER_MATCHES$`)
	results := make(chan Result, 1)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- FindKeys(ctx, Options{Regex: re}, results)
	}()

	// Let it run briefly, then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("FindKeys returned error on cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FindKeys did not return after context cancellation")
	}
}

func TestFindKeysCounterIncrement(t *testing.T) {
	t.Parallel()
	ResetCounters()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	re := regexp.MustCompile(`ssh-ed25519`)
	results := make(chan Result, 1)

	go func() {
		_ = FindKeys(ctx, Options{Regex: re}, results)
	}()

	select {
	case <-results:
		cancel()
	case <-ctx.Done():
		t.Fatal("timed out waiting for match")
	}

	if KeyCount() == 0 {
		t.Error("KeyCount() = 0 after finding a match")
	}
	if MatchCount() == 0 {
		t.Error("MatchCount() = 0 after finding a match")
	}
}
