package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// ED25519 SSH wire format: uint32(11) + "ssh-ed25519" + uint32(32) + pubkey(32) = 51 bytes
const wireKeyLen = 51
const pubKeyOffset = 19

var globalCounter atomic.Int64
var matchCounter atomic.Int64

// Result holds a matched key pair and its metadata.
type Result struct {
	PrivateKeyPEM []byte
	AuthorizedKey string
	Fingerprint   string
}

// Options configures key generation behavior.
type Options struct {
	Regex       *regexp.Regexp
	Fingerprint bool
}

// KeyCount returns the total number of keys generated.
func KeyCount() int64 { return globalCounter.Load() }

// MatchCount returns the total number of matches found.
func MatchCount() int64 { return matchCounter.Load() }

// ResetCounters zeroes the global and match counters (for test isolation).
func ResetCounters() {
	globalCounter.Store(0)
	matchCounter.Store(0)
}

// newWireKeyBuf returns a pre-initialized ED25519 SSH wire format buffer.
func newWireKeyBuf() []byte {
	buf := make([]byte, wireKeyLen)
	buf[3] = 11 // big-endian uint32(11) — length of "ssh-ed25519"
	copy(buf[4:15], "ssh-ed25519")
	buf[18] = 32 // big-endian uint32(32) — length of public key
	return buf
}

// getFingerprint returns the SHA256 fingerprint of an ssh.PublicKey.
func getFingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(h[:])
}

// getAuthorizedKey returns the authorized_keys line for an ssh.PublicKey.
func getAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// FindKeys generates ED25519 keys in a tight loop, matching against the regex.
// Matched keys are sent on the results channel. Returns nil on context
// cancellation, or an error if key generation fails.
func FindKeys(ctx context.Context, opts Options, results chan<- Result) error {
	wireKey := newWireKeyBuf()

	authKeyPrefix := []byte("ssh-ed25519 ")
	b64Len := base64.StdEncoding.EncodedLen(wireKeyLen)
	authKeyBuf := make([]byte, len(authKeyPrefix)+b64Len)
	copy(authKeyBuf, authKeyPrefix)

	fpBuf := make([]byte, base64.StdEncoding.EncodedLen(sha256.Size))

	var localCount int64
	const flushInterval = 1024

	for {
		localCount++
		if localCount >= flushInterval {
			globalCounter.Add(localCount)
			localCount = 0
			if ctx.Err() != nil {
				return nil
			}
		}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate ed25519 key: %w", err)
		}
		copy(wireKey[pubKeyOffset:], pubKey)

		var matched bool
		if opts.Fingerprint {
			sum := sha256.Sum256(wireKey)
			base64.StdEncoding.Encode(fpBuf, sum[:])
			matched = opts.Regex.Match(fpBuf)
		} else {
			base64.StdEncoding.Encode(authKeyBuf[len(authKeyPrefix):], wireKey)
			matched = opts.Regex.Match(authKeyBuf)
		}

		if !matched {
			continue
		}

		// Match found — slow path: flush counter, build result
		globalCounter.Add(localCount)
		localCount = 0
		matchCounter.Add(1)

		publicKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return fmt.Errorf("convert public key: %w", err)
		}

		pemKey, err := ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}

		result := Result{
			PrivateKeyPEM: pem.EncodeToMemory(pemKey),
			AuthorizedKey: getAuthorizedKey(publicKey),
			Fingerprint:   getFingerprint(publicKey),
		}

		select {
		case results <- result:
		case <-ctx.Done():
			return nil
		}
	}
}
