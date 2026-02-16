package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/danielewood/vanityssh-go/display"
)

// ED25519 SSH wire format: uint32(11) + "ssh-ed25519" + uint32(32) + pubkey(32) = 51 bytes
const wireKeyLen = 51
const pubKeyOffset = 19

var globalCounter atomic.Int64
var matchCounter atomic.Int64
var startTime time.Time

func init() {
	startTime = time.Now()
}

// Options configures key generation behavior.
type Options struct {
	Regex       *regexp.Regexp
	Fingerprint bool
	Streaming   bool
}

// KeyCount returns the total number of keys generated.
func KeyCount() int64 { return globalCounter.Load() }

// MatchCount returns the total number of matches found.
func MatchCount() int64 { return matchCounter.Load() }

// Elapsed returns the duration since key generation started.
func Elapsed() time.Duration { return time.Since(startTime) }

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
func FindKeys(opts Options) {
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
		}

		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
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

		// Match found — slow path
		globalCounter.Add(localCount)
		localCount = 0
		matchCounter.Add(1)

		publicKey, _ := ssh.NewPublicKey(pubKey)
		pemKey, _ := ssh.MarshalPrivateKey(privKey, "")
		privateKey := pem.EncodeToMemory(pemKey)
		authorizedKey := getAuthorizedKey(publicKey)
		fingerprint := getFingerprint(publicKey)

		if display.IsTTY() {
			display.PrintAboveStatus("--- Match #%d ---", matchCounter.Load())
			for _, line := range strings.Split(strings.TrimSpace(string(privateKey)), "\n") {
				display.PrintAboveStatus("%s", line)
			}
			display.PrintAboveStatus("%s", authorizedKey)
			display.PrintAboveStatus("SHA256:%s", fingerprint)
		}

		if !display.IsTTY() && opts.Streaming {
			fmt.Printf("%s", privateKey)
		}

		if !opts.Streaming {
			if display.IsTTY() {
				display.Reset()
				fmt.Printf("%s", privateKey)
				fmt.Printf("%s\n", authorizedKey)
				fmt.Printf("SHA256:%s\n", fingerprint)
			} else {
				fmt.Printf("%s", privateKey)
			}
			_ = os.WriteFile("id_ed25519", privateKey, 0600)
			_ = os.WriteFile("id_ed25519.pub", []byte(authorizedKey), 0644)
			os.Exit(0)
		}
	}
}
