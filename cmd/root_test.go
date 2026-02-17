// Tests in this file mutate process-global state (os.Stdout, os.Chdir,
// package-level flag variables) and must NOT use t.Parallel().
package cmd

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danielewood/vanityssh-go/display"
	"github.com/danielewood/vanityssh-go/keygen"
)

// captureStdout redirects os.Stdout to a pipe, calls fn, then returns
// everything written to stdout. Must not be called concurrently.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("closing pipe reader: %v", err)
	}
	return string(data)
}

// captureStderr redirects os.Stderr to a pipe, calls fn, then returns
// everything written to stderr. Must not be called concurrently.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	origStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer: %v", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("closing pipe reader: %v", err)
	}
	return string(data)
}

// fakeResult returns a minimal valid keygen.Result for testing.
func fakeResult(t *testing.T) keygen.Result {
	t.Helper()
	return keygen.Result{
		PrivateKeyPEM: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"),
		AuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey",
		Fingerprint:   "dGVzdA==",
	}
}

// saveFlags saves the current flag values and restores them on cleanup.
func saveFlags(t *testing.T) {
	t.Helper()
	origFingerprint := flagFingerprint
	origContinuous := flagContinuous
	origJobs := flagJobs
	t.Cleanup(func() {
		flagFingerprint = origFingerprint
		flagContinuous = origContinuous
		flagJobs = origJobs
		rootCmd.SetArgs(nil)
	})
}

// chdirTemp changes to a temp directory and restores on cleanup.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("Chdir restore: %v", err)
		}
	})
	return dir
}

func TestRun_InvalidRegex(t *testing.T) {
	saveFlags(t)
	rootCmd.SetArgs([]string{"[invalid"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error = %q, want substring %q", err, "invalid regex")
	}
}

func TestRun_NegativeJobs(t *testing.T) {
	saveFlags(t)
	rootCmd.SetArgs([]string{"--jobs", "-1", "."})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "--jobs must be non-negative") {
		t.Errorf("error = %q, want substring %q", err, "--jobs must be non-negative")
	}
}

func TestRun_WrongArgCount(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{name: "zero args", args: []string{}, wantSub: "accepts 1 arg(s)"},
		{name: "two args", args: []string{"foo", "bar"}, wantSub: "accepts 1 arg(s)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveFlags(t)
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err, tt.wantSub)
			}
		})
	}
}

func TestRun_JobsZeroAccepted(t *testing.T) {
	saveFlags(t)
	// Invalid regex exits early after flag validation.
	rootCmd.SetArgs([]string{"--jobs", "0", "[invalid"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Error should be about regex, not --jobs.
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error = %q, want substring %q (--jobs 0 should be accepted)", err, "invalid regex")
	}
}

func TestHandleResult_NonTTY_SingleMode(t *testing.T) {
	dir := chdirTemp(t)
	saveFlags(t)
	flagContinuous = false

	r := fakeResult(t)
	got := captureStdout(t, func() {
		if err := handleResult(r); err != nil {
			t.Fatalf("handleResult: %v", err)
		}
	})

	if got != string(r.PrivateKeyPEM) {
		t.Errorf("stdout = %q, want PEM", got)
	}

	// Private key file: exists, 0600.
	info, err := os.Stat(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatalf("private key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key permissions = %o, want 0600", perm)
	}

	// Public key file: exists, 0644.
	info, err = os.Stat(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("public key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("public key permissions = %o, want 0644", perm)
	}
}

func TestHandleResult_NonTTY_ContinuousMode(t *testing.T) {
	dir := chdirTemp(t)
	saveFlags(t)
	flagContinuous = true

	r := fakeResult(t)
	got := captureStdout(t, func() {
		if err := handleResult(r); err != nil {
			t.Fatalf("handleResult: %v", err)
		}
	})

	if got != string(r.PrivateKeyPEM) {
		t.Errorf("stdout = %q, want PEM", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519")); err == nil {
		t.Error("private key file should not exist in continuous mode")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519.pub")); err == nil {
		t.Error("public key file should not exist in continuous mode")
	}
}

func TestHandleResult_WriteError_PrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission test not supported on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}

	dir := filepath.Join(t.TempDir(), "nonexistent")
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("Chdir restore: %v", err)
		}
	})

	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Errorf("restoring dir permissions: %v", err)
		}
	})

	saveFlags(t)
	flagContinuous = false

	r := fakeResult(t)
	got := captureStdout(t, func() {
		err := handleResult(r)
		if err == nil {
			t.Fatal("expected write error, got nil")
		}
		if !strings.Contains(err.Error(), "write private key") {
			t.Errorf("error = %q, want substring %q", err, "write private key")
		}
	})

	// PEM must still be on stdout even though file write failed.
	if got != string(r.PrivateKeyPEM) {
		t.Errorf("stdout = %q, want PEM preserved on write error", got)
	}
}

func TestHandleResult_WriteError_PublicKey(t *testing.T) {
	dir := chdirTemp(t)

	// Pre-create id_ed25519.pub as a directory so write fails.
	if err := os.Mkdir(filepath.Join(dir, "id_ed25519.pub"), 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	saveFlags(t)
	flagContinuous = false

	r := fakeResult(t)
	captureStdout(t, func() {
		err := handleResult(r)
		if err == nil {
			t.Fatal("expected write error, got nil")
		}
		if !strings.Contains(err.Error(), "write public key") {
			t.Errorf("error = %q, want substring %q", err, "write public key")
		}
	})
}

func TestRun_EndToEnd(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "public key mode", args: []string{"--jobs", "1", "."}},
		{name: "fingerprint mode", args: []string{"--fingerprint", "--jobs", "1", "."}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := chdirTemp(t)
			saveFlags(t)
			keygen.ResetCounters()
			t.Cleanup(func() { keygen.ResetCounters() })

			rootCmd.SetArgs(tt.args)

			got := captureStdout(t, func() {
				if err := rootCmd.Execute(); err != nil {
					t.Fatalf("Execute error: %v", err)
				}
			})

			if !strings.Contains(got, "-----BEGIN OPENSSH PRIVATE KEY-----") {
				t.Error("stdout missing PEM header")
			}

			// Key files must exist with correct permissions.
			privInfo, err := os.Stat(filepath.Join(dir, "id_ed25519"))
			if err != nil {
				t.Fatalf("private key file: %v", err)
			}
			if perm := privInfo.Mode().Perm(); perm != 0600 {
				t.Errorf("private key permissions = %o, want 0600", perm)
			}

			pubInfo, err := os.Stat(filepath.Join(dir, "id_ed25519.pub"))
			if err != nil {
				t.Fatalf("public key file: %v", err)
			}
			if perm := pubInfo.Mode().Perm(); perm != 0644 {
				t.Errorf("public key permissions = %o, want 0644", perm)
			}

			pubData, err := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
			if err != nil {
				t.Fatalf("read public key: %v", err)
			}
			if !strings.HasPrefix(string(pubData), "ssh-ed25519 ") {
				t.Errorf("public key = %q, want prefix %q", pubData, "ssh-ed25519 ")
			}

			if keygen.KeyCount() == 0 {
				t.Error("KeyCount() = 0, want > 0")
			}
			if keygen.MatchCount() < 1 {
				t.Errorf("MatchCount() = %d, want >= 1", keygen.MatchCount())
			}
		})
	}
}

func TestRun_FlagWiring(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T)
	}{
		{
			name: "long --jobs",
			args: []string{"--jobs", "3", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if flagJobs != 3 {
					t.Errorf("flagJobs = %d, want 3", flagJobs)
				}
			},
		},
		{
			name: "short -j",
			args: []string{"-j", "5", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if flagJobs != 5 {
					t.Errorf("flagJobs = %d, want 5", flagJobs)
				}
			},
		},
		{
			name: "long --fingerprint",
			args: []string{"--fingerprint", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if !flagFingerprint {
					t.Error("flagFingerprint = false, want true")
				}
			},
		},
		{
			name: "short -f",
			args: []string{"-f", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if !flagFingerprint {
					t.Error("flagFingerprint = false, want true")
				}
			},
		},
		{
			name: "long --continuous",
			args: []string{"--continuous", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if !flagContinuous {
					t.Error("flagContinuous = false, want true")
				}
			},
		},
		{
			name: "short -c",
			args: []string{"-c", "[invalid"},
			check: func(t *testing.T) {
				t.Helper()
				if !flagContinuous {
					t.Error("flagContinuous = false, want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveFlags(t)
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "invalid regex") {
				t.Errorf("error = %q, want substring %q", err, "invalid regex")
			}
			tt.check(t)
		})
	}
}

func TestHandleResult_TTY_SingleMode(t *testing.T) {
	dir := chdirTemp(t)
	saveFlags(t)
	flagContinuous = false

	restore := display.OverrideTTY(true, 24)
	t.Cleanup(restore)

	r := fakeResult(t)

	var stdoutGot string
	stderrGot := captureStderr(t, func() {
		stdoutGot = captureStdout(t, func() {
			if err := handleResult(r); err != nil {
				t.Fatalf("handleResult: %v", err)
			}
		})
	})

	if !strings.Contains(stdoutGot, string(r.PrivateKeyPEM)) {
		t.Error("stdout missing PEM")
	}
	if !strings.Contains(stdoutGot, r.AuthorizedKey) {
		t.Error("stdout missing authorized key")
	}
	if !strings.Contains(stderrGot, "Match #") {
		t.Error("stderr missing match header")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519")); err != nil {
		t.Fatalf("private key file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519.pub")); err != nil {
		t.Fatalf("public key file: %v", err)
	}
}

func TestHandleResult_TTY_ContinuousMode(t *testing.T) {
	dir := chdirTemp(t)
	saveFlags(t)
	flagContinuous = true

	restore := display.OverrideTTY(true, 24)
	t.Cleanup(restore)

	r := fakeResult(t)

	var stdoutGot string
	stderrGot := captureStderr(t, func() {
		stdoutGot = captureStdout(t, func() {
			if err := handleResult(r); err != nil {
				t.Fatalf("handleResult: %v", err)
			}
		})
	})

	if stdoutGot != string(r.PrivateKeyPEM) {
		t.Errorf("stdout = %q, want PEM", stdoutGot)
	}
	if !strings.Contains(stderrGot, "Match #") {
		t.Error("stderr missing match header")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519")); err == nil {
		t.Error("private key file should not exist in continuous mode")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519.pub")); err == nil {
		t.Error("public key file should not exist in continuous mode")
	}
}

func TestSetVersion_VersionFlag(t *testing.T) {
	saveFlags(t)
	SetVersion("test-v1.2.3")
	t.Cleanup(func() { rootCmd.Version = "" })

	rootCmd.SetArgs([]string{"--version"})

	got := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("Execute with --version: %v", err)
		}
	})

	if !strings.Contains(got, "test-v1.2.3") {
		t.Errorf("output = %q, want substring %q", got, "test-v1.2.3")
	}
}
