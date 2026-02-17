package display

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// setTTY overrides the ttyFlag and termHeight for testing and registers a
// cleanup function via t.Cleanup to restore the original values. Must be
// called from non-parallel tests.
func setTTY(t *testing.T, tty bool, height int) {
	t.Helper()
	mu.Lock()
	origTTY := ttyFlag.Load()
	origHeight := termHeight
	ttyFlag.Store(tty)
	termHeight = height
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		ttyFlag.Store(origTTY)
		termHeight = origHeight
		mu.Unlock()
	})
}

// captureStderr redirects os.Stderr to a pipe, calls fn, then returns
// everything written to stderr.
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

func TestFormatCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n    int64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
		{-1, "-1"},
		{-1234, "-1,234"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.n), func(t *testing.T) {
			t.Parallel()
			if got := FormatCount(tt.n); got != tt.want {
				t.Errorf("FormatCount(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

func TestIsTTY(t *testing.T) {
	// Not parallel: modifies package-level state via setTTY.

	if IsTTY() {
		t.Error("IsTTY() = true in test environment, want false")
	}

	setTTY(t, true, 24)
	if !IsTTY() {
		t.Error("IsTTY() = false after setTTY(true), want true")
	}
}

func TestInit_NonTTY(t *testing.T) {
	// Not parallel: modifies package-level state.

	origTTY := ttyFlag.Load()
	origHeight := termHeight
	t.Cleanup(func() {
		ttyFlag.Store(origTTY)
		termHeight = origHeight
	})

	got := captureStderr(t, func() { Init() })

	if IsTTY() {
		t.Error("IsTTY() = true after Init() in test, want false")
	}
	if got != "" {
		t.Errorf("Init() non-TTY output = %q, want empty", got)
	}
}

func TestReset_NonTTY(t *testing.T) {
	// Not parallel: depends on package-level state.

	got := captureStderr(t, func() { Reset() })
	if got != "" {
		t.Errorf("Reset() non-TTY output = %q, want empty", got)
	}
}

func TestPrintAboveStatus_NonTTY(t *testing.T) {
	// Not parallel: redirects os.Stderr.

	got := captureStderr(t, func() {
		PrintAboveStatus("test: %s", "hello")
	})

	if got != "test: hello\n" {
		t.Errorf("output = %q, want %q", got, "test: hello\n")
	}
	if strings.Contains(got, "\033[") {
		t.Errorf("non-TTY output contains ANSI escapes: %q", got)
	}
}

func TestUpdateStatusBar_NonTTY(t *testing.T) {
	// Not parallel: depends on package-level state.

	got := captureStderr(t, func() {
		UpdateStatusBar("test status")
	})
	if got != "" {
		t.Errorf("UpdateStatusBar non-TTY output = %q, want empty", got)
	}
}

func TestPrintAboveStatus_TTY(t *testing.T) {
	// Not parallel: modifies package-level state and redirects os.Stderr.

	setTTY(t, true, 24)

	got := captureStderr(t, func() {
		PrintAboveStatus("found key: %s", "abc123")
	})

	if !strings.Contains(got, "\033[s") {
		t.Error("missing cursor save")
	}
	if !strings.Contains(got, "\033[u") {
		t.Error("missing cursor restore")
	}
	if !strings.Contains(got, "found key: abc123") {
		t.Error("missing content")
	}
	if !strings.Contains(got, "\033[2K") {
		t.Error("missing line clear")
	}
	if saves, restores := strings.Count(got, "\033[s"), strings.Count(got, "\033[u"); saves != restores {
		t.Errorf("unbalanced: %d saves vs %d restores", saves, restores)
	}
}

func TestUpdateStatusBar_TTY(t *testing.T) {
	// Not parallel: modifies package-level state and redirects os.Stderr.

	setTTY(t, true, 24)

	got := captureStderr(t, func() {
		UpdateStatusBar("Keys: 1,000")
	})

	if !strings.Contains(got, "\033[s") {
		t.Error("missing cursor save")
	}
	if !strings.Contains(got, "\033[u") {
		t.Error("missing cursor restore")
	}
	if !strings.Contains(got, "\033[7m Keys: 1,000 \033[0m") {
		t.Errorf("missing reverse-video content in %q", got)
	}
	if saves, restores := strings.Count(got, "\033[s"), strings.Count(got, "\033[u"); saves != restores {
		t.Errorf("unbalanced: %d saves vs %d restores", saves, restores)
	}
}

func TestReset_TTY(t *testing.T) {
	// Not parallel: modifies package-level state and redirects os.Stderr.

	setTTY(t, true, 24)

	got := captureStderr(t, func() { Reset() })

	if !strings.Contains(got, "\033[r") {
		t.Error("missing scroll region reset")
	}
	if !strings.Contains(got, fmt.Sprintf("\033[%d;1H\n", 24)) {
		t.Error("missing cursor reposition")
	}
}

func TestPrintAboveStatus_Concurrent_NonTTY(t *testing.T) {
	// Not parallel: redirects os.Stderr.

	const goroutines = 10
	const iterations = 50

	got := captureStderr(t, func() {
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := range goroutines {
			go func() {
				defer wg.Done()
				for j := range iterations {
					PrintAboveStatus("worker %d iter %d", i, j)
				}
			}()
		}
		wg.Wait()
	})

	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != goroutines*iterations {
		t.Errorf("got %d lines, want %d", len(lines), goroutines*iterations)
	}
	lineRe := regexp.MustCompile(`^worker \d+ iter \d+$`)
	for i, line := range lines {
		if !lineRe.MatchString(line) {
			t.Errorf("line %d corrupted: %q", i, line)
		}
	}
}

func TestReset_Concurrent_TTY(t *testing.T) {
	// Not parallel: modifies package-level state and redirects os.Stderr.

	setTTY(t, true, 24)

	// Test passes if no race or panic occurs (run with -race).
	captureStderr(t, func() {
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for range 20 {
				PrintAboveStatus("msg %d", 1)
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				UpdateStatusBar("status")
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				Reset()
			}
		}()
		wg.Wait()
	})
}

func TestPrintAboveStatus_EmptyFormat(t *testing.T) {
	// Not parallel: redirects os.Stderr.

	got := captureStderr(t, func() { PrintAboveStatus("") })
	if got != "\n" {
		t.Errorf("output = %q, want %q", got, "\n")
	}
}

func TestPrintAboveStatus_FormatDirectivesInContent(t *testing.T) {
	// Not parallel: redirects os.Stderr.

	got := captureStderr(t, func() {
		PrintAboveStatus("rate: %s", "50% complete")
	})
	if got != "rate: 50% complete\n" {
		t.Errorf("output = %q, want %q", got, "rate: 50% complete\n")
	}
}

func TestUpdateStatusBar_EmptyString(t *testing.T) {
	// Not parallel: modifies package-level state and redirects os.Stderr.

	setTTY(t, true, 24)

	got := captureStderr(t, func() { UpdateStatusBar("") })
	if got == "" {
		t.Error("produced no output in TTY mode")
	}
}
