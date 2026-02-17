package display

import (
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

var (
	mu         sync.Mutex
	termHeight int
	ttyFlag    atomic.Bool
)

// Init detects the terminal and sets up the scroll region if interactive.
func Init() {
	tty := term.IsTerminal(int(os.Stdout.Fd()))
	ttyFlag.Store(tty)
	if !tty {
		return
	}
	_, h, err := term.GetSize(int(os.Stderr.Fd()))

	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		termHeight = 24
	} else {
		termHeight = h
	}
	// ANSI row numbers are 1-indexed and we need at least a content row
	// and a status row. Clamp to minimum 3 to prevent invalid sequences.
	if termHeight < 3 {
		termHeight = 3
	}
	fmt.Fprintf(os.Stderr, "\033[1;%dr", termHeight-1)
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight-1)
}

// IsTTY returns whether stdout is a terminal.
func IsTTY() bool { return ttyFlag.Load() }

// OverrideTTY overrides the TTY state for testing. It sets the ttyFlag and
// termHeight, returning a function that restores the original values.
// This must only be called from tests.
func OverrideTTY(tty bool, height int) func() {
	mu.Lock()
	origTTY := ttyFlag.Load()
	origHeight := termHeight
	ttyFlag.Store(tty)
	termHeight = height
	mu.Unlock()
	return func() {
		mu.Lock()
		ttyFlag.Store(origTTY)
		termHeight = origHeight
		mu.Unlock()
	}
}

// Reset restores the terminal scroll region.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	if !ttyFlag.Load() {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[r")
	fmt.Fprintf(os.Stderr, "\033[%d;1H\n", termHeight)
}

// PrintAboveStatus prints a line in the scroll region above the status bar.
func PrintAboveStatus(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if !ttyFlag.Load() {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		return
	}
	fmt.Fprintf(os.Stderr, "\033[s\033[%d;1H", termHeight)
	fmt.Fprintf(os.Stderr, "\033[1A")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight-1)
	fmt.Fprintf(os.Stderr, "\033[2K")
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintf(os.Stderr, "\033[u")
}

// UpdateStatusBar updates the pinned bottom line.
func UpdateStatusBar(status string) {
	mu.Lock()
	defer mu.Unlock()
	if !ttyFlag.Load() {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[s")
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight)
	fmt.Fprintf(os.Stderr, "\033[2K")
	fmt.Fprintf(os.Stderr, "\033[7m %s \033[0m", status)
	fmt.Fprintf(os.Stderr, "\033[u")
}

// FormatCount formats an integer with comma separators.
func FormatCount(n int64) string {
	if n < 0 {
		if n == math.MinInt64 {
			// -math.MinInt64 overflows int64; handle by formatting
			// the positive portion after separating the sign.
			return "-9,223,372,036,854,775,808"
		}
		return "-" + FormatCount(-n)
	}
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
