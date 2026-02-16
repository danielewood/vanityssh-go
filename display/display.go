package display

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

var (
	mu         sync.Mutex
	termHeight int
	isTTY      bool
)

// Init detects the terminal and sets up the scroll region if interactive.
func Init() {
	isTTY = term.IsTerminal(int(os.Stdout.Fd()))
	if !isTTY {
		return
	}
	_, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil {
		termHeight = 24
	} else {
		termHeight = h
	}
	fmt.Fprintf(os.Stderr, "\033[1;%dr", termHeight-1)
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight-1)
}

// IsTTY returns whether stdout is a terminal.
func IsTTY() bool { return isTTY }

// Reset restores the terminal scroll region.
func Reset() {
	if !isTTY {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[r")
	fmt.Fprintf(os.Stderr, "\033[%d;1H\n", termHeight)
}

// PrintAboveStatus prints a line in the scroll region above the status bar.
func PrintAboveStatus(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if !isTTY {
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
	fmt.Fprintf(os.Stderr, "\033[s")
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight)
	fmt.Fprintf(os.Stderr, "\033[2K")
	fmt.Fprintf(os.Stderr, "\033[7m %s \033[0m", status)
	fmt.Fprintf(os.Stderr, "\033[u")
}

// FormatCount formats an integer with comma separators.
func FormatCount(n int64) string {
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
