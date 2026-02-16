package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/danielewood/vanityssh-go/display"
	"github.com/danielewood/vanityssh-go/keygen"
)

var (
	flagFingerprint bool
	flagContinuous  bool
	flagJobs        int
)

var rootCmd = &cobra.Command{
	Use:   "vanityssh <regex>",
	Short: "Generate ED25519 SSH keys with vanity public keys",
	Long: `vanityssh generates ED25519 SSH key pairs at high speed and matches
the resulting public keys (or SHA256 fingerprints) against a regex pattern.

On first match, the key pair is written to id_ed25519 and id_ed25519.pub
in the current directory. Use --continuous to keep finding keys.

When piping, only the private key is written to stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: run,
}

func init() {
	rootCmd.Flags().BoolVarP(&flagFingerprint, "fingerprint", "f", false, "match against SHA256 fingerprint instead of public key")
	rootCmd.Flags().BoolVarP(&flagContinuous, "continuous", "c", false, "keep finding keys after a match")
	rootCmd.Flags().IntVarP(&flagJobs, "jobs", "j", 0, "number of parallel workers (default: number of CPUs)")
}

// SetVersion sets the version string for the root command.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func run(_ *cobra.Command, args []string) error {
	re, err := regexp.Compile(args[0])
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}

	display.Init()

	// Clean up terminal on interrupt
	if display.IsTTY() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			display.Reset()
			os.Exit(0)
		}()
	}

	numJobs := flagJobs
	if numJobs == 0 {
		numJobs = runtime.NumCPU()
	}

	opts := keygen.Options{
		Regex:       re,
		Fingerprint: flagFingerprint,
		Continuous:  flagContinuous,
	}

	for i := 0; i < numJobs; i++ {
		go keygen.FindKeys(opts)
	}

	// Status bar update loop
	for {
		time.Sleep(250 * time.Millisecond)
		if display.IsTTY() {
			count := keygen.KeyCount()
			elapsed := keygen.Elapsed()
			rate := int64(float64(count) / elapsed.Seconds())
			matches := keygen.MatchCount()

			status := fmt.Sprintf("Keys: %s | Rate: %s/s | Matches: %d | Elapsed: %s | Ctrl+C to exit",
				display.FormatCount(count), display.FormatCount(rate), matches,
				elapsed.Truncate(time.Second))
			display.UpdateStatusBar(status)
		}
	}
}
