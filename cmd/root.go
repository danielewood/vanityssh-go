package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

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
	defer display.Reset()

	startTime := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Clean up terminal on interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	numJobs := flagJobs
	if numJobs == 0 {
		numJobs = runtime.NumCPU()
	}

	opts := keygen.Options{
		Regex:       re,
		Fingerprint: flagFingerprint,
	}

	results := make(chan keygen.Result, numJobs)
	g, gctx := errgroup.WithContext(ctx)

	// Launch workers
	for i := 0; i < numJobs; i++ {
		g.Go(func() error {
			return keygen.FindKeys(gctx, opts, results)
		})
	}

	// Result consumer
	g.Go(func() error {
		for {
			select {
			case r := <-results:
				if err := handleResult(r); err != nil {
					return err
				}
				if !flagContinuous {
					cancel()
					return nil
				}
			case <-gctx.Done():
				return nil
			}
		}
	})

	// Status bar updater
	g.Go(func() error {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if display.IsTTY() {
					count := keygen.KeyCount()
					elapsed := time.Since(startTime)
					rate := int64(float64(count) / elapsed.Seconds())
					matches := keygen.MatchCount()

					status := fmt.Sprintf("Keys: %s | Rate: %s/s | Matches: %d | Elapsed: %s | Ctrl+C to exit",
						display.FormatCount(count), display.FormatCount(rate), matches,
						elapsed.Truncate(time.Second))
					display.UpdateStatusBar(status)
				}
			case <-gctx.Done():
				return nil
			}
		}
	})

	return g.Wait()
}

func handleResult(r keygen.Result) error {
	if display.IsTTY() {
		display.PrintAboveStatus("--- Match #%d ---", keygen.MatchCount())
		for _, line := range strings.Split(strings.TrimSpace(string(r.PrivateKeyPEM)), "\n") {
			display.PrintAboveStatus("%s", line)
		}
		display.PrintAboveStatus("%s", r.AuthorizedKey)
		display.PrintAboveStatus("SHA256:%s", r.Fingerprint)
	}

	if !display.IsTTY() && flagContinuous {
		fmt.Printf("%s", r.PrivateKeyPEM)
	}

	if !flagContinuous {
		if display.IsTTY() {
			display.Reset()
			fmt.Printf("%s", r.PrivateKeyPEM)
			fmt.Printf("%s\n", r.AuthorizedKey)
			fmt.Printf("SHA256:%s\n", r.Fingerprint)
		} else {
			fmt.Printf("%s", r.PrivateKeyPEM)
		}
		if err := os.WriteFile("id_ed25519", r.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := os.WriteFile("id_ed25519.pub", []byte(r.AuthorizedKey), 0644); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}
	}

	return nil
}
