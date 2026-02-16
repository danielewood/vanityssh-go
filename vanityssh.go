package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TylerBrock/colorjson"
	"github.com/klauspost/cpuid/v2"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var flag_regex string
var flag_forever bool
var flag_fingerprint bool
var flag_json bool
var flag_json_verbose bool
var flag_json_indent int
var flag_normal_priority bool
var flag_benchmark bool
var flag_update_rate int
var flag_threads int

var global_counter atomic.Int64
var matchCount atomic.Int64
var initTime time.Time
var re *regexp.Regexp
var err error
var outputMu sync.Mutex
var termHeight int

type json_stats struct {
	Num_keys    int64   `json:"num_keys"`
	Elapsed_sec int64   `json:"elapsed_sec"`
	Rate        int64   `json:"rate"`
	Cpu_user    float64 `json:"usage_cpu_user_pct"`
}

type json_all_stats struct {
	Num_keys    int64   `json:"num_keys"`
	Elapsed_sec int64   `json:"elapsed_sec"`
	Rate        int64   `json:"rate"`
	Cpu_user    float64 `json:"usage_cpu_user_pct"`
	Cpu_system  float64 `json:"usage_cpu_system_pct"`
	Cpu_idle    float64 `json:"usage_cpu_idle_pct"`
}

type json_keyout struct {
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

func init() {
	flag.StringVar(&flag_regex, "regex", "", "regex pattern goes here")
	flag.BoolVar(&flag_json, "json", false, "json output")
	flag.BoolVar(&flag_json_verbose, "morejson", false, "more json output")
	flag.IntVar(&flag_json_indent, "json-indent", 0, "json indentation")
	flag.BoolVar(&flag_normal_priority, "no-nice", false, "sets normal priority, otherwise we use idle priority")
	flag.BoolVar(&flag_forever, "streaming", false, "Keep processing keys, even after a match")
	flag.BoolVar(&flag_fingerprint, "fingerprint", false, "Match against fingerprint instead of public key")
	flag.BoolVar(&flag_benchmark, "benchmark", false, "Benchmark mode")
	flag.IntVar(&flag_update_rate, "update-rate", 1, "frequency for updates in seconds")
	flag.IntVar(&flag_threads, "threads", 0, "number of threads to use")
	flag.Parse()
}

func printJsonStruct(json_struct any, indent int) {
	json_bytes, _ := json.Marshal(json_struct)
	var json_obj map[string]interface{}
	json.Unmarshal(json_bytes, &json_obj)

	formatter := colorjson.NewFormatter()
	formatter.Indent = indent

	json_color_bytes, _ := formatter.Marshal(json_obj)
	fmt.Println(string(json_color_bytes))
}

// printAboveStatus prints content in the scroll region above the pinned status bar.
func printAboveStatus(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	// Save cursor, move to scroll region, print, restore cursor
	fmt.Fprintf(os.Stderr, "\033[s\033[%d;1H", termHeight) // save + move to status line
	fmt.Fprintf(os.Stderr, "\033[1A")                      // move up one into scroll region
	fmt.Fprintf(os.Stderr, "\n")                           // scroll the region up
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight-1)     // position at bottom of scroll region
	fmt.Fprintf(os.Stderr, "\033[2K")                      // clear line
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintf(os.Stderr, "\033[u") // restore cursor
}

// updateStatusBar updates the pinned bottom line.
func updateStatusBar(status string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintf(os.Stderr, "\033[s")                     // save cursor
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight)     // move to status line
	fmt.Fprintf(os.Stderr, "\033[2K")                    // clear line
	fmt.Fprintf(os.Stderr, "\033[7m %s \033[0m", status) // inverse video
	fmt.Fprintf(os.Stderr, "\033[u")                     // restore cursor
}

// setupScrollRegion reserves the bottom line for the status bar.
func setupScrollRegion() {
	_, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil {
		termHeight = 24 // fallback
	} else {
		termHeight = h
	}
	fmt.Fprintf(os.Stderr, "\033[1;%dr", termHeight-1) // scroll region: rows 1 to h-1
	fmt.Fprintf(os.Stderr, "\033[%d;1H", termHeight-1) // position cursor in scroll region
}

// resetScrollRegion restores normal terminal behavior.
func resetScrollRegion() {
	fmt.Fprintf(os.Stderr, "\033[r")                   // reset scroll region
	fmt.Fprintf(os.Stderr, "\033[%d;1H\n", termHeight) // move past status line
}

func findSSHKeys() {
	for {
		global_counter.Add(1)
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		publicKey, _ := ssh.NewPublicKey(pubKey)

		matched := false
		if flag_fingerprint {
			matched = re.MatchString(getFingerprint(publicKey))
		} else {
			matched = re.MatchString(getAuthorizedKey(publicKey))
		}

		if matched {
			matchCount.Add(1)
			pemKey := &pem.Block{
				Type:  "OPENSSH PRIVATE KEY",
				Bytes: edkey.MarshalED25519PrivateKey(privKey),
			}
			privateKey := pem.EncodeToMemory(pemKey)
			authorizedKey := getAuthorizedKey(publicKey)
			fingerprint := getFingerprint(publicKey)

			if flag_json || flag_json_verbose {
				printJsonStruct(json_keyout{string(privateKey), authorizedKey, fingerprint}, flag_json_indent)
			} else {
				printAboveStatus("--- Match #%d ---", matchCount.Load())
				printAboveStatus("%s", authorizedKey)
				printAboveStatus("SHA256:%s", fingerprint)
			}
			if !flag_forever {
				resetScrollRegion()
				fmt.Printf("%s", privateKey)
				fmt.Printf("%s\n", authorizedKey)
				fmt.Printf("SHA256:%s\n", fingerprint)
				_ = os.WriteFile("id_ed25519", privateKey, 0600)
				_ = os.WriteFile("id_ed25519.pub", []byte(authorizedKey), 0644)
				os.Exit(0)
			}
		}
	}
}

func benchmark() {
	for {
		global_counter.Add(1)
		ed25519.GenerateKey(rand.Reader)
	}
}

func formatCount(n int64) string {
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

// Generate a SHA256 fingerprint of a public key
func getFingerprint(key ssh.PublicKey) string {
	h := sha256.New()
	h.Write(key.Marshal())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Generate an `authorized_keys` line for a public key
func getAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func printCPUInfo() {
	info := struct {
		cpuid.CPUInfo
		Features []string
		X64Level int
	}{
		CPUInfo:  cpuid.CPU,
		Features: cpuid.CPU.FeatureSet(),
		X64Level: cpuid.CPU.X64Level(),
	}
	printJsonStruct(info, flag_json_indent)
}

func main() {
	if flag_json_verbose {
		printCPUInfo()
	}

	if !flag_benchmark {
		re, err = regexp.Compile(flag_regex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}

	// default to lower priority
	if !flag_normal_priority {
		syscall.Setpriority(syscall.PRIO_PROCESS, 0, 20)
	}

	initTime = time.Now()

	// set up pinned status bar for interactive (non-JSON) mode
	if !(flag_json || flag_json_verbose) {
		setupScrollRegion()

		// clean up terminal on exit or interrupt
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			resetScrollRegion()
			os.Exit(0)
		}()
	}

	numThreads := flag_threads
	if numThreads == 0 {
		numThreads = runtime.NumCPU()
	}
	for i := 0; i < numThreads; i++ {
		if !flag_benchmark {
			go findSSHKeys()
		} else {
			go benchmark()
		}
	}

	for {
		if flag_json || flag_json_verbose {
			before, err := cpu.Get()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return
			}
			time.Sleep(time.Duration(flag_update_rate) * time.Second)

			after, err := cpu.Get()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return
			}
			total := float64(after.Total - before.Total)

			cpuUser := math.Floor(float64(after.User-before.User) / total * 100)
			cpuSystem := math.Floor(float64(after.System-before.System) / total * 100)
			cpuIdle := math.Floor(float64(after.Idle-before.Idle) / total * 100)

			elapsed := time.Since(initTime).Seconds()
			count := global_counter.Load()
			rate := int64(float64(count) / elapsed)

			if flag_json_verbose {
				printJsonStruct(json_all_stats{count, int64(elapsed), rate, cpuUser, cpuSystem, cpuIdle}, flag_json_indent)
			} else {
				printJsonStruct(json_stats{count, int64(elapsed), rate, cpuUser}, flag_json_indent)
			}

			if flag_benchmark && elapsed >= 60 {
				os.Exit(0)
			}
		} else {
			time.Sleep(250 * time.Millisecond)
			count := global_counter.Load()
			elapsed := time.Since(initTime)
			rate := int64(float64(count) / elapsed.Seconds())
			matches := matchCount.Load()

			status := fmt.Sprintf("Keys: %s | Rate: %s/s | Matches: %d | Elapsed: %s | Ctrl+C to exit",
				formatCount(count), formatCount(rate), matches,
				elapsed.Truncate(time.Second))
			updateStatusBar(status)
		}
	}
}
