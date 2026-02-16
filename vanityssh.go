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
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/TylerBrock/colorjson"
	"github.com/klauspost/cpuid/v2"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
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

// var flagvar int
var global_counter int64
var initTime time.Time
var re *regexp.Regexp
var err error

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

func findSSHKeys() {
	matched := false
	for {
		global_counter++
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		publicKey, _ := ssh.NewPublicKey(pubKey)

		if flag_fingerprint {
			matched = re.MatchString(getFingerprint(publicKey))
		} else {
			matched = re.MatchString(getAuthorizedKey(publicKey))
		}

		if matched {
			pemKey := &pem.Block{
				Type:  "OPENSSH PRIVATE KEY",
				Bytes: edkey.MarshalED25519PrivateKey(privKey),
			}
			privateKey := pem.EncodeToMemory(pemKey)

			if flag_json || flag_json_verbose {
				printJsonStruct(json_keyout{string(privateKey), getAuthorizedKey(publicKey), getFingerprint(publicKey)}, flag_json_indent)
			} else {
				fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
				fmt.Println("\nTotal execution time", time.Since(initTime))
				fmt.Printf("%s\n", privateKey)
				fmt.Printf("%s\n", getAuthorizedKey(publicKey))
				fmt.Printf("SHA256:%s\n\n", getFingerprint(publicKey))
			}
			if !flag_forever {
				_ = os.WriteFile("id_ed25519", privateKey, 0600)
				_ = os.WriteFile("id_ed25519.pub", []byte(getAuthorizedKey(publicKey)), 0644)
				os.Exit(0)
			}
		}
	}
}

func benchmark() {
	for {
		global_counter++
		ed25519.GenerateKey(rand.Reader)
	}
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
		fmt.Fprintln(os.Stderr, "regex =", flag_regex)
		re, err = regexp.Compile(flag_regex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error =", err)
			os.Exit(1)
		}
	}

	// default to lower priority
	if !flag_normal_priority {
		syscall.Setpriority(syscall.PRIO_PROCESS, 0, 20)
	}

	initTime = time.Now()

	//	input threads, else numcpu
	if flag_threads == 0 {
		for i := 1; i <= runtime.NumCPU(); i++ {
			if !flag_benchmark {
				go findSSHKeys()
			} else {
				go benchmark()
			}
		}
	} else {
		for i := 1; i <= flag_threads; i++ {
			if !flag_benchmark {
				go findSSHKeys()
			} else {
				go benchmark()
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Press Ctrl+C to end\n")

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

			var cpu_user = math.Floor(float64(after.User-before.User) / total * 100)
			var cpu_system = math.Floor(float64(after.System-before.System) / total * 100)
			var cpu_idle = math.Floor(float64(after.Idle-before.Idle) / total * 100)

			var Now = time.Now()
			var Elapsed = Now.Sub(initTime).Seconds()
			var Rate = int64(float64(global_counter) / Elapsed)

			if flag_json_verbose {
				printJsonStruct(json_all_stats{global_counter, int64(Elapsed), Rate, cpu_user, cpu_system, cpu_idle}, flag_json_indent)
			} else {
				printJsonStruct(json_stats{global_counter, int64(Elapsed), Rate, cpu_user}, flag_json_indent)
			}

			if flag_benchmark && Elapsed >= 60 {
				os.Exit(0)
			}

		} else {
			time.Sleep(time.Duration(flag_update_rate) * time.Second)
			fmt.Fprintf(os.Stdout, "\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
		}

	}
}
