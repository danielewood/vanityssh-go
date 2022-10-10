package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/TylerBrock/colorjson"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mikesmitty/edkey"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var global_user_input string
var global_user_insensitive bool
var global_user_streaming bool
var global_user_fingerprint bool
var global_user_json bool
var global_user_json_verbose bool
var global_user_high_priority bool
var global_user_update_rate int
var global_user_threads int

// var flagvar int
var global_counter int64
var initTime time.Time
var re *regexp.Regexp
var err error

type json_stats struct {
	Num_keys    int64 `json:"num_keys"`
	Elapsed_sec int64 `json:"elapsed_sec"`
	Rate        int64 `json:"rate"`
	Cpu_user    int8  `json:"user_cpu_pct"`
}

type json_all_stats struct {
	Num_keys    int64           `json:"num_keys"`
	Elapsed_sec int64           `json:"elapsed_sec"`
	Rate        int64           `json:"rate"`
	Cpu_user    decimal.Decimal `json:"usage_cpu_user_pct"`
	Cpu_system  decimal.Decimal `json:"usage_cpu_system_pct"`
	Cpu_idle    decimal.Decimal `json:"usage_cpu_idle_pct"`
}

type json_keyout struct {
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

func init() {
	flag.StringVar(&global_user_input, "regex", "", "regex pattern goes here")
	flag.BoolVar(&global_user_json, "json", false, "json output")
	flag.BoolVar(&global_user_json_verbose, "morejson", false, "more json output")
	flag.BoolVar(&global_user_high_priority, "high-priority", false, "sets normal priority, otherwise we use idle priority")
	flag.BoolVar(&global_user_insensitive, "insensitive", false, "case-insensitive")
	flag.BoolVar(&global_user_streaming, "streaming", false, "Keep processing keys, even after a match")
	flag.BoolVar(&global_user_fingerprint, "fingerprint", false, "Match against fingerprint instead of public key")
	flag.IntVar(&global_user_update_rate, "update-rate", 1, "frequency for updates in seconds")
	flag.IntVar(&global_user_threads, "threads", 0, "number of threads to use")
	flag.Parse()
	initTime = time.Now()

	if global_user_insensitive {
		re, err = regexp.Compile("(?i)" + global_user_input)
	} else {
		re, err = regexp.Compile(global_user_input)
	}
	if err != nil {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "global_user_input =", global_user_input)
}

// func jsonPrintKey(privateKey string, publicKey string, fingerprint string) {
// 	json_struct := json_keyout{privateKey, publicKey, fingerprint}
// 	json_bytes, _ := json.Marshal(json_struct)
// 	var json_obj map[string]interface{}
// 	json.Unmarshal(json_bytes, &json_obj)

// 	formatter := colorjson.NewFormatter()
// 	formatter.Indent = 0

// 	json_color_bytes, _ := formatter.Marshal(json_obj)
// 	fmt.Println(string(json_color_bytes))
// }

// func jsonPrintBytes(json_bytes []byte) {
// 	var json_obj map[string]interface{}
// 	json.Unmarshal(json_bytes, &json_obj)

// 	formatter := colorjson.NewFormatter()
// 	formatter.Indent = 0

// 	json_color_bytes, _ := formatter.Marshal(json_obj)
// 	fmt.Println(string(json_color_bytes))
// }

func jsonPrintStruct(json_struct any) {
	json_bytes, _ := json.Marshal(json_struct)
	var json_obj map[string]interface{}
	json.Unmarshal(json_bytes, &json_obj)

	formatter := colorjson.NewFormatter()
	formatter.Indent = 0

	json_color_bytes, _ := formatter.Marshal(json_obj)
	fmt.Println(string(json_color_bytes))
}

func findsshkeys() {
	for {
		global_counter++
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		publicKey, _ := ssh.NewPublicKey(pubKey)
		pemKey := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(privKey),
		}
		privateKey := pem.EncodeToMemory(pemKey)

		matched := false
		if global_user_fingerprint {
			matched = re.MatchString(getFingerprint(publicKey))
		} else {
			matched = re.MatchString(getAuthorizedKey(publicKey))
		}

		if matched {
			if global_user_json || global_user_json_verbose {
				//jsonPrintKey(string(privateKey), getAuthorizedKey(publicKey), getFingerprint(publicKey))
				jsonPrintStruct(json_keyout{string(privateKey), getAuthorizedKey(publicKey), getFingerprint(publicKey)})
				// json_struct := json_keyout{string(privateKey), getAuthorizedKey(publicKey), getFingerprint(publicKey)}
				// json_bytes, _ := json.Marshal(json_struct)
				// jsonPrintBytes(json_bytes)
			} else {
				fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
				fmt.Println("\nTotal execution time", time.Since(initTime))
				fmt.Printf("%s\n", privateKey)
				fmt.Printf("%s\n", getAuthorizedKey(publicKey))
				fmt.Printf("SHA256:%s\n\n", getFingerprint(publicKey))
			}
			if !global_user_streaming {
				_ = os.WriteFile("id_ed25519", privateKey, 0600)
				_ = os.WriteFile("id_ed25519.pub", []byte(getAuthorizedKey(publicKey)), 0644)
				os.Exit(0)
			}
		}
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

func main() {
	// default to lower priority
	if !global_user_high_priority {
		syscall.Setpriority(syscall.PRIO_PROCESS, 0, 20)
	}
	//	input threads, else numcpu
	if global_user_threads == 0 {
		for i := 1; i <= runtime.NumCPU(); i++ {
			go findsshkeys()
		}
	} else {
		for i := 1; i <= global_user_threads; i++ {
			go findsshkeys()
		}
	}

	fmt.Fprintf(os.Stderr, "Press Ctrl+C to end\n")

	for {

		if global_user_json || global_user_json_verbose {
			before, err := cpu.Get()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return
			}
			time.Sleep(time.Duration(global_user_update_rate) * time.Second)

			after, err := cpu.Get()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return
			}
			total := float64(after.Total - before.Total)

			var cpu_user = decimal.NewFromFloat(float64(after.User-before.User) / total * 100).Round(int32(2))
			var cpu_system = decimal.NewFromFloat(float64(after.System-before.System) / total * 100).Round(int32(2))
			var cpu_idle = decimal.NewFromFloat(float64(after.Idle-before.Idle) / total * 100).Round(int32(2))

			var cpu_user_int = int8(float64(after.User-before.User) / total * 100)

			var Now = time.Now()
			var Elapsed = Now.Sub(initTime).Seconds()
			var Rate = int64(float64(global_counter) / Elapsed)

			if global_user_json_verbose {
				jsonPrintStruct(json_all_stats{global_counter, int64(Elapsed), Rate, cpu_user, cpu_system, cpu_idle})
			} else {
				jsonPrintStruct(json_stats{global_counter, int64(Elapsed), Rate, cpu_user_int})
			}
			// json_struct := json_stats{global_counter, int64(Elapsed), Rate}
			// json_bytes, _ := json.Marshal(json_struct)
			// jsonPrintBytes(json_bytes)

		} else {
			time.Sleep(time.Duration(global_user_update_rate) * time.Second)
			fmt.Fprintf(os.Stdout, "\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
		}

	}
}
