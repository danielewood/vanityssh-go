package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var global_user_input string
var global_user_insensitive bool
var global_user_streaming bool
var global_user_fingerprint bool

//var flagvar int
var global_counter int64
var start time.Time
var re *regexp.Regexp
var err error

func init() {
	flag.StringVar(&global_user_input, "regex", "", "regex pattern goes here")
	flag.BoolVar(&global_user_insensitive, "insensitive", false, "case-insensitive")
	flag.BoolVar(&global_user_streaming, "streaming", false, "Keep processing keys, even after a match")
	flag.BoolVar(&global_user_fingerprint, "fingerprint", false, "Match against fingerprint instead of public key")
	flag.Parse()
	start = time.Now()

	if global_user_insensitive == false {
		re, err = regexp.Compile(global_user_input)
	} else {
		re, err = regexp.Compile("(?i)" + global_user_input)
	}
	if err != nil {
		os.Exit(1)
	}
	fmt.Println("global_user_input =", global_user_input)
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()
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
			fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
			fmt.Println("\nTotal execution time", time.Since(start))
			fmt.Printf("%s\n", privateKey)
			fmt.Printf("%s\n", getAuthorizedKey(publicKey))
			fmt.Printf("SHA256:%s\n", getFingerprint(publicKey))
			if global_user_streaming == false {
				_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
				_ = ioutil.WriteFile("id_ed25519.pub", []byte(getAuthorizedKey(publicKey)), 0644)
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
	//	input threads, else numcpu
	for i := 1; i <= runtime.NumCPU(); i++ {
		go findsshkeys()
	}

	fmt.Printf("Press Ctrl+C to end\n")
	for {
		fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
		time.Sleep(250 * time.Millisecond)
	}

	WaitForCtrlC()
	fmt.Printf("\n")
}
