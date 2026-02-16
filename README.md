# vanityssh-go

Generate ED25519 SSH key pairs at high speed and match the resulting public
keys (or SHA256 fingerprints) against a regex pattern.

## Is it safe to use?

Yes. Key generation uses Go's `crypto/ed25519` and `crypto/rand` from the
standard library. vanityssh does not implement any cryptography itself -- it
generates keys using the same functions as `ssh-keygen` and filters the
output. Private keys are serialized with `golang.org/x/crypto/ssh.MarshalPrivateKey`
in the current OpenSSH format.

## Installation

### From releases

Download a prebuilt binary from the
[releases page](https://github.com/danielewood/vanityssh-go/releases).

### From source

```bash
go install github.com/danielewood/vanityssh-go@latest
```

## Usage

```text
vanityssh generates ED25519 SSH key pairs at high speed and matches
the resulting public keys (or SHA256 fingerprints) against a regex pattern.

On first match, the key pair is written to id_ed25519 and id_ed25519.pub
in the current directory. Use --continuous to keep finding keys.

When piping, only the private key is written to stdout.

Usage:
  vanityssh <regex> [flags]

Flags:
  -c, --continuous    keep finding keys after a match
  -f, --fingerprint   match against SHA256 fingerprint instead of public key
  -h, --help          help for vanityssh
  -j, --jobs int      number of parallel workers (default: number of CPUs)
  -v, --version       version for vanityssh
```

## Examples

Find a key ending with "vanity" (case-insensitive):

```bash
vanityssh '(?i)vanity$'
```

Find a key ending with "dwd" (case-sensitive), continuous mode:

```bash
vanityssh -c 'dwd$'
```

Find a key whose SHA256 fingerprint starts with `0000`:

```bash
vanityssh -f '^0000'
```

Pipe the private key directly into a file:

```bash
vanityssh 'pattern$' > my_key
```

## Resource usage

vanityssh uses all available CPU cores by default. Use `-j` to limit workers.
With `--continuous` or a very difficult pattern, it will run until you press
Ctrl+C.

## License

[MIT](LICENSE)
