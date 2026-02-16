# CLAUDE.md — vanityssh-go

## 0 — Project Overview

**vanityssh-go** generates ED25519 SSH key pairs at high speed and matches the
resulting public keys (or SHA256 fingerprints) against a user-supplied regex.

- **Module**: `github.com/danielewood/vanityssh-go`
- **Go version**: 1.19+ (will be upgraded)
- **License**: MIT
- **Binary**: `vanityssh`
- **Architecture**: Single-file CLI (`vanityssh.go`), no library surface

### Key behaviors

- Spawns N goroutines (default: `runtime.NumCPU()`) generating keys in tight loops
- First match writes `id_ed25519` / `id_ed25519.pub` and exits (unless `--streaming`)
- JSON output modes (`--json`, `--morejson`) emit colorized stats to stdout
- Benchmark mode (`--benchmark`) runs pure key generation for 60s

## 1 — Rules & Standards

Rules are classified by enforcement level:

- **MUST**: Enforced by CI and code review
- **SHOULD**: Strong recommendations
- **CAN**: Allowed without extra approval

Stable IDs (e.g., **BP-1**, **ERR-2**) enable precise code-review comments.
Keep IDs stable; deprecate with notes instead of renumbering.

### Before Coding

- **BP-1 (MUST)** Ask clarifying questions for ambiguous requirements.
- **BP-2 (MUST)** Draft and confirm an approach (API shape, data flow, failure
  modes) before writing code.
- **BP-3 (SHOULD)** When multiple approaches exist, list pros/cons and rationale.
- **BP-4 (SHOULD)** Define testing strategy and observability signals up front.

### Modules & Dependencies

- **MD-1 (SHOULD)** Prefer stdlib; introduce deps only with clear payoff.
- **MD-2 (SHOULD)** Run `govulncheck` before adding or updating dependencies.

### Code Style

- **CS-1 (MUST)** Enforce `gofmt`, `go vet`, `goimports`.
- **CS-2 (MUST)** Avoid stutter: `package kv; type Store` not `KVStore`.
- **CS-3 (SHOULD)** Small interfaces near consumers; composition over inheritance.
- **CS-4 (SHOULD)** Avoid reflection on hot paths; prefer generics when clearer.
- **CS-5 (MUST)** Use input structs for functions receiving more than 2
  arguments. `context.Context` stays outside input structs.
- **CS-6 (SHOULD)** Declare function input structs before the consuming function.
- **CS-7 (MUST)** Imports in two groups: stdlib, then third-party. Alphabetical
  within each group.
- **CS-8 (SHOULD)** Boring and readable over clever.

### Errors

- **ERR-1 (MUST)** Wrap with `%w` and context:
  `fmt.Errorf("compile regex %q: %w", pattern, err)`.
- **ERR-2 (MUST)** Use `errors.Is`/`errors.As` for control flow; no string
  matching.
- **ERR-3 (SHOULD)** Define sentinel errors; document behavior.
- **ERR-4 (MUST)** Lowercase error strings, no trailing punctuation.
- **ERR-5 (MUST)** Never silently ignore errors.
- **ERR-6 (MUST)** Fail fast with descriptive messages.

### Concurrency

- **CC-1 (MUST)** The **sender** closes channels; receivers never close.
- **CC-2 (MUST)** Tie goroutine lifetime to a `context.Context`; prevent leaks.
- **CC-3 (MUST)** Protect shared state with `sync.Mutex`/`atomic`; no "probably
  safe" races. `global_counter` must use `atomic` operations.
- **CC-4 (SHOULD)** Use `errgroup` for fan-out work; cancel on first error.
- **CC-5 (CAN)** Prefer buffered channels only with rationale.

### Contexts

- **CTX-1 (MUST)** `ctx context.Context` as first parameter; never store in
  structs.
- **CTX-2 (MUST)** Propagate non-nil `ctx`; honor `Done`/deadlines/timeouts.

### Testing

- **T-1 (MUST)** All tests pass before committing.
- **T-2 (MUST)** Table-driven tests with descriptive subtest names.
- **T-3 (MUST)** Run `-race` in CI; use `t.Cleanup` for teardown.
- **T-4 (SHOULD)** Mark safe tests with `t.Parallel()`.
- **T-5 (SHOULD)** stdlib `testing` only (no testify/gomock).

### Logging & Observability

- **OBS-1 (MUST)** Diagnostic output to stderr; data output to stdout.
- **OBS-2 (SHOULD)** Structured logging for JSON modes.

### Performance

- **PERF-1 (MUST)** Measure before optimizing: `pprof`, `go test -bench`,
  `benchstat`.
- **PERF-2 (SHOULD)** Avoid allocations on hot paths (key generation loop).
  Defer expensive operations (PEM encoding) until match.
- **PERF-3 (CAN)** Add microbenchmarks for key generation throughput.

### Configuration

- **CFG-1 (MUST)** Config via flags; validate on startup; fail fast.
- **CFG-2 (SHOULD)** Provide sane defaults and clear help text.

### APIs & Boundaries

- **API-1 (MUST)** Document exported items; keep exported surface minimal.
- **API-2 (MUST)** Accept interfaces where variation is needed; return concrete
  types.
- **API-3 (SHOULD)** Keep functions small, orthogonal, and composable.

### Security

- **SEC-1 (MUST)** Never log private keys in plaintext outside explicit output.
- **SEC-2 (MUST)** Generated key files use correct permissions (`0600`/`0644`).
- **SEC-3 (SHOULD)** Use `crypto/rand` exclusively for key generation.
- **SEC-4 (CAN)** Add fuzz tests for regex/input parsing.

### CLI Output

- **CLI-1 (MUST)** Stdout for data (keys, JSON stats); stderr for diagnostics.
- **CLI-2 (MUST)** JSON output (`--json`) is valid JSON; no mixed text/JSON.
- **CLI-3 (MUST)** Exit codes: 0 = success, 1 = error.

## 2 — Git, CI & Pre-commit

### Branch Protection

- **GIT-1 (MUST)** No direct pushes to `main`.
- **GIT-2 (MUST)** CI status checks must pass before merge.
- **GIT-3 (MUST)** Branch names: `(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)/<description>`.
- **GIT-4 (MUST)** Conventional Commits: `type: description` or
  `type(scope): description`.
- **GIT-5 (MUST)** Valid types:
  feat/fix/docs/style/refactor/perf/test/build/ci/chore/revert.
- **GIT-6 (MUST)** Commit messages explain "why"; the diff shows "what".

### CI Checks (`.github/workflows/ci.yml`)

1. PR Title — Conventional Commits format
2. PR Conventions — Branch name, commits, verified commits
3. Go Checks — build, vet, goimports
4. Go Test — `go test -race -count=1 ./...`
5. Lint — golangci-lint (default linters)
6. Vulnerability Check — `govulncheck ./...`
7. Markdown lint — markdownlint

### Pre-commit Installation

```sh
brew install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit run --all-files
```

### Tooling Gates

- **G-1 (MUST)** `go vet ./...` passes.
- **G-2 (MUST)** `go test -race ./...` passes.
- **G-3 (MUST)** `golangci-lint run` passes.
- **G-4 (MUST)** `go build -trimpath ./...` succeeds.

## 3 — Changelog (CHANGELOG.md)

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

- **CL-1 (MUST)** Every behavior/feature/bug fix updates `## [Unreleased]`.
- **CL-2 (MUST)** Correct subsection:
  Added/Changed/Fixed/Removed/Deprecated/Security.
- **CL-3 (MUST)** Write from user's perspective.
- **CL-4 (SHOULD)** Update changelog before committing, not after.

## 4 — Build & Release

```sh
make build   # go build -trimpath ./...
make test    # go test -race ./...
make vet     # go vet ./...
```

Releases are automated via GoReleaser on `v*` tags:

- **Platforms**: darwin/linux/windows (amd64/arm64)
- **Formats**: tar.gz (Unix), zip (Windows), deb (Linux)
- **Flags**: `-s -w -trimpath -X main.version={{.Version}}`

## 5 — Writing Functions

1. Can you read the function and honestly follow what it's doing? If yes, stop.
2. Does it have high cyclomatic complexity? If so, simplify.
3. Are there data structures or algorithms that would make it clearer?
4. Does it have hidden untested dependencies that could be arguments instead?
5. Brainstorm 3 better function names — is the current one best and consistent
   with the codebase?
