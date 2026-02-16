# CLAUDE.md — vanityssh-go

## Rule Severity

**MUST** rules are enforced by CI/pre-commit; **SHOULD** rules are strong
recommendations; **CAN** rules are allowed without extra approval. Stable IDs
(e.g., **ERR-1**, **CC-2**) enable precise code-review comments and automated
policy checks. Keep IDs stable; deprecate with notes instead of renumbering.

---

## 0 — Project Overview

Go module: `github.com/danielewood/vanityssh-go`
Go version: 1.24+
License: MIT
Binary: `vanityssh`

Generates ED25519 SSH key pairs at high speed and matches the resulting public
keys (or SHA256 fingerprints) against a user-supplied regex. First match writes
`id_ed25519` / `id_ed25519.pub` and exits (unless `--continuous`).

### Key behaviors

- Spawns N goroutines (default: `runtime.NumCPU()`) generating keys in tight
  loops
- First match writes key files and exits (unless `--continuous`)
- Supports matching against base64 public key or SHA256 fingerprint
  (`--fingerprint`)
- Benchmark mode for pure key generation throughput

---

## 1 — Before Coding

- **BP-1 (MUST)** Ask clarifying questions for ambiguous requirements.
- **BP-2 (MUST)** Draft and confirm an approach (API shape, data flow, failure
  modes) before writing code.
- **BP-3 (SHOULD)** When >2 approaches exist, list pros/cons and rationale.
- **BP-4 (SHOULD)** Define testing strategy and observability signals up front.

---

## 2 — Package Structure

```text
main.go                 # Thin entry point — sets version, calls cmd.Execute()
cmd/
  root.go               # Cobra CLI: flags, validation, worker orchestration
keygen/
  keygen.go             # Hot-path key generation worker, Result type
  keygen_test.go        # Unit tests for generation, matching, cancellation
display/
  display.go            # TTY detection, scroll-region status bar, formatting
  display_test.go       # Tests for formatting and TTY helpers
```

---

## 3 — Modules & Dependencies

- **MD-1 (SHOULD)** Prefer stdlib; introduce deps only with clear payoff.
- **MD-2 (SHOULD)** Run `govulncheck` before adding or updating dependencies.

---

## 4 — Code Style

- **CS-1 (MUST)** Enforce `gofmt`, `go vet`, `goimports` before committing.
- **CS-2 (MUST)** Avoid stutter in names: `package kv; type Store` (not
  `KVStore` in `kv`).
- **CS-3 (SHOULD)** Small interfaces near consumers; prefer composition over
  inheritance.
- **CS-4 (SHOULD)** Avoid reflection on hot paths; prefer generics when it
  clarifies and speeds.
- **CS-5 (MUST)** Use input structs for functions receiving more than 2
  arguments. `context.Context` stays outside input structs.
- **CS-6 (SHOULD)** Declare function input structs before the function consuming
  them.

### Go version

Target the latest stable Go release. Use modern stdlib features freely:
`slices` package, `min`/`max` builtins, range-over-integers where it simplifies
iteration.

### Formatting and imports

- Two import groups: stdlib, then third-party. Alphabetical within each group.
- No blank lines within an import group.

### Naming

- Exported functions: doc comment required (godoc style). No exceptions.
- Unexported functions: doc comment if the purpose isn't obvious from the name.
- Error variables: `errFoo` (unexported), `ErrFoo` (exported).
- Test helpers: always call `t.Helper()`.

### Philosophy

- Boring and readable over clever and terse.
- DRY: extract helpers when logic repeats.
- No premature abstractions — keep code straightforward.
- Consistency with existing patterns trumps personal preference.

---

## 5 — Errors

- **ERR-1 (MUST)** Wrap with `%w` and context:
  `fmt.Errorf("compile regex %q: %w", pattern, err)`.
- **ERR-2 (MUST)** Use `errors.Is`/`errors.As` for control flow; no string
  matching.
- **ERR-3 (SHOULD)** Define sentinel errors in the package; document behavior.
- **ERR-4 (MUST)** Lowercase error strings, no trailing punctuation.
- **ERR-5 (MUST)** Never silently ignore errors.
- **ERR-6 (MUST)** Fail fast with descriptive messages.

---

## 6 — Concurrency

- **CC-1 (MUST)** The **sender** closes channels; receivers never close.
- **CC-2 (MUST)** Tie goroutine lifetime to a `context.Context`; prevent leaks.
- **CC-3 (MUST)** Protect shared state with `sync.Mutex`/`atomic`; no "probably
  safe" races. `global_counter` must use `atomic` operations.
- **CC-4 (SHOULD)** Use `errgroup` for fan-out work; cancel on first error.
- **CC-5 (CAN)** Prefer buffered channels only with rationale
  (throughput/back-pressure).

---

## 7 — Contexts

- **CTX-1 (MUST)** If a function takes `ctx context.Context` it must be the
  first parameter; never store ctx in structs.
- **CTX-2 (MUST)** Propagate non-nil `ctx`; honor `Done`/deadlines/timeouts.

---

## 8 — Testing

### Requirements

- **T-1 (MUST)** All tests must pass before committing. Run `go test ./...`,
  `go vet ./...`, and `golangci-lint run`.
- **T-2 (MUST)** Table-driven tests with descriptive subtest names as the
  default pattern.
- **T-3 (MUST)** Run `-race` in CI; add `t.Cleanup` for teardown.
- **T-4 (SHOULD)** Mark safe tests with `t.Parallel()`.
- **T-5 (SHOULD)** Tests use stdlib `testing` only (no testify/gomock).

```sh
go test ./...          # Run all tests
go build ./...         # Verify compilation
go vet ./...           # Static analysis
golangci-lint run      # Lint (errcheck, unused, staticcheck, etc.)
```

### Test style

- One assertion per logical check — don't bundle unrelated assertions.
- Test names describe the scenario: `TestFindKeys_CancelsOnContextDone`, not
  `TestFindKeys2`.
- Context-based timeouts for async tests.

### Edge cases

- **T-6 (SHOULD)** Tests should cover: invalid regex patterns, context
  cancellation mid-generation, concurrent counter access, TTY vs non-TTY
  output, fingerprint vs public key matching modes.

### Ralph Loop — iterative test hardening

Invoke `/ralph` for comprehensive test validation. Full protocol in
`.claude/skills/ralph/SKILL.md`.

---

## 9 — Logging & Observability

- **OBS-1 (MUST)** Diagnostic output to stderr; data output to stdout.
- **OBS-2 (SHOULD)** Structured logging for JSON modes.

---

## 10 — Performance

- **PERF-1 (MUST)** Measure before optimizing: `pprof`, `go test -bench`,
  `benchstat`.
- **PERF-2 (SHOULD)** Avoid allocations on hot paths (key generation loop).
  Defer expensive operations (PEM encoding) until match.
- **PERF-3 (CAN)** Add microbenchmarks for key generation throughput.

---

## 11 — Configuration

- **CFG-1 (MUST)** Config via flags; validate on startup; fail fast.
- **CFG-2 (SHOULD)** Provide sane defaults and clear help text.

---

## 12 — APIs & Boundaries

- **API-1 (MUST)** Document exported items: `// Foo does …`; keep exported
  surface minimal.
- **API-2 (MUST)** Accept interfaces where variation is needed; **return
  concrete types** unless abstraction is required.
- **API-3 (SHOULD)** Keep functions small, orthogonal, and composable.

---

## 13 — Security

- **SEC-1 (MUST)** Never log private keys in plaintext outside explicit output.
- **SEC-2 (MUST)** Generated key files use correct permissions (`0600` private,
  `0644` public).
- **SEC-3 (SHOULD)** Use `crypto/rand` exclusively for key generation.
- **SEC-4 (CAN)** Add fuzz tests for regex/input parsing.

---

## 14 — CLI Output

- **CLI-1 (MUST)** Stdout is for data, stderr is for everything else. Keys,
  JSON stats — anything a user might pipe goes to stdout. Status bar, progress,
  warnings go to stderr.
- **CLI-2 (MUST)** JSON output is valid JSON; no mixed text/JSON. No log lines
  on stdout when JSON mode is used.
- **CLI-3 (MUST)** Exit codes: `0` = success, `1` = error.

---

## 15 — Changelog

This project maintains a `CHANGELOG.md` following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

- **CL-1 (MUST)** Every commit that changes behavior, fixes a bug, or adds a
  feature must add a line to the `## [Unreleased]` section of `CHANGELOG.md`.
  Internal-only changes (CI config, CLAUDE.md, test-only) do not require an
  entry unless they are notable. **When in doubt, add an entry** — a commit
  that touches production code (not just tests) always needs one.
- **CL-1a (MUST)** Verify the changelog is updated **before** running
  `git commit`. Do not defer changelog updates to a follow-up commit.
- **CL-2 (MUST)** Use the correct subsection: `Added` (new features), `Changed`
  (behavior changes), `Fixed` (bug fixes), `Removed` (removed features),
  `Deprecated` (soon-to-be-removed), `Security` (vulnerability fixes), `Tests`
  (test-only improvements).
- **CL-3 (MUST)** Write entries from the user's perspective — describe what
  changed, not how the code changed. Prefer "Add `--foo` flag" over "Add
  fooFlag variable to root.go".
- **CL-4 (SHOULD)** Update changelog before committing, not after.

### Entry format

```markdown
## [Unreleased]

### Added

- Add `--foo` flag to control bar behavior

### Fixed

- Fix nil panic when regex pattern is empty
```

### Release workflow

```markdown
## [Unreleased]

## [0.2.0] - 2026-02-16

### Added
...
```

---

## 16 — Git, CI & Pre-commit

### Branch protection

Main branch is protected. All code reaches `main` via pull request only.

- **GIT-1 (MUST)** No direct pushes to `main`. All changes go through PRs.
- **GIT-2 (MUST)** CI status checks must pass before merging.

### Branch naming

Branches follow `type/description` format using kebab-case descriptions.

- **GIT-3 (MUST)** Branch names must match:
  `(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)/<description>`.

Examples: `feat/json-output`, `fix/race-condition`, `ci/add-govulncheck`.

### Conventional Commits

PR titles **and** commit messages must follow
[Conventional Commits](https://www.conventionalcommits.org/) format.

- **GIT-4 (MUST)** Format: `type: description` or `type(scope): description`.
- **GIT-5 (MUST)** Valid types: `feat`, `fix`, `docs`, `style`, `refactor`,
  `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- **GIT-6 (MUST)** Commit messages explain "why", not "what". The diff shows
  what changed.

Examples: `feat: add fingerprint matching mode`,
`fix(keygen): prevent counter race`, `ci: add govulncheck`.

### CI checks

Every PR runs parallel checks via reusable workflows
(`.github/workflows/ci.yml`):

| Check | What it validates |
|---|---|
| PR Conventions | PR title, branch name, commit messages, verified commits |
| Go CI | `go build`, `go vet`, goimports, `go test -race -count=1 ./...` |
| Lint | golangci-lint (errcheck, staticcheck, unused, etc.), govulncheck, markdownlint |
| CI | Gate — fails if any above failed |

- **CI-1 (MUST)** All checks must pass before merging. The `ci-ok` gate job
  aggregates results.
- **CI-2 (SHOULD)** Reproducible builds with `-trimpath`; embed version via
  `-ldflags "-X main.version=$TAG"`.

### Pre-commit

Install [pre-commit](https://pre-commit.com/) and set up the hooks:

```sh
brew install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit run --all-files  # Manual run against all files
```

Configured hooks: `no-commit-to-branch`, `branch-name`, `commit-message`
(commit-msg stage), `goimports`, `go-vet`, `go-build`, `go-test`,
`markdownlint`.

### Tooling gates

- **G-1 (MUST)** `go vet ./...` passes.
- **G-2 (MUST)** `go test -race ./...` passes.
- **G-3 (MUST)** `golangci-lint run` passes with default linters.
- **G-4 (MUST)** `go build -trimpath ./...` succeeds.

---

## 17 — Build & Release

```sh
make build   # go build -trimpath ./...
make test    # go test -race ./...
make vet     # go vet ./...
make clean   # rm -f vanityssh-go
```

Releases are automated via GoReleaser on `v*` tags:

- **Platforms**: darwin/linux/windows (amd64/arm64)
- **Formats**: tar.gz (Unix), zip (Windows), deb (Linux)
- **Flags**: `-s -w -trimpath -X main.version={{.Version}}`
- **Homebrew**: `brew install sensiblebit/tap/vanityssh`

---

## 18 — Key Design Decisions

- **Worker pool uses `errgroup`.** N goroutines generate keys in tight loops;
  first match cancels the context (unless `--continuous`).
- **Hot-path optimization is critical.** Pre-allocated buffers, wire format
  caching, and batched atomic counter flushes (every 1024 keys) minimize
  overhead in the generation loop.
- **PEM encoding is deferred.** Expensive serialization
  (`ssh.MarshalPrivateKey`) only happens after a regex match — never in the
  hot loop.
- **Display uses ANSI scroll regions.** Persistent status bar on the last
  terminal line; regular output scrolls above it. Falls back to stderr when
  not a TTY.
- **No library surface.** This is a CLI tool only. Packages are internal to
  the binary; exported symbols exist for inter-package use, not public API.

---

## 19 — Writing Functions

1. Can you read the function and honestly follow what it's doing? If yes, stop.
2. Does it have high cyclomatic complexity? If so, simplify.
3. Are there data structures or algorithms that would make it clearer?
4. Does it have hidden untested dependencies that could be arguments instead?
5. Brainstorm 3 better function names — is the current one best and consistent
   with the codebase?
