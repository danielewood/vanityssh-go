# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-16

### Added

- Cobra CLI rewrite with `--fingerprint`, `--continuous`, `--jobs` flags
- Context-based goroutine lifecycle with `errgroup` for clean shutdown
- `keygen.Result` type — `FindKeys` is now a pure worker sending results via channel
- Error handling for all key generation operations (no silent suppression)
- Pinned terminal status bar with scroll region for TTY output
- SHA256 fingerprint display on match
- Homebrew tap via GoReleaser (`brew install sensiblebit/tap/vanityssh`)
- GoReleaser-based release automation (darwin/linux/windows, amd64/arm64)
- CI pipeline with reusable workflows (go-ci, pr-conventions, lint)
- Pre-commit hooks (branch naming, commit messages, go-vet, go-build, go-test)
- Dependabot for GitHub Actions and Go module updates
- Makefile with build, test, vet targets
- Export `ErrNilRegex` sentinel error for programmatic nil-regex detection
  via `errors.Is`
- CHANGELOG.md

### Fixed

- Fix data race on `isTTY` flag by converting to `atomic.Bool`
- Fix `Reset()` writing to stderr without holding the display mutex
- Fix `UpdateStatusBar` writing ANSI escapes in non-TTY environments
- Fix `FormatCount` for negative numbers and `math.MinInt64` overflow
- Clamp terminal height to minimum 3 to prevent invalid ANSI sequences
- Reject negative `--jobs` values that caused the program to hang
- Return `ErrNilRegex` from `FindKeys` instead of panicking on nil regex
- Fix `OverrideTTY` data race on `termHeight` (CC-3: missing mutex)
- Fix `--continuous` in TTY mode silently discarding matched keys

### Changed

- Default branch renamed from `master` to `main`
- Deferred PEM encoding until match found (performance optimization)
- Hot loop uses pre-allocated buffers and batched atomic counters
- Replaced `ioutil.WriteFile` with `os.WriteFile`

### Removed

- Seven external dependencies ejected during Cobra rewrite
- Old CI workflows (build-go.yml, create-release-tag.yaml, release-artefacts.yaml)
- `build-cmds.txt` (replaced by Makefile)

### Tests

- Add `cmd` test suite: CLI validation, `handleResult` file writing and
  permissions, TTY/non-TTY output paths, write-error propagation, flag
  wiring, end-to-end pipeline
- Add `display` TTY-mode tests, concurrency stress tests, and edge cases
- Add `keygen` tests: cancellation, blocked-send, selective regex, concurrent
  workers, hot-path/slow-path equivalence, fingerprint-mode isolation
