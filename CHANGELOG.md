# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Context-based goroutine lifecycle with `errgroup` for clean shutdown
- `keygen.Result` type — `FindKeys` is now a pure worker sending results via channel
- Error handling for all key generation operations (no silent suppression)
- Test suite for `display` (FormatCount, IsTTY) and `keygen` (helpers + FindKeys)
- Homebrew tap via GoReleaser (`brew install sensiblebit/tap/vanityssh`)
- Cobra CLI rewrite with `--fingerprint`, `--continuous`, `--jobs` flags
- Pinned terminal status bar with scroll region for TTY output
- SHA256 fingerprint display on match
- GoReleaser-based release automation (darwin/linux/windows, amd64/arm64)
- CI pipeline with reusable workflows (go-ci, pr-conventions, lint)
- Pre-commit hooks (branch naming, commit messages, go-vet, go-build, go-test)
- Dependabot for GitHub Actions and Go module updates
- Makefile with build, test, vet targets
- CHANGELOG.md

### Changed

- Default branch renamed from `master` to `main`
- Deferred PEM encoding until match found (performance optimization)
- Hot loop uses pre-allocated buffers and batched atomic counters
- Replaced `ioutil.WriteFile` with `os.WriteFile`

### Removed

- Seven external dependencies ejected during Cobra rewrite
- Old CI workflows (build-go.yml, create-release-tag.yaml, release-artefacts.yaml)
- `build-cmds.txt` (replaced by Makefile)
