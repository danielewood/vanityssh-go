# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Structured JSON output (`--json`, `--morejson`) with colorized formatting
- CPU stats reporting (user/system/idle percentages)
- CPU info display via cpuid
- Benchmark mode (`--benchmark`) for key generation performance testing
- Configurable thread count (`--threads`)
- Process priority control (`--no-nice`, defaults to idle priority)
- Update rate control (`--update-rate`)
- SHA256 fingerprint display on match
- GoReleaser-based release automation (darwin/linux/windows, amd64/arm64)
- CI pipeline with reusable workflows (go-ci, pr-conventions, lint)
- Claude Code and Claude Code Review integrations
- Pre-commit hooks (branch naming, commit messages, go-vet, go-build, go-test)
- Dependabot for GitHub Actions and Go module updates
- Makefile with build, test, vet targets
- CHANGELOG.md

### Changed

- Default branch renamed from `master` to `main`
- Deferred PEM encoding until match found (performance optimization)
- Replaced `ioutil.WriteFile` with `os.WriteFile`

### Removed

- Old CI workflows (build-go.yml, create-release-tag.yaml, release-artefacts.yaml)
- `build-cmds.txt` (replaced by Makefile)
