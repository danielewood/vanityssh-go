---
name: ralph
description: Iterative test hardening protocol. Adversarial review of tests, fix gaps, loop until clean.
disable-model-invocation: true
---

# Ralph Loop — Iterative Test Hardening Protocol

Use this whenever a feature, fix, or module needs comprehensive test validation.
The goal is **functional correctness, not line coverage vanity metrics**.

## Phase 1: Adversarial Review

- **RL-1 (MUST)** Spawn parallel sub-agents to review every test in the target
  package. Each reviewer is **hypercritical** — assume the tests are hiding
  bugs, not proving correctness.
- **RL-2 (MUST)** For each test, answer: *What specific behavior does this
  prove? What failure would it catch that no other test catches?* If you can't
  answer both, the test is suspect.
- **RL-3 (MUST)** Flag these categories explicitly:
  - **Missing edge cases** — refer to **T-6** for the baseline checklist, then
    go further. Think: boundary values, nil/zero inputs, concurrent access,
    empty regex, timeout/cancellation paths, invalid regex patterns.
  - **False confidence** — tests that pass for the wrong reason (e.g.,
    asserting no error without verifying the output, checking length but not
    content).
  - **Duplicates** — tests covering the same logical path. Consolidate into
    table-driven tests per **T-2**.
  - **Happy-path-only** — functions tested only with valid input. Every
    exported function needs at least one error-path test.

## Phase 2: Fix and Fill

- **RL-4 (MUST)** Fix every gap found in Phase 1. Don't batch — fix one
  category at a time, run `go test -race ./...` between each batch.
- **RL-5 (MUST)** Every test function must have a `// WHY:` comment on the
  first line of the test body explaining what specific behavior or regression
  it guards against. One sentence. If you can't write it, the test shouldn't
  exist.

  ```go
  func TestFindKeys_CancelsOnContextDone(t *testing.T) {
      // WHY: Verifies that workers exit promptly when the context is
      // cancelled — prevents goroutine leaks in normal operation.
      t.Parallel()
      // ...
  }
  ```

- **RL-6 (MUST)** Evaluate overall coverage *qualitatively*: does the test
  suite prove the module works as advertised? Map tests to documented behaviors
  and exported API surface. Missing mappings are gaps.
- **RL-7 (SHOULD)** Add negative tests for concurrency-relevant paths: race
  conditions on shared counters, context cancellation during key generation,
  channel behavior under load.

## Phase 3: Loop

- **RL-8 (MUST)** Return to Phase 1 with the updated test suite. Loop until a
  full review pass surfaces **zero new findings**.
- **RL-9 (MUST)** Clear context between loop iterations to preserve context
  window runway. Summarize findings and fixes from the current pass before
  starting the next.
- **RL-10 (SHOULD)** Cap at 3 iterations for a single package. If issues
  persist after 3 passes, stop and document remaining gaps as TODOs with
  `// TODO(ralph):` tags.

## Anti-patterns (reject on sight)

- Tests that only assert `err == nil` with no output validation.
- `TestFoo1`, `TestFoo2` naming — use descriptive scenario names.
- Commented-out tests or `t.Skip()` without an issue reference.
- Tests that depend on execution order or global state.
- Catch-all tests that assert 10 unrelated things — split them.
- Tests that duplicate stdlib behavior (don't re-test `crypto/ed25519`).
