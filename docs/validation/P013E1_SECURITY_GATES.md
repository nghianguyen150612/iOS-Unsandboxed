# P013E-1 security audit gates

Baseline branch: `feat/p013-authenticated-provenance`

Baseline SHA: `cbd015e3b5b292013e449d26e04a8d9993f84d31`

Existing PR: [#13](https://github.com/nghianguyen150612/iOS-Unsandboxed/pull/13)

Audit date: 2026-10-31

## Local evidence

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --locked --workspace` | PASS: 49 library and 83 CLI tests |
| C17 readdir-fault reproduction before fix | FAILS as expected: the old scanner returned success after injected `EIO` |
| C17 readdir regression after fix | PASS: real publisher scanner rejects the partial scan |
| `make p013-security-test` | PASS |
| `make builder-production-test` | PASS; production helper excludes the test entrypoint/flags |
| `make builder-sanitizer-test` | PASS; ASan/UBSan recovery and lifecycle suites |
| `make test` | PASS |
| `git diff --check` | PASS after final edits |

The focused builder suites include 81 deterministic process interruptions and
IO/adversarial filesystem fixtures. Rust and C17 host tests use temporary
fixture roots; no production or physical-device trust store was touched.

## Hosted qualification

The audit increment adds `make p013-security-test` to Linux CI. Hosted Linux
and Apple ARM64 results are checked against the final pushed SHA as part of
delivery. Apple CI cross-compiles and inspects the iOS
12.0+ ARM64 CLI, daemon and installer helper, then checks package integrity and
reproducibility. It does not run the Linux-only host fault-injection suites.
No Apple runtime or physical-device execution result is implied.

Final audit SHA and run URLs are reported in the P013E-1 delivery result and
can be cross-checked against PR #13's status checks; local results in this file
are not substitutes for hosted qualification.

## Status that remains independent of these gates

```text
Independent builder identity: UNVERIFIED
Build origin: BUILD_ORIGIN_UNVERIFIED
Protected origin: UNKNOWN
Rollback protection: UNVERIFIED
Amethyst runtime: UNVERIFIED
Launch boundary: NOT_IMPLEMENTED
Execution activation: DISABLED
Operational authorization: FALSE
Device validation: NOT RUN
```

Passing this offline audit increment does not make overall P013 complete.
