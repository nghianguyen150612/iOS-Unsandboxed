# P013D-2B-3 persistence gates

Baseline: `feat/p013-authenticated-provenance`,
`43ac3d3adbf37eb8a31454beb1e9e3312a117316`; existing Draft PR #13.
Physical-device validation: **NOT RUN**. Overall P013 remains **PARTIAL** until
independent builder identity and authoritative protected-origin gates exist.

## Implemented qualification

- C17 helper platform/install/explicit-confirmation gates and P007 lock.
- In-process Rust static library with versioned C ABI; exact shared canonical
  schemas/parser/planner, strict canonical Ed25519 public keys and derived IDs.
- Five explicit mutations; no automatic signer/policy enrollment or reactivation.
- Bounded descriptor-relative stage/journal/marker writes; forward-only recovery,
  old-record reconciliation, private ownership/modes and safe cleanup.
- Production provider rejects all pending artifacts and absent combined marker.
- Package/publisher conflict guards; upgrade/rollback/uninstall preserve history.
- Deterministic process termination in separate manager/recovery processes;
  exact final canonical bytes, generations and marker digests checked.
- IO failures, symlinks/hardlinks, foreign names, mode/owner/group checks, corrupt
  stores/stages/journals/markers, missing stage, stale live generation/digest,
  concurrent managers and shared package/publisher lock fixtures.
- Initial combined enrollment plus independently constructed existing two-store
  revocation; roots-first, policies-first and both-replaced recovery fixtures.
- C ABI fixture checks foreign UID/GID without requiring host chown privilege.
- Production build verifies no test entrypoint and rejects host override flags.
- C17 ASan/UBSan helper recovery/lifecycle runs; Rust static objects use ordinary
  checked Rust builds, not compiler sanitizer instrumentation.

## Required commands

```
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build
make builder-trust-test builder-transaction-test builder-mutation-test
make builder-persistence-test builder-recovery-test builder-lifecycle-test
make builder-production-test builder-sanitizer-test
make trust-manager-test trust-recovery-test installer-test
make authenticated-binding-test build-attestation-test
make test
git diff --check
```

Linux CI executes the new suites and C sanitizer fixtures. Apple CI links the
same production Rust static library into the iOS 12.0 ARM64 helper, inspects
Mach-O/dependencies and privileged symbols, checks for absent test hooks, and
verifies rootful package contents, integrity and deterministic reproduction.
Actual CI conclusions must be checked on the final pushed SHA; this document
specifies gates and does not substitute for a successful workflow run.

Process interruption and injected errors do not establish power-loss behavior
on an iPad. Durability assumes truthful file/directory fsync and atomic local
rename. Local metadata does not defend against wholesale privileged history
replacement. Independent identity, protected origin and rollback protection
remain unverified; execution remains disabled. No device startup or package
installation on a physical iPad was attempted.

## Local Linux result (2026-10-31)

PASS: format, strict clippy (default and testing feature), 47 shared-library plus
81 CLI Rust test executions, all requested targeted make gates and full
`make test`. The builder suites pass 81 deterministic process interruptions,
including recovery-process interruptions, additional combined two-store states,
IO failures and adversarial filesystem fixtures. C17 ASan/UBSan recovery and
lifecycle suites pass. Production helper rejects test flags and has no test
entrypoint. A subsequent Darwin mode/vararg portability adjustment was checked
with format, clippy, Rust tests and all builder/production/sanitizer suites.

Remote Linux/Apple conclusions and package results are reported on PR #13 for
the pushed commit. This local result is not a claim of remote CI completion or
physical-device validation.
