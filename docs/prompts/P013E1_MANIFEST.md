# P013E-1 manifest

## Objective

Audit the implemented P013 publisher, descriptor-binding, DSSE/build-attestation,
builder-trust, privileged persistence, recovery, installer lifecycle, and ARM64
packaging boundaries. Reproduce and repair confirmed issues, add regression
coverage, and record verifiable offline readiness evidence.

## Baseline and delivery

- Branch: `feat/p013-authenticated-provenance`
- Starting SHA: `cbd015e3b5b292013e449d26e04a8d9993f84d31`
- Existing PR: https://github.com/nghianguyen150612/iOS-Unsandboxed/pull/13
- Requested scope: P013E-1 only; do not merge; do not start P014.

## Finding

`SEC-P013E1-001` reproduced that POSIX `readdir()` errors could be treated as
normal end-of-directory in publisher/builder trust enumeration and installer
cross-transaction/cleanup scans. Before correction, the C harness returned
success after injected `EIO`; after correction, scans fail closed. Severity is
moderate, with no identified unprivileged trigger under the private-directory
ownership requirements. Full reproduction, impact, fix and validation are in
`docs/security/P013_TRUST_BOUNDARY_AUDIT.md`.

## Regression and validation entrypoints

- `tests/trust/readdir-error-test.c` — fault-injected real publisher scanner.
- `cli/src/directory_scan.rs` — Rust EOF/error classification tests.
- `make p013-security-test` — new scanner regression plus existing P013 trust,
  persistence, recovery, lifecycle, authentication and attestation suites.
- `make test`, strict clippy/formatting, production-helper symbol checks, and
  ASan/UBSan recovery/lifecycle tests.

## Preserved security limits

No automatic trust anchors, arbitrary execution, sandbox or AMFI bypass,
kernel changes, trust-cache insertion, or private Amethyst XPC are introduced.
Builder identity and protected origin remain unverified/unknown, rollback
protection remains unverified, launch boundary is unimplemented, execution is
disabled, operational authorization is false, and device validation is not
run. See the threat model and security gates for assumptions and residual risk.
