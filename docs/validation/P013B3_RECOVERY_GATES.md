# P013B-3 recovery gates

## Offline implementation

- C17 canonical transaction and generation-anchor parsers with SHA-256 digest binding: implemented.
- Durable stage, journal, rename, verification, and cleanup sequence: implemented.
- Read-only classification and privileged `trust recover --apply --confirm`: implemented.
- Rust verifier rejection of transaction journals and staged artifacts: implemented with unit fixtures.
- Package mutation blocking and trust-metadata preservation across rollback/uninstall: implemented.
- Persistent local generation/digest marker detects later store rollback or same-generation byte changes while retained.
- Interruption, corruption, generation, foreign-file, revocation, rotation, and lock fixtures: added to `make trust-recovery-test` and `make test`.
- Operational authorization: remains false; execution activation remains disabled.

## Required host gates

Run `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace`, `make build`, `make trust-format-test`, `make trust-manager-test`, `make trust-recovery-test`, and `make test`. CI runs the recovery fixture directly and again through the full test target.

## Apple and device gates

Apple ARM64 CI cross-compiles the installer helper and Rust CLI for iOS 12.0+, inspects Mach-O architecture and linker dependencies, validates rootful package contents and reproducibility, and reports signing status. This is compile-time evidence only. Physical-device validation remains **NOT RUN**.

The local generation is not an external monotonic anchor. See [trust rollback semantics](../architecture/trust-rollback-semantics.md). P013C authenticated P012 provider integration remains a separate prerequisite and is not part of this increment.
