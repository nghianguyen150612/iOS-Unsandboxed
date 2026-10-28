# P007 implementation manifest

## Scope and baseline

P007 delivers the v0.1.0 rootful package builder and fixed-path project installer, including journaled install, upgrade, rollback, uninstall, and recovery. It preserves the P005 schema-v1 state record with `execution_activation=disabled`. The LaunchDaemon plist remains private and inactive; P007 adds no Amethyst integration, signing operation, trust-cache change, kernel operation, sandbox change, or user-binary installation feature.

Verified base: `a66e0838ddaeac42893f1008e3af969f83adcdb9` (P006 merge on `main`).

Feature branch: `feat/p007-rootful-installer`.

## Implementation record

- Package builder accepts only the actual ARM64 iOS CLI, daemon, and installer-helper builds. It validates Mach-O architecture, minimum iOS version, dependencies, plist fields, and records per-artifact signing status without changing signatures.
- Package output is an expanded directory and deterministic USTAR/GZip archive with fixed payload paths/modes, package metadata, and SHA-256 records.
- `packaging/rootful/manager.sh` is the management entrypoint; the paired C17 helper enforces the fixed ownership table, explicit `--apply`, production target checks, fixture-root isolation, package validation, persistent locking, private staging/backups, journaling, and disabled-state verification through the P005 reader.
- The install manifest accepts only the fixed project destinations and schema v1. The journal allows recovery after interrupted multi-directory replacement; the implementation does not claim a single atomic transaction across filesystems.
- `docs/architecture/rootful-installer.md`, `install-transactions.md`, `package-format.md`, and `upgrade-rollback.md` describe operations and limits.

## Validation record

The following were run successfully on the Linux host:

- `cargo fmt --all -- --check`
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
- `cargo test --locked --workspace`
- `make build`
- `make test`
- `make native-test`
- `make ipc-test`
- `make packaging-test`
- `make installer-test`
- `make device-harness-test`
- `make smoke-test`
- Installer fixtures include explicit outside-root sentinel, oversized metadata, malformed version, and blank-record checks.
- Python syntax compilation for the package builder and both package test scripts.
- `git diff --check`

`make package-rootful` was attempted on Linux and stopped at the explicit platform check because Xcode and the iPhoneOS SDK are unavailable. It does not substitute host binaries. The macOS workflow run for this branch is the authority for Apple ARM64 cross-compilation, package creation, package reproducibility/integrity, artifact signing metadata, and package upload; consult the CI check attached to the P007 pull request.

## Device evidence and next prompt

All physical-device gates remain **NOT RUN**. Host fixtures simulate ownership using the host UID/GID and do not verify root:wheel, iOS filesystem behavior, binary startup, signature acceptance, launchd, SSH recovery, Amethyst compatibility, or reboot behavior. P007 does not deploy to a device.

P008 may add controlled, explicitly authorized LaunchDaemon lifecycle management and service recovery using host mocks. It must build on the fixed project ownership manifest and disabled schema-v1 state, retain the independent SSH recovery route, and continue to defer physical certification until real device evidence is scheduled. It must not add operational unsandbox activation or patch Amethyst.
