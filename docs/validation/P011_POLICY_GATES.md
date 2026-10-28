# P011 policy validation gates

`make policy-test` runs isolated manager fixtures against the test-only helper, including strict store parsing, safe registration, dry-run and confirmation, simulated previews, lock contention, interrupted replacement, upgrade/rollback and uninstall preservation. Fixtures use the calling host UID/GID and make no runtime claims. `make test` also runs the existing Rust, P003, P005, IPC, P007, P008, P009, P010, package and device-harness regressions. Strict C17 compilation uses warnings as errors.

Linux host commands and CI results are recorded in the P011 implementation manifest and PR. The macOS CI job builds real Apple ARM64 iOS 12.0+ CLI, daemon and installer helper, inspects Mach-O and signing status, and verifies deterministic rootful packaging and dependencies. It never substitutes Linux binaries. Local Apple builds require Xcode/iPhoneOS SDK and cannot be established by Linux results.

All physical device gates are **NOT RUN**: root:wheel and filesystem crash semantics, installed Amethyst provenance, active hooks, launchd behavior, signature acceptance, SSH safety, and runtime launch or sandbox behavior on iPad4,4 / iOS 12.5.7. No operational unsandboxing is claimed.
