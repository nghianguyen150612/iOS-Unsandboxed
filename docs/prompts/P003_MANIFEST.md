# P003 manifest — Amethyst compatibility preflight and execution policy

## Outcome

**P003: COMPLETE.** The host and Apple ARM64 CI jobs pass. The local Rust and Apple SDK commands were unavailable on this Linux execution host, so those gates were verified by the actual GitHub Actions results recorded below. P003 implements read-only platform/component diagnostics, a versioned C17 preflight result, and a deterministic in-memory eligibility policy with fail-closed defaults. It does not implement launch intervention, signing, trust-cache mutation, unsandboxing, activation, or installation.

The reference iPad was not available. No device compatibility or runtime claim is made. Host C fixtures are simulated policy evidence only.

## Verified repository baseline

- Repository: https://github.com/nghianguyen150612/iOS-Unsandboxed
- Fetched `origin/main`: `7776f536250023571791a8b224bc3d80b8466fc5`
- Checkout HEAD before edits: `7776f536250023571791a8b224bc3d80b8466fc5`
- P002 merge `7776f536250023571791a8b224bc3d80b8466fc5` is the baseline and is an ancestor of `origin/main`.
- Working tree before edits: clean.
- Work branch: `feat/p003-amethyst-preflight`, created from the verified baseline.
- P002 source commit: `46b7701182e1a8d0c7085ae3344d91f9393d6bbe`.
- Audited Amethyst source revision: `61ce86d7d3f00e5395f4d42bebda0e5dce04946a`.

The P002 findings were treated as constraints: Amethyst has no stable external ABI; hook coverage depends on injection; installed Amethyst provenance and SSH hook state are unknown; ordinary preparation skips missing or unparseable `LC_CODE_SIGNATURE`; private signing/trust results may be ignored; and AUTO unsandbox behavior is not the product's opt-in policy.

## Implemented files and behavior

- `native/include/iu_preflight.h`, `native/src/iu_preflight.c`: C17 ABI v1 result, explicit compatibility and error enums, platform and version facts, bounded text, fixed-width component metadata, rootful-path assessment, and project-path presence mask. Read-only probes use the audited candidate paths `/amethyst/launchd_hook.dylib` and `/usr/lib/base_hook.dylib`; they never execute or load them.
- `native/include/iu_policy.h`, `native/src/iu_policy.c`: explicit in-memory policy and target structures, descriptor-based read-only inspection, and deterministic evaluator. Default/malformed input denies. Directories are never auto-enabled.
- `cli/src/main.rs`: `iu doctor` reports platform, architecture, rootful path assessment, Amethyst component metadata, compatibility state, capability, remaining requirements, and device acceptance. It does not require root or resolve a daemon through `PATH`.
- `daemon/src/main.c`: `ios-unsandboxedd --probe` prints the native result and exits nonzero unless verified. Other daemon modes remain fail-safe and do not start services.
- `tests/native-preflight-test.c`: host fixture tests for compatibility classification and policy denials/eligibility.
- `Makefile`, `.github/workflows/ci.yml`, `tests/host-smoke.sh`: strict C17 build/test integration and diagnostic smoke checks.
- `README.md`, `native/README.md`, architecture docs, and this manifest describe current behavior and limits.

## Compatibility-state rules

The C classifier can return `UNSUPPORTED_PLATFORM`, `VERSION_MISMATCH`, `COMPONENT_MISSING`, `INTERNAL_ERROR`, or `UNVERIFIED`. When all observed platform facts and both component files match, it still returns `UNVERIFIED` because no installed Amethyst binary provenance or live hook verification exists. `SUPPORTED_AND_VERIFIED` is reserved for future trustworthy evidence and is not emitted by P003. A Linux host is reported as unsupported, not as an iPad.

The policy permits only a hypothetical `ALLOW_ELIGIBLE` when an explicit in-memory config is enabled, compatibility is verified, the canonical target is a regular executable in an explicitly configured safe directory, ownership and modes pass, no symlink/hard-link or protected-path rule applies, and descriptor/path identity facts agree. `ALLOW_ELIGIBLE` does not mean execution will work. A future launch gate remains blocked because P003 does not hold or revalidate the target descriptor through the actual launch.

## Validation results

| Gate | Result |
| --- | --- |
| `make native-test` | **PASS** — strict C17 fixture compile with `-Wall -Wextra -Wpedantic -Werror`; simulated compatibility and policy cases pass. |
| C17 daemon compilation | **PASS** — direct `cc -std=c17 -Wall -Wextra -Wpedantic -Werror` build with both native modules. |
| Daemon `--help` and `--version` | **PASS** — manually exercised. |
| Daemon `--probe` on this host | **PASS as a diagnostic** — reports Linux, missing device components, `UNSUPPORTED_PLATFORM`, `Device acceptance: NOT TESTED`, and exits 4 as required. |
| `cargo fmt --all -- --check` | Local: **BLOCKED** — `cargo: command not found` (exit 127). PR CI: **PASS**. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Local: **BLOCKED** — `cargo: command not found` (exit 127). PR CI: **PASS**. |
| `cargo test --locked --workspace` | Local: **BLOCKED** — `cargo: command not found` (exit 127). PR CI: **PASS**. |
| `make build` | Local: **BLOCKED** before compilation — Make cannot find Cargo (child exit 127). PR CI's `make test` host-build prerequisite: **PASS**. |
| `make test` and `make smoke-test` | Local: **BLOCKED** before host build for the same missing Cargo toolchain. PR CI: **PASS**, including Rust tests, C17 fixtures, and host CLI/daemon smoke checks. |
| `make build-ios` | Local: **BLOCKED** — this host is Linux and lacks Xcode/iPhoneOS SDK. Apple ARM64 CI: **PASS**. |
| GitHub Actions | **PASS** — PR run [39246475667](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/39246475667) completed successfully on source commit `228a1fa0aaddde0d274056c32ec51cfdc7b0eb81`; both Linux host validation and Apple ARM64 iOS cross-compilation passed. The matching push run [39246470352](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/39246470352) also passed. |
| Physical-device runtime gates | **NOT RUN** — no reference iPad was available. |

## Security boundary

The code adds no launch hook, Amethyst patch, private jailbreak-server request, dynamic code loading, kernel access, file mutation, service activation, signing, trust-cache insertion, or sandbox change. Preflight success is diagnostic only. The configured `enabled` field and directory metadata are test facts, not authenticated authorization; persistent production policy must be owned and verified by the future daemon.

## Device gates still NOT RUN

- Installed Amethyst binary provenance/revision and exact ABI compatibility.
- iOS 12.5.7 runtime compatibility, hook initialization, inheritance, and SSH launch interception.
- Native IPC, signing, trust-cache behavior, and per-process unsandbox policy.
- Fully unsigned Mach-O execution, installer lifecycle, enable/disable, rollback, and restart behavior.
- Device/jailbreak restart and SSH stability.

## P004 prerequisites

1. Obtain and verify the exact Amethyst build on the reference iPad; rerun the source/ABI audit if it differs from P002.
2. Establish trustworthy installed-build and live-hook evidence before any compatibility state can be verified.
3. Define authenticated project CLI-to-daemon IPC with peer credentials, root-only management verbs, and independently verified launch request identity. Do not reuse Amethyst's private protocol as public product IPC.
4. Have the future daemon own persistent enabled state and configured directories; never accept a caller-supplied `enabled=true` as production authorization.
5. Preserve/revalidate the target file identity through any eventual launch boundary and separately review all Amethyst-owned hook changes.
6. Complete the host and Apple cross-compilation gates, then run each device gate above before making runtime claims.

P003 stops at diagnostics and policy. P004 and launch-hook work have not started.
