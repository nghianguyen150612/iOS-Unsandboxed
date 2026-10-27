# P006 manifest — iOS device runtime qualification and Amethyst provenance

## Outcome

**P006: PARTIAL.** The bounded qualification harness, host fixtures, source audit, and documentation are reviewable. Physical iPad mini 2 qualification is **NOT RUN** because no reference-device session or credentials were available. Do not mark device gates PASS from source inspection, host tests, or cross-compilation.

## Baseline and Git workflow

- Repository: https://github.com/nghianguyen150612/iOS-Unsandboxed
- Fetched `origin/main` before edits. Verified current main SHA: `5e0229e9221b9eec909c1ae72c2ecc01e5abdb86`.
- Verified P005 implementation commit `5d66afaa2371e2d7c5e783680fb37bbd8a59b0f3` is an ancestor of `origin/main`.
- The freshly cloned target repository was clean before edits. The unrelated `/workspace/Synveil` worktree was left untouched.
- Created branch `feat/p006-device-runtime-qualification` from the verified main commit.
- P006 is limited to the requested project repository. No Amethyst source or device file was modified.

## Harness and safety behavior

- `tests/device/ios-runtime-qualification.sh` defaults to read-only inventory; it detects missing tools, records hardware/OS/kernel and numeric identity facts, inspects the requested rootful paths and two Amethyst candidates, and hashes regular candidate binaries when SHA-256 tooling is available.
- Environment values that could contain private data are omitted. The script does not collect passwords, SSH keys, authentication tokens, general process lists, or unrelated package inventories.
- `--root DIR` provides an isolated host filesystem fixture mode and is clearly labeled as non-device evidence.
- `--runtime-test` is opt-in and requires explicit CLI and daemon paths. It creates a fresh mode-0700 project-named temporary directory, tests only `--test-socket`, checks read-only IPC and peer UID/GID, sends SIGTERM, and removes only its own temporary directory. It does not use production `--serve`, supply a state path, or invoke management operations.
- SSH continuity and both root/non-root cases require separate existing SSH sessions and remain manual device checks.
- `tests/device/inspect-ios-build.sh` records Apple ARM64 build hashes, Mach-O headers, deployment/load commands, dependencies, and code-signing display/host validation. It never signs or deploys a binary.
- `make test` includes a fixture-only host test; ordinary CI does not require a physical iPad.

## Amethyst source audit and provenance

Inspected upstream revision `61ce86d7d3f00e5395f4d42bebda0e5dce04946a` read-only.

- `launchd_hook/Makefile` and `base_hook/Makefile` build arm64/arm64e dynamic libraries for iOS 12+ and invoke `ldid -S` after stripping.
- Upstream `basebins/Makefile` stages `launchd_hook.dylib` at `amethyst/launchd_hook.dylib` and `base_hook.dylib` at `usr/lib/base_hook.dylib`.
- The source package control file reports `com.staturnz.tnsv2-updater`, version `1.1`, architecture `iphoneos-arm`.
- No device component or package database was inspected. No installed binary hash was compared against an upstream artifact. A matching package version or filename cannot establish source revision or live injection. Installed-build provenance remains `UNVERIFIED`.
- Source build use of `ldid -S` does not by itself establish installed signature validity, Amethyst trust, sandbox exemption, or successful device startup.

## Preflight, IPC, and launchd findings

- Existing source classification preserves `UNVERIFIED` where provenance/live hook state is absent; no C, IPC protocol, state schema, or default-disabled behavior change was needed.
- P004 GET_STATUS wire payload, P005 state schema v1, authenticated IPC behavior, root-only management boundary, and safe daemon shutdown are unchanged.
- The existing `0600` production socket fits root-capable SSH operation; ordinary non-root access is expected to be denied. No mode change was made.
- The passive LaunchDaemon template remains `root:wheel`, `RunAtLoad=true`, `KeepAlive=false`; host plist validation does not prove iOS launchd acceptance. The project job was not loaded or activated.
- No launch interception, signing bypass, trust-cache change, process unsandboxing, kernel patch, installer, state writer, or operational enable/disable command was added.

## Validation

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --locked --workspace` | PASS — 11 unit tests |
| `make build` | PASS |
| `make test` | PASS — includes native/state, IPC, packaging, host smoke, and host fixture checks |
| `make native-test`, `make ipc-test`, `make packaging-test`, `make smoke-test` | PASS — each ran under `make test` |
| `make device-harness-test` | PASS — host-only path fixtures; explicitly not device simulation |
| Local `make build-ios` | BLOCKED — runner is Linux without macOS/Xcode/iPhoneOS SDK |
| PR macOS Apple ARM64 cross-build and Mach-O inspection | PASS — [Actions run 40507338074](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/40507338074), source commit `e119ea0e28b33fe005a6f492540ada9d273ce364` |
| Physical reference iPad runtime matrix | NOT RUN |

Rust tooling was available under `/home/agent/.cargo/bin` and was put on `PATH` for validation. No toolchain/dependency files were changed.

CI reported both outputs as Mach-O 64-bit ARM64 executables with `LC_BUILD_VERSION` minimum iOS 12.0 and `/usr/lib/dyld` as the dynamic loader. Both depend on `/usr/lib/libSystem.B.dylib`. CLI SHA-256: `28c59aa5a090e33ccdf35fc221664ff9b5026c873d20f606c8156bc1edf8d39b`; daemon SHA-256: `ec6559d228b4c8733748dd6ce0ee7c8e9c0237f0c41dfc8f80508c3682b45f70`. On the macOS runner, `codesign -dv` and `codesign --verify --strict` returned 1 with “code object is not signed at all” for both. No signing was performed. Actual iOS startup and whether signing or Amethyst trust preparation is needed remain NOT RUN.

## Physical-device gates

All actual device gates remain **NOT RUN**: A1489/A7/iOS product/build identification; CLI/daemon startup and `--probe`; dynamic loader/dependency behavior; installed Amethyst file metadata/hash/package/build provenance; Procursus/rootful paths and root/wheel ownership; native Darwin `getpeereid`; root and non-root test-socket IPC; production socket access model; preflight output; SIGTERM cleanup; unexpected temporary files; SSH continuity; installed plist/path state; iOS launchd behavior; and reboot/jailbreak-environment recovery.

The exact required procedures and result fields are in [ios-device-ipc-qualification.md](../validation/ios-device-ipc-qualification.md). Current results are in [P006_DEVICE_RESULTS.md](../validation/P006_DEVICE_RESULTS.md). No device command, device timestamp, device OS build, or device binary hash has been invented.

## P007 readiness

P007 is not ready to start. Complete and review all device rows, retain the independent SSH recovery path, establish installed Amethyst provenance or keep compatibility `UNVERIFIED`, and verify launchd without activating the job before proposing integration. Execution remains disabled.

## Git follow-through

- Branch: `feat/p006-device-runtime-qualification`.
- Logical commit: recorded in the final task report after commit.
- Pull request: [#6](https://github.com/nghianguyen150612/iOS-Unsandboxed/pull/6) against `main`; do not merge.
