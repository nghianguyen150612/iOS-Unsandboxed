# P006 device qualification results

**P006 outcome: PARTIAL.** The bounded harness, source audit, and host validation are reviewable. Physical iPad runtime qualification is **NOT RUN** because no reference-device session, address, or credentials were available in this workspace. No device output, binary startup, Darwin `getpeereid`, root/non-root SSH, filesystem permission, production socket, SSH-continuity, or launchd result is claimed.

**Expected target profile:** iPad mini 2 Wi-Fi A1489, Apple A7 ARM64 (`hw.machine` expected `iPad4,4`), iOS 12.5.7. This is the requested profile, not an observed device. No device OS build, device timestamp, tested device binary hash, command exit status, or sanitized device output exists for this P006 run.

## Evidence rules

For physical-device rows, the exact tested device is `NOT AVAILABLE`, OS/build is `NOT OBSERVED`, tested binary SHA-256 is `N/A`, command/procedure is `NOT RUN`, exit status is `N/A`, sanitized output is `NONE`, and timestamp is `N/A`. Evidence source is the task workspace state: no reference-device session was provided. Limitations: source inspection, Linux tests, the qualification procedure, and a successful Apple cross-build cannot substitute for device evidence.

`BLOCKED` identifies a result that requires unavailable device access. `NOT RUN` means no device command or operation was performed. Source-review and host-test results appear in separate sections and never mark a device gate as passed.

## Physical-device evidence matrix

| Device gate | Result | Exact device / OS build / binary SHA-256 | Command, exit, sanitized output, timestamp | Evidence source and limitation |
|---|---|---|---|---|
| A1489 / Apple A7 / iOS 12.5.7 identity | NOT RUN | Device not available / OS build not observed / N/A | `sysctl -n hw.machine`, `sw_vers -productVersion`, `sysctl -n kern.osversion`, `uname -m`; no exit/output/time | No device session. Expected values are not observations. |
| Installed Amethyst candidate existence, type, owner, mode, size, and hashes | NOT RUN | Device not available / OS build not observed / N/A | Inventory harness not run on device; no output/time | `/amethyst/launchd_hook.dylib` and `/usr/lib/base_hook.dylib` were not inspected on the device. |
| Installed Amethyst package/build provenance | BLOCKED; preserve `UNVERIFIED` | Device not available / OS build not observed / N/A | Exact package query and candidate hash comparison not run; no exit/output/time | Upstream source facts cannot identify installed binary bytes. |
| CLI and daemon normal startup / `--probe` | NOT RUN | Device not available / OS build not observed / no device binary hashes | Explicit temporary-path `--version` and `--probe` commands not run; no exit/output/time | Linux build and iOS cross-compilation are not device startup evidence. |
| Device `iu doctor` / GET_PREFLIGHT compatibility state | NOT RUN | Device not available / OS build not observed / no device binary hashes | Device preflight commands and GET_PREFLIGHT response not run; no exit/output/time | Source and host fixtures show the intended decision rules; actual device facts remain unknown. |
| Mach-O loader and dynamic dependency behavior on iOS 12.5.7 | NOT RUN | Device not available / OS build not observed / no device binary hashes | No device launch or loader diagnostics; no exit/output/time | macOS `file`/`otool` output can assess binary metadata only. |
| Native Darwin `getpeereid` UID/GID | NOT RUN | Device not available / OS build not observed / N/A | Private-socket `check` not run; no exit/output/time | Linux `SO_PEERCRED` fixtures are separate host evidence. |
| Isolated test-socket PING, GET_STATUS, GET_PREFLIGHT, GET_LIFECYCLE_STATUS | NOT RUN | Device not available / OS build not observed / no device binary hashes | `--test-socket … check` not run; no exit/output/time | Host IPC tests cannot establish iOS socket behavior. |
| Peer credentials match root SSH identity | NOT RUN | Device not available / OS build not observed / N/A | Root SSH test not run; no exit/output/time | No root device session was supplied. |
| Peer credentials match a non-root SSH identity | NOT RUN | Device not available / OS build not observed / N/A | Non-root SSH test not run; no exit/output/time | No non-root device session was supplied. |
| Rootful paths, root/wheel IDs, state ownership/mode | NOT RUN | Device not available / OS build not observed / N/A | Read-only path and `id` inventory not run on device; no exit/output/time | Host filesystem fixtures do not establish the device layout. |
| Production `/var/run` and socket owner/mode; `0600` SSH model | NOT RUN | Device not available / OS build not observed / N/A | Production path inspection only was prescribed; none was run; no exit/output/time | No socket was created or permission changed. The intended `0600` contract grants pathname access only to root-capable SSH identities. |
| SIGTERM shutdown, socket cleanup, and no persistent temp files | NOT RUN | Device not available / OS build not observed / no device binary hashes | Temporary IPC runtime test not run; no exit/output/time | The host test checks Linux behavior only. |
| Unrelated SSH session and new SSH command remain usable | NOT RUN | Device not available / OS build not observed / N/A | No independent SSH continuity check; no exit/output/time | Must be verified manually on device during a later runtime session. |
| Installed plist syntax, executable/log path availability | NOT RUN | Device not available / OS build not observed / N/A | Device plist/path inventory not run; no exit/output/time | Host plist parsing is a separate packaging check. |
| iOS launchd accepts the job and starts/stops it | NOT RUN | Device not available / OS build not observed / N/A | No `launchctl` query and no load/bootstrap/kickstart; no exit/output/time | The job remains passive and was not activated. |
| Reboot and jailbreak-environment restart recovery | NOT RUN | Device not available / OS build not observed / N/A | No reboot or lifecycle operation; no exit/output/time | Separate future device gate. |

## Audited Amethyst source evidence

Source revision inspected read-only: [`61ce86d7d3f00e5395f4d42bebda0e5dce04946a`](https://github.com/staturnzz/amethyst/tree/61ce86d7d3f00e5395f4d42bebda0e5dce04946a), commit date 2026-10-11, subject `1.1`.

- `basebins/launchd_hook/Makefile` builds `launchd_hook.dylib` as a dynamic library for iOS 12+ and includes arm64 and arm64e. It strips symbols and invokes `ldid -S`.
- `basebins/base_hook/Makefile` builds `base_hook.dylib` as a dynamic library for iOS 12+ and includes arm64 and arm64e. It strips symbols and invokes `ldid -S`.
- `basebins/Makefile` stages the artifacts at `amethyst/launchd_hook.dylib` and `usr/lib/base_hook.dylib`.
- `basebins/resources/control` names package `com.staturnz.tnsv2-updater`, version `1.1`, architecture `iphoneos-arm`.

This confirms the audited source's output names, build configuration, and package metadata. It does not show that a device has those files or that its files match this source. No upstream build artifact was compared with a device hash. No Amethyst source was modified and no package or post-install script was run. Installed provenance remains `UNVERIFIED`.

## Host validation

Host validation ran on Linux x86_64 on 2026-10-27. These results do not qualify the iPad.

| Gate | Result | Evidence / limitation |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | Completed with exit 0. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | PASS | Completed with exit 0. |
| `cargo test --locked --workspace` | PASS | 11 unit tests passed. |
| `make build` | PASS | Rust host CLI and strict C17 daemon built. |
| `make native-test` and state fixtures | PASS | Executed by `make test`; preflight/policy, peer-auth, and persistent-state fixtures passed. |
| `make ipc-test` | PASS | Executed by `make test`; Linux `SO_PEERCRED`, protocol/lifecycle, and same-UID socket cases passed. |
| `make packaging-test` | PASS | Executed by `make test`; host `plistlib` syntax/field checks passed. This is not iOS launchd evidence. |
| `make device-harness-test` | PASS | Temporary fixture tree checked present-file, symlink, and missing-path reporting. It ran in explicit host-fixture mode and exercised no device path. |
| `make smoke-test` | PASS | Host read-only/fail-safe CLI and daemon smoke checks passed. |
| `make test` | PASS | Full host suite passed, including the new fixture-only harness test. |
| Local `make build-ios` | BLOCKED | This runner is Linux and lacks macOS, Xcode, and the iPhoneOS SDK; the Makefile stopped before building. |
| PR macOS `make build-ios` and Mach-O inspection | PASS | [Actions run 40507338074](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/40507338074), source commit `e119ea0e28b33fe005a6f492540ada9d273ce364`; observed output details follow. |

Rust tools were available under `/home/agent/.cargo/bin` and were placed on the command path for the requested checks. No toolchain or dependency files were changed.

## Apple ARM64 cross-build and binary inspection

The build target is `aarch64-apple-ios`; `Makefile` sets deployment target `12.0`, uses Xcode's iPhoneOS SDK and clang for the C17 daemon, and builds the Rust CLI with the Apple target. The CI workflow runs `make build-ios`, then `tests/device/inspect-ios-build.sh` over the CLI at `target/aarch64-apple-ios/release/ios-unsandboxed` and daemon at `build/ios/ios-unsandboxedd`.

The local Linux cross-build result is BLOCKED. The pull-request Actions run [40507338074](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/40507338074) passed host validation and the macOS ARM64 cross-build/inspection for source commit `e119ea0e28b33fe005a6f492540ada9d273ce364`. The read-only inspector reported:

| Build output | SHA-256 | Format and architecture | Minimum OS / loader metadata | Dynamic dependency | Code-sign result on macOS runner |
|---|---|---|---|---|---|
| `ios-unsandboxed` CLI | `28c59aa5a090e33ccdf35fc221664ff9b5026c873d20f606c8156bc1edf8d39b` | Mach-O 64-bit executable, ARM64, `MH_EXECUTE` | `LC_BUILD_VERSION`, iOS `minos 12.0`; `LC_LOAD_DYLINKER` `/usr/lib/dyld` | `/usr/lib/libSystem.B.dylib` | `codesign -dv` and `codesign --verify --strict` each returned 1: “code object is not signed at all.” |
| `ios-unsandboxedd` daemon | `ec6559d228b4c8733748dd6ce0ee7c8e9c0237f0c41dfc8f80508c3682b45f70` | Mach-O 64-bit executable, ARM64, `MH_EXECUTE` | `LC_BUILD_VERSION`, iOS `minos 12.0`; `LC_LOAD_DYLINKER` `/usr/lib/dyld` | `/usr/lib/libSystem.B.dylib` | `codesign -dv` and `codesign --verify --strict` each returned 1: “code object is not signed at all.” |

The build and inspection passed; code-sign validation did not pass because neither output is signed. The workflow does not sign or modify binaries. This establishes the CI artifacts' metadata only: iOS 12.5.7 loader acceptance, whether conventional signing or Amethyst trust preparation is required on the reference device, Amethyst trust, sandbox state, and successful startup remain NOT RUN. No signature/trust operation was attempted. A future ad-hoc signature, if used for a separate diagnostic bootstrap, must be recorded separately and is not proof of trust or startup.

## LaunchDaemon readiness and P007

Host plist syntax and declared fields pass. The template invokes the production daemon path as `root:wheel`, uses `RunAtLoad=true` and `KeepAlive=false`, and writes logs below `/var/log/ios-unsandboxed`. On-device path availability, plist acceptance by iOS 12.5.7 launchd, foreground start/stop, logging, restart behavior, and SSH impact are NOT RUN. No load/bootstrap/kickstart or production socket startup occurred.

P007 is not ready to start. Before proposing LaunchDaemon integration, complete and review the device identity, binary startup, installed Amethyst hashes/provenance, actual `getpeereid`, root/non-root SSH, filesystem and socket permissions, SIGTERM cleanup, SSH continuity, and passive launchd inspection rows above. Preserve an independent SSH recovery route. Keep the production socket `0600` unless a separately reviewed read-only access model is supported by real root/non-root authorization tests. Keep execution activation disabled; this qualification adds no launch interception, signing bypass, trust-cache changes, sandbox changes, or kernel patch.
