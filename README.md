# iOS-Unsandboxed

**Version:** 0.1.0 · **License:** MIT

iOS-Unsandboxed is an experimental, SSH-oriented foundation for running compatible Mach-O ARM64 command-line programs on a rootful jailbroken iPad. It has no graphical interface. P001 established the project layout and rootful path contract. P003 adds read-only diagnostics and a side-effect-free native eligibility policy. P004 adds authenticated local CLI-to-daemon IPC. P005 adds a read-only disabled-state loader, richer lifecycle status, and a passive LaunchDaemon template. P007/P008 add a project-owned installer and controlled LaunchDaemon lifecycle. P009 adds a read-only, versioned Amethyst compatibility adapter and capability contracts. P010 adds local executable identity recording and a read-only preparation preview. No release enables the experimental execution engine, prepares user binaries, changes sandboxes, or activates launch interception.

## Scope and reference device

The only supported runtime target for v0.1 is the reference configuration below:

- iPad mini 2 Wi-Fi, model A1489
- Apple A7 ARM64
- iOS 12.5.7
- Amethyst jailbreak with Procursus bootstrap, rootful

Host compilation is useful for development checks only. A Linux or macOS build is not an iOS build, and an iOS cross-compile is not evidence that an executable runs on this iPad.

The long-term workflow is intended to look like:

```sh
sudo iu enable
chmod +x ./binary
./binary
```

That workflow is aspirational. `iu inspect PATH` performs local read-only inspection and records the file identity; it grants no launch permission. CLI operations such as `enable`, `disable`, signing, and user-binary installation still fail as unimplemented. The separate rootful project manager can install and maintain only this project's own package. Transparent preparation of signatures, entitlements, or jailbreak trust mechanisms is not implemented. Executables without `LC_CODE_SIGNATURE` are a critical future experiment; P010 reports preparation as not implemented and makes no claim that they can run. No kernel exploit or kernel patch is part of this project.

## Components

- `cli/`: Rust CLI named `ios-unsandboxed`; local `inspect` uses a small C17 FFI wrapper to keep parsing in the shared native planner.
- `daemon/`: strict C17 executable named `ios-unsandboxedd`; its foreground IPC server handles read-only status and preflight requests.
- `native/`: reusable C17 read-only preflight, deterministic execution-eligibility policy, versioned Amethyst adapter and capability classifier, bounded Mach-O inspector, executable identity planner, fail-closed persistent-state loader, and a fixed-path installer helper.
- `packaging/rootful/`: centralized path contract, disabled-state example, passive plist template, and manager entrypoint. The paired C17 helper handles package verification and filesystem transactions.
- `docs/architecture/`: component boundaries, target build requirements, security limits, and installation ownership.

The intended future flow and current boundaries are described in [the architecture overview](docs/architecture/overview.md), [the native preflight contract](docs/architecture/preflight-contract.md), [the execution eligibility policy](docs/architecture/execution-policy.md), [the Amethyst adapter ABI](docs/architecture/amethyst-adapter.md), [the capability contract](docs/architecture/amethyst-capability-contract.md), [the Mach-O inspection contract](docs/architecture/macho-inspection-contract.md), [executable identity](docs/architecture/executable-identity.md), [the launch preparation planner](docs/architecture/launch-preparation-planner.md), [the planner policy contract](docs/architecture/planner-policy-contract.md), [service lifecycle](docs/architecture/service-lifecycle.md), [persistent state](docs/architecture/persistent-state.md), and [recovery/rollback](docs/architecture/recovery-rollback.md).

P002 inspected Amethyst source at a pinned upstream revision. The audit found a source-level launch hook suitable for a narrowly opted-in experiment, but Amethyst's normal preparation path skips Mach-O files without LC_CODE_SIGNATURE. A lower-level F_ADDSIGS path can construct an in-memory signature when directly invoked, but acceptance and launch behavior for a completely unsigned ARM64 executable are unverified on the reference iPad. See the [source audit](docs/research/amethyst-source-audit.md), [launch-path matrix](docs/research/launch-path-matrix.md), [signing and trust-cache audit](docs/research/signing-trustcache-audit.md), [ABI contract](docs/architecture/amethyst-abi-contract.md), and [unsigned Mach-O assessment](docs/architecture/unsigned-macho-feasibility.md). P002 did not implement or activate any of these mechanisms.

## Prerequisites

For host builds and C17 fixture tests:

- Rust stable with Cargo (minimum Rust 1.74)
- A C17 compiler (`cc`, Clang, or GCC) with strict warning support
- `make`
- Python 3 for packaging and host integration fixtures

For the separate Apple ARM64 iOS build, use macOS with Xcode command line tools, the iPhoneOS SDK, stable Rust, and the `aarch64-apple-ios` Rust target. Rust links with that target and `xcrun` supplies the iPhoneOS SDK to Clang for the C17 daemon and installer helper; the deployment target is iOS 12.0. No developer-specific SDK paths are assumed. The Makefile reports a clear error when the Apple toolchain or SDK is unavailable. The build remains unsigned unless the artifacts already have a signature; P007 records that status without changing it.

## Build and validation

```sh
make help
make build       # host CLI and host diagnostic daemon
make test        # Rust, native, planner, IPC, packaging, installer fixtures, and host smoke checks
make adapter-test # Amethyst adapter, capability, evidence, and Mach-O fixtures
make planner-test # executable identity, parser corpus, policy, and revalidation fixtures
make native-test # isolated C17 preflight, policy, and peer-auth fixtures
make state-test  # persistent-state format and safety fixtures
make ipc-test    # temporary-socket protocol and lifecycle tests
make packaging-test # passive LaunchDaemon plist syntax and contract
make installer-test # isolated rootful install/upgrade/rollback/uninstall fixtures
make package-rootful # macOS-only Apple ARM64 package assembly
make device-harness-test # host fixtures only; not device validation
make clean
```

`make build-ios` is a separate macOS-only cross-compilation gate for the Apple ARM64 iOS target, with an iOS 12.0 deployment target. `make package-rootful` builds the CLI, daemon, and C17 installer helper, inspects their Mach-O architecture, dependencies, and signing metadata, and emits a deterministic distribution archive. Neither target runs the outputs, signs them for device use, nor establishes jailbreak compatibility.

CI keeps these gates distinct:

1. Linux host compilation, Rust checks, C17 fixture tests, and smoke checks.
2. Apple ARM64 iOS cross-compilation on macOS.
3. Runtime validation on the physical reference iPad, which CI does not run.

Passing one gate does not imply that a later gate passed.

## Executable behavior in P010

The CLI supports `--help`, `--version`, read-only `doctor`, `doctor --amethyst`, and `status`. `doctor --amethyst` uses additive read-only IPC v1 when available and remains usable without the daemon. It reports the pinned source provenance, component file type, installed build and hook state as unverified, SSH path coverage as not tested, fully unsigned Mach-O support as blocked, and activation as disabled. It never calls private Amethyst XPC. `status` reports daemon response, IPC reachability, local daemon/plist file presence, the root-owned installation record, state file/schema, disabled activation, P003 Amethyst compatibility, and device acceptance as separate facts. It uses the additive P005 lifecycle request while preserving the P004 `GET_STATUS` wire response. If IPC is unavailable, activation and persistent-state facts are `UNKNOWN`. The daemon starts only when explicitly requested with `ios-unsandboxedd --serve` (foreground, root only). Development uses a private temporary directory with `ios-unsandboxedd --test-socket <path>`. `doctor` remains usable when IPC is unavailable.

```text
ios-unsandboxed doctor
ios-unsandboxed doctor --amethyst
ios-unsandboxed status
ios-unsandboxed --test-socket <private-socket-path> check
ios-unsandboxed inspect <binary>
ios-unsandboxed sign <binary>
ios-unsandboxed sign <binary> --entitlements <file>
ios-unsandboxed install <binary>
ios-unsandboxed enable
ios-unsandboxed disable
ios-unsandboxed logs
```

`doctor` reports the detected platform, rootful path assumptions, Amethyst candidate component metadata, compatibility state, current diagnostic capability, remaining requirements, and device-test status. It exits nonzero when compatibility is unsupported, missing, or unverified. Diagnostic collection success is separate from activation eligibility. The Rust CLI does not claim to know the device model or exact iOS product version when its standard-library probe cannot establish them.

The explicit `--test-socket ... check` command exercises PING, the unchanged P004 status request, preflight, and lifecycle status against an isolated test socket. It reports kernel-authenticated peer credentials for physical-device qualification.

`iu inspect PATH` performs local descriptor-based inspection under the invoking user's permissions and remains available when the daemon is unavailable. It reports a bounded Mach-O state, SHA-256 and filesystem identity, P003 policy outcome, P009 capability/compatibility state, and a preparation preview. Structural signature parsing does not imply cryptographic validity or trust; no launch permission is returned. `ios-unsandboxedd --probe` exposes the native C17 read-only preflight. PING confirms only that this project IPC endpoint responds; it does not establish Amethyst initialization or operational eligibility. `enable`, `disable`, `sign`, `install <binary>`, and `logs` remain unimplemented and fail safely. The project manager is separate from `iu install <binary>`: it installs only this project package and cannot prepare a user executable. The root-owned state format accepts only a disabled activation value; only the transaction manager can write the exact schema-v1 record, and it is not exposed through daemon IPC. The LaunchDaemon plist is staged inactive; lifecycle operations do not activate execution interception. The adapter's evidence/hash model and device gates are in [P009 validation](docs/validation/P009_ADAPTER_GATES.md); P010 offline gates are in [P010 validation](docs/validation/P010_PLANNER_GATES.md). See [the IPC protocol](docs/architecture/ipc-protocol.md), [daemon security](docs/architecture/daemon-security.md), [IPC lifecycle](docs/architecture/ipc-lifecycle.md), and [device qualification](docs/validation/ios-device-ipc-qualification.md).

## Rootful installation contract

P005 documents paths and packages a dormant plist template only; it does not deploy to a device, install an alias, create the canonical state file, load launchd, or ship a complete installer. The canonical constants are in [`packaging/rootful/paths.env`](packaging/rootful/paths.env), and ownership, lifecycle, and rollback requirements are in [the rootful layout](docs/architecture/rootful-layout.md), [service lifecycle](docs/architecture/service-lifecycle.md), and [recovery/rollback](docs/architecture/recovery-rollback.md).

P007 provides the rootful package builder and project-owned manager. The manager accepts an expanded package directory and separates read-only planning from mutation with explicit `--apply`:

```sh
manager.sh plan --package /path/to/ios-unsandboxed-0.1.0-rootful-arm64
manager.sh install --package /path/to/ios-unsandboxed-0.1.0-rootful-arm64 --apply
manager.sh status
manager.sh upgrade --package /path/to/new-rootful-package --apply
manager.sh rollback --apply
manager.sh uninstall --apply
manager.sh recover --apply
```

Production mutation is limited to effective UID 0 on the reference `iPad4,4` (A1489), iOS 12.5.7, with safe rootful `root:wheel` directories and no foreign destination collisions. Host tests use `--test-root` with an isolated directory and simulated ownership; they are not device evidence. Package installation stages the LaunchDaemon plist but does not register it. Explicit lifecycle commands and their device-only limitations are documented in [launchd service controller](docs/architecture/launchd-service-controller.md), [registration](docs/architecture/service-registration.md), and [recovery](docs/architecture/service-recovery.md).

## Security and current limitations

P003's C17 policy evaluator accepts only explicit in-memory test configuration and target facts. `ALLOW_ELIGIBLE` means a hypothetical target passes policy checks; it does not mean execution will work. P004 IPC does not remove the iOS sandbox, bypass AMFI, prepare or sign binaries, mutate trust-cache state, enable/disable a service, activate launchd jobs, or intercept process launches. A daemon by itself cannot universally observe or change how iOS processes are launched. No internal Amethyst interface is assumed stable here.

The implementation and package have not been installed or run on the reference iPad. Socket creation under `/var/run`, Darwin `getpeereid`, root/non-root SSH authorization, Apple A7 IPC, launchd lifecycle, exact installed Amethyst build provenance, hook initialization/inheritance, signing/trust-cache operations, fully unsigned launch, enable/disable, installer ownership, upgrade/rollback, reboot recovery, and SSH stability remain NOT RUN. Host fixtures and Apple cross-compilation do not establish device compatibility. The bounded device procedure and evidence ledger are in [the P005 qualification document](docs/validation/ios-device-ipc-qualification.md).

### Root-controlled policy preview

The rootful manager supports `policy status`, `plan`, `list`, `preview PATH`, `add-directory PATH`, `remove-directory PATH`, and `reset`. Configuration changes require `--apply --confirm`; scopes are limited to initially empty administrator-owned directories under `/opt/ios-unsandboxed-scopes/`. The separate policy is preview-only: execution remains disabled and no preview authorizes a launch. See [root execution policy](docs/architecture/root-execution-policy.md). Physical-device validation remains **NOT RUN**.

P012 adds the local read-only `iu plan PATH` preview. It records identity, reports scope and provenance separately, and never grants launch authorization. See [artifact provenance](docs/architecture/artifact-provenance.md) and [launch binding](docs/architecture/launch-binding-contract.md).
