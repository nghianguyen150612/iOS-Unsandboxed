# iOS-Unsandboxed

**Version:** 0.1.0 · **License:** MIT

iOS-Unsandboxed is an experimental, SSH-oriented foundation for running compatible Mach-O ARM64 command-line programs on a rootful jailbroken iPad. It has no graphical interface. P001 establishes the project layout, diagnostic executables, host build checks, and a documented installation contract; it does not implement binary preparation, sandbox changes, service activation, or launch interception.

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

That workflow is aspirational. `enable` and all other operational commands currently fail as unimplemented. Transparent preparation of signatures, entitlements, or jailbreak trust mechanisms is not implemented. Executables without `LC_CODE_SIGNATURE` are a critical future experiment; P001 makes no claim that they can run. No kernel exploit or kernel patch is part of this project.

## Components

- `cli/`: Rust CLI named `ios-unsandboxed`; designed for SSH use and future diagnostics/configuration/error handling.
- `daemon/`: strict C17 diagnostic executable named `ios-unsandboxedd`; it does not daemonize or perform privileged work.
- `native/`: architectural boundary for a future native execution layer and platform adapter. No native backend or launch hook is implemented in P001.
- `packaging/rootful/`: centralized rootful path contract. It is not an installer.
- `docs/architecture/`: component boundaries, target build requirements, security limits, and installation ownership.

The intended future flow and the current boundary are described in [the architecture overview](docs/architecture/overview.md).

P002 inspected Amethyst source at a pinned upstream revision. The audit found a source-level launch hook suitable for a narrowly opted-in experiment, but Amethyst's normal preparation path skips Mach-O files without LC_CODE_SIGNATURE. A lower-level F_ADDSIGS path can construct an in-memory signature when directly invoked, but acceptance and launch behavior for a completely unsigned ARM64 executable are unverified on the reference iPad. See the [source audit](docs/research/amethyst-source-audit.md), [launch-path matrix](docs/research/launch-path-matrix.md), [signing and trust-cache audit](docs/research/signing-trustcache-audit.md), [ABI contract](docs/architecture/amethyst-abi-contract.md), and [unsigned Mach-O assessment](docs/architecture/unsigned-macho-feasibility.md). P002 did not implement or activate any of these mechanisms.

## Prerequisites

For host builds:

- Rust stable with Cargo (minimum Rust 1.74)
- A C17 compiler (`cc`, Clang, or GCC) with strict warning support
- `make`

For the separate Apple ARM64 iOS build, use macOS with Xcode command line tools, the iPhoneOS SDK, stable Rust, and the `aarch64-apple-ios` Rust target. Rust links with that target and `xcrun` supplies the iPhoneOS SDK to Clang for the C17 daemon; the deployment target is iOS 12.0. No developer-specific SDK paths are assumed. The Makefile reports a clear error when the Apple toolchain or SDK is unavailable. P001 does not sign the resulting binaries for device use; a validated jailbreak trust/signing path is still required before runtime claims can be made.

## Build and validation

```sh
make help
make build       # host CLI and host diagnostic daemon
make test        # Rust unit tests and host executable smoke checks
make clean
```

`make build-ios` is a separate macOS-only cross-compilation gate for the Apple ARM64 iOS target, with an iOS 12.0 deployment target. It does not run the outputs, install them, sign them for device use, or establish jailbreak compatibility. Device signing/trust handling must be researched and validated in later work.

CI keeps these gates distinct:

1. Host compilation and tests.
2. Apple ARM64 iOS cross-compilation on macOS.
3. Runtime validation on the physical reference iPad.

Passing one gate does not imply that a later gate passed.

## Executable behavior in P001

The CLI supports `--help` and `--version`. It registers these reserved commands:

```text
ios-unsandboxed doctor
ios-unsandboxed status
ios-unsandboxed inspect <binary>
ios-unsandboxed sign <binary>
ios-unsandboxed sign <binary> --entitlements <file>
ios-unsandboxed install <binary>
ios-unsandboxed enable
ios-unsandboxed disable
ios-unsandboxed logs
```

Every reserved command reports that it is not implemented, exits nonzero, and does not modify system state. In particular, `enable` performs no activation.

The daemon supports only `--help` and `--version`. Starting it without a diagnostic flag, or giving it an operational mode, fails explicitly. It has no IPC listener, launch interception, AMFI or sandbox manipulation, kernel changes, or privileged background behavior.

## Rootful installation contract

P001 documents paths only; it does not deploy to a device, install an alias, create a LaunchDaemon, or ship a complete installer. The canonical constants are in [`packaging/rootful/paths.env`](packaging/rootful/paths.env), and ownership and rollback requirements are in [the rootful layout document](docs/architecture/rootful-layout.md).

The future installer must use rootful filesystem paths, preserve Procursus conventions, avoid Apple system and Amethyst-owned files, and support verified backup, atomic installation, rollback, and reversible uninstall. The `iu` command must be a filesystem symlink at `/usr/local/bin/iu` pointing to `/usr/local/bin/ios-unsandboxed`; it must not depend on an interactive shell alias.

## Security and current limitations

P001 does not remove the iOS sandbox, bypass AMFI, prepare or sign binaries, enable/disable a service, activate launchd jobs, or intercept process launches. A daemon by itself cannot universally observe or change how iOS processes are launched. Any future launch integration must be validated against the actual Amethyst source and ABI in use; no internal Amethyst interface is assumed stable here.

The implementation has not been installed or run on the reference iPad. Amethyst compatibility, daemon startup under launchd, native IPC, transparent Mach-O preparation, fully unsigned launch, enable/disable, rollback, and SSH stability after activation remain unverified.
