# Native preflight contract

## Scope

P003 adds a project-owned C17 read-only compatibility probe in `native/`. The public interface is `native/include/iu_preflight.h`; it does not include or link to an Amethyst header, private structure, request code, kernel address, or symbol. The daemon uses the same module for `ios-unsandboxedd --probe`.

This contract reports evidence and unknowns. It does not prepare an executable, establish that a hook is loaded, or authorize activation. `SUPPORTED_AND_VERIFIED` is reserved for a future implementation that can establish the exact supported device and iOS build, verify all mandatory components, and identify the installed Amethyst build through trustworthy provenance. P003 has no such installed-build verification and never returns that state from its classifier.

## Versioned C interface

The interface version is `IU_PREFLIGHT_ABI_VERSION == 1`. Every public structure starts with fixed-width `abi_version` and `struct_size` fields. `iu_preflight_result_v1` contains fixed-width enum and bit-mask values, bounded `iu_text_v1` values, and fixed-width owner, mode, link-count, device, inode, and size metadata for each Amethyst candidate. Text has an explicit length and a terminating NUL. The result has no raw pointers, implicit ownership, private Amethyst data, or kernel addresses.

The result carries the hardware identifier, iOS product version, system build identifier, and kernel release as separate bounded text fields.

The relevant entry points are:

- `iu_preflight_detect_v1(result)` collects current host/device facts using read-only system and filesystem metadata calls.
- `iu_preflight_classify_v1(facts, result)` classifies supplied facts. Host tests use this entry point with simulated fixtures.
- Name helpers return stable diagnostic labels for statuses, errors, operating-system families, and architectures.

The classifier requires a supported iOS/ARM64 platform, a matching reference device and OS version, and readable regular files at both audited component paths before it can return a compatibility state better than `COMPONENT_MISSING`. Even with all those facts present, it returns `UNVERIFIED`: file presence and platform facts do not prove the installed Amethyst revision or live hook state.

### Compatibility statuses

| Status | Meaning |
| --- | --- |
| `SUPPORTED_AND_VERIFIED` | Reserved. Requires trustworthy exact platform, component, installed-Amethyst provenance, and required runtime evidence. P003 never emits it. |
| `UNVERIFIED` | The visible platform/components do not establish the exact installed Amethyst build or live hook state. Operational policy must deny. |
| `COMPONENT_MISSING` | An expected Amethyst hook file is absent, is not a regular file, or cannot be opened read-only. |
| `VERSION_MISMATCH` | The observed iOS product version is known not to be iOS 12.5.7. |
| `UNSUPPORTED_PLATFORM` | The target is not iOS ARM64 on the expected iPad mini 2 Wi-Fi hardware. A Linux host is reported this way, never as an iPad. |
| `INTERNAL_ERROR` | The probe contract or system collection failed. |

Stable error codes distinguish invalid arguments, ABI mismatch, unsupported platform, missing component, unverified version, version mismatch, I/O failure, and internal failure. Unknown integer values render as unknown labels and must not be treated as success.

## Evidence collected

The probe reads `uname` fields and, on Apple targets, asks `sysctlbyname` for `hw.machine`, `kern.osproductversion`, and `kern.osversion`. It records the system build and kernel release separately from the product version. It checks the audited Amethyst candidates:

- `/amethyst/launchd_hook.dylib`
- `/usr/lib/base_hook.dylib`

These are candidate paths from source revision `61ce86d7d3f00e5395f4d42bebda0e5dce04946a`; they are not assumed to match the installed device. The probe uses filesystem metadata, read-only open, and descriptor metadata. It reports candidate ownership, mode, link count, size, and file identity where a candidate exists. It never loads a dylib or executes a component. A present file, readable file, Amethyst heartbeat, or source revision is not installed-binary provenance and does not prove an active hook.

The rootful assessment checks that the documented parent directories are available: `/usr/local/bin`, `/usr/local/lib`, `/var/lib`, `/var/run`, `/var/log`, and `/Library/LaunchDaemons`. This is a path-layout assessment only; those directories do not prove that the jailbreak is rootful. The result also reports a bit mask for the ten documented project files/directories. Missing project installation paths are diagnostic data, not a request to create them.

## Diagnostics and failure behavior

`ios-unsandboxedd --probe` runs the C probe and prints the platform, architecture, machine/version/kernel identifiers, rootful path assessment, candidate Amethyst component metadata, compatibility state, project-path count, remaining requirements, and `Device acceptance: NOT TESTED`. It exits nonzero unless compatibility is verified. It does not start a service or open a socket.

`iu doctor` provides read-only Rust-side diagnostics without resolving a companion executable through `PATH` and without requiring root. It deliberately reports hardware model and product version as unknown because the Rust standard-library probe does not establish those native facts. On a non-iOS development host it reports `UNSUPPORTED_PLATFORM`, exits nonzero, and clearly separates successful diagnostic collection from activation eligibility. A later CLI-to-daemon integration must use the authenticated project IPC planned for P004; P003 does not add a shortcut or transport.

All other reserved commands, especially `enable`, remain unimplemented and fail safely. No result from P003 activates or changes any system state.

## Future daemon consumption

A future project daemon can consume `iu_preflight_result_v1` without understanding Amethyst internals. It must validate `abi_version`, `struct_size`, enum ranges, and required masks, and it must independently establish installed-build provenance and hook readiness before returning a verified state. The preflight result is not an IPC message format or authorization credential. P004 must define authenticated peer credentials and a separate narrow CLI-to-daemon IPC contract; it must not expose Amethyst's private protocol.

## Limits

The current environment does not provide the reference iPad. Installed Amethyst binary provenance, iOS 12.5.7 runtime compatibility, hook initialization and inheritance, SSH interception, and all signing/trust-cache/unsandbox behavior remain **NOT RUN**. No build result or filesystem existence check substitutes for those device gates.
