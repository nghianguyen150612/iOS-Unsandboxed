# Execution eligibility policy

## Purpose and boundary

P003 provides a deterministic C17 policy evaluator for a hypothetical future preparation request. The interface is `native/include/iu_policy.h`. It is independent of Amethyst's AUTO unsandbox policy and has no signing, trust-cache, launch, unsandbox, installation, or file-mutation operation.

The policy API takes fixed-layout, versioned inputs. `iu_policy_inspect_path_v1` is the separate read-only input collector; `iu_policy_evaluate_v1` only examines the supplied configuration and target facts and fills a fixed-layout result. The evaluator makes no system calls. The configuration is explicitly an in-memory test/configuration object, not authenticated production authorization. A future daemon must own and independently validate persistent policy state.

`ALLOW_ELIGIBLE` means only that the supplied facts pass the hypothetical policy. It does not mean the image is a supported Mach-O, that Amethyst can prepare it, that it can execute, or that launch is authorized. P003 has no execution caller.

## Configuration

Configuration ABI v1 requires:

- `enabled` to be exactly zero or one. The default state is disabled.
- A compatibility state. Only `SUPPORTED_AND_VERIFIED` can pass; `UNVERIFIED`, missing components, a version mismatch, unsupported platform, or an internal error fail closed.
- One or more explicitly configured eligible user-data directories when enabled. P003 configures no directory automatically and does not require per-file enrollment.
- Each directory to be represented by an absolute canonical path, expected owner, directory type, safe mode, and a metadata-verified marker. It must be owned by the configured UID, provide owner read/traverse access, and not be writable by group or others.
- The target owner to match the configured owner. Targets must have at least one execute bit and must not be group/world writable.

Malformed ABI values, lengths, booleans, directory counts, paths, or directory metadata produce `DENY_INTERNAL_ERROR`. The metadata marker and enabled value are test inputs only; they are not proof of root-owned state or authenticated authorization.

## Target inspection and identity

The path inspector accepts a pointer plus explicit bounded byte length for the duration of the call. It copies into a local buffer, rejects embedded NULs, detects symlink components without opening them, resolves relative paths to a canonical absolute path, and opens regular targets read-only with no-follow handling. It compares the opened descriptor's `fstat` identity to path metadata, checks the input path again, and records device/inode, owner, group, mode, file type, and link count. Non-regular inputs are rejected from metadata without opening a FIFO or other blocking object; they are never represented as descriptor-verified targets.

The policy denies a final symlink, hard-linked target (`st_nlink != 1`), nonregular file, non-executable file, setuid/setgid file, group/world-writable file, unsafe owner, and identity mismatch. Descriptor/path identity mismatches map to `DENY_IDENTITY_MISMATCH`. Inspector errors map to a denial; an unexpected I/O error cannot become eligibility.

The descriptor is closed after inspection. Path canonicalization and a matching device/inode snapshot do not pin that object through a future `execve`/`posix_spawn`. A file can change after P003 inspection. The final launch gate therefore remains blocked until a reviewed integration can verify the actual launch request against a held or independently re-opened descriptor and recheck identity immediately before launch.

## Protected and targeted paths

The policy checks component boundaries rather than raw string prefixes. `/usr/bin/tool` is under `/usr`; `/usr-local/tool` is not. The target is protected if it lies at or below:

- Apple/system roots `/System`, `/bin`, `/sbin`, `/usr`, `/Library/Apple`, `/Applications`, `/Developer`, `/private/etc`, and `/private/var/root`.
- Amethyst root `/amethyst` or a protected system subtree such as `/usr/lib`.
- Project-owned CLI, daemon, `iu` alias, manager/data state, native library directory, LaunchDaemon plist, runtime socket, or log directory from the P001 rootful contract.
- `/var/jb`, to avoid treating a rootless bootstrap as an eligible rootful data directory.

Protected locations are denied even if a test configuration includes an overlapping directory. A safe regular executable outside every configured eligible directory returns `SKIP_NOT_TARGETED`. This allows broad automatic eligibility within a deliberately configured safe user-data directory without introducing per-binary enrollment.

## Outcomes and order

The result is versioned (`IU_POLICY_ABI_VERSION == 1`) and has fixed-width outcome and reason codes. It contains no pointers or implicit ownership.

| Outcome | Meaning |
| --- | --- |
| `ALLOW_ELIGIBLE` | Hypothetical policy checks pass; no execution action follows. |
| `SKIP_NOT_TARGETED` | Safe-looking target is outside configured user-data directories. |
| `DENY_DISABLED` | Global configuration is disabled. |
| `DENY_UNVERIFIED_BACKEND` | Amethyst compatibility is unknown or unverified. |
| `DENY_PROTECTED_PATH` | Target belongs to a protected Apple, Amethyst, jailbreak, or project location. |
| `DENY_UNSAFE_FILE` | Type, symlink, hard-link, permission, ownership, or mode check fails. |
| `DENY_IDENTITY_MISMATCH` | Path and descriptor identity facts disagree. |
| `DENY_UNSUPPORTED_TARGET` | Input is malformed or compatibility is explicitly unsupported. |
| `DENY_INTERNAL_ERROR` | Configuration or inspection is missing, malformed, or failed unexpectedly. |

The evaluator's default result is `DENY_INTERNAL_ERROR`. Valid disabled configuration returns `DENY_DISABLED`. A configured but unverified backend returns `DENY_UNVERIFIED_BACKEND`. No ordinary diagnostic failure can result in `ALLOW_ELIGIBLE`.

P010's local planner passes descriptor-derived target facts to this evaluator and keeps production policy disabled/unverified. A fixture-only context supports simulated evaluator coverage; its hypothetical outcome is not exposed through CLI or daemon IPC and does not set operational authorization.

## Test coverage and limits

`tests/native-preflight-test.c` uses a temporary host fixture and synthetic platform/configuration facts. It covers compatibility classification, missing components, unsupported OS and device/version facts, disabled and unverified policy, protected Apple/Amethyst/project paths, prefix-boundary cases, relative/absolute paths, symlinks, hard links, directories, FIFO files, setuid/setgid modes, unsafe permissions/ownership, identity mismatch, malformed configuration, missing paths, and a hypothetical eligible regular executable. Tests require no root and do not touch jailbreak files. Passing these tests is simulated host-policy evidence, not device compatibility.

No user-data directory is enabled by P003. No persistent policy is loaded. No command can use the evaluator to launch, sign, trust, modify, install, or unsandbox an executable.

P011 adds a root-controlled preview-only store. The production P003 context remains disabled; an explicit temporary simulation checks scopes without producing execution authorization. See [root execution policy](root-execution-policy.md).
