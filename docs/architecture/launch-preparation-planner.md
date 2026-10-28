# Read-only launch preparation planner

P010 adds a local, deterministic planning path from an executable pathname to an artifact identity and a non-mutating preparation preview. The C17 ABI is in `native/include/iu_execution_planner.h`; `cli/src/planner.rs` is the small Rust FFI wrapper used by `iu inspect PATH`. Inspection is local under the CLI user's credentials and does not send paths to `ios-unsandboxedd`.

```text
path validation -> safe descriptor open -> metadata snapshot
 -> P009 bounded ARM64 Mach-O parser -> SHA-256 on the same descriptor
 -> P003 policy evaluation -> P009 capability classification
 -> read-only preview
```

P009 now exposes `iu_ame_macho_inspect_fd_v1`. It is the existing bounded Mach-O parser with a borrowed descriptor entry point, not a second parser. It checks the same descriptor without changing its offset or closing it. Planner parsing and hashing each require complete bounded reads and stable descriptor metadata.

## States describe evidence, not permission

P010 keeps parsing, signature structure, platform trust, and runtime as separate facts:

| P009 parser state | P010 preparation description |
| --- | --- |
| Parseable CodeDirectory | `PARSEABLE_SIGNATURE` |
| Ad-hoc CodeDirectory | `ADHOC_SIGNATURE` |
| Malformed or empty/unusable signature | `REQUIRES_REPAIR` |
| No `LC_CODE_SIGNATURE` | `PREPARATION_REQUIRED_BUT_NOT_IMPLEMENTED` |
| Unsupported architecture/format | `UNSUPPORTED_TARGET` |
| Truncated/corrupt input | `INVALID_BINARY` |

These states do not establish cryptographic signature validity. The existing parser checks selected CodeDirectory and SuperBlob bounds; it does not verify CMS, code-page hashes, entitlements, or a trust chain. Amethyst trust-cache support, kernel code-signing acceptance, sandbox policy, and dynamic-loader startup remain separate and unverified. In particular, no `LC_CODE_SIGNATURE` means preparation is not implemented; P009's parser and existing Amethyst launch path do not solve fully unsigned execution.

The adapter capability result preserves evidence levels. A `SOURCE_CONFIRMED` capability means the pinned source supports that classification; it is not `RUNTIME_VERIFIED`. Component presence and a collected hash without a trusted reference do not establish the installed build. Hook state, SSH interception coverage, signing, and process unsandbox operations remain unverified, blocked, or unavailable.

## Fail-closed production policy

The production planner evaluates P003 using a disabled policy and unverified Amethyst facts. It reports the exact policy outcome/reason and adapter classification; it cannot load authorization from IPC or accept caller-provided claims that Amethyst is verified. `iu inspect` never contacts the daemon, executes the target, signs or rewrites the file, inserts trust, modifies sandbox labels, or calls private Amethyst APIs.

`operational_authorization` and `device_runtime_verified` are always zero. `INSPECTION_COMPLETE` reports only that bounded local reads produced a record. A preview cannot be converted into a permit, and future execution cannot rely only on this earlier pathname or hash.

## P011 prerequisites

P011 may define a separate root-controlled opt-in policy and an authorization-preview contract. It must not promote a P010 artifact plan to execution permission. Before any mutating launch work, the project still needs authoritative installed Amethyst identity, independent runtime hook evidence, a reviewed same-object launch boundary, reviewed root authorization, reference-device runtime evidence, and explicit activation/recovery design.

P011 uses this planner in the root manager's read-only policy preview and checks target identity again. The policy is not activation and the resulting preview is not a launch permit. See [policy authorization preview](policy-authorization-preview.md).
