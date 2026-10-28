# Amethyst capability contract v1

## Result model

`iu_ame_capabilities_v1` returns 14 fixed records. Each record has a capability ID, classification, evidence type, and evidence flags. The capability set is separate from adapter compatibility and P003 execution policy. No capability record contains a function pointer, XPC command number, PID, kernel address, or operation callback.

Classifications are `SOURCE_CONFIRMED`, `RUNTIME_VERIFIED`, `UNVERIFIED`, `UNSUPPORTED`, `NOT_IMPLEMENTED`, and `BLOCKED`. Evidence kinds are `NONE`, `PINNED_SOURCE_AUDIT`, `FILESYSTEM_METADATA`, `BINARY_IDENTITY`, `HOST_FIXTURE`, and `DEVICE_OBSERVATION`. Source evidence never upgrades itself to runtime evidence.

| Capability | v1 classification | Evidence | Meaning |
| --- | --- | --- | --- |
| `READ_ONLY_PROBE` | SOURCE_CONFIRMED | host fixture | Project read-only probe interface exists. |
| `AMETHYST_BUILD_IDENTIFICATION` | UNVERIFIED | none | Package/build identity collection has no trusted source. |
| `LAUNCHD_HOOK_DETECTION` | NOT_IMPLEMENTED | filesystem metadata | Filename presence is not hook activation evidence. |
| `BASE_HOOK_DETECTION` | NOT_IMPLEMENTED | filesystem metadata | Filename presence is not hook activation evidence. |
| `SSH_EXEC_PATH_COVERAGE` | BLOCKED | none | No device observation or supported interception contract. |
| `ARM64_MACHO_INSPECTION` | SOURCE_CONFIRMED | host fixture | The project parser classifies bounded ARM64 Mach-O input. |
| `SIGNED_MACHO_PREPARATION` | NOT_IMPLEMENTED | none | No signature builder or mutator exists. |
| `ADHOC_MACHO_PREPARATION` | NOT_IMPLEMENTED | none | No signature builder or mutator exists. |
| `MALFORMED_SIGNATURE_HANDLING` | SOURCE_CONFIRMED | host fixture | The project parser rejects malformed bounded signature structures. |
| `NO_LC_CODE_SIGNATURE_HANDLING` | SOURCE_CONFIRMED | host fixture | The parser can report the missing-command condition. |
| `PROCESS_UNSANDBOX` | BLOCKED | pinned source audit | Amethyst source has private mutating internals; this project does not invoke them. |
| `EXECVE_INTERCEPTION` | BLOCKED | pinned source audit | Amethyst implementation is not a project adapter API. |
| `POSIX_SPAWN_INTERCEPTION` | BLOCKED | pinned source audit | Amethyst implementation is not a project adapter API. |
| `FUTURE_EXECUTION_ADAPTER` | NOT_IMPLEMENTED | none | Reserved operations return not implemented. |

`RUNTIME_VERIFIED` is intentionally unused in the checked-in production capability set. Host fixture success only validates the project parser and policy glue. It cannot establish Amethyst runtime behavior on an iPad.

## Evidence and authorization boundary

The pinned source revision `61ce86d7d3f00e5395f4d42bebda0e5dce04946a` (tag `v1.1`) proves only what was inspected in that source. A package version proves only the package manager's reported version. Filesystem metadata proves only what was observed at a path. A SHA-256 value is useful as binary identity only when compared with a trusted reference artifact; P009 has no such reference hash. An independent device observation is required to claim runtime hook state.

The capability result is descriptive. P003 remains the hypothetical eligibility policy, and P009 does not grant operational authorization. The preview output includes `operational_authorization=0`; a source-confirmed record cannot override disabled policy, unverified backend, unsafe file, protected path, ownership mismatch, descriptor identity mismatch, or unsupported architecture.

P012 consumes these capability classifications as read-only prerequisites; unknown runtime evidence does not become verified through a provenance or scope match. See [trust model](provenance-trust-model.md).
