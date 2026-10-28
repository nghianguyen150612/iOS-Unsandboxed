# Amethyst adapter ABI v1

## Boundary and pinned provenance

The project-owned C17 adapter is compiled into `ios-unsandboxedd`. It has no dependency on Amethyst binaries, private headers, private XPC, kernel offsets, or jailbreak-server RPC. Its only production actions are bounded filesystem reads, metadata collection, platform preflight, compatibility classification, and Mach-O inspection. `preview` evaluates the existing P003 policy and never executes its request. The reserved operation function returns `IU_AME_ERROR_NOT_IMPLEMENTED` for every defined future operation.

The source audit is pinned to Amethyst repository `staturnzz/amethyst`, tag `v1.1`, revision `61ce86d7d3f00e5395f4d42bebda0e5dce04946a`. This value is source provenance in the project; it is not evidence that an installed dylib was built from that revision. The probe has no reliable package database or trusted reference binary hash, so its installed package version is empty and build evidence remains `UNKNOWN`.

## ABI

Public layouts are in `native/include/iu_amethyst_adapter.h` and `iu_amethyst_capabilities.h`. ABI version is 1. Every public result starts with `abi_version` and `struct_size`; ABI inputs are rejected unless both match exactly. Integers use fixed-width types, strings are bounded, results contain no pointers, and static assertions lock the current ARM64/x86-64-compatible C17 sizes. No Amethyst private type appears in the public interface.

| Structure | ABI v1 size (bytes) |
| --- | ---: |
| `iu_ame_text_v1` | 132 |
| `iu_ame_component_evidence_v1` | 112 |
| `iu_ame_probe_result_v1` | 816 |
| `iu_ame_observed_facts_v1` | 444 |
| `iu_ame_capability_result_v1` | 16 |
| `iu_ame_preview_request_v1` | 9496 |
| `iu_ame_preview_result_v1` | 36 |
| `iu_ame_macho_result_v1` | 80 |
| `iu_ame_capability_record_v1` | 20 |
| `iu_ame_capability_set_v1` | 296 |

The large preview input embeds P003 policy values by copy; it is not the IPC payload. The additive daemon request `GET_AMETHYST_ADAPTER` is still IPC protocol v1 and returns only the compatibility/evidence enums, two component file-type states, and the pinned 40-byte source revision. It does not return candidate paths, hashes, ownership, or private XPC details. Existing IPC v1 verbs and payloads are unchanged.

## Compatibility and evidence

Adapter compatibility is a separate enum from P003's existing numeric compatibility enum. Its states are `SUPPORTED_AND_VERIFIED`, `SOURCE_REVISION_KNOWN`, `INSTALLED_BUILD_UNVERIFIED`, `COMPONENT_MISSING`, `VERSION_MISMATCH`, `UNSUPPORTED_PLATFORM`, `HOOK_STATE_UNVERIFIED`, `ABI_INCOMPATIBLE`, and `INTERNAL_ERROR`.

Production probe combines native P003 platform facts with component evidence. It can report unsupported platform/version and missing components. A component path or package version cannot establish hook activity. The production classifier deliberately does not emit `SUPPORTED_AND_VERIFIED`: v1 has no independently authenticated Amethyst runtime evidence collector or authoritative binary hash. `SOURCE_REVISION_KNOWN` is only available when the caller supplies a matching revision fact; it does not establish installed binary identity. Full verified facts are accepted by the test-only mock build for policy fixtures, not by the production classifier.

Component candidates are fixed to `/amethyst/launchd_hook.dylib` and `/usr/lib/base_hook.dylib`. Collection rejects noncanonical/symlinked parent traversal, final symlinks, non-regular files, hard links, non-root ownership in production, group/world-writable or set-id modes, files larger than 64 MiB, unreadable files, descriptor identity changes, and metadata changes during a read. SHA-256 is set valid only after the complete bounded read and stable descriptor check. `iu_ame_component_evidence_recheck_v1` can compare a later read with the collected metadata and digest; this detects changed local evidence, not a match to a reference build. There is no audited reference binary hash, so the adapter never calls it a match for the pinned source. Package metadata remains unknown. A filename never proves hook initialization.

The module does not query or call Amethyst's private heartbeat/XPC service. `launchd_hook_evidence` and `base_hook_evidence` are `UNKNOWN` in production. SSH exec path coverage remains untested. Runtime hook status requires separate device evidence.

## Preview and future operations

`iu_ame_adapter_preview_v1` checks exact ABI sizes, calls P003 `iu_policy_evaluate_v1`, reads current adapter compatibility, and checks the required capability. A P003 deny is preserved. P003 `ALLOW_ELIGIBLE` is necessary but insufficient: the adapter also requires verified compatibility and an available capability. The result labels eligible results as hypothetical and always sets `operational_authorization=0`. Production compatibility currently remains unverified/unsupported, so preview fails closed.

Reserved operation identifiers are `PREPARE_EXECUTABLE`, `REGISTER_TRUST`, `APPLY_PROCESS_POLICY`, and `VERIFY_LAUNCH_BOUNDARY`. They return not implemented. There is no generic dispatch, PID argument, kernel address, mutation code, or private command number. Future work needs root-owned opt-in policy, exact target identity checks, pinned backend verification, per-launch scope, detailed error handling, and a reviewed rollback plan.

## Diagnostic behavior

`ios-unsandboxed doctor --amethyst` uses the authenticated daemon read-only request when available. It prints the project source pin, component file-type classifications, unknown installed build/hook state, blocked fully unsigned Mach-O support, disabled activation, and `Device runtime validation: NOT RUN`. When the daemon is absent it prints the static source pin and explicit unknown runtime fields, and exits successfully. It does not contact Amethyst XPC.

The adapter is not proof of launch success and does not make Amethyst's internal helpers an SDK. P009 performs no signing, trust-cache changes, sandbox changes, process manipulation, launch interception, file writes, or system/jailbreak mutations.
