# P010 implementation manifest

## Scope

P010 implements executable identity recording and a deterministic read-only launch-preparation preview for iOS-Unsandboxed v0.1.0. It uses P003 policy and P009 parser/capability contracts. It does not implement P011 or execution behavior.

## Git baseline and delivery

- Main baseline observed before implementation: `d9eebb14d83248644f07182261cd589743eaf22a`.
- P009 PR #9 was open with successful Linux and Apple ARM64 checks; P009 head: `11296aef8b240ac1b2a35bec32d4f1cde2a047bb`.
- P010 branch: `feat/p010-executable-identity-planner`.
- The P010 pull request targets P009 while #9 is unmerged. Retarget only after P009 merges, then rerun/review the diff and CI.

## Deliverables

- `native/include/iu_execution_planner.h` and `native/src/iu_execution_planner.c`: fixed-layout C17 ABI v1 create/revalidate API, path safety, descriptor-backed SHA-256 and Mach-O identity, P003 outcome, P009 capability classification, and permanently false operational authorization.
- P009 additions: borrowed-fd parser and SHA-256 entry points. The parser implementation and public path API remain intact.
- `cli/build.rs` and `cli/src/planner.rs`: static C archive build and bounded Rust FFI wrapper for local `iu inspect PATH`.
- `tests/planner/`: isolated parser/identity/policy fixtures and bounded malformed corpus; `make planner-test` is part of `make test`.
- Architecture, policy, validation, and this manifest document P010 boundaries and gates.

## Security and validation boundaries

Planning runs under the local user's permissions. It opens no daemon file request, performs no signing or execution, and writes no executable or system state. A recorded SHA-256 is identity evidence only. Revalidation is a later pathname observation and cannot eliminate replacement between that call and a future path-based launch. No P010 result authorizes execution.

Offline coverage is host fixture coverage plus existing project gates and macOS Apple ARM64 package CI. The reference iPad tests remain NOT RUN. No claim is made about fully unsigned execution, cryptographic validity, Amethyst runtime, trust-cache support, kernel acceptance, sandbox status, or dynamic-loader startup.
