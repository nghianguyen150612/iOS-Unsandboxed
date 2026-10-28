# P009 — Amethyst Compatibility Adapter & Capability Contracts

## Baseline and branch

- Latest verified `origin/main`: `159a6c76c4675ec62854c4283356584e3ac3450a`.
- P008 PR #8 was checked before work and remained OPEN, with head `cb93337f8643601ca790f3db801318a5cd3f6463` on `feat/p008-launchd-lifecycle`.
- Work branch: `feat/p009-amethyst-adapter`, based on P008 head to preserve P008 changes.
- Target base while P008 is open: `feat/p008-launchd-lifecycle`. Retarget to `main` only after P008 merges, and verify the final merge-base/diff so P008 commits are not duplicated.

## Provenance and limits

- Amethyst upstream: `https://github.com/staturnzz/amethyst`.
- Audited pin/tag: `61ce86d7d3f00e5395f4d42bebda0e5dce04946a`, `v1.1`.
- This revision is source-audit provenance, never installed-build proof.
- P009 does not link private binaries, call Amethyst XPC, invoke undocumented offsets, or modify kernel, trust-cache, signing, sandbox, process, or launch state.
- Compatibility evidence, P003 policy eligibility, and actual runtime capability remain separate. Production compatibility cannot be promoted by source-only or test-only facts.

## Implemented scope

- C17 adapter ABI v1 with fixed-width fields, fixed structure sizes, bounded strings, explicit errors, and pointer-free result structures.
- Read-only fixed-path component evidence with safe path traversal, no-follow opens, type/owner/mode/link checks, stable identity checks, 64 MiB bounds, and SHA-256. The hash is not compared to an unavailable authoritative reference artifact.
- Explicit compatibility classifier and 14 capability records with status and evidence type.
- Safe bounded ARM64 Mach-O CodeDirectory/signature-state parser; no file mutation or signature generation.
- P003 policy preview; P003 remains authoritative, and preview reports hypothetical eligibility only with operational authorization fixed false.
- Four typed future operations return not implemented; no generic privileged dispatch exists.
- Test-only mock backend compiled only into host fixtures.
- Additive read-only `GET_AMETHYST_ADAPTER` IPC v1 request and `ios-unsandboxed doctor --amethyst`; status and ordinary doctor behavior remain available without daemon IPC.

## Gates and evidence

Record commands and results in the PR summary. `make adapter-test`, all existing host tests, Rust fmt/clippy/test, package integrity, and final GitHub Linux CI must be checked. Apple ARM64 build/package integrity is a separate macOS CI gate. Device validation must be reported as **NOT RUN** until actual hardware evidence exists.

Remaining device blockers: exact installed Amethyst build identity, trusted reference dylib hashes, independent live hook evidence, SSH exec interception coverage, runtime Mach-O launch behavior, and target-specific Darwin/Procursus/launchd behavior.

P010 is not started. Prerequisites include an evidence-authenticated installed-build/hook verification contract and security review of any execution preparation/authorization model.
