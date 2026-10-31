# P013D-2B-3 delivery manifest

Continue Draft [PR #13](https://github.com/nghianguyen150612/iOS-Unsandboxed/pull/13)
on `feat/p013-authenticated-provenance` from `43ac3d3adbf37eb8a31454beb1e9e3312a117316`.
Do not merge, create a replacement PR, begin P014 or activate execution.

Implementation files: `cli/src/builder_admin.rs`, `cli/src/lib.rs`, the C17
`iu_builder_trust_manager` header/wrapper, installer dispatch/lifecycle guards,
shared canonical schema/planner updates, reader marker-stage recognition,
Makefile/CI linkage and qualification, and the three `tests/builder-trust/`
persistence/recovery/lifecycle suites plus shared/ABI fixtures.

Architecture and constraints are recorded in
[privileged persistence](../architecture/builder-trust-persistence.md),
[forward recovery](../architecture/builder-trust-recovery.md),
[lifecycle](../architecture/builder-trust-lifecycle.md), and
[validation gates](../validation/P013D2B3_PERSISTENCE_GATES.md).

Management supports add/revoke/rotate signer and add/revoke policy. Persistence
and recovery require explicit `--apply --confirm`; the CLI remains read-only.
The Rust boundary accepts explicit request arguments and held descriptors,
never a CLI plan, digest, journal or authority flag. `state.stage.v1` is the only
additional durable artifact; journal/marker schema v1 compatibility is retained.
Forward recovery never restores old trust. Canonical orphan stages can only be
discarded when the unchanged live state is proved; corrupt/unsafe evidence stays.

Independent builder identity and protected origin are outstanding. No GitHub
Actions/Fulcio/Sigstore authenticity, reproducibility attestation, adversarial
rollback resistance, Amethyst runtime, launch authorization, sandbox bypass,
AMFI/trust-cache/kernel modification or physical-device validation is claimed.
Package reproducibility is a separate CI packaging check, not build-origin proof.
