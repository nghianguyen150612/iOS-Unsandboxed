# P013D-2B-2 builder trust mutation planning

`cli/src/builder_mutation.rs` computes deterministic, read-only previews for signer enrollment, signer revocation, signer rotation, policy enrollment, and policy revocation. It accepts a typed request plus canonical state from `LocalBuilderVerificationProviderV1`. It does not write stores, stages, markers, or journals and does not provide an apply mode.

## Inputs

Signer public-key files contain exactly 64 lowercase hexadecimal characters and one trailing LF. The 32 decoded bytes must parse as an Ed25519 key and must not be a weak small-order key. Signing private keys and other encodings are rejected. An optional enrollment reference is bounded audit metadata only; it does not authenticate an external enrollment process.

Policy request files are bounded to 64 KiB and contain one JSON object with exactly these fields: `version` (integer 1), `signerIdentity`, `builderId`, `buildType`, `externalParameters`, `sourceUri`, and `allowedGitRevisions`. Duplicate JSON fields, unknown fields, missing fields, non-object external parameters, invalid URI forms, wildcard strings in external parameters, wildcard builder/source identities, non-full revisions, duplicate revisions, and a missing or disallowed `externalParameters.revision` are rejected. The request does not accept `state` or `policyId`; the engine assigns active state and derives the ID. Whitespace and object key order in the input do not affect the canonical output.

## Deterministic operations

- **Add signer:** derive the key ID from the public key, reject any existing key ID or signer identity, then add one active record. It does not add a builder policy.
- **Revoke signer:** change an active record to revoked and retain its key bytes. A repeated request for the revoked key is a no-op. Policies for that identity remain as records but cannot authorize while the signer is revoked.
- **Rotate signer:** revoke the active old key and add the new key under a distinct signer identity. It retains the old key record, never transfers policy authority, and reports affected policy IDs. Same-identity rotation is rejected under schema v1.
- **Add policy:** require an active known signer; bind the exact builder, build type, complete external parameter object, source URI, and sorted allowed full revisions. One signer/builder pair is permitted by schema v1, even if its earlier policy is revoked.
- **Revoke policy:** retain the policy as revoked and derive its new policy ID because state participates in the digest. Repeating the request with either the current revoked ID or the old active ID is a no-op. The old active ID alias is derived from the retained revoked record; it does not reactivate the record.

When revoking the last active signer, its active policy records remain present but are unusable. Policy replacement is not automatic. A caller must explicitly plan a separately reviewed policy addition for the new signer identity; policy IDs and the v1 uniqueness rule prevent silently adding an active replacement beside a revoked record.

## Canonical output and generations

Root and policy stores use the existing compact, sorted-key canonical JSON v1 formats. Each proposed document is run back through the existing strict reader and its generation and digest are checked. A present changed store advances by exactly one; a present unchanged store preserves its generation and digest; a newly materialized store starts at generation 1; overflow rejects. A semantic no-op has no proposed store bytes, marker, or transaction and does not advance generations.

For a real change, the plan derives the journal operation (`roots`, `policies`, or `combined`) from the actual changed pair. It emits the fixed `roots.stage.v1` and `policies.stage.v1` names with `phase=prepared`, and a next `state.v1` marker. The Rust journal and marker parsers validate those bytes before a plan is returned. Shared vector `tests/builder-trust/mutation-vectors.json` is checked by Rust and round-tripped by the C17 ABI fixture.

The displayed canonical store documents, journal, marker, old/new generations, digests, and affected IDs are a preview only. `Persistence: NOT_APPLIED` and `Operational authorization: FALSE` remain unconditional. The snapshot is re-read after planning; changed content or file/directory identity rejects the result. Pending journals, orphan stages, malformed stores, unsafe files, or invalid markers prevent plan construction.

## Privileged boundary

A future privileged writer must load and validate its own current descriptor-bound state, reconstruct the requested operation from explicit arguments, independently rerun all limits and policy checks, and compare the current snapshot immediately before persistence. It must not treat CLI-produced canonical bytes or their hashes as authority. Enrollment authentication, persistent mutation, journaling writes, crash recovery, and rollback strategy are outside this increment. Local store ownership does not independently authenticate CI identity; production trust establishment stays UNVERIFIED and build origin stays `BUILD_ORIGIN_UNVERIFIED`.
