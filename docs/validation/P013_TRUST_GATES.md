# P013 trust gates

P013D-2B-1 adds read-only crash-state classification and C17/Rust journal parity. That increment was read-only; P013D-2B-3 now supplies privileged persistence and forward recovery. See [transaction gates](P013D2B1_TRANSACTION_GATES.md).

## Offline implementation status

- Rust verifier: Ed25519 via `ed25519-dalek` 2.x; fixed algorithm and strict canonical signature length.
- Artifact binding: P010 SHA-256, size, architecture, and Mach-O type.
- Trust reader: strict root ownership/mode, no final symlink, single-link file, bounded 64-key schema, explicit IDs and active/revoked state.
- Trust mutation manager: add/revoke/rotate, durable v1 journal, recovery, and package lifecycle protection are implemented in P013B-3; see [P013B-3 recovery gates](P013B3_RECOVERY_GATES.md).
- Independent build-attestation verifier: implemented for DSSE Protocol v1.0.2, in-toto Statement v1, and SLSA Provenance v1.0. P013D-2A adds read-only canonical builder root/policy stores and exact signer-to-builder policy matching. Production has zero embedded or automatically provisioned builder keys; administrator-provisioned local files do not establish external CI identity. Independent enrollment trust is UNVERIFIED and production remains `BUILD_ORIGIN_UNVERIFIED`.
- Authoritative protected-origin classification: NOT AVAILABLE; always `UNKNOWN`.
- P012 C verifier integration: implemented by P013C's pointer-free descriptor summary ABI v2; P012 ABI v1 remains unchanged and its legacy provenance result is not treated as Ed25519 proof.
- P011 scope: included in the integrated C preview and revalidated by P012; policy/store staleness fails closed. P009 Amethyst runtime remains unverified.
- Operational authorization: always false; no launch API added.

## Required tests and CI

`make trust-provider-test`, `make origin-policy-test`, `make trust-manager-test`, and `make trust-recovery-test` cover RFC 8032 verification, signed fixture results, malformed store/journal bytes, interruption recovery, rotation/revocation, shared-lock contention, and lifecycle preservation. CI performs Linux host tests and Apple ARM64 iOS 12.0 cross-compilation/package checks separately. Device validation remains a distinct gate and is not implied by CI.

## P013D-2B-2 mutation planning

The builder-trust plan subcommands produce canonical, snapshot-bound previews for signer add/revoke/rotation and policy add/revoke. `make builder-mutation-test` checks planner operations, CLI grammar, read-only fixture behavior, and Rust/C17 transaction-vector parity. Plans never write stores or transaction files. They report `Persistence: NOT_APPLIED`, `Operational authorization: FALSE`, and independent trust establishment `UNVERIFIED`. Independent enrollment authentication, independent rollback protection, production build-origin verification, and protected-origin classification remain outstanding; P013D-2B-3 supplies local privileged persistence and recovery.

The publisher command is `iu provenance plan MANIFEST ARTIFACT`. The attestation command is `iu provenance attestation verify ATTESTATION ARTIFACT`; it uses the P013C opened descriptor for P010/C inspection, Rust hashing, exact DSSE payload verification, subject binding, and final revalidation. Read-only builder-store diagnostics are `iu provenance builder-trust status|list|inspect SIGNER_ID`. See [P013C integration gates](P013C_INTEGRATION_GATES.md), [P013D-1 gates](P013D1_ATTESTATION_GATES.md), and [P013D-2A gates](P013D2A_BUILDER_TRUST_GATES.md). Filesystem-only generations are not adversarial rollback protection. Independent production enrollment trust and authoritative protected-origin classification remain unavailable, so overall P013 remains PARTIAL. Physical-device testing remains NOT RUN. Never infer Apple runtime behavior from cross-compilation.

## P013D-2B-3 persistence/recovery

Privileged local builder administration, independent reconstruction, durable
two-store commit, forward-only recovery and package/publisher lifecycle guards
are implemented. See [P013D-2B-3 gates](P013D2B3_PERSISTENCE_GATES.md) for required
fixtures and CI. Prior statements above that privileged persistence/recovery are
unimplemented describe earlier increments. Independent enrollment authenticity,
protected-origin classification and privileged-attacker rollback resistance
remain outstanding; Overall P013: PARTIAL. DEVICE VALIDATION: NOT RUN.
