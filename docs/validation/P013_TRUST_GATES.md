# P013 trust gates

## Offline implementation status

- Rust verifier: Ed25519 via `ed25519-dalek` 2.x; fixed algorithm and strict canonical signature length.
- Artifact binding: P010 SHA-256, size, architecture, and Mach-O type.
- Trust reader: strict root ownership/mode, no final symlink, single-link file, bounded 64-key schema, explicit IDs and active/revoked state.
- Trust mutation manager: add/revoke/rotate, durable v1 journal, recovery, and package lifecycle protection are implemented in P013B-3; see [P013B-3 recovery gates](P013B3_RECOVERY_GATES.md).
- Independent build-attestation verifier: implemented in P013D-1 for DSSE Protocol v1.0.2, in-toto Statement v1, and SLSA Provenance v1.0. Production signer/builder roots and policy are NOT AVAILABLE; production remains `BUILD_ORIGIN_UNVERIFIED`.
- Authoritative protected-origin classification: NOT AVAILABLE; always `UNKNOWN`.
- P012 C verifier integration: implemented by P013C's pointer-free descriptor summary ABI v2; P012 ABI v1 remains unchanged and its legacy provenance result is not treated as Ed25519 proof.
- P011 scope: included in the integrated C preview and revalidated by P012; policy/store staleness fails closed. P009 Amethyst runtime remains unverified.
- Operational authorization: always false; no launch API added.

## Required tests and CI

`make trust-provider-test`, `make origin-policy-test`, `make trust-manager-test`, and `make trust-recovery-test` cover RFC 8032 verification, signed fixture results, malformed store/journal bytes, interruption recovery, rotation/revocation, shared-lock contention, and lifecycle preservation. CI performs Linux host tests and Apple ARM64 iOS 12.0 cross-compilation/package checks separately. Device validation remains a distinct gate and is not implied by CI.

The publisher command is `iu provenance plan MANIFEST ARTIFACT`. The attestation command is `iu provenance attestation verify ATTESTATION ARTIFACT`; it uses the P013C opened descriptor for P010/C inspection, Rust hashing, exact DSSE payload verification, subject binding, and final revalidation. See [P013C integration gates](P013C_INTEGRATION_GATES.md) and [P013D-1 gates](P013D1_ATTESTATION_GATES.md). Filesystem-only generation checks are not adversarial rollback protection; the result exposes `ROLLBACK_PROTECTION_UNVERIFIED`. Production builder trust and authoritative protected-origin classification remain unavailable, so overall P013 remains PARTIAL. Physical-device testing remains NOT RUN. Never infer Apple runtime behavior from cross-compilation.
