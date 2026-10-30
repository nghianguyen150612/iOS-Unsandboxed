# Builder-trust contract

P013D-2B-1 adds a versioned C17 journal codec, matching Rust parser, combined marker parser, and read-only classifier for old, staged, partially replaced, committed, corrupt, unsafe, and conflicting observations. Every journal or stage artifact still withholds signer and policy authority, including a complete new pair; no recovery writes are implemented. See [transaction metadata](builder-trust-transactions.md).

Publisher trust and builder trust are different authorities. P013 publisher keys authenticate publisher statements about artifacts. P013D's builder provider independently maps DSSE signer keys to signer identities and signer identities to authorized builder identities and build policies. A publisher key is never promoted into a builder key automatically.

## Versioned provider

`BuilderVerificationProviderV1` exposes version 1, a signer-key lookup, and a signer/builder authority lookup. The signer key lookup supplies an Ed25519 public key from provider configuration; the untrusted DSSE `keyid` selects a lookup only. The second lookup binds the verified signer identity to the claimed `runDetails.builder.id` and returns either an explicit policy, an untrusted result, an unknown authority, or an identity mismatch.

An accepted policy includes:

- the exact builder identity;
- the expected SLSA `buildType`;
- the complete expected `externalParameters` object;
- the expected source dependency URI;
- the set of allowed full Git revisions.

The verifier keeps these statuses independent: `SIGNATURE_VALID`, `SIGNER_IDENTITY_VERIFIED`, `BUILDER_IDENTITY_CLAIMED`, `BUILDER_IDENTITY_TRUSTED`, `BUILD_PARAMETERS_ACCEPTED`, and `BUILD_ORIGIN_VERIFIED`. They represent different checks. A signature may be valid while the signer identity is unknown; a verified signer may claim an unknown or untrusted builder; a trusted builder may provide unacceptable parameters; and a policy-accepted statement still needs an exact descriptor subject match before origin is verified.

## Production behavior in P013D-2A

`LocalBuilderVerificationProviderV1` reads the separate, administrator-provisioned `roots.v1` and `policies.v1` files under `/var/lib/ios-unsandboxed/builder-trust/` (using `/private/var` on iOS). It does not create either file. Missing or malformed roots fail closed; a recognized signer with no valid policy remains untrusted. Revoked keys are never returned as usable signers. The production default contains zero embedded keys and does not read the publisher store.

Local roots bind an exact Ed25519 key ID and public key to one exact signer identity. Policies separately bind that identity to exact builder IDs, build types, complete external-parameter objects, source URIs, and explicitly allowed full Git revisions. The DSSE key ID is only a lookup hint. Structural parameter equality rejects missing or extra fields.

The read-only provider reports root/policy generations and SHA-256 digests, signer key ID and identity, builder identity, and applicable policy ID. It reloads both stores before returning a successful diagnostic and invalidates trust if file or directory identity, content, or generation changes. If transaction artifacts exist, status reports their classified state and observed store generations while signer and policy access remain unavailable. The local generations do not provide adversarial rollback protection.

P013D-2A does not implement an independently reviewed enrollment chain. Root ownership proves only that local administration installed a file; it does not prove the real-world identity of the named CI system. Thus even a matching production key and policy report `Independent trust establishment: UNVERIFIED` and `BUILD_ORIGIN_UNVERIFIED`. Later P013D-2B increments must establish enrollment, revocation, rotation, transaction commit/recovery writes, and a reviewed rollback strategy before production may claim build origin.

Host tests use deterministic synthetic Ed25519 keys and isolated temporary root/policy stores. No CLI option, environment variable, or production configuration selects those fixtures. Their successful cryptographic and policy verification demonstrates implementation behavior only.

P013D-2B-2 adds deterministic read-only plans for adding/revoking/rotating signers and adding/revoking policies. It derives canonical store bytes, exact generation/digest changes, a compatible prepared journal, and the proposed pair marker, then revalidates the descriptor-bound snapshot. CLI plans report their complete proposed bytes and `Persistence: NOT_APPLIED`. They are not authorization tokens; a future privileged helper must independently reconstruct and revalidate each requested mutation. No trust-store or recovery writes are implemented.

Production trust requires an independently authenticated root, a reviewed mapping from root to signer identities and builder IDs, managed key enrollment/revocation/rotation, rollback-resistant lifecycle, and reviewed build-type/source/parameter policy. P013D-2B-2 provides planning only; lifecycle and privileged persistence remain deferred. No GitHub Actions, Sigstore, Fulcio, external PKI authenticity, or SLSA level is asserted. See [storage](builder-trust-storage.md), [policy schema](builder-policy-schema.md), [mutation planning](builder-trust-mutation-planning.md), and [P013D-2B-2 gates](../validation/P013D2B2_MUTATION_GATES.md).
