# Builder-trust contract

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

## Production behavior in P013D-1

No independently authenticated production builder root is configured. `UnconfiguredBuilderProviderV1` returns no signer keys and no trusted builder policy. The production CLI therefore fails closed with `UNKNOWN_SIGNER`, unknown builder authority, and `BUILD_ORIGIN_UNVERIFIED`. It never consults or modifies the publisher store.

Host tests use deterministic synthetic Ed25519 keys and builder policies. Those fixtures are compiled only into the test module; no CLI option, environment variable, or production configuration selects them. Their successful verification demonstrates code behavior only and is not production builder verification.

Production trust requires an independently authenticated root, a reviewed mapping from root to signer identities and builder IDs, key rotation and revocation semantics, rollback-resistant lifecycle, and reviewed build-type/source/parameter policy. Those enrollment and lifecycle tasks are deferred to P013D-2. No GitHub Actions authenticity is asserted, and no SLSA level is claimed.
