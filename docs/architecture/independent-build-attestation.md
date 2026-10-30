# Independent build-attestation verification

P013D-1 adds an offline, read-only verifier for a bounded DSSE envelope containing an in-toto Statement v1 and a SLSA Provenance v1.0 predicate. The verified specifications are DSSE Protocol v1.0.2, the in-toto Statement v1 schema, and the SLSA Provenance v1.0 schema. The predicate URI is `https://slsa.dev/provenance/v1`.

The verifier uses the established RustCrypto `ed25519-dalek` implementation. DSSE does not negotiate an algorithm inside the signed document: the versioned builder provider selects the supported key algorithm out of band. P013D-1 accepts Ed25519 only. The DSSE `keyid` is an untrusted lookup hint and is not an identity or trust decision by itself.

## Supported profile

- Payload type is exactly `application/vnd.in-toto+json`.
- One DSSE signature is required. The signature entry must contain `keyid` and `sig`; multiple signatures and unknown DSSE envelope fields are unsupported.
- The envelope may use standard or URL-safe base64. The decoded signature must be exactly 64 bytes.
- The DSSE signing input is `DSSEv1 ` followed by the decimal UTF-8 payload-type byte length, a space, the exact payload-type bytes, a space, the decimal payload byte length, a space, and the exact decoded payload bytes. The verifier never reserializes payload JSON for signature verification.
- The Statement `_type` is exactly `https://in-toto.io/Statement/v1`. `predicateType` is exactly `https://slsa.dev/provenance/v1`.
- Each supported subject has one lowercase 64-character `sha256` digest. Exactly one subject must match the SHA-256 computed from the P013C opened artifact descriptor. Zero matches fail; multiple matches are ambiguous. Other digest algorithms are unsupported by this profile.
- The predicate requires `buildDefinition.buildType`, object-valued `externalParameters`, `runDetails.builder.id`, and a bounded `resolvedDependencies` list for build-origin acceptance.
- For source verification, exactly one dependency with a `digest.gitCommit` is accepted. Its URI must match builder policy and its lowercase revision must be a full 40- or 64-character Git object ID allowed by that policy.
- `buildType` and the complete `externalParameters` object must match builder policy exactly. External parameters are treated as untrusted input as required by SLSA.
- Unknown in-toto and predicate extension fields are ignored as the specifications require. Duplicate JSON object keys are rejected throughout. Parsing is bounded to a 2 MiB envelope, 768 KiB decoded payload, 32 nested levels, 8,192 values, 256 array items or object fields, and 16 KiB payload strings. No field causes a network fetch.

This is a deliberately narrow profile, not a replacement format. A document that needs unsupported subject digests, multiple signatures, or a different predicate version is rejected as unsupported.

## Separate verification outcomes

The typed result reports syntax, signature validity, signer identity, subject match, claimed builder identity, builder authority, parameter acceptance, source revision, build type, and build-origin status separately. A valid signature authenticates the attestation bytes under the provider key; it does not by itself authorize that signer for the claimed builder. A trusted builder still does not pass if its build type, external parameters, source URI/revision, or artifact subject falls outside policy.

P013C supplies the descriptor-derived SHA-256 only after C/P010 inspection and Rust hashing agree on the same opened artifact. It revalidates that descriptor and the attestation file before returning. A replaced or mutated artifact invalidates the subject binding. The attestation command does not reopen the artifact pathname for its digest.

P013D-2A replaces the empty production provider with a read-only `LocalBuilderVerificationProviderV1` over the separate local builder root and policy files. No keys are embedded or automatically provisioned. If an administrator has installed a valid root and exact policy, the verifier can authenticate the Ed25519 DSSE signature and report that the key/policy matched; a recognized signer without a policy is untrusted. Publisher roots are never reused.

Local installation alone does not independently authenticate the real-world identity of a CI system. Until P013D-2B provides a reviewed enrollment chain, production reports `Independent trust establishment: UNVERIFIED` and `BUILD_ORIGIN_UNVERIFIED`, even for a valid matching local key and policy. Root and policy snapshot digests/generations are re-read and checked before return, but local generation values do not prevent adversarial rollback. The schemas and limitations are described in [builder trust storage](builder-trust-storage.md), [builder policy schema](builder-policy-schema.md), and [the builder trust contract](builder-trust-contract.md).

Publisher-authenticated claims remain distinct from an independently trusted builder attestation. A source revision recorded in the predicate remains a claim until it matches an independently trusted source policy. Reproducible-build evidence is not produced here. Protected-origin classification remains `UNKNOWN` and cannot be inferred from an attestation. No SLSA level is claimed.

The diagnostics are `iu provenance attestation verify ATTESTATION ARTIFACT` and `iu provenance builder-trust status|list|inspect`. They do not contact the daemon or mutate system trust. `Protected origin: UNKNOWN`, `Amethyst runtime: UNVERIFIED`, `Launch boundary: NOT IMPLEMENTED`, `Execution activation: DISABLED`, and `Operational authorization: FALSE` remain fixed. Physical-device validation is NOT RUN.

## Specification references

- [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- [SLSA artifact verification](https://github.com/slsa-framework/slsa/blob/main/spec/verifying-artifacts.md)
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
