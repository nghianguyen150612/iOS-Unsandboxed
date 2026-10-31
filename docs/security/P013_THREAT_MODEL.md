# P013 threat model (offline review)

## Scope

This model covers local publisher trust and signed-manifest verification,
descriptor-bound P012/P013C authentication, P013D DSSE/in-toto/SLSA verification,
builder signer and policy stores, privileged trust mutation and recovery, and the
rootful package lifecycle. It evaluates the implemented offline checks. It does
not claim that publisher or builder enrollment identifies an external
organization.

## Assets and security decisions

- `trusted-publishers/store.v1` and its transaction/generation records.
- Builder `roots.v1`, `policies.v1`, `transaction.v1`, `state.v1`, and fixed
  stages.
- Artifact descriptors, their inode/metadata/digest snapshots, signed manifests,
  and DSSE envelopes.
- Package-owned files, install manifests, backups, and the shared P007 lock.
- The status labels shown to operators; no preview status is an execution token.

The protected decision is whether evidence is described as authenticated,
trusted, stale, rejected, or unknown. Execution activation is separately
disabled. The implemented path never turns a successful signature or local
trust record into operational authorization.

## Principals and capabilities

1. **Unprivileged local process:** may supply artifact, manifest, attestation,
   public-key, and policy input paths; may attempt concurrent CLI requests and
   path replacement.
2. **Untrusted publisher or builder:** may choose signed claims, key IDs,
   source revisions, DSSE fields, or artifacts, but cannot choose a trusted
   verification key through those claims alone.
3. **Rootful administrator:** explicitly enrolls/revokes local trust using the
   privileged manager. Local root configuration is an administrative decision,
   not independent identity proof.
4. **Filesystem/storage fault:** may cause short writes, failed `fsync`, failed
   directory enumeration, or process interruption. Host fixtures model
   selected failures, not sudden power loss.
5. **Compromised root/kernel or an uncooperative privileged writer:** can
   replace local history and is outside the protection claim. P007 serializes
   cooperating manager processes only.

## Trust boundaries and controls

| Boundary | Implemented control | Evidence |
| --- | --- | --- |
| Artifact pathname to P012 descriptor | Opened descriptor retained; C/Rust metadata and bytes revalidated | `cli/src/authenticated_binding.rs`; authenticated-binding tests |
| Manifest claim to publisher identity | Canonical parser, explicit key lookup, strict Ed25519 verification, revoked-key rejection, trust-snapshot revalidation | `cli/src/provenance.rs`; `authenticated_binding.rs` |
| DSSE key ID to builder signer | Key ID is lookup-only; provider supplies key and signer identity; builder roots are independent from publisher trust | `cli/src/build_attestation.rs`; `builder_trust.rs` |
| Builder signer to builder/policy | Exact signer identity, builder identity, build type, parameters and full source revision are checked | `builder_mutation.rs`; `build_attestation.rs` |
| Unprivileged plan to persistent trust | Privileged helper reconstructs the mutation and journal from input; it does not accept caller-supplied digests or plans | `builder_admin.rs`; C ABI header and fixtures |
| Two-store update to recovered state | Journal-before-replacement; per-rename directory sync; combined marker; forward-only recovery; stale/conflicting states fail closed | `builder_admin.rs`; `builder_transaction.rs`; recovery fixtures |
| Installer to publisher/builder trust | Shared P007 lock and cross-transaction gates; package-owned backups exclude administrator trust | `iu_installer.c`; lifecycle fixtures |

## Explicit limits

The supported local filesystem must provide same-directory atomic rename and
truthful file/directory `fsync`. Process-exit fixtures do not prove physical
flash ordering or power-cut behavior on an iPad. Local generation markers are
not rollback-resistant against wholesale privileged history replacement.
Builder identity, protected-origin classification, the completeness of any
protected-artifact catalog, and Amethyst runtime behavior are not independently
established. Physical-device qualification remains unperformed.

The required status values remain:

```text
Independent builder identity: UNVERIFIED
Build origin: BUILD_ORIGIN_UNVERIFIED
Protected origin: UNKNOWN
Rollback protection: UNVERIFIED
Amethyst runtime: UNVERIFIED
Launch boundary: NOT_IMPLEMENTED
Execution activation: DISABLED
Operational authorization: FALSE
Device validation: NOT RUN
```

This is an implementation-level review with tests. It is not a formal proof or
an independent external security audit.
