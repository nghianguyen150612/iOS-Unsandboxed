# P013 signed provenance verifier

`iu provenance verify MANIFEST ARTIFACT` is an offline, read-only verifier. It reads a local manifest, obtains the artifact's SHA-256, size, architecture, and Mach-O type through the P010 inspector, and checks the manifest against a root-owned publisher trust store. It never contacts a service and never asks the daemon to open a path.

The verifier authenticates a publisher's canonical statement. A valid publisher signature does not prove the claimed source repository, revision, workflow, builder, or reproducibility. P013D adds a separate bounded DSSE/in-toto/SLSA verifier. P013D-2A adds read-only local builder roots and exact policies, but root-owned files alone do not establish an external CI identity. Production therefore remains `BUILD_ORIGIN_UNVERIFIED` until an independently reviewed enrollment chain exists. Builder keys are never derived from publisher trust. There is still no authoritative Apple artifact catalog; protected-origin classification is `UNKNOWN` and policy is rejected.

The implementation uses `ed25519-dalek` 2.x, whose Ed25519 verifier is a maintained RustCrypto implementation. The accepted algorithm is exactly `ed25519`; unknown algorithms fail closed. Verification is strict and requires 64 signature bytes and 32 public-key bytes. The CLI is read-only; trust-anchor install, revoke, rotation, and root manager integration are not implemented in this increment.

The P012 C ABI v1 remains unchanged and has no production crypto provider. P013C's composite Rust provider binds publisher verification and P013D attestation subject verification to the borrowed descriptor, then revalidates publisher and builder snapshots. P009 runtime backend evidence remains unverified. The result does not change P012 operational authorization.

## Threats and limits

- Key compromise permits false publisher statements within that publisher identity until revocation reaches this host.
- A malicious publisher can sign false repository, revision, workflow, builder, and origin claims; no attestation is independently checked here.
- Artifact substitution is detected by exact digest, size, architecture, and file-type comparison against the inspected open file identity.
- Replay of an old manifest for the same bytes is possible; there is no freshness claim.
- Revoked keys are rejected by trust-store state, but trust-store updates are not yet managed by the installer.
- The trust-store generation is parsed, but there is no hardware-backed or independent monotonic counter. Filesystem rollback by a privileged actor cannot be detected.
- The artifact and manifest are opened without following final symlinks and checked for regular-file and link-count constraints. Filesystem races outside the checked descriptors remain a local verification limitation.
- No verification result grants execution or creates a reusable authorization token.
