# P013C integration gates

P013C implements the offline, read-only publisher-authentication preview. P013D adds bounded independent build-attestation verification; P013D-2A adds separate read-only local builder stores without claiming a production verified origin chain or implementing execution.

## Implemented checks

- C descriptor-summary ABI v2: fixed 3376-byte pointer-free summary, borrowed descriptor, strict ABI/size/enum checks, P012 v1 delegation, false authorization, and v2 revalidation.
- Rust provider: production `iu provenance plan MANIFEST ARTIFACT` opens the artifact once and uses the same descriptor for C/P010 inspection, Rust hashing, manifest binding, and final revalidation.
- Cryptography: the existing RustCrypto `ed25519-dalek` verifier checks canonical P013 signed bytes. No external boolean or runtime test selector supplies a positive result.
- Trust: hardened descriptor traversal, local generation/digest comparison, explicit pending-transaction rejection, and a fresh final snapshot check.
- Scope: P011 scope/store observations arrive through P012 and P012 revalidates them. Rust keeps policy staleness distinct from artifact and trust failures.
- Limits: build origin remains unverified, protected origin remains unknown, runtime evidence is unverified, and operational authorization remains false.
- P013D: a separate DSSE/in-toto/SLSA verifier uses `ed25519-dalek`, exact DSSE PAE payload bytes, bounded duplicate-rejecting JSON, and a versioned builder provider that does not reuse publisher trust. P013D-2A adds canonical `roots.v1`/`policies.v1`, descriptor-relative no-follow reads, exact signer-to-builder policy mapping, and trust snapshot revalidation. The attestation CLI supplies the same opened-descriptor SHA-256 snapshot to subject matching.

## Host validation

`make authenticated-binding-test` runs P013C Rust integration tests, a strict C17 ABI fixture with warnings as errors, and sanitizer fixtures when supported. `make build-attestation-test` runs DSSE/SLSA adversarial fixtures and P013C descriptor-bound attestation cases. Coverage includes exact DSSE signatures, invalid or changed payloads, strict schema versions, subject mismatch/ambiguity, unknown signer, trusted and untrusted synthetic builders, unexpected parameters/source revisions, malformed/duplicate/oversized JSON, truncated signatures, unsupported algorithms, artifact replacement/mutation, missing runtime evidence, and false operational authorization. The CLI is local and does not require the daemon.

The test-only builder roots use a private test-only constructor and isolated temporary directories. The production provider always reads the fixed rootful path; no environment variable or CLI option selects fixture state. `preview` always binds `C17P012Binding` and `load_production_snapshot`; the P012 scope fixtures also cover an unconfigured path, a policy-store identity mismatch, removing an enrolled scope, and replacing that directory while the old device/inode remains recorded.

## CI gates

Linux CI runs formatting, clippy, the locked Cargo workspace tests, `make builder-trust-test`, and `make test`, which also includes the authenticated-binding and build-attestation suites. The Apple ARM64 job runs `make package-rootful`; Cargo compiles the Rust verifier for `aarch64-apple-ios` at iOS 12.0. CI then inspects ARM64 Mach-O architecture, dependencies, and signing status and validates package integrity and reproducibility. Those checks establish compilation/package properties only.

Physical iPad tests are NOT RUN. They remain necessary for installation ownership, actual iOS filesystem and descriptor behavior, rootful policy/trust paths, SSH command use, package lifecycle, and any future Amethyst/runtime claims. No device result can be inferred from host fixtures or Apple cross-compilation.

## Remaining P013 gates

P013C authenticates a publisher statement about exact bytes. P013D verifies a supported attestation profile, and P013D-2A can read local builder roots/policies; production still lacks independently authenticated enrollment, so build origin remains unverified. Neither feature establishes reproducible-build evidence, safe behavior, or complete Apple protected-artifact classification. Local generation history is not adversarial rollback protection. Overall P013 remains PARTIAL until independent builder trust and protected-origin gates are met; execution remains blocked.
