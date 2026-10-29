# P013C integration gates

P013C implements the offline, read-only authenticated provenance preview. It does not implement execution or claim a verified origin chain.

## Implemented checks

- C descriptor-summary ABI v2: fixed 3376-byte pointer-free summary, borrowed descriptor, strict ABI/size/enum checks, P012 v1 delegation, false authorization, and v2 revalidation.
- Rust provider: production `iu provenance plan MANIFEST ARTIFACT` opens the artifact once and uses the same descriptor for C/P010 inspection, Rust hashing, manifest binding, and final revalidation.
- Cryptography: the existing RustCrypto `ed25519-dalek` verifier checks canonical P013 signed bytes. No external boolean or runtime test selector supplies a positive result.
- Trust: hardened descriptor traversal, local generation/digest comparison, explicit pending-transaction rejection, and a fresh final snapshot check.
- Scope: P011 scope/store observations arrive through P012 and P012 revalidates them. Rust keeps policy staleness distinct from artifact and trust failures.
- Limits: build origin remains unverified, protected origin remains unknown, runtime evidence is unverified, and operational authorization remains false.

## Host validation

`make authenticated-binding-test` runs focused Rust integration tests, a strict C17 ABI fixture with warnings as errors, and AddressSanitizer/UndefinedBehaviorSanitizer fixtures when supported. The fixtures cover valid and invalid signatures, unknown/revoked/rotated keys, publisher mismatch, manifest identity mismatch, replacement and in-place mutation, metadata change, symlink/hard-link rejection, malformed and unsupported Mach-O, manifest/trust/policy staleness, pending/corrupt trust metadata, generation mismatch, protected-path fail-closed behavior, invalid ABI/enums, no authorization, and no mutation in the successful path. Existing P012 scope fixtures exercise scope removal and directory identity changes. The CLI is local and does not require the daemon.

The test-only trust roots are injected through private test closures and temporary directories. `preview` always binds `C17P012Binding` and `load_production_snapshot`; no environment variable or CLI option selects fixture state. The P012 scope fixtures also cover an unconfigured path, a policy-store identity mismatch, removing an enrolled scope, and replacing that directory while the old device/inode remains recorded.

## CI gates

Linux CI runs formatting, clippy, the locked Cargo workspace tests, and `make test`, which includes `make authenticated-binding-test`. The Apple ARM64 job runs `make package-rootful`; Cargo's build script compiles and links the C17 planner, provenance and launch-binding sources for `aarch64-apple-ios` at iOS 12.0. CI then inspects ARM64 Mach-O architecture, dependencies, and signing status and validates package integrity and reproducibility. Those checks establish compilation/package properties only.

Physical iPad tests are NOT RUN. They remain necessary for installation ownership, actual iOS filesystem and descriptor behavior, rootful policy/trust paths, SSH command use, package lifecycle, and any future Amethyst/runtime claims. No device result can be inferred from host fixtures or Apple cross-compilation.

## Remaining P013 gates

P013C authenticates a publisher statement about exact bytes. It does not independently establish source origin, builder identity, reproducibility, safe behavior, or complete Apple protected-artifact classification. A reviewed external provenance and protected-origin provider is required before those fields can become verified. Local generation history is not adversarial rollback protection. Overall P013 remains PARTIAL until those external provenance gates are met; execution remains blocked.
