# P013 trust gates

## Offline implementation status

- Rust verifier: Ed25519 via `ed25519-dalek` 2.x; fixed algorithm and strict canonical signature length.
- Artifact binding: P010 SHA-256, size, architecture, and Mach-O type.
- Trust reader: strict root ownership/mode, no final symlink, single-link file, bounded 64-key schema, explicit IDs and active/revoked state.
- Trust mutation manager: NOT IMPLEMENTED.
- Independent build-origin attestation: NOT AVAILABLE; always `ORIGIN_UNVERIFIED`.
- Authoritative protected-origin classification: NOT AVAILABLE; always `UNKNOWN`.
- P012 C verifier integration: NOT IMPLEMENTED; existing v1 remains fail closed.
- P011 scope and P009 backend in CLI result: scope not checked, backend unverified.
- Operational authorization: always false; no launch API added.

## Required tests and CI

`make trust-provider-test` and `make origin-policy-test` cover RFC 8032 verification, deterministic signed fixture results, altered manifest/artifact, and revoked key behavior. The broader acceptance set still requires malformed trust-store, key rotation/update atomicity, concurrent mutation, symlink/hard-link store operations, launch integration, host sanitizer coverage, Linux CI, Apple ARM64 iOS 12.0 cross-compilation, and package reproducibility. These gates are not satisfied merely by the Rust unit tests.

Physical-device testing remains NOT RUN. Never infer Apple runtime behavior from cross-compilation.
