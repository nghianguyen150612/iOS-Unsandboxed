# P013D-1 attestation validation gates

P013D-1 is an offline, read-only verification foundation. Its host fixtures use real `ed25519-dalek` signatures and deterministic synthetic builder roots. They do not represent a production builder trust root or device evidence.

## Focused fixtures

`make build-attestation-test` runs DSSE and SLSA verifier tests, descriptor-bound P013C integration cases, and an end-to-end local CLI fixture. The fixtures cover valid and invalid DSSE signatures, payload modification after signing, strict payload type and schema versions, matching/wrong/missing/ambiguous subjects, unknown signer, trusted and untrusted synthetic builders, builder mismatch, unexpected external parameters, an untrusted source revision, malformed and duplicate-key JSON, size/depth/array/string limits, truncated signatures, unsupported algorithms, artifact replacement and mutation, missing runtime evidence, and false operational authorization.

The production provider contains no test roots. A test provider is injected only by Rust unit tests. The CLI exposes no fixture selector.

## Required local gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build-attestation-test
make test
```

Linux CI runs formatting, clippy, workspace tests, and `make test`; the new focused suite is part of `make test`.

Apple ARM64 CI runs `make package-rootful`, cross-compiling the Rust workspace for `aarch64-apple-ios` with an iOS 12.0 deployment target, then checks Mach-O architecture, dependencies, package integrity, and reproducibility. Cross-compilation and package validation do not establish iPad runtime behavior.

## Result limits

P013D-1 has no production builder key or independent builder root. Even a well-formed attestation from a synthetic host fixture does not change production `BUILD_ORIGIN_UNVERIFIED`. Publisher-authenticated claims, source identity claims, independently verified source identity, reproducible-build evidence, and protected-origin classification are separate. Protected origin remains `UNKNOWN`; Amethyst runtime remains `UNVERIFIED`; launch boundary remains `NOT IMPLEMENTED`; execution activation remains disabled; operational authorization remains false. Device validation is NOT RUN.
