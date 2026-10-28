# P011 implementation manifest

Baseline: fetched main `3dfb74f73e52815d940c124889f1d81e8ab2e85b`, with P010 `826816277e8f35b281ede03bfc554ca8f539f1e6` in its ancestry. Branch: `feat/p011-root-execution-policy`. Physical-device validation: NOT RUN.

The implementation adds a bounded root-owned preview-only policy store, safe directory registration, shared installer lock and atomic policy writer, and a read-only P003/P009/P010 authorization preview. The P005 state remains disabled. Installer upgrades and rollbacks preserve supported policy, and uninstall preserves and reports policy and unknown data. No execution activation, launch, private Amethyst operations, or privileged arbitrary-path IPC is added.

See [policy gates](../validation/P011_POLICY_GATES.md) and the PR checks for host and Apple CI evidence. Host fixtures are not device evidence. New scopes must be empty at enrollment, but the narrow scope namespace does not establish the provenance of files copied into them afterward; administrators must not include Apple service executables. P012 still needs a reviewed identity-bound launch boundary and independently verified device/runtime evidence.

Local Linux: `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace`, and `make test` passed, including all listed host fixture targets. The local `make build-ios` gate is unavailable on Linux because the iPhoneOS SDK requires macOS. See PR checks for Apple ARM64 and package validation.
