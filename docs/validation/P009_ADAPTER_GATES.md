# P009 adapter validation gates

## Offline gates

`make adapter-test` compiles the production adapter separately from the test-only mock and runs deterministic host fixtures without root or device access. It covers ABI mismatches and malformed sizes, invalid enums and bounded text, compatibility precedence including iPad4,1 mismatch and unexpected OS/build, missing/unsafe/symlinked/hard-linked components, SHA-256 output and recorded-hash mismatch/recheck, invalid load commands, signature states, unsigned ARM64 Mach-O, unsupported architecture, bounds/overflow cases, P003 disabled/unverified policy and target identity mismatch, mock hypothetical eligibility, reserved mutation operations, and fail-closed production classification.

The mock is linked only into the adapter test executable using `IU_AME_TESTING`; production daemon builds do not compile or link it. No environment variable selects a mock. Fixture paths are temporary host files and no system or jailbreak paths are written.

Run the existing project gates as well:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build
make test
make native-test
make ipc-test
make packaging-test
make installer-test
make service-test
make device-harness-test
make smoke-test
make adapter-test
make package-rootful  # macOS + Xcode SDK only
```

CI's Linux job runs Rust formatting/lints/tests and the host `make test` suite, including `adapter-test`. Its macOS job cross-compiles and checks the ARM64 iOS package. P009 must not be described as passing Apple cross-compilation or package integrity until the corresponding macOS CI result is complete.

## Device-only gates — NOT RUN

Physical iPad mini 2 A1489 (`iPad4,4`), iOS 12.5.7, Amethyst rootful v1.1 behavior is unverified. Device gates include installed Amethyst build provenance, authoritative reference binary hashes, independent live launchd/base hook evidence, SSH exec path coverage, runtime ARM64 Mach-O acceptance, launch behavior for each signature classification, Darwin filesystem ownership/path guarantees, and daemon IPC peer behavior on target hardware. The P009 probe does not call private Amethyst XPC and does not infer hook activity from a heartbeat or dylib filename.

P010 prerequisites: a reviewed source of trusted installed-build identity, an independent and authorized hook/runtime evidence mechanism, explicit artifact identity/authorization model, and security review of the adapter/daemon trust boundary. No P010 execution preparation or mutation is included here.
