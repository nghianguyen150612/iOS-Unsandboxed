# P013D-2B-2 mutation planning gates

This increment adds a deterministic read-only planner. It does not apply a mutation, create a transaction artifact, recover a transaction, authenticate builder enrollment, authorize execution, or classify protected origin.

## Local gates

Run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build
make builder-trust-test
make builder-transaction-test
make builder-mutation-test
make build-attestation-test
make authenticated-binding-test
make test
git diff --check
```

`builder-mutation-test` exercises deterministic operation cases and CLI parsing, passes the first-enrollment transaction vector through the C17 codec, and checks malformed/symlink input rejection without touching production trust paths. Rust fixture tests use isolated temporary roots for snapshot, pending-stage, marker, and read-only checks. Inputs and vectors are offline and deterministic.

## CI gates

Linux runs the mutation suite directly and through `make test`, in addition to formatting and Clippy. Apple ARM64 runs the existing iOS 12.0 cross-compilation, Mach-O/dependency inspection, package integrity, and reproducibility checks; inclusion of the Rust module in the CLI build is part of that compile. Apple cross-compilation does not establish device runtime behavior.

## Claims retained

- Mutation planning and serialization are offline implementation only.
- No trust file is written and no automatic builder key is installed.
- Independently authenticated builder identity is UNVERIFIED.
- `BUILD_ORIGIN_UNVERIFIED`, protected origin `UNKNOWN`, execution activation disabled, and operational authorization `FALSE` remain in force.
- Device validation is NOT RUN.

## Deferred work

Privileged persistence must independently reconstruct operations from explicit arguments and revalidate the on-disk snapshot. Enrollment, revocation, rotation, policy writes, journal creation, crash recovery writes, authenticated enrollment, and rollback protection remain future work. No P013D-2B-3 or P014 work is included.
