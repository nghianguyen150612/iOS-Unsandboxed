# P013D-2B-1 transaction gates

## Scope

This increment implements an offline, read-only transaction foundation. It
parses the canonical journal in C17 and Rust, parses the combined-generation
marker in Rust, classifies on-disk pair states from actual store and stage
digests, and withholds builder signer/policy authority whenever a transaction
artifact exists. It does not commit, repair, remove, rename, or recover any
artifact. A completed classification is not crash recovery.

## Canonical format and state checks

- C17 and Rust consume the same 24-case corpus in
  `tests/builder-trust/transaction-vectors.json`; accepted inputs must encode
  back to the same exact bytes through the C codec.
- The corpus covers first enrollment, root-only, policy-only and combined
  transitions, duplicates, reordered fields, unsupported schema/operation,
  invalid and overflowing generations, generation jumps, digest errors,
  unexpected stage names, path traversal, unsupported phase, CRLF, unknown
  fields, and missing final LF.
- Rust classifier fixtures cover all recognized states, store and marker
  conflicts, missing or changed stages, orphan stages, unsafe artifacts, and
  unavailable observations. The journal phase is never used as evidence of
  progress.
- Reader fixtures cover real first-enrollment checkpoints through prepared,
  first-store replacement, marker pending, and complete marker observation.
  Each checkpoint remains non-authoritative while the journal exists.
- Symlink, hard-link, mode, directory replacement, file replacement, stale
  root/policy snapshot, malformed journal, marker mismatch, no-write, and
  unknown-entry cases fail closed.

## Required local gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make build
make builder-trust-test
make builder-transaction-test
make build-attestation-test
make authenticated-binding-test
make test
```

`builder-transaction-test` compiles C with `-std=c17 -Wall -Wextra -Wpedantic
-Werror`, executes the shared C/Rust vectors, and runs ASan/UBSan when the host
compiler supports them.

Linux CI runs the builder transaction suite and regressions. Apple ARM64 CI
cross-compiles the C17 codec and Rust reader for iOS 12.0, checks Mach-O
architecture/dependencies, and verifies package integrity and
reproducibility. These checks do not establish device runtime behavior.

No independent builder identity or adversarial rollback protection is
established by local files. `BUILD_ORIGIN_UNVERIFIED`, protected origin
`UNKNOWN`, and operational authorization `FALSE` remain the required outcomes.
Device validation is NOT RUN.
