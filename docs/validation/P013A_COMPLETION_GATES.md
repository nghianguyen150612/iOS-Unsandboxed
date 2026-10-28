# P013A completion gates

P013A remains PARTIAL. Trust-store reads use held directory descriptors and `openat` with no-follow checks; their identity and timestamps are checked across the read. The local verifier reports the P012 scope preview after comparing artifact device, inode, and digest to its P010 snapshot. It rechecks that identity after verification. These operations remain separate snapshots, not a P012 authenticated-provider integration or a launch boundary.

Trust enrollment, revocation and rotation mutations, transactions, crash recovery, C/Rust store compatibility, independent generation checks, and a versioned P012 verification interface remain unimplemented. There is no independently trusted monotonic counter and rollback protection is unverified. Build-origin evidence remains unverified and protected-origin classification unknown. No execution authorization is granted.

The Rust test fixtures exercise the descriptor-based reader with a symlinked directory, hard-linked store, and unsafe file mode. Full mutation, concurrency, interruption and cross-language fixture coverage is still required. Physical-device validation remains NOT RUN.
