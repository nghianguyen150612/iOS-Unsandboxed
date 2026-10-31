# Trust generation and rollback semantics

P013B-3 implements crash recovery and local consistency checks. A normal mutation increases the canonical store generation by exactly one. After a completed mutation, `generation.v1` records the last generation and digest. Generation zero, overflow, a decrease relative to that marker, duplicate generation with different bytes, a digest mismatch, and stale transaction artifacts fail closed. Recovery checks old and new bytes against the journal and does not replay a mutation when the current store already matches the new digest. A legacy store without a marker remains readable until a P013B-3 mutation completes.

These checks are local consistency checks, not adversarial rollback protection. The filesystem does not provide an independent trusted monotonic counter. A privileged attacker who can replace the store, journal, staged bytes, and all local history can restore an older valid generation or construct a different local history. The manager and verifier therefore expose `ROLLBACK_PROTECTION_UNVERIFIED`; they do not claim that local generation numbers defeat a privileged rollback.

The distinctions are:

1. **Crash recovery:** identify whether an interrupted same-filesystem rename left a verified old or new store, then complete or finalize it safely.
2. **Local consistency:** enforce canonical bytes, one-step generation increments, matching digests, and coherent operation transitions while the recorded local history is present.
3. **Adversarial rollback resistance:** unavailable without a trusted monotonic anchor outside the replaceable filesystem.

Package upgrade and rollback do not copy trust-store data from package backups. Uninstall preserves the trust directory. These lifecycle rules preserve a committed revocation during package rollback, but do not protect against a privileged attacker replacing all trust history.
