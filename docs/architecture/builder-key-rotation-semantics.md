# Builder key rotation identity semantics

The existing v1 store requires globally unique signer identities, including revoked records. That interpretation remains unchanged. Retaining multiple revoked historical keys under one signer identity while permitting at most one active key requires a versioned schema migration and complete fixtures before it can be accepted. Key IDs remain unique and a revoked key must never be implicitly reactivated. Rotation must not expand builder authority. P013D-2B-3 implements the v1 rotation writer; no schema migration writer exists.

P013D-2B-2 can preview a v1 rotation only when the new key uses a different signer identity. It retains the old revoked record, adds the new active key, reports policy IDs attached to the old identity, and does not migrate those policies. A separately reviewed new policy must be planned for the new identity. The CLI planner has no persistence interface; the separate privileged manager reconstructs and persists the request. Schema v2 would need an explicit historical-key model, rules for one active key per identity, policy history/replacement semantics, and migration fixtures before same-identity rotation can be considered.

## P013D-2B-3 implementation

The privileged manager now persists the same v1 rotation semantics atomically
within one roots generation. Forward recovery retains the old revoked record
and completes the new active record; package rollback cannot restore old root
bytes. No identity reuse, automatic policy transfer or schema migration occurs.
See [recovery invariants](builder-trust-recovery.md).
