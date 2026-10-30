# Builder key rotation identity semantics

The existing v1 store requires globally unique signer identities, including revoked records. That interpretation remains unchanged. Retaining multiple revoked historical keys under one signer identity while permitting at most one active key requires a versioned schema migration and complete fixtures before it can be accepted. Key IDs remain unique and a revoked key must never be implicitly reactivated. Rotation must not expand builder authority. No rotation or migration writer is implemented here.
