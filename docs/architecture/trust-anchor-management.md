# P013 trust-anchor storage

The production reader looks only at `/var/lib/ios-unsandboxed/trusted-publishers/store.v1`. The containing directory must be owned by uid/gid 0 and mode 0700. The file must be a regular, single-link, non-symlink file owned by uid/gid 0, mode 0600, and at most 16 KiB. Schema versions other than 1, malformed metadata, duplicate IDs, and more than 64 keys deny trust.

The reader traverses from an open root descriptor using `openat` and `O_NOFOLLOW`, retains each directory descriptor, and checks the directory entries again after reading. On iOS it uses the fixed `/private/var` backing path for `/var`; other hosts use `/var`. File identity, ownership, mode, link count, size, and nanosecond timestamps are compared before and after reading. This is a snapshot, not a guarantee that the store cannot change after verification.

The canonical ASCII/LF format is:

```text
ios-unsandboxed-trust-store
schema_version=1
generation=1
key_count=1
key_0=<key-id>|ed25519|<64-lowercase-hex-public-key>|publisher|<publisher-id>|active
```

Records have contiguous indexes and strictly ascending key IDs. Key ID is the first 16 bytes of SHA-256(public key), lowercase hex. Stores previously accepted in a different order now fail closed and require deliberate administrator review before reordering. `active` and `revoked` are explicit states. The only authority scope implemented is the exact publisher identity in the record. A publisher key cannot establish source/build origin or claim an artifact is non-protected.

Add/revoke/rotation management uses a versioned transaction journal and staged canonical store. The journal binds old and new generations and SHA-256 digests; the store replacement is atomic within the trust directory. The journal is durable before the final rename where directory fsync is supported. The precise filesystem limit is documented in [trust transactions](trust-transactions.md).

## P013B-2 manager

`manager.sh trust status|list|plan|recover` inspects without writing. Use `trust add-key FILE --publisher ID`, `trust revoke-key ID`, or `trust rotate-key OLD_ID FILE --publisher ID`; append both `--apply --confirm` to persist. FILE contains 64 lowercase public-key hex digits and LF. Trust changes require a verified installed package and the shared installer lock. Repeated revocation is a no-op. Rotation revokes the old key and enrolls the new key in one generation. `trust recover --apply --confirm` completes a verified prepared operation or finalizes a verified committed one; conflicting and unjournaled artifacts remain untouched. Pending state blocks the Rust verifier and package mutations. See [trust recovery](trust-recovery.md).

The verifier reports `TRUST_TRANSACTION_PENDING` when the journal or fixed staged artifacts exist or their safety cannot be established. It also compares `generation.v1` with the canonical store when that local marker exists and rejects a generation/digest mismatch. It does not recover or mutate the store. A filesystem-only generation is not an independent rollback anchor; `ROLLBACK_PROTECTION_UNVERIFIED` remains the honest status.
