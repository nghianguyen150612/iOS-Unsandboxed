# Builder trust forward recovery

`manager.sh builder-trust recover` inspects without writes. Applying recovery
requires root, the verified installed project, `--apply --confirm`, the shared
P007 lock and no package or publisher transaction. The privileged Rust engine
uses the same P013D-2B-1A classifier as the provider. Phase text never overrides
observed canonical bytes, generation/digest pairs or filesystem safety.

| Observation | Applying recovery |
| --- | --- |
| NO_TRANSACTION, validated complete pair/marker or empty initial pair | No-op |
| PREPARED_OLD_PAIR | Verify both intended new stores and old history; consume necessary stages forward |
| FIRST_STORE_REPLACED | Verify new roots and old policies; finish policies |
| SECOND_STORE_REPLACED | Verify old roots and new policies; finish roots |
| BOTH_STORES_REPLACED | Verify new pair; publish the new marker |
| COMMITTED_PAIR_MARKER_PENDING | Verify new pair; create/publish marker |
| COMPLETE_COMMIT | Sync verified marker/directory; remove verified journal last |
| RECOVERY_REQUIRED with no journal and canonical orphan store stages | Cleanup only under the proof below; never promote orphan bytes |
| RECOVERY_REQUIRED with a journal but missing necessary stage | Preserve evidence; refuse |
| CONFLICTING_STATE / CORRUPT_TRANSACTION / UNSAFE_TRANSACTION_ARTIFACT / UNKNOWN_STATE | Preserve evidence; refuse |

A valid `state.stage.v1` is permitted only alongside a valid journal and a fully
new live pair, and must equal the journal's exact new combined marker. It can
be consumed by recovery after a crash between marker fsync and marker rename.
An unsafe/corrupt or orphan marker stage is preserved.

## Orphan stage cleanup proof

Before journal durability, stages are not mutation authority. Applying recovery
may discard only canonical next-generation orphan store stages when the entire
live state is either absent (first enrollment) or an intact pair matching its
combined marker. All identities and exact entries are revalidated before each
unlink. No live store is touched. A missing marker, half pair, generation
conflict, unsafe entry, truncated stage or unexpected artifact prevents cleanup.
This also handles a journal removed externally before any replacement, provided
the unchanged old pair proof still holds. Deletion of the journal after a live
replacement leaves a marker/pair inconsistency and cannot trigger rollback.

## Revocation and crash invariants

The engine contains no old-store restoration operation. Every replacement uses
the intended new generation and SHA-256 bound by a trusted journal. Old records
still available are reconciled with new records: old key IDs/public keys,
identities and metadata are retained, revoked keys never reactivate, and policy
records either remain identical or become exact retained revoked records with
their derived policy IDs. Revoked policy scope cannot disappear. A consumed
stage is correctly absent after its rename; a missing stage before its required
rename fails closed. Once an old store has been consumed, recovery relies on the
previously validated journal and the new digest; it does not invent old bytes.

Before any recovery replacement, the engine flushes the verified journal and
directory again, then flushes each necessary stage before consuming it. Complete
bytes after a failed fsync never substitute for a successful recovery flush.
Each new invocation resynchronizes a pair/marker that a previous process may
have renamed before directory fsync. A journal remains until the fully new pair
and marker have been verified and synchronized. Repeated successful recovery
is an idempotent no-op. Corruption never converts into a best-effort rollback.
A failure with a retained journal reports `RECOVERY_REQUIRED`, never committed.

Fault checkpoints cover before stages, each stage fsync, before/after journal,
before/after each rename and directory sync, before marker, after marker fsync
and rename, and before/during/after cleanup. Host-only IO fixtures exercise short
writes, ENOSPC after one byte, write/fsync/directory-sync/rename errors. Fault
selection is an explicit host-helper argument requiring an isolated test root;
production Rust has no testing feature and the production C helper cannot call
the test entrypoint. No environment or remote fault override exists.

The provider withholds signer/policy authority for every journal, store stage or
marker stage, even COMPLETE_COMMIT awaiting cleanup. A missing combined marker
also withholds authority; legacy unanchored files remain inspectable/plannable
but do not supply verification authority. No external CI identity or rollback
resistance is inferred from local recovery.
