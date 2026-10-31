# P013 transaction and recovery audit

## Publisher trust transaction

The publisher store uses `store.v1`, `stage.v1`, `transaction.v1`,
`generation.v1`, and fixed temporary names. `scan_artifacts()` inventories the
trust directory; the revised checked enumerator now rejects `readdir()` and
`closedir()` errors. The reader separately loads each recognized artifact and
compares canonical generation/digest values with the journal and generation
anchor.

`validate_transition()` only permits the requested operation: add one active
key, revoke one active key without removing history, or rotate one active key
to one new active key for the same publisher. Recovery proceeds forward from a
validated old store plus exact stage, or finalizes a store already matching the
journal’s new digest. It never writes an old store over the current store.
Missing, unjournaled, corrupt, unsafe, or conflicting evidence is preserved.

`generation.v1` is a local rollback diagnostic. `syncdir()` retains the
existing iOS compatibility behavior for filesystems that reject directory
`fsync` with `EINVAL`/`ENOTSUP`; this is not proof of power-loss durability.

## Builder trust transaction

The builder pair uses `roots.v1`, `policies.v1`, fixed root/policy stages,
`transaction.v1`, `state.stage.v1`, and combined `state.v1`. The reviewed order
is: acquire P007 lock, validate the complete old snapshot, independently
reconstruct the canonical proposal, write and sync stages, write and sync the
journal, revalidate old state, replace each changed store with a directory sync
after each rename, publish and verify the combined marker, sync the settled
pair, then remove verified artifacts with the journal last.

Recovery classifies observed bytes, generations, digests, marker state, and
artifact identities. The supported classifications are prepared old pair,
first store replaced, second store replaced, both stores replaced, marker
pending, and complete commit. A stage is promoted only when an authoritative
journal binds it to the intended new store. A marker stage is usable only with
that journal and the complete new pair. Unknown entries and corrupt evidence
fail closed.

Recovery reconciles old key and policy records with the proposed pair. Key
history remains present; revoked keys cannot become active. Policies remain
identical or become exact retained revoked records with recomputed IDs. Orphan
stages without a journal are cleanup-only and only when the live pair is
settled; they are never mutation authority.

## Interruption coverage and limits

The builder fixtures exercise first enrollment and root-only, policy-only, and
combined mutations; each store replacement order; marker publication and
cleanup; interrupted recovery; repeated recovery; short write, ENOSPC and
write/sync/rename errors; corrupt and missing stages/journals/markers; unsafe
links, ownership/mode and foreign names; stale live data; lock conflicts; and
revocation tombstones. They compare exact canonical bytes, generations and
marker digests.

The publisher and package fixtures also cover prepared/committed trust states,
recovery, conflicting transactions, lock contention, and lifecycle preservation.
The P013E-1 regression adds a deterministic `readdir()` error after a partial
inventory, which previously passed as EOF and now aborts the scan.

Process termination and injected syscall errors do not simulate power loss.
The protocol assumes truthful file and directory synchronization plus atomic
same-directory rename. It does not protect against wholesale replacement by
uncooperative root or kernel compromise. Device validation remains not run.
