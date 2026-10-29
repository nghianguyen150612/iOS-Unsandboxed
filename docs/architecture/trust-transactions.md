# Trust-store transaction journal

P013B-3 serializes publisher-store changes under the P007 lock at `/var/lib/.ios-unsandboxed-installer.lock`. The trust directory remains `/var/lib/ios-unsandboxed/trusted-publishers`; the canonical store remains `store.v1`.

## Journal schema

The fixed journal path is `transaction.v1`. Its bounded canonical ASCII/LF format is:

```text
ios-unsandboxed-trust-transaction
schema_version=1
operation=add|revoke|rotate
old_generation=none|<canonical-uint64>
new_generation=<canonical-uint64>
old_store_sha256=none|<64 lowercase hex>
new_store_sha256=<64 lowercase hex>
stage_name=stage.v1
phase=prepared|committing|committed
```

Field order and values are exact. Unknown schemas, operations, phases, fields, duplicated or reordered fields, noncanonical integers, invalid digests, path separators, and a generation other than `old + 1` are rejected. First enrollment records `old_generation=none` and `old_store_sha256=none`, and must create generation 1. The journal contains no secret or private-key material. Its path is fixed by the helper; callers cannot supply journal contents or names.

The transaction binds the old store generation and SHA-256 plus the new generation and SHA-256. Recovery parses both stores with the canonical v1 codec. Before a pre-rename recovery it checks the exact old bytes and verifies the operation-specific transition: add preserves all old records and adds one active record; revoke changes exactly one active record to revoked; rotation does both in the same generation and preserves the publisher identity.

After commit verification and before journal cleanup, the helper atomically updates `generation.v1` with the last committed generation and store digest:

```text
ios-unsandboxed-trust-generation
schema_version=1
generation=<canonical-uint64>
store_sha256=<64 lowercase hex>
```

The marker detects local rollback or conflicting bytes when it remains present. Older P013B-2 stores without a marker remain readable and are reported with `ROLLBACK_PROTECTION_UNVERIFIED`; the first completed P013B-3 mutation establishes the marker.

## Durable commit sequence

1. Acquire the shared installer lock, verify the installed package and disabled state, and reject package or trust transactions already in progress.
2. Load and validate the current canonical store and prepare the next generation in memory.
3. Create `.stage.tmp` with fixed ownership and mode, write all bytes with EINTR and partial-write handling, fsync the file, verify it, then rename it to `stage.v1` and sync the trust directory.
4. Write the complete journal to `.transaction.tmp`, fsync and verify it, rename it to `transaction.v1`, and sync the trust directory.
5. Re-read the old store, stage, and journal and compare bytes and digests to the prepared transaction.
6. Atomically rename `stage.v1` to `store.v1`, sync the directory, and verify the canonical committed bytes and generation.
7. Atomically write and sync `generation.v1` while the transaction journal still exists.
8. Remove only the verified transaction journal and sync the directory. Unknown and foreign files are never swept.

The current implementation leaves the phase at `prepared`; the phase is descriptive metadata and is never used as proof of commit. Recovery decides from observed file contents. A directory `fsync` returning `EINVAL`, `ENOTSUP`, or `EOPNOTSUPP` is treated as unsupported on that filesystem; other errors fail the operation and retain available evidence. On filesystems that support directory fsync, the file and rename sequence is durably ordered. Where directory fsync is unsupported, the guarantee is limited to file fsync plus atomic same-directory rename and cannot promise survival of sudden power loss.

`execution_activation` remains `disabled`; no operational authorization is produced.
