# Privileged builder trust persistence (P013D-2B-3)

The rootful `manager.sh builder-trust` group enters the existing C17 installer
helper. C validates the command grammar, explicit `--apply --confirm`, effective
root, reference platform, verified installation and conflicting transactions,
and holds the P007 exclusive fcntl lock for the entire operation. On iOS the
held project data descriptor comes through the verified `/private/var` backing
path. No environment variable selects a production store or fault mode.

`native/include/iu_builder_trust_manager.h` defines a 64-byte ABI v1 request:
version, size, held data descriptor, expected UID/GID, apply bit, four borrowed
argv pointers and a zero reserved word. C asserts size and offsets; Rust uses
`repr(C)` and asserts size. Host C ABI fixtures reject version/size/flags,
foreign ownership, nonzero reserved fields and unknown requests. The static
library is linked into the helper for host and ARM64 iOS 12.0. No executable is
spawned for validation. Rust panics are caught at the C boundary.

The library reuses the exact bounded JSON parser, canonical schemas and
P013D-2B-2 mutation logic. It reads public-key/policy input itself, derives key
and policy IDs, reconstructs both proposed documents, validates the final
canonical stores, checks generations/digests, and generates the v1 journal and
marker internally. CLI output, supplied digests, journals and authority flags
are never request inputs. Canonical Ed25519 enrollment also rejects small-order
keys and noncanonical Edwards-Y encodings (Y >= 2^255-19).

## Commands

```
manager.sh builder-trust help
manager.sh builder-trust status
manager.sh builder-trust list
manager.sh builder-trust inspect SIGNER_ID
manager.sh builder-trust add-signer PUBLIC_KEY_FILE --identity SIGNER_ID
manager.sh builder-trust revoke-signer KEY_ID
manager.sh builder-trust rotate-signer OLD_KEY_ID NEW_PUBLIC_KEY_FILE --new-identity SIGNER_ID
manager.sh builder-trust add-policy POLICY_FILE
manager.sh builder-trust revoke-policy POLICY_ID
manager.sh builder-trust recover
```

Mutations and recovery are read-only unless both `--apply --confirm` occur.
Read-only administration never creates directories. Public-key files contain
64 lowercase hexadecimal characters plus one LF; no private key is created.
Policies use the existing exact seven-field request schema. Unknown arguments,
identities, operations, duplicate keys/identities, count limits and generation
overflow fail before persistence. Rotating a signer requires a new identity;
policies are retained without transfer. Policy revocation recalculates the
state-dependent policy ID; either the old active ID or current revoked ID can
be used for an idempotent repeated revocation. Re-enrollment cannot reactivate
retained revoked keys or policy scopes.

## Exact write ordering

1. Under the shared lock, verify the installed project and absence of package
   and publisher transactions. Verify the builder directory, complete live pair
   and matching marker, or the wholly absent initial pair; reject artifacts.
2. Read explicit request input; reconstruct and validate canonical proposed
   stores, digests, next generations, journal and marker.
3. Revalidate the complete old snapshot (bytes, metadata, inode identities and
   directory identity). Create only changed `roots.stage.v1` and/or
   `policies.stage.v1` using `openat(O_EXCL|O_NOFOLLOW|O_CLOEXEC)`.
4. Write bounded bytes with short-write/EINTR handling. Set/verify private
   owner/group/mode and one hard link. `fsync` each completed stage; reopen and
   compare its bytes and inode. `fsync` the trust directory.
5. Create `transaction.v1` exclusively, write canonical prepared v1 bytes,
   `fsync` the journal, then `fsync` the directory. Revalidate the exact old live
   entries and stages and require `PREPARED_OLD_PAIR`.
6. Revalidate journal, live and staged evidence, including old tombstones where
   old bytes remain. Consume a validated roots stage with `renameat`, then
   `fsync` the directory. Repeat for a changed policy store. Each rename has its
   own durability boundary; there is no atomic two-file rename assumption.
7. Revalidate both new generations/digests. Create `state.stage.v1` exclusively,
   write and `fsync` the canonical combined marker, and `fsync` the directory.
   Revalidate, rename onto a known safe old/absent `state.v1`, then `fsync` the
   directory. Reopen and verify the complete new pair and marker.
8. Sync the verified marker and directory again (including retries after a
   prior process died immediately after rename). Remove only verified known
   leftover marker stage, if present, then the verified journal last; synchronize
   each cleanup. Revalidate the settled pair. Only now report `COMMITTED`.

The additional fixed `state.stage.v1` is recognized and bounded by both the
reader and recovery engine. No PID/random temporary trust filenames exist.
Unknown files, symlinks, nonregular files, hard links, foreign owners/groups,
incorrect 0700/0600 modes and oversized entries fail closed. Snapshot checks
reopen entries relative to held descriptors before writes/renames/unlinks.
Cooperating root administrators must use the P007 lock. An arbitrary privileged
attacker can still replace all local files/history; this is not a defense
against such an attacker or an uncooperative root process racing syscalls.

## Filesystem assumptions and limits

This protocol requires regular-file and directory `fsync`, atomic same-directory
rename and truthful filesystem/storage flush ordering. Builder code treats every
sync failure as an error, including unsupported directory synchronization; it
does not inherit the installer's historical EINVAL/ENOTSUP sync exception.
An interrupted write can leave truncated/corrupt evidence; recovery preserves
it rather than guessing. Simulated process exits validate reachable ordering,
not power-cut behavior or physical flash durability. Rootful device durability
and filesystem behavior still require physical-device qualification.

Local persistence proves transaction consistency and explicit local configuration
only. Independent trust establishment and rollback protection remain
`UNVERIFIED`; build origin stays `BUILD_ORIGIN_UNVERIFIED`, protected origin
`UNKNOWN`, Amethyst runtime `UNVERIFIED`, launch boundary `NOT IMPLEMENTED`,
execution `DISABLED`, and operational authorization `FALSE`.
