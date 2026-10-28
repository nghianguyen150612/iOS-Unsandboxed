# Install transaction states (P007)

The manager uses a fixed path table and a separate install manifest. Package metadata is bounded ASCII data and is never sourced. The C17 helper uses no-follow file opens, descriptor-relative operations, single-link checks, owner/mode checks, and same-directory atomic renames for file replacement. The POSIX shell entrypoint only locates the paired helper and forwards arguments.

## Apply sequence

1. Open and validate the fixed rootful directories; acquire a nonblocking `fcntl` write lock on `/var/lib/.ios-unsandboxed-installer.lock`.
2. Reject an existing transaction journal, unsupported manifest schemas, modified installed files, wrong ownership/modes, unsafe directory parents, and foreign destination collisions.
3. Validate the incoming package manifest, `SHA256SUMS`, all fixed payload hashes and modes, the iOS ARM64 Mach-O headers/minimum target, and the passive plist contract.
4. Stage package files and the exact disabled state record under `/var/lib/ios-unsandboxed/staging/<generation>/`. Hash staged copies again.
5. Copy the current installation into a complete backup generation. The generation is first built under private staging and renamed into `backups/` only after all expected files and metadata are written.
6. Write a root-owned mode `0600` transaction journal with the action, recovery generation, staging generation, package generation, and phase.
7. For each destination, create and verify a unique temporary sibling in the destination directory, set owner and mode, `fsync` it, then rename it over only the absent path or verified project-owned previous file. Sync the containing directory where supported.
8. Verify deployed files. Atomically write `install-manifest`, then write `install-state` last using its own exclusive temporary file and rename. P005's `iu_service_state_load_v1` reader verifies the result.
9. Remove the completed journal and staging generation, then release the kernel lock.

The deployment spans `/usr/local/bin` and `/var/lib`; they may be separate filesystems. Each replacement rename is atomic within its directory, but the full installation is not a single atomic operation. The journal and full prior generation make a mixed deployment recoverable.

## Recovery matrix

| Interruption point | Durable evidence | `recover --apply` action |
| --- | --- | --- |
| Package staging before journal | Private staging generation; no deployed files changed | Remove only fixed-name staging entries with safe type/owner/link metadata. Remove now-empty uninstalled data directories. |
| Backup creation before journal | Backup is assembled under staging and only renamed into `backups/` when complete | Remove partial backup staging; retain any already complete, unreferenced backup for review. |
| Journal written before first destination rename | Journal plus verified recovery backup, or staged first-install manifest | Restore the prior generation, or remove matching files from an interrupted first install. |
| Between destination renames | Journal, staged target, and verified prior snapshot | Restore each destination from the prior generation; current files must match either the old manifest or staged target. Foreign edits are preserved and reported. |
| After manifest write, before disabled state | Journal and prior backup | Restore the prior files, manifest, and state. |
| After state rename, before journal removal | Journal remains authoritative | Restore the prior generation. The transaction is considered committed only after journal removal. |
| Interrupted rollback or uninstall | Journal and a complete snapshot of the pre-operation installation | Restore that snapshot, writing the disabled state last. |

The manager reports a journal in `status` and refuses another install or upgrade until recovery. A corrupt/missing backup or unexpected file is preserved; recovery fails with the journal retained. `recover` never reads arbitrary external restore directories.

## Durability limits

Regular files and metadata are synchronized before rename. The helper synchronizes containing directories where the filesystem supports it. Some Darwin/iOS filesystems may reject directory `fsync` with `EINVAL` or `ENOTSUP`; the helper tolerates only those unsupported-operation errors. Device behavior for the reference iOS filesystem remains NOT RUN. This portable POSIX design does not claim crash atomicity across mounts, power-loss guarantees beyond the journaled sequence, or protection against a malicious concurrent root process.
