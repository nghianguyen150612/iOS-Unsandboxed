# Upgrade, rollback, and uninstall (P007)

P007 updates only the fixed, project-owned rootful files. It does not migrate an unknown manifest schema or accept arbitrary destination paths.

## Upgrade

`upgrade --package DIR --apply` requires a schema-v1 install manifest and verifies each installed file's type, single-link count, owner, mode, and hash before proceeding. The incoming package must be valid and have a strictly newer semantic version. A modified file, changed symlink, unexpected hard link, foreign owner, unsupported manifest/state, unsafe parent, or foreign destination stops the operation.

Before replacing files, the helper captures a complete generation containing all eight owned destinations and a strict backup manifest. It stages replacements first, commits same-directory renames, writes the new ownership manifest, writes the unchanged disabled state schema last, then removes the transaction journal. Rollback generations keep fixed known paths, file type/mode/owner, SHA-256, project version, package generation, signing status, and the preceding backup identifier.

## Rollback

`rollback --apply` validates the current installation and the manifest-selected backup. It verifies the generation identifier, metadata schema, all expected paths, file types, hashes, ownership, modes, and completeness. It snapshots the current version for recovery, restores only the selected backup, writes the install manifest, and writes the disabled state last. Missing, corrupt, incomplete, unsupported, or foreign backups fail without loading files from external locations.

Filesystem rollback restores project-owned files only. P007 creates no kernel-resident trust-cache entries, vnode signing state, process sandbox changes, or Amethyst modifications; filesystem rollback cannot reverse such runtime state if a different component created it.

## Uninstall

`uninstall --apply` first verifies the manifest, state, and every owned file, then saves a complete recovery generation. It removes only the fixed verified project files, removes its manifest, and removes the disabled state last. It cleans only generation directories whose metadata and contents verify. Unknown files, modified files, foreign files, and non-empty shared directories are preserved. The manager never recursively deletes arbitrary data.

P007 never installs the plist into `/Library/LaunchDaemons`. If the active project plist path exists, uninstall is blocked pending the separately reviewed service-lifecycle implementation. The command does not stop a daemon, invoke `launchctl`, or remove Apple/Amethyst jobs. P007 does not create log files or a project log directory; there are no P007 logs to delete. The persistent advisory lock file under `/var/lib` remains so a future manager does not race lock-file replacement.

Repeated uninstall returns success when no verified install manifest remains and leaves any unowned remnants for review. A transaction journal remains after interrupted work; run `recover --apply` before retrying a mutating command.

P011 policy is independent of package generations: valid policy is preserved across upgrades and rollbacks, unsupported/corrupt policy blocks those operations, and uninstall preserves it for review. See [policy recovery](policy-recovery.md).
