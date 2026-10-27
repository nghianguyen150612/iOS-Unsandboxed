# Recovery and rollback (P005)

P005 adds no installer, state writer, launch hook, signing path, trust-cache operation, kernel operation, or sandbox mutation. Recovery uses the existing SSH route and the local `doctor`/`--probe` diagnostics; it does not depend on the experimental execution engine.

## Recovery cases

| Condition | Safe response |
|---|---|
| Daemon crash | Check `ios-unsandboxed status`, then `ios-unsandboxedd --probe`. A process crash does not make activation enabled. A stale project socket is removed only by a later explicit daemon start after the root-owned path and inode checks pass. |
| Socket startup failure | Read stderr/launchd stderr logs. Check `/var/run` ownership/mode and the exact socket/lock file. Do not recursively change `/var/run`; do not delete a path that is not a project-owned socket. |
| Stale socket | The foreground daemon probes the existing root-owned socket. An active or ambiguous listener causes startup failure. A refused/missing endpoint is rechecked by device/inode/owner before only that stale socket is unlinked. |
| Missing runtime directory | Startup fails. P005 does not create or chmod the system runtime directory. A future installer must follow validated Procursus/iOS layout requirements. |
| Missing/corrupt/unsafe state | Status reports the exact state. The daemon remains disabled. Preserve the file for review; do not repair it by accepting unknown keys or copying user-provided flags. A future manager can restore a verified backup or write a fresh disabled schema under separate review. |
| Unsupported schema | Fail closed and report the version. P005 performs no automatic migration. Recovery requires a reviewed version-aware manager or restoring a known schema-1 disabled backup. |
| Interrupted state write | P005 has no production writer. Under the documented future atomic contract, a crash before rename leaves the old canonical file, and a crash after rename leaves the complete replacement. Orphan temporary files are ignored; cleanup must verify project ownership and must not remove arbitrary files. |
| Missing Amethyst components | Read-only service status and preflight remain available when the socket can start. Compatibility stays missing/unverified. This cannot set activation or trigger an Amethyst action. |
| Device reboot | The passive plist is not installed or loaded by P005, so no service starts automatically from this change. Run `doctor`/`--probe` over the existing SSH route, check the socket, and record state. Reboot and jailbreak-restart behavior is a device gate, not host evidence. |
| Jailbreak environment restart | If the daemon is unavailable, keep the ordinary SSH route and use local diagnostics. P005 does not assume Procursus or Amethyst startup ordering and does not modify their jobs. |
| Partial future upgrade | P005 has no installer. A future manager must stage and verify new project files beside the active set, retain checksummed backups, update the state marker last, and roll back only files it owns. It must not load the plist until the entire reviewed installation is complete. |
| LaunchDaemon startup failure | The plist directs stderr to `/var/log/ios-unsandboxed/daemon.stderr.log`; inspect it over SSH. Validate the binary, log directory, runtime directory, ownership, and plist syntax. Do not repeatedly kickstart or enable a restart loop. |

`ios-unsandboxed doctor` is local and does not require the daemon. `ios-unsandboxed status` reports state and activation as `UNKNOWN` if it cannot reach IPC. `enable` and `disable` remain explicit no-op errors.

## Rollback boundary

The P005 code and packaging template are reversible project-owned repository changes. On a future installed device, rollback may remove or restore only verified project-owned CLI/daemon files, symlink, state/data files, native libraries, logs, plist, and the exact socket/lock artifacts after verifying their identities and that no process owns them. P005 itself writes none of those installation paths.

This project has no proven restoration mechanism for Amethyst trust-cache entries, vnode-attached code-signing state, kernel-resident changes, process sandbox changes, or modifications owned by Amethyst. P005 performs none of these actions and makes no claim that a filesystem rollback could undo them. SSH remains a separate recovery route; neither an execution failure nor a failed preflight should require the experimental engine to restore access.
