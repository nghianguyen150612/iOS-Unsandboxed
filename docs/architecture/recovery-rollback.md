# Recovery and rollback (P005/P007)

P005 added no installer or state writer. P007 adds a project-owned package manager, a journaled filesystem transaction engine, and an installer-only state writer. Neither component adds a launch hook, signing path, trust-cache operation, kernel operation, or sandbox mutation. Recovery uses the existing SSH route and the local `doctor`/`--probe` diagnostics; it does not depend on the experimental execution engine.

## Recovery cases

| Condition | Safe response |
|---|---|
| Daemon crash | Check `ios-unsandboxed status`, then `ios-unsandboxedd --probe`. A process crash does not make activation enabled. A stale project socket is removed only by a later explicit daemon start after the root-owned path and inode checks pass. |
| Socket startup failure | Read stderr/launchd stderr logs. Check `/var/run` ownership/mode and the exact socket/lock file. Do not recursively change `/var/run`; do not delete a path that is not a project-owned socket. |
| Stale socket | The foreground daemon probes the existing root-owned socket. An active or ambiguous listener causes startup failure. A refused/missing endpoint is rechecked by device/inode/owner before only that stale socket is unlinked. |
| Missing runtime directory | Startup fails. P005 does not create or chmod the system runtime directory. A future installer must follow validated Procursus/iOS layout requirements. |
| Missing/corrupt/unsafe state | Status reports the exact state. The daemon remains disabled. Preserve the file for review; do not repair it by accepting unknown keys or copying user-provided flags. P007 can restore only a verified schema-v1 backup as part of `recover --apply` or rollback. |
| Unsupported schema | Fail closed and report the version. P005 performs no automatic migration. Recovery requires a reviewed version-aware manager or restoring a known schema-1 disabled backup. |
| Interrupted state write | P007 uses a same-directory exclusive temporary file and atomic rename. A transaction journal and prior backup let `recover --apply` restore the previous complete generation. Orphan temporary files are cleaned only when their fixed name, owner, type, and link count pass checks; unknown entries are preserved. |
| Missing Amethyst components | Read-only service status and preflight remain available when the socket can start. Compatibility stays missing/unverified. This cannot set activation or trigger an Amethyst action. |
| Device reboot | Package install and upgrade keep the plist staged and do not register a startup job. P008 registration is explicit and its `RunAtLoad`/reboot behavior remains a device gate. Run `doctor`/`--probe` over the existing SSH route, check the socket, and record state. Reboot and jailbreak-restart behavior is not host evidence. |
| Jailbreak environment restart | If the daemon is unavailable, keep the ordinary SSH route and use local diagnostics. P005 does not assume Procursus or Amethyst startup ordering and does not modify their jobs. |
| Partial P007 upgrade | The journal records a verified prior generation. Run `manager.sh status`, then `manager.sh recover --apply`; recovery restores only the old or staged known files. It does not register or load the plist. |
| LaunchDaemon startup failure | The plist directs stderr to `/var/log/ios-unsandboxed/daemon.stderr.log`; inspect it over SSH. Validate the binary, log directory, runtime directory, ownership, and plist syntax. Do not repeatedly kickstart or enable a restart loop. |

`ios-unsandboxed doctor` is local and does not require the daemon. `ios-unsandboxed status` reports state and activation as `UNKNOWN` if it cannot reach IPC. `enable` and `disable` remain explicit no-op errors. The separate rootful manager's `status` inspects only its installation manifest/state and does not claim that launchd or a daemon process is active.

## P007 rollback boundary

The P007 manager records and restores only verified project-owned CLI/daemon files, symlink, manager/helper, path contract, inactive plist copy, schema-v1 state, manifest, backup generations, and transaction artifacts. It does not remove an active plist or stop a service; uninstall is blocked when the active project plist path exists. P007 does not create logs, a runtime socket, or native hooks.

This project has no proven restoration mechanism for Amethyst trust-cache entries, vnode-attached code-signing state, kernel-resident changes, process sandbox changes, or modifications owned by Amethyst. P005 performs none of these actions and makes no claim that a filesystem rollback could undo them. SSH remains a separate recovery route; neither an execution failure nor a failed preflight should require the experimental engine to restore access.
