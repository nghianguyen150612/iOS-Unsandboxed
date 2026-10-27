# Service lifecycle (P005)

P005 adds a foreground C17 service lifecycle foundation. It does not install, load, bootstrap, kickstart, or activate a LaunchDaemon. It does not implement `iu enable` or `iu disable`, launch interception, signing, trust-cache changes, sandbox changes, or executable preparation. Execution activation is fixed to **disabled** in this release.

## Independent status facts

`ios-unsandboxed status` reports these facts separately:

| Fact | Source | Meaning |
|---|---|---|
| Daemon process | Successful IPC response | A daemon answered; this does not mean execution is enabled or that launchd owns it. |
| IPC reachability | Successful local request | The socket accepted the CLI and returned a valid response. |
| Daemon executable and plist files | Local `lstat` checks | Files are present as regular files. This does not prove that launchd loaded the job. |
| Installation record | Valid root-owned state file | The state file records `service_installation=installed`; it is an installation marker, not authorization. |
| State file/schema | Daemon's bounded, read-only loader | Reports missing, valid, unsafe, unsupported, corrupt, or I/O-error state. |
| Amethyst compatibility | Fresh P003 preflight | Component presence and platform facts are not binary provenance or a live hook check. |
| Execution activation | P005 implementation invariant | Always disabled. The state parser accepts only the literal `disabled`. |
| Device acceptance | Project validation record | `NOT TESTED` until physical-device evidence is added. |

When IPC is unavailable, the CLI reports activation, state, and schema as `UNKNOWN`; it does not read a local file and guess the daemon's persistent state. `doctor` remains a local diagnostic.

The P004 `GET_STATUS` request and its 8-byte response are unchanged. P005 adds request ID 4, `GET_LIFECYCLE_STATUS`, with its own payload ABI. P005 CLI can fall back to P004 status when an older daemon answers `NOT_IMPLEMENTED` for the new request.

## Foreground daemon and dependencies

Production starts only through the explicit `ios-unsandboxedd --serve` option. The process stays in the foreground and does not fork or double-daemonize. It requires effective UID 0 and a pre-existing `root:wheel` `/var/run` parent without group/world write bits. It creates `/var/run/ios-unsandboxedd.sock` as `root:wheel` mode `0600`, and a root-owned `0600` lock file prevents a second production owner.

The daemon installs SIGTERM and SIGINT handlers before socket setup. A normal signal stops the poll loop, closes the listener, removes only the socket inode created by this process, and releases the lock. A fatal poll or accept error is logged to stderr, follows the same owned-socket cleanup, and exits unsuccessfully. The lock pathname is retained so that another process cannot race lock-file replacement. Stale socket cleanup is limited to a root-owned socket in the validated runtime directory after a failed connection and an inode recheck.

The persistent state file and Amethyst components are diagnostic dependencies, not startup dependencies. If either is missing or invalid, the read-only daemon can still answer status requests, reports the condition, and remains disabled. It does not load Amethyst code or require a jailbreak-private service. `/var/run` is a required startup dependency; if it is missing or unsafe, startup fails in place and the daemon does not create a replacement directory.

Startup and failure logs contain fixed messages and OS errors only; request payloads and secrets are not logged. The LaunchDaemon redirects stdout/stderr to the project log directory, which a future manager must create with root ownership and restrictive permissions before loading the job.

## Passive LaunchDaemon package

The reviewable template is [`packaging/rootful/com.ios-unsandboxed.daemon.plist`](../../packaging/rootful/com.ios-unsandboxed.daemon.plist). Its label is `com.ios-unsandboxed.daemon`, it runs `/usr/local/bin/ios-unsandboxedd --serve` as `root:wheel`, uses `RunAtLoad=true`, and sets `KeepAlive=false`. It does not use launchd socket activation. A daemon exit is not configured for an unrestricted restart loop.

The plist is packaging material only. P005 does not copy it to `/Library/LaunchDaemons`, invoke `launchctl`, or enable a job. Python's host `plistlib` parses and checks its keys in CI; that establishes XML/property-list syntax and the intended field values only. It does not establish that iOS 12.5.7 launchd accepts or starts the job. The `RunAtLoad`, identity, log-path, and shutdown behavior remain device gates.

Before a future manager loads this job, it must verify the daemon and CLI files, the `iu` symlink, state/data/native/log directories, state permissions, and log paths. It must preserve backups and be able to remove or restore only project-owned files. It must never change Apple or Amethyst-owned jobs and must not install an app container.

## Socket authorization

Read-only IPC requests require successful kernel peer credential collection. Darwin/iOS uses `getpeereid(2)`; Linux uses `SO_PEERCRED`. The daemon returns the credentials it authenticated in the P005 lifecycle response so the device check can record actual UID/GID values.

The production socket remains `0600`, so normal pathname access is root-only even though the read-only operation authorizer accepts any successfully authenticated local UID. This is deliberate. The protocol does not make privileged access available: management request IDs remain `NOT_IMPLEMENTED` for root and are denied to non-root peers; launch preparation remains denied.

If non-root SSH diagnostics are needed later, evaluate a separately provisioned `ios-unsandboxed-readonly` group and a `root:ios-unsandboxed-readonly` `0660` socket. Kernel pathname permissions must enforce membership; `getpeereid` exposes effective UID/GID and must not be treated as a supplementary-group query. Tests must prove root access, selected group-member access to read-only IDs only, nonmember denial, and continued root-only management authorization. P005 does not change socket mode or create a group.

## P006 prerequisites

- Verify the plist and `/var/run` behavior on iOS 12.5.7.
- Record the exact Amethyst package/build provenance and live component state from the device.
- Complete the root/non-root SSH and native `getpeereid` matrix without changing SSH configuration.
- Review an authenticated root-owned state mutation operation before any state writer exists.
- Keep execution disabled until compatibility, authorization, and launch integration receive separate review and device evidence.
