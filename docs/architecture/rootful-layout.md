# Rootful filesystem layout

The canonical paths are maintained in [`packaging/rootful/paths.env`](../../packaging/rootful/paths.env). P007 packages the contract and provides a project-owned installer; host fixture success is not device installation evidence.

| Component | Destination | Planned ownership |
| --- | --- | --- |
| CLI | `/usr/local/bin/ios-unsandboxed` | `root:wheel`, executable |
| CLI alias | `/usr/local/bin/iu` | `root:wheel` symlink to `/usr/local/bin/ios-unsandboxed` |
| Daemon | `/usr/local/bin/ios-unsandboxedd` | `root:wheel`, executable |
| Installer manager | `/var/lib/ios-unsandboxed/manager.sh` | `root:wheel`, mode `0700`, restricted to administrators; installed and verified by the P007 manager |
| Installation state | `/var/lib/ios-unsandboxed/install-state` | `root:wheel`, file mode `0600`; schema 1 is always execution-disabled |
| Installation manifest | `/var/lib/ios-unsandboxed/install-manifest` | `root:wheel`, file mode `0600`; strict project-owned schema v1 |
| Installer backups | `/var/lib/ios-unsandboxed/backups/` | `root:wheel`, directory mode `0700`; verified generations only |
| Installer staging | `/var/lib/ios-unsandboxed/staging/` | `root:wheel`, directory mode `0700`; transaction-scoped files |
| Configuration and project data | `/var/lib/ios-unsandboxed/` | `root:wheel`, directory mode `0700`; future subpaths must define access explicitly |
| Native hooks, if needed | `/usr/local/lib/ios-unsandboxed/` | `root:wheel`; absent in P001 |
| Inactive LaunchDaemon copy | `/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive` | `root:wheel`, mode `0600`; staged by P007 |
| Active LaunchDaemon definition | `/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist` | Reserved for a later explicit service lifecycle step; P007 does not install it |
| Runtime IPC socket | `/var/run/ios-unsandboxedd.sock` | `root:wheel`, mode `0600`; root-only by pathname |
| Logs | `/var/log/ios-unsandboxed/` | `root:wheel`, directory mode `0700`; files created by launchd under this directory |

## Installation rules

- Install into the rootful filesystem. Do not use an ordinary iOS application container.
- Keep CLI and daemon in `/usr/local/bin`, preserving Procursus conventions and avoiding Apple system executable paths.
- Do not overwrite Apple system files or files owned by Amethyst.
- Do not require a particular interactive shell. The `iu` alias is a filesystem symlink, so SSH and non-interactive commands resolve it consistently.
- The CLI and daemon are planned as root-owned files. P001 does not install them or determine final runtime privilege boundaries.
- P007 validates a fixed project-owned manifest, stages complete generations, replaces each destination atomically where possible, and retains a journal because one atomic rename cannot span `/usr/local` and `/var` filesystems.
- P007 requires explicit `--apply` for changes, preserves the exact disabled state schema, and never activates the LaunchDaemon or installs native hooks.
- The package's SHA-256 manifest proves consistency with its included metadata, not publisher authenticity. Package signing and device execution remain unverified.
