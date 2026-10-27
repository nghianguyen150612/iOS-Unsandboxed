# Rootful filesystem layout

The canonical paths are maintained in [`packaging/rootful/paths.env`](../../packaging/rootful/paths.env). This is a path contract, not an executable installer, and P001 does not source it or write to a device.

| Component | Destination | Planned ownership |
| --- | --- | --- |
| CLI | `/usr/local/bin/ios-unsandboxed` | `root:wheel`, executable |
| CLI alias | `/usr/local/bin/iu` | `root:wheel` symlink to `/usr/local/bin/ios-unsandboxed` |
| Daemon | `/usr/local/bin/ios-unsandboxedd` | `root:wheel`, executable |
| Installer manager | `/var/lib/ios-unsandboxed/manager.sh` | `root:wheel`, mode `0700`, restricted to administrators; future installer only |
| Installation state | `/var/lib/ios-unsandboxed/install-state` | `root:wheel`, file mode `0600`; schema 1 is always execution-disabled |
| Configuration and project data | `/var/lib/ios-unsandboxed/` | `root:wheel`, directory mode `0700`; future subpaths must define access explicitly |
| Native hooks, if needed | `/usr/local/lib/ios-unsandboxed/` | `root:wheel`; absent in P001 |
| LaunchDaemon definition | `/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist` | `root:wheel`; inactive and absent in P001 |
| Runtime IPC socket | `/var/run/ios-unsandboxedd.sock` | `root:wheel`, mode `0600`; root-only by pathname |
| Logs | `/var/log/ios-unsandboxed/` | `root:wheel`, directory mode `0700`; files created by launchd under this directory |

## Installation rules

- Install into the rootful filesystem. Do not use an ordinary iOS application container.
- Keep CLI and daemon in `/usr/local/bin`, preserving Procursus conventions and avoiding Apple system executable paths.
- Do not overwrite Apple system files or files owned by Amethyst.
- Do not require a particular interactive shell. The `iu` alias is a filesystem symlink, so SSH and non-interactive commands resolve it consistently.
- The CLI and daemon are planned as root-owned files. P001 does not install them or determine final runtime privilege boundaries.
- Future installation must be atomic, verify backups before replacement, and support rollback and uninstall that restores prior state. These behaviors are not implemented in P001.
- Do not activate the LaunchDaemon or install native hooks as part of P001.
