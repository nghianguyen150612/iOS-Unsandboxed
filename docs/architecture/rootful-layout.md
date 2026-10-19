# Rootful filesystem layout

The canonical paths are maintained in [`packaging/rootful/paths.env`](../../packaging/rootful/paths.env). This is a path contract, not an executable installer, and P001 does not source it or write to a device.

| Component | Destination | Planned ownership |
| --- | --- | --- |
| CLI | `/usr/local/bin/ios-unsandboxed` | `root:wheel`, executable |
| CLI alias | `/usr/local/bin/iu` | `root:wheel` symlink to `/usr/local/bin/ios-unsandboxed` |
| Daemon | `/usr/local/bin/ios-unsandboxedd` | `root:wheel`, executable |
| Installer manager | `/var/lib/ios-unsandboxed/manager.sh` | `root:wheel`, restricted to administrators |
| Installation state | `/var/lib/ios-unsandboxed/install-state` | `root:wheel`, restricted to administrators |
| Configuration and project data | `/var/lib/ios-unsandboxed/` | `root:wheel`; future subpaths must define access explicitly |
| Native hooks, if needed | `/usr/local/lib/ios-unsandboxed/` | `root:wheel`; absent in P001 |
| LaunchDaemon definition | `/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist` | `root:wheel`; inactive and absent in P001 |
| Runtime IPC socket | `/var/run/ios-unsandboxedd.sock` | Owned by the service; access policy remains to be designed with IPC |
| Logs | `/var/log/ios-unsandboxed/` | `root:wheel`; access policy to be defined with logging |

## Installation rules

- Install into the rootful filesystem. Do not use an ordinary iOS application container.
- Keep CLI and daemon in `/usr/local/bin`, preserving Procursus conventions and avoiding Apple system executable paths.
- Do not overwrite Apple system files or files owned by Amethyst.
- Do not require a particular interactive shell. The `iu` alias is a filesystem symlink, so SSH and non-interactive commands resolve it consistently.
- The CLI and daemon are planned as root-owned files. P001 does not install them or determine final runtime privilege boundaries.
- Future installation must be atomic, verify backups before replacement, and support rollback and uninstall that restores prior state. These behaviors are not implemented in P001.
- Do not activate the LaunchDaemon or install native hooks as part of P001.
