# Service registration (P008)

Registration is separate from package installation. `install` and `upgrade` only install the daemon and stage the inactive plist; they never call launchctl or create the active plist.

## Explicit command

```sh
manager.sh service register --apply --confirm --acknowledge-run-at-load
```

The `--confirm` token records explicit user intent in the command. `--acknowledge-run-at-load` is mandatory because the packaged plist intentionally retains `RunAtLoad=true`; launchd may start the daemon during registration. P008 does not modify `RunAtLoad` or `KeepAlive` silently.

Before registration, the helper verifies the P007 install manifest, disabled schema-v1 state, daemon and staged plist entries, staging file type/mode/owner/link count, safe active parent, exact project label through launchd's fixed query, and a safe log directory. It refuses if the job state is unavailable, unsupported, already loaded without its verified active plist, or collides with a foreign active file. Active content is copied from the verified inactive template and installed mode `0644`.

The launchd adapter uses `/bin/launchctl load /Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist`, bounded to five seconds, then queries the read-only job listing for the exact label. Exit zero from `load` alone does not prove registration, process startup, or IPC readiness. `service status` reports the launchd PID column separately from bounded IPC PING v1 responsiveness. Explicit `service start` requires a running PID report and successful bounded IPC readiness after `launchctl start`.

The exact command syntax, active plist behavior, root:wheel ownership, Procursus filesystem paths, signing/trust acceptance, and `RunAtLoad` behavior on iOS 12.5.7 are **NOT RUN** until verified on the reference device. No host result substitutes for those gates.
