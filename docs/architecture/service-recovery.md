# Service recovery (P008)

The controller persists a bounded record at `/var/lib/ios-unsandboxed/service-registration`:

```text
ios-unsandboxed-service
schema_version=1
label=com.ios-unsandboxed.daemon
state=registered
```

Allowed states while the record exists are `registering`, `registered`, `stopping`, and `unregistering`. The record is removed after verified unregister. This record describes service registration only. It does not extend or authorize execution state; `install-state` remains byte-for-byte schema v1 with `execution_activation=disabled`.

A separate fixed-format journal at `service-transaction` records only the same fixed label and a bounded lifecycle stage (`registering`, `starting`, `stopping`, or `unregistering`). It contains no executable command or user data. The helper serializes mutations using P007's advisory lock. Recovery verifies the journal, installation manifest, staged plist, active plist contents and owner, and current launchd label query. It never replays a journal command.

`manager.sh service recover` is read-only. `manager.sh service recover --apply --confirm` reconciles a verified active plist and job state, removes a verified partial active plist only for interrupted registration or unregister when launchd verifiably reports the label absent, and clears a complete journal. It removes only a verified same-directory staging file or a partial prefix of the verified template. A journal from start/stop with an absent job, corrupt metadata, unsupported launchctl state, a foreign active file, or a loaded job without the owned plist fails closed and leaves evidence for manual review.

Operations have a five-second launchctl bound; `start` also has a five-second bounded PING v1 readiness check. `stop` requests the exact label through launchctl and waits for both its PID column to become stopped and the project IPC socket to stop responding. `unregister` unloads only the exact label/plist and removes the active plist only after the job is absent and project IPC no longer responds. A failed stop or ambiguous state prevents file cleanup. Apple's referenced launchctl source warns that `stop` may restart some jobs; target-device behavior remains NOT RUN.

## Manual SSH recovery

Keep an independent SSH session available. If controller recovery fails, inspect without broad process or launchd operations:

```sh
ls -l /Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist
/bin/launchctl list
cat /var/lib/ios-unsandboxed/service-registration
```

Only after verifying the exact project label and plist by hand, an operator may use the device's supported launchctl command to stop or unload this one service. Preserve foreign or modified files and journal contents for review. Do not use `killall`, broad `pkill`, wildcard launchctl commands, SSH service changes, launchd/SpringBoard restarts, or reboot as recovery steps. P008 does not execute this manual path automatically.
