# Launchd service controller (P008)

P008 extends the P007 `installer-helper`; it does not add a privileged executable or change the package manifest format. `native/src/iu_service_lifecycle.c` receives a fixed action enum from the existing parser. The parser does not accept a label, launchctl path, plist path, or command string from the caller.

## Commands and authorization

```sh
manager.sh service plan
manager.sh service status
manager.sh service register --apply --confirm --acknowledge-run-at-load
manager.sh service start --apply --confirm
manager.sh service stop --apply --confirm
manager.sh service unregister --apply --confirm
manager.sh service recover --apply --confirm
```

Plan and status are read-only. Every service mutation requires `--apply --confirm`. Production service mutations also require effective UID 0, `hw.machine=iPad4,4`, iOS 12.5.7, the P007 rootful path/owner checks, a valid installation manifest and schema-v1 disabled state, and verified daemon and staged-plist entries. There is no force switch. Fixture mode exists only in the test helper and never silently substitutes for a failed production gate.

Registration requires the separately named `--acknowledge-run-at-load`. The plist semantics remain `RunAtLoad=true`, `KeepAlive=false`. `launchctl load` can therefore start the service during registration. Registration output distinguishes an accepted launchctl request from verified IPC readiness; it does not claim a process started just because launchctl returned zero.

## Adapter and status facts

The narrow adapter calls `/bin/launchctl` through `posix_spawn`, captures bounded stdout/stderr, and applies a five-second bound. It does not use `system()`, a shell, wildcard labels, or global launchd changes. It runs the read-only `list` command and parses only the exact project label row to distinguish loaded, PID-present, and stopped states. Mutations use `load ACTIVE_PLIST`, `start LABEL`, `stop LABEL`, and `unload ACTIVE_PLIST`. The exact iOS 12.5.7 command acceptance and list output format remain physical-device gates; unsupported or ambiguous output fails closed and never triggers a fallback.

The controller design references Apple's open-source [launchctl manual](https://github.com/apple-oss-distributions/launchd/blob/launchd-842.92.1/man/launchctl.1) and [launchctl implementation](https://github.com/apple-oss-distributions/launchd/blob/launchd-842.92.1/support/launchctl.c) at release `launchd-842.92.1`. That source documents the legacy verbs, `list` PID/status/label columns, and warns that `stop` can restart non-demand jobs and is discouraged. It is not verified as the exact iOS 12.5.7 build. P008 uses `unload` directly for unregister to avoid a stop-triggered restart, but ordinary stop behavior still needs device validation.

`service status` reports installation integrity, daemon and staged template integrity, active plist comparison, registration record, label query result, IPC PING v1 responsiveness, and execution activation independently. A successful `list` means only that launchctl reported the job. The daemon process identity is not derived from that fact. IPC responsiveness is checked with a bounded PING v1 request; that does not establish signing/trust acceptance beyond observed response.

The test build has a compile-time mock boundary. When `--test-root` is selected, it requires `IU_LAUNCHCTL_MOCK` pointing to a path under that root; without it, adapter calls fail before spawning. Production builds do not read this environment override.

## Filesystem and safety boundaries

Canonical staged plist:

`/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive`

Canonical active plist:

`/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist`

The P007 manifest verifier checks the staged plist and daemon by fixed path, type, mode, ownership, link count, and hash. The active file must be a single-link regular file, mode `0644`, owner/group matching the verified stage, and byte-identical to the staged template. Foreign or modified files are preserved. The LaunchDaemons parent is checked for safe ownership and no group/other write. Registration creates the project log directory only after authorization and verifies its mode and owner.

No service command touches SSH, Amethyst jobs, other LaunchDaemons, launchd itself, SpringBoard, or device reboot. Stopping this daemon does not undo kernel-resident changes or sandbox state; P008 makes no such changes.

## Limits

The controller does not implement `iu enable`/`iu disable`, privileged IPC management, signing, executable unsandboxing, Amethyst integration, or startup qualification. The current adapter can confirm command status and bounded IPC readiness for `start`; service process PID, code-signing eligibility, RunAtLoad runtime behavior, and iOS launchctl details need device evidence. See [service registration](service-registration.md), [recovery](service-recovery.md), and [P008 gates](../validation/P008_SERVICE_GATES.md).
