# Daemon IPC security boundary

## Identity and authorization

For every accepted connection, the server obtains the peer UID/GID from the connected socket: Darwin/iOS uses `getpeereid(2)`; Linux host builds use `getsockopt(SO_PEERCRED)`. If credential collection fails, the request is dropped. Request payloads never contain identity fields.

Peer identification, operation authorization, and executable/process identity verification are separate concerns. P004 identifies local peers and allows any successfully identified local UID to make read-only status/preflight requests. Management requests require UID 0 and are still rejected as `NOT_IMPLEMENTED`, because authentication does not create an implementation. Launch preparation is always `PERMISSION_DENIED`; no PID/path is accepted and no Amethyst operation is called.

## Socket

Production `--serve` is restricted to effective UID 0, validates the `/var/run` parent as a root-owned non-group/world-writable directory, applies `umask(077)`, and sets socket mode `0600`. A root-owned lock file held with `flock(LOCK_EX|LOCK_NB)` prevents simultaneous production owners. Existing final paths are inspected with `lstat`; symlinks and non-sockets are preserved and rejected. A root-owned socket is probed before stale cleanup; a live listener or ambiguous failure is rejected. On shutdown, cleanup checks socket type, device, inode, and owner against the socket created by this process.

No permission setting is treated as peer authentication. P004 writes no product state and never invokes a shell.

## Resource and failure limits

The request and response payload cap is 512 bytes. The listener backlog is four and the server serves one client at a time, so active client work is bounded without per-connection threads. Reads and writes use partial-I/O loops and an absolute two-second deadline per frame transfer. A disconnect, timeout, malformed frame, or credential failure cannot change product state. SIGTERM/SIGINT stop the foreground loop and trigger owned-socket cleanup.

Linux fixture tests exercise host `SO_PEERCRED` and simulated authorization inputs. They do not prove Darwin `getpeereid` behavior on iOS. A same-UID local process can still make read-only requests by design; socket mode is an additional local boundary, not a user allowlist.

## Out of scope

No endpoint forwards raw Amethyst operations. No arbitrary PID/path, caller authorization boolean, kernel address, descriptor integer, or private Amethyst struct is accepted. No signing, trust-cache mutation, launch interception, sandbox change, persistent activation state, or lifecycle state transition exists.
