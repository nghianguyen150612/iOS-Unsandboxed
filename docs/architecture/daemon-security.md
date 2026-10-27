# Daemon IPC security boundary

## Identity and authorization

For every accepted connection, the server obtains peer UID/GID from the connected socket: Darwin/iOS uses `getpeereid(2)`; Linux host builds use `getsockopt(SO_PEERCRED)`. If credential collection fails, the request is dropped. Request payloads never contain identity fields. P005 `GET_LIFECYCLE_STATUS` returns the authenticated UID/GID to that same peer as diagnostic evidence; it is not an authorization input.

Peer identification, operation authorization, and executable/process identity verification are separate concerns. P004/P005 identify local peers and allow successfully authenticated local UIDs to make read-only status/preflight requests. The production socket is mode `0600`, so normal pathname permissions restrict it to root. This permission is intentional; read-only request semantics do not make the production socket world-readable. Management requests require UID 0 and remain `NOT_IMPLEMENTED` even for root. Launch preparation is always `PERMISSION_DENIED`; no PID/path is accepted and no Amethyst operation is called.

## Socket and cleanup

Production `--serve` requires effective UID 0, validates `/var/run` as a root-owned, non-group/world-writable directory, applies `umask(077)`, and creates the socket as `0600`. A root-owned lock file held with `flock(LOCK_EX|LOCK_NB)` prevents simultaneous production owners. Existing final paths are inspected with `lstat`; symlinks and non-sockets are preserved and rejected. A root-owned socket is probed before stale cleanup; an active listener or ambiguous connection failure is rejected. Shutdown checks socket type, device, inode, and owner against the socket this process created. The lock pathname remains after close so the lock object is not replaced underneath another starter.

The state reader opens the project data directory as a directory without following its final path component, then opens `install-state` relative to that descriptor with `openat`, `O_NOFOLLOW`, and `O_NONBLOCK`. It checks the directory/file UID, GID, exact restrictive mode, regular-file type, link count, size, and descriptor metadata. A raced FIFO does not block the daemon. Only the exact schema-1 disabled record is valid.

## Resource and failure limits

The request and response payload cap is 512 bytes. The listener backlog is four and the server serves one client at a time, so active client work is bounded without per-connection threads. Reads and writes use partial-I/O loops and an absolute two-second deadline per frame transfer. A disconnect, timeout, malformed frame, or credential failure cannot change product state. SIGTERM/SIGINT handlers are installed before socket creation. Signals stop the foreground loop and trigger owned-socket cleanup. Fatal poll/accept errors are logged and return failure after cleanup.

Linux fixtures exercise host `SO_PEERCRED`, expose actual host peer credentials in the lifecycle response, and test management authorization. They do not prove Darwin `getpeereid` behavior on iOS. A same-UID local process can make read-only requests by design; socket mode is an additional local boundary, not a UID allowlist.

## Framing boundary

The server parses one length-delimited request per connection and closes after one response. It rejects trailing bytes visible at the immediate post-frame check. A stream client could race extra bytes after that check. Since all P005 operations are read-only and mutating IDs remain unimplemented, this cannot change product state. Any future mutating operation needs a separately reviewed, unambiguous frame boundary; the current best-effort trailing-byte check is not sufficient authorization for state mutation.

## Out of scope

No endpoint forwards raw Amethyst operations. No arbitrary PID/path, caller-supplied authorization boolean, kernel address, descriptor integer, or private Amethyst struct is accepted. No signing, trust-cache mutation, launch interception, sandbox change, state writer, or execution activation exists. See [service lifecycle](service-lifecycle.md) and [persistent state](persistent-state.md).
