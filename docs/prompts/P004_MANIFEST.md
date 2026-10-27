# P004 manifest — authenticated CLI–daemon IPC foundation

## Scope and outcome

P004 implements a project-owned version 1 AF_UNIX stream protocol between the Rust CLI and C17 daemon. Only PING, GET_STATUS, and GET_PREFLIGHT are functional. Read-only requests require successful kernel peer credential collection; no caller-supplied identity is trusted. Root-only management identifiers remain unimplemented even for root peers, and launch preparation is denied. No jailbreak activation, interception, signing, trust-cache, kernel, or unsandbox operation is implemented.

## Implementation

- `native/include/iu_ipc_protocol.h`: fixed header constants, IDs, stable errors, size limits.
- `daemon/src/ipc_server.c`: foreground Unix socket listener, bounded protocol parsing, serialized P003 preflight/status, explicit socket ownership and cleanup.
- `daemon/src/peer_auth.c`: Darwin `getpeereid` and Linux `SO_PEERCRED`, separated authorization helpers.
- `cli/src/ipc/`: matching Rust codec, UnixStream client, response checks and `status` output; `doctor` remains local and read-only with optional IPC diagnostics.
- `tests/ipc-integration.py`, `tests/peer-auth-test.c`, Rust unit tests: host framing, service behavior, auth, malformed connections, socket lifecycle.
- Architecture docs define framing, authorization, startup, limits, races, and device gates.

## Protocol

20-byte header with `IUIP` magic; u16 version/type, u32 request ID/payload length/status; all big-endian. Payload limit is 512 bytes. One frame per connection. Implemented operations: PING (version), GET_STATUS (service facts), GET_PREFLIGHT (explicitly serialized fields from existing `iu_preflight_detect_v1`). Error IDs are stable 0–9. C structs are not transmitted directly.

## Verification

Host checks must be recorded from actual commands/CI. Linux credential fixtures do not prove iOS authentication. macOS iOS cross-compilation does not prove device behavior. Physical iPad gates remain NOT RUN unless actual results are added: `/var/run` creation, `getpeereid`, SSH UID authorization, A7 IPC, launchd, installed Amethyst provenance/runtime behavior, signing/trust-cache, unsigned execution, enable/disable, installer/rollback, reboot, and SSH stability.

## P005 prerequisites

Before P005 lifecycle/state work: review this wire contract and server security; validate `/var/run` and `getpeereid` on reference iOS 12.5.7; establish root/non-root SSH peer behavior; design owned persistent state and explicit recovery/rollback; then introduce service integration in a separately reviewed change. No P005 work starts in P004. Any future launch interception must use a separately reviewed Amethyst integration component and independently verified target identity. The uncertain unsigned Mach-O experiment remains blocked pending device-specific evidence and reviewed activation controls.
