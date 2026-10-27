# Project IPC protocol v1

The CLI talks directly to the project daemon over an AF_UNIX `SOCK_STREAM` socket. Production uses `/var/run/ios-unsandboxedd.sock`; there is no TCP listener and this protocol does not speak Amethyst's private jailbreak-server protocol.

## Frame

Each connection carries one request frame and one response frame, then closes. Integers use network byte order (big endian); framing is independent of C struct layout. The fixed header is 20 bytes:

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII magic `IUIP` |
| 4 | 2 | protocol version (`1`) |
| 6 | 2 | message type |
| 8 | 4 | request ID, echoed in response |
| 12 | 4 | payload length, at most 512 |
| 16 | 4 | request status (must be zero); response status code |

The total frame is at most 532 bytes. P004's implemented requests have empty bodies. Unknown future payloads are not interpreted. A response type is request type OR `0x8000`. A response must match the request ID, type, and protocol version.

## Message types

| Request | ID | Body | Response body |
|---|---:|---|---|
| PING | 1 | empty | u8 UTF-8 byte length, then project version (`0.1.0`) |
| GET_STATUS | 2 | empty | 8 bytes: daemon responsive u8, compatibility enum u32, activation u8, interception implemented u8, device acceptance verified u8 |
| GET_PREFLIGHT | 3 | empty | five u32 values (compatibility, system family, architecture, reference-device match, reference-OS match), then four u8-length-prefixed UTF-8 strings (machine, product version, build, kernel release) |
| ENABLE | `0x100` | empty | denied or not implemented |
| DISABLE | `0x101` | empty | denied or not implemented |
| SET_POLICY | `0x102` | empty | denied or not implemented |
| PREPARE_LAUNCH | `0x200` | empty | always denied in P004 |

Preflight fields are individually serialized; raw C result structures are never sent. Status enum values match the C17 preflight ABI in `iu_preflight.h`. Unknown Amethyst revision remains `UNVERIFIED`. Activation/interception/device acceptance are false in P004. PING confirms only an IPC response.

## Stable response statuses

`SUCCESS=0`, `UNSUPPORTED_VERSION=1`, `INVALID_REQUEST=2`, `PERMISSION_DENIED=3`, `NOT_IMPLEMENTED=4`, `SERVICE_UNAVAILABLE=5`, `PREFLIGHT_UNVERIFIED=6`, `UNSUPPORTED_PLATFORM=7`, `INTERNAL_ERROR=8`, `TIMEOUT=9`.

Malformed magic, nonzero request status, unknown/invalid fields, oversized length, unexpected payload/trailing bytes, and truncation are rejected. Invalid v1 requests receive `INVALID_REQUEST` when a safe response can be formed. Unsupported protocol versions receive `UNSUPPORTED_VERSION`. The server closes connections on incomplete frames after the bounded I/O timeout. Clients must reject invalid response status values and mismatched correlation fields.

P005 may reserve additional message IDs only after separate protocol review. No launch, signing, trust-cache, kernel, or unsandbox operation is implemented here.
