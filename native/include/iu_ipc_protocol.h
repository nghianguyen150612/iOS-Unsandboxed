#ifndef IU_IPC_PROTOCOL_H
#define IU_IPC_PROTOCOL_H

#include <stdint.h>

/* Wire format: 20 byte header; all integers are unsigned big endian.
 * Offsets: magic[0..4], version u16@4, type u16@6, request_id u32@8,
 * payload_length u32@12, status u32@16. Requests require status=0. */
#define IU_IPC_PROTOCOL_VERSION UINT16_C(1)
#define IU_IPC_HEADER_SIZE 20U
#define IU_IPC_MAX_PAYLOAD 512U
#define IU_IPC_MAX_FRAME (IU_IPC_HEADER_SIZE + IU_IPC_MAX_PAYLOAD)
#define IU_IPC_MAGIC "IUIP"
#define IU_IPC_RESPONSE_BIT UINT16_C(0x8000)

enum iu_ipc_type {
    IU_IPC_PING = 1,
    IU_IPC_GET_STATUS = 2,
    IU_IPC_GET_PREFLIGHT = 3,
    IU_IPC_GET_LIFECYCLE_STATUS = 4,
    IU_IPC_ENABLE = 0x100,
    IU_IPC_DISABLE = 0x101,
    IU_IPC_SET_POLICY = 0x102,
    IU_IPC_PREPARE_LAUNCH = 0x200
};

enum iu_ipc_status {
    IU_IPC_SUCCESS = 0,
    IU_IPC_UNSUPPORTED_VERSION = 1,
    IU_IPC_INVALID_REQUEST = 2,
    IU_IPC_PERMISSION_DENIED = 3,
    IU_IPC_NOT_IMPLEMENTED = 4,
    IU_IPC_SERVICE_UNAVAILABLE = 5,
    IU_IPC_PREFLIGHT_UNVERIFIED = 6,
    IU_IPC_UNSUPPORTED_PLATFORM = 7,
    IU_IPC_INTERNAL_ERROR = 8,
    IU_IPC_TIMEOUT = 9
};

#endif
