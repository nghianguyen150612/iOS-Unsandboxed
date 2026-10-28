#ifndef IU_AMETHYST_CAPABILITIES_H
#define IU_AMETHYST_CAPABILITIES_H

#include <stdint.h>

#define IU_AME_CAPABILITY_ABI_VERSION UINT32_C(1)
#define IU_AME_CAPABILITY_COUNT UINT32_C(14)
#define IU_AME_CAPABILITY_RECORD_V1_SIZE UINT32_C(20)
#define IU_AME_CAPABILITY_SET_V1_SIZE UINT32_C(296)

enum iu_ame_capability_id_v1 {
    IU_AME_CAP_READ_ONLY_PROBE = 1,
    IU_AME_CAP_BUILD_IDENTIFICATION = 2,
    IU_AME_CAP_LAUNCHD_HOOK_DETECTION = 3,
    IU_AME_CAP_BASE_HOOK_DETECTION = 4,
    IU_AME_CAP_SSH_EXEC_PATH_COVERAGE = 5,
    IU_AME_CAP_ARM64_MACHO_INSPECTION = 6,
    IU_AME_CAP_SIGNED_MACHO_PREPARATION = 7,
    IU_AME_CAP_ADHOC_MACHO_PREPARATION = 8,
    IU_AME_CAP_MALFORMED_SIGNATURE_HANDLING = 9,
    IU_AME_CAP_NO_LC_CODE_SIGNATURE_HANDLING = 10,
    IU_AME_CAP_PROCESS_UNSANDBOX = 11,
    IU_AME_CAP_EXECVE_INTERCEPTION = 12,
    IU_AME_CAP_POSIX_SPAWN_INTERCEPTION = 13,
    IU_AME_CAP_FUTURE_EXECUTION_ADAPTER = 14
};

enum iu_ame_capability_status_v1 {
    IU_AME_CAP_SOURCE_CONFIRMED = 1,
    IU_AME_CAP_RUNTIME_VERIFIED = 2,
    IU_AME_CAP_UNVERIFIED = 3,
    IU_AME_CAP_UNSUPPORTED = 4,
    IU_AME_CAP_NOT_IMPLEMENTED = 5,
    IU_AME_CAP_BLOCKED = 6
};

enum iu_ame_evidence_type_v1 {
    IU_AME_EVIDENCE_NONE = 0,
    IU_AME_EVIDENCE_PINNED_SOURCE_AUDIT = 1,
    IU_AME_EVIDENCE_FILESYSTEM_METADATA = 2,
    IU_AME_EVIDENCE_BINARY_IDENTITY = 3,
    IU_AME_EVIDENCE_HOST_FIXTURE = 4,
    IU_AME_EVIDENCE_DEVICE_OBSERVATION = 5
};

struct iu_ame_capability_record_v1 {
    uint32_t struct_size;
    uint32_t capability_id;
    uint32_t status;
    uint32_t evidence_type;
    uint32_t evidence_flags;
};

struct iu_ame_capability_set_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t record_count;
    uint32_t reserved;
    struct iu_ame_capability_record_v1 records[IU_AME_CAPABILITY_COUNT];
};

int32_t iu_ame_capabilities_v1(struct iu_ame_capability_set_v1 *result);
const char *iu_ame_capability_status_name_v1(uint32_t status);
const char *iu_ame_capability_name_v1(uint32_t capability_id);

#endif
