#ifndef IU_EXECUTION_PLANNER_H
#define IU_EXECUTION_PLANNER_H

#include "iu_amethyst_adapter.h"
#include <stdint.h>

#define IU_EXECUTION_PLAN_ABI_VERSION UINT32_C(1)
#define IU_EXECUTION_PLAN_PATH_CAPACITY IU_POLICY_PATH_CAPACITY
#define IU_EXECUTION_PLAN_SHA256_SIZE IU_AME_SHA256_SIZE
#define IU_EXECUTION_PLAN_V1_SIZE UINT32_C(1232)

enum iu_execution_plan_error_v1 {
    IU_EXECUTION_PLAN_ERROR_NONE = 0,
    IU_EXECUTION_PLAN_ERROR_INVALID_ARGUMENT = 1,
    IU_EXECUTION_PLAN_ERROR_ABI = 2,
    IU_EXECUTION_PLAN_ERROR_PATH = 3,
    IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE = 4,
    IU_EXECUTION_PLAN_ERROR_IO = 5,
    IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED = 6,
    IU_EXECUTION_PLAN_ERROR_INTERNAL = 7
};

enum iu_execution_preparation_v1 {
    IU_EXECUTION_PREP_PARSEABLE_SIGNATURE = 1,
    IU_EXECUTION_PREP_ADHOC_SIGNATURE = 2,
    IU_EXECUTION_PREP_REQUIRES_REPAIR = 3,
    IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND = 4,
    IU_EXECUTION_PREP_UNSUPPORTED_TARGET = 5,
    IU_EXECUTION_PREP_INVALID_BINARY = 6,
    IU_EXECUTION_PREP_UNVERIFIED_RUNTIME = 7
};

enum iu_execution_preview_status_v1 {
    IU_EXECUTION_PREVIEW_INSPECTION_COMPLETE = 1,
    IU_EXECUTION_PREVIEW_INSPECTION_BLOCKED = 2,
    IU_EXECUTION_PREVIEW_NOT_TARGETED = 3,
    IU_EXECUTION_PREVIEW_POLICY_DISABLED = 4,
    IU_EXECUTION_PREVIEW_BACKEND_UNVERIFIED = 5,
    IU_EXECUTION_PREVIEW_PREPARATION_NOT_IMPLEMENTED = 6,
    IU_EXECUTION_PREVIEW_IDENTITY_CHANGED = 7,
    IU_EXECUTION_PREVIEW_UNSUPPORTED_BINARY = 8,
    IU_EXECUTION_PREVIEW_RUNTIME_NOT_VERIFIED = 9
};

enum iu_execution_identity_status_v1 {
    IU_EXECUTION_IDENTITY_UNVERIFIED = 0,
    IU_EXECUTION_IDENTITY_RECORDED = 1,
    IU_EXECUTION_IDENTITY_CHANGED = 2
};

enum iu_execution_inspection_status_v1 {
    IU_EXECUTION_INSPECTION_UNKNOWN = 0,
    IU_EXECUTION_INSPECTION_COMPLETE = 1,
    IU_EXECUTION_INSPECTION_BLOCKED = 2
};

enum iu_execution_missing_prerequisite_v1 {
    IU_EXECUTION_MISSING_TRUSTED_BUILD_IDENTITY = 1,
    IU_EXECUTION_MISSING_HOOK_RUNTIME_EVIDENCE = 2,
    IU_EXECUTION_MISSING_SSH_COVERAGE = 4,
    IU_EXECUTION_MISSING_SIGNATURE_PREPARATION = 8,
    IU_EXECUTION_MISSING_EXECUTION_ADAPTER = 16,
    IU_EXECUTION_MISSING_TRUST_CACHE = 32,
    IU_EXECUTION_MISSING_KERNEL_ACCEPTANCE = 64,
    IU_EXECUTION_MISSING_SANDBOX_OUTCOME = 128,
    IU_EXECUTION_MISSING_DYLD_STARTUP = 256,
    IU_EXECUTION_MISSING_LAUNCH_BOUNDARY = 512
};

struct iu_execution_plan_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t error_code;
    uint32_t inspection_status;
    uint32_t file_type;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint32_t mode;
    uint32_t link_count;
    uint32_t identity_status;
    uint32_t macho_state;
    uint32_t architecture;
    uint32_t macho_filetype;
    uint32_t signature_preparation;
    uint32_t policy_outcome;
    uint32_t policy_reason;
    uint32_t adapter_compatibility;
    uint32_t required_capabilities;
    uint32_t missing_prerequisites;
    uint32_t preview_status;
    uint32_t blocking_reason;
    uint32_t device_runtime_verified;
    uint32_t operational_authorization;
    uint64_t device_number;
    uint64_t inode;
    uint64_t file_size;
    int64_t modification_seconds;
    uint32_t modification_nanoseconds;
    uint32_t reserved0;
    int64_t change_seconds;
    uint32_t change_nanoseconds;
    uint32_t reserved1;
    uint8_t sha256[IU_EXECUTION_PLAN_SHA256_SIZE];
    uint32_t canonical_path_length;
    char canonical_path[IU_EXECUTION_PLAN_PATH_CAPACITY];
    uint32_t reserved[4];
};

_Static_assert(sizeof(struct iu_execution_plan_v1) == IU_EXECUTION_PLAN_V1_SIZE,
               "execution plan ABI size changed");

int32_t iu_execution_plan_create_v1(const char *path, struct iu_execution_plan_v1 *result);
/* The descriptor is borrowed and remains owned by the caller. P010 obtains
 * path/canonicalization evidence separately, but hashes and parses this fd. */
int32_t iu_execution_plan_create_fd_v2(int borrowed_fd, const char *requested_path,
                                       struct iu_execution_plan_v1 *result);
int32_t iu_execution_plan_revalidate_v1(const struct iu_execution_plan_v1 *plan);
const char *iu_execution_plan_preparation_name_v1(uint32_t state);
const char *iu_execution_plan_preview_name_v1(uint32_t status);

#ifdef IU_EXECUTION_PLANNER_TESTING
/* Test-only policy injection. Never compile this interface into production CLI/daemon. */
struct iu_execution_planner_test_context_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct iu_policy_config_v1 policy;
};
int32_t iu_execution_plan_test_evaluate_v1(const struct iu_execution_planner_test_context_v1 *context,
                                            const struct iu_policy_target_v1 *target,
                                            uint32_t *policy_outcome);
#endif

#endif
