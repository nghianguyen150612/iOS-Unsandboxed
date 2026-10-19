#ifndef IU_POLICY_H
#define IU_POLICY_H

#include "iu_preflight.h"

#define IU_POLICY_ABI_VERSION UINT32_C(1)
#define IU_POLICY_MAX_DIRECTORIES UINT32_C(8)
#define IU_POLICY_PATH_CAPACITY UINT32_C(1024)

enum iu_policy_outcome_v1 {
    IU_POLICY_ALLOW_ELIGIBLE = 0,
    IU_POLICY_SKIP_NOT_TARGETED = 1,
    IU_POLICY_DENY_DISABLED = 2,
    IU_POLICY_DENY_UNVERIFIED_BACKEND = 3,
    IU_POLICY_DENY_PROTECTED_PATH = 4,
    IU_POLICY_DENY_UNSAFE_FILE = 5,
    IU_POLICY_DENY_IDENTITY_MISMATCH = 6,
    IU_POLICY_DENY_UNSUPPORTED_TARGET = 7,
    IU_POLICY_DENY_INTERNAL_ERROR = 8
};

enum iu_policy_file_type_v1 {
    IU_POLICY_FILE_UNKNOWN = 0,
    IU_POLICY_FILE_REGULAR = 1,
    IU_POLICY_FILE_DIRECTORY = 2,
    IU_POLICY_FILE_OTHER = 3
};

enum iu_policy_inspection_state_v1 {
    IU_POLICY_INSPECTION_UNKNOWN = 0,
    IU_POLICY_INSPECTION_OK = 1,
    IU_POLICY_INSPECTION_ERROR = 2
};

enum iu_policy_inspection_error_v1 {
    IU_POLICY_INSPECTION_ERROR_NONE = 0,
    IU_POLICY_INSPECTION_ERROR_INVALID_ARGUMENT = 1,
    IU_POLICY_INSPECTION_ERROR_PATH = 2,
    IU_POLICY_INSPECTION_ERROR_IO = 3,
    IU_POLICY_INSPECTION_ERROR_IDENTITY = 4
};

struct iu_policy_directory_v1 {
    uint32_t path_length;
    char path[IU_POLICY_PATH_CAPACITY];
    uint32_t owner_uid;
    uint32_t mode;
    uint32_t file_type;
    uint32_t metadata_verified;
};

/* Explicit, in-memory configuration for deterministic tests. It is not an
 * authenticated production authorization source. A future daemon must load
 * and verify persistent policy state itself. */
struct iu_policy_config_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t enabled;
    uint32_t compatibility_status;
    uint32_t expected_owner_uid;
    uint32_t eligible_directory_count;
    struct iu_policy_directory_v1 eligible_directories[IU_POLICY_MAX_DIRECTORIES];
};

/* Facts about a target collected from a bounded path and an opened descriptor.
 * Device/inode fields are fixed-width snapshots, not proof that a later exec
 * will consume the same object. */
struct iu_policy_target_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t inspection_state;
    uint32_t inspection_error;
    uint32_t file_type;
    uint32_t owner_uid;
    uint32_t group_uid;
    uint32_t mode;
    uint32_t link_count;
    uint32_t path_was_symlink;
    uint32_t canonical_path_length;
    char canonical_path[IU_POLICY_PATH_CAPACITY];
    uint64_t path_device;
    uint64_t path_inode;
    uint64_t descriptor_device;
    uint64_t descriptor_inode;
};

struct iu_policy_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t outcome;
    uint32_t reason_code;
};

enum iu_policy_reason_v1 {
    IU_POLICY_REASON_NONE = 0,
    IU_POLICY_REASON_INVALID_CONFIG = 1,
    IU_POLICY_REASON_DISABLED = 2,
    IU_POLICY_REASON_BACKEND_UNVERIFIED = 3,
    IU_POLICY_REASON_PROTECTED_PATH = 4,
    IU_POLICY_REASON_UNSAFE_PATH_OR_FILE = 5,
    IU_POLICY_REASON_FILE_IDENTITY_CHANGED = 6,
    IU_POLICY_REASON_NOT_CONFIGURED = 7,
    IU_POLICY_REASON_UNSUPPORTED_INPUT = 8,
    IU_POLICY_REASON_INSPECTION_FAILED = 9,
    IU_POLICY_REASON_PREFLIGHT_ERROR = 10
};

int32_t iu_policy_inspect_path_v1(const char *path,
                                  uint32_t path_length,
                                  struct iu_policy_target_v1 *target);
int32_t iu_policy_evaluate_v1(const struct iu_policy_config_v1 *config,
                              const struct iu_policy_target_v1 *target,
                              struct iu_policy_result_v1 *result);
const char *iu_policy_outcome_name_v1(uint32_t outcome);

#endif /* IU_POLICY_H */
