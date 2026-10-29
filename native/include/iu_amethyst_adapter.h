#ifndef IU_AMETHYST_ADAPTER_H
#define IU_AMETHYST_ADAPTER_H

#include "iu_amethyst_capabilities.h"
#include "iu_policy.h"

#include <stdint.h>
#include <stddef.h>

#define IU_AME_ADAPTER_ABI_VERSION UINT32_C(1)
#define IU_AME_SOURCE_REVISION "61ce86d7d3f00e5395f4d42bebda0e5dce04946a"
#define IU_AME_TAG "v1.1"
#define IU_AME_TEXT_CAPACITY UINT32_C(128)
#define IU_AME_COMPONENT_COUNT UINT32_C(2)
#define IU_AME_MAX_FILE_SIZE UINT64_C(67108864)
#define IU_AME_SHA256_SIZE UINT32_C(32)
#define IU_AME_EVIDENCE_COMPLETE_READ UINT32_C(1)
#define IU_AME_TEXT_V1_SIZE UINT32_C(132)
#define IU_AME_COMPONENT_EVIDENCE_V1_SIZE UINT32_C(112)
#define IU_AME_PROBE_RESULT_V1_SIZE UINT32_C(816)
#define IU_AME_OBSERVED_FACTS_V1_SIZE UINT32_C(444)
#define IU_AME_CAPABILITY_RESULT_V1_SIZE UINT32_C(16)
#define IU_AME_PREVIEW_REQUEST_V1_SIZE UINT32_C(9496)
#define IU_AME_PREVIEW_RESULT_V1_SIZE UINT32_C(36)
#define IU_AME_MACHO_RESULT_V1_SIZE UINT32_C(80)

enum iu_ame_error_v1 {
    IU_AME_ERROR_NONE = 0,
    IU_AME_ERROR_INVALID_ARGUMENT = 1,
    IU_AME_ERROR_ABI_MISMATCH = 2,
    IU_AME_ERROR_INVALID_ENUM = 3,
    IU_AME_ERROR_IO = 4,
    IU_AME_ERROR_UNSAFE_COMPONENT = 5,
    IU_AME_ERROR_BOUNDS = 6,
    IU_AME_ERROR_INTERNAL = 7,
    IU_AME_ERROR_NOT_IMPLEMENTED = 8,
    IU_AME_ERROR_IDENTITY_MISMATCH = 9
};

enum iu_ame_compatibility_v1 {
    IU_AME_SUPPORTED_AND_VERIFIED = 0,
    IU_AME_SOURCE_REVISION_KNOWN = 1,
    IU_AME_INSTALLED_BUILD_UNVERIFIED = 2,
    IU_AME_COMPONENT_MISSING = 3,
    IU_AME_VERSION_MISMATCH = 4,
    IU_AME_UNSUPPORTED_PLATFORM = 5,
    IU_AME_HOOK_STATE_UNVERIFIED = 6,
    IU_AME_ABI_INCOMPATIBLE = 7,
    IU_AME_INTERNAL_ERROR = 8
};

enum iu_ame_component_id_v1 {
    IU_AME_COMPONENT_LAUNCHD_HOOK = 0,
    IU_AME_COMPONENT_BASE_HOOK = 1
};

enum iu_ame_file_type_v1 {
    IU_AME_FILE_MISSING = 0,
    IU_AME_FILE_REGULAR = 1,
    IU_AME_FILE_SYMLINK = 2,
    IU_AME_FILE_OTHER = 3,
    IU_AME_FILE_UNREADABLE = 4,
    IU_AME_FILE_UNSAFE = 5
};

enum iu_ame_macho_state_v1 {
    IU_AME_MACHO_PARSEABLE_CODEDIRECTORY = 1,
    IU_AME_MACHO_ADHOC_SIGNATURE = 2,
    IU_AME_MACHO_MALFORMED_SIGNATURE = 3,
    IU_AME_MACHO_EMPTY_SIGNATURE = 4,
    IU_AME_MACHO_NO_CODE_SIGNATURE = 5,
    IU_AME_MACHO_UNSUPPORTED_FORMAT = 6,
    IU_AME_MACHO_TRUNCATED_OR_CORRUPT = 7,
    IU_AME_MACHO_IO_ERROR = 8
};

enum iu_ame_hook_evidence_v1 {
    IU_AME_HOOK_UNKNOWN = 0,
    IU_AME_HOOK_REPORTED_PRESENT = 1,
    IU_AME_HOOK_INDEPENDENTLY_VERIFIED = 2
};

enum iu_ame_build_evidence_v1 {
    IU_AME_BUILD_UNKNOWN = 0,
    IU_AME_BUILD_PACKAGE_REPORTED = 1,
    IU_AME_BUILD_TRUSTED_HASH_MATCH = 2,
    IU_AME_BUILD_VERSION_MISMATCH = 3
};

enum iu_ame_reserved_operation_v1 {
    IU_AME_OP_PREPARE_EXECUTABLE = 1,
    IU_AME_OP_REGISTER_TRUST = 2,
    IU_AME_OP_APPLY_PROCESS_POLICY = 3,
    IU_AME_OP_VERIFY_LAUNCH_BOUNDARY = 4
};

enum iu_ame_preview_decision_v1 {
    IU_AME_PREVIEW_BLOCKED = 0,
    IU_AME_PREVIEW_HYPOTHETICALLY_ELIGIBLE = 1,
    IU_AME_PREVIEW_NOT_IMPLEMENTED = 2
};

enum iu_ame_preview_block_reason_v1 {
    IU_AME_PREVIEW_REASON_NONE = 0,
    IU_AME_PREVIEW_REASON_POLICY = 1,
    IU_AME_PREVIEW_REASON_ADAPTER_COMPATIBILITY = 2,
    IU_AME_PREVIEW_REASON_CAPABILITY = 3,
    IU_AME_PREVIEW_REASON_RESERVED_OPERATION = 4,
    IU_AME_PREVIEW_REASON_INVALID_INPUT = 5
};

struct iu_ame_text_v1 {
    uint32_t length;
    char value[IU_AME_TEXT_CAPACITY];
};

/* Filesystem evidence only. `sha256_valid` is set only after a complete
 * bounded read of an opened file whose descriptor identity still matches. */
struct iu_ame_component_evidence_v1 {
    uint32_t struct_size;
    uint32_t component_id;
    uint32_t file_type;
    uint32_t evidence_flags;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint32_t mode;
    uint32_t link_count;
    uint32_t sha256_valid;
    uint32_t macho_identity;
    uint32_t macho_cputype;
    uint32_t macho_cpusubtype;
    uint32_t macho_filetype;
    uint64_t device;
    uint64_t inode;
    uint64_t file_size;
    uint8_t sha256[IU_AME_SHA256_SIZE];
};

struct iu_ame_probe_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t error_code;
    uint32_t compatibility;
    uint32_t component_count;
    uint32_t build_evidence;
    uint32_t launchd_hook_evidence;
    uint32_t base_hook_evidence;
    struct iu_ame_text_v1 source_revision;
    struct iu_ame_text_v1 reported_package_version;
    struct iu_ame_component_evidence_v1 components[IU_AME_COMPONENT_COUNT];
    struct iu_ame_capability_set_v1 capabilities;
};

/* Caller-supplied facts exist for deterministic classification tests and a
 * future evidence collector. Production probe never fabricates device facts. */
struct iu_ame_observed_facts_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t system_family;
    uint32_t architecture;
    uint32_t reference_device_match;
    uint32_t reference_os_match;
    uint32_t component_present_mask;
    uint32_t component_safe_mask;
    uint32_t build_evidence;
    uint32_t launchd_hook_evidence;
    uint32_t base_hook_evidence;
    uint32_t device_evidence_complete;
    struct iu_ame_text_v1 device_identifier;
    struct iu_ame_text_v1 product_version;
    struct iu_ame_text_v1 source_revision;
};

struct iu_ame_capability_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t compatibility;
    uint32_t error_code;
};

/* Policy/config data is copied by value for preview. The returned decision is
 * hypothetical and never confers operational authorization. */
struct iu_ame_preview_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t required_capability;
    uint32_t reserved_operation;
    struct iu_policy_config_v1 policy_config;
    struct iu_policy_target_v1 target;
};

struct iu_ame_preview_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t policy_outcome;
    uint32_t adapter_compatibility;
    uint32_t required_capability;
    uint32_t capability_status;
    uint32_t preview_decision;
    uint32_t blocking_reason;
    uint32_t operational_authorization;
};

struct iu_ame_macho_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t state;
    uint32_t architecture;
    uint32_t error_code;
    uint32_t file_type;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint32_t mode;
    uint32_t link_count;
    uint32_t macho_cputype;
    uint32_t macho_cpusubtype;
    uint32_t macho_filetype;
    uint64_t device;
    uint64_t inode;
    uint64_t file_size;
};

int32_t iu_ame_adapter_probe_v1(struct iu_ame_probe_result_v1 *result);
int32_t iu_ame_collect_component_v1(uint32_t component_id, const char *path,
                                    struct iu_ame_component_evidence_v1 *result);
int32_t iu_ame_component_evidence_recheck_v1(
    const struct iu_ame_component_evidence_v1 *evidence, const char *path);
int32_t iu_ame_adapter_classify_v1(const struct iu_ame_observed_facts_v1 *facts,
                                   struct iu_ame_capability_result_v1 *result);
int32_t iu_ame_adapter_preview_v1(const struct iu_ame_preview_request_v1 *request,
                                  struct iu_ame_preview_result_v1 *result);
int32_t iu_ame_adapter_reserved_operation_v1(uint32_t operation);
int32_t iu_ame_macho_inspect_v1(const char *path, struct iu_ame_macho_result_v1 *result);
/* Inspects a borrowed, already-open descriptor. The caller retains ownership;
 * the descriptor offset is not changed. */
int32_t iu_ame_macho_inspect_fd_v1(int fd, struct iu_ame_macho_result_v1 *result);
/* Complete bounded SHA-256 of a regular, single-link file on a borrowed fd. */
int32_t iu_ame_sha256_fd_v1(int fd, uint8_t digest[IU_AME_SHA256_SIZE]);
/* Hash a bounded in-memory byte sequence using the same SHA-256 implementation. */
int32_t iu_ame_sha256_bytes_v1(const uint8_t *bytes, size_t length, uint8_t digest[IU_AME_SHA256_SIZE]);
const char *iu_ame_compatibility_name_v1(uint32_t compatibility);
const char *iu_ame_macho_state_name_v1(uint32_t state);

#endif
