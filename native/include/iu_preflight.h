#ifndef IU_PREFLIGHT_H
#define IU_PREFLIGHT_H

#include <stdint.h>

#define IU_PREFLIGHT_ABI_VERSION UINT32_C(1)
#define IU_PREFLIGHT_TEXT_CAPACITY UINT32_C(64)
#define IU_PREFLIGHT_COMPONENT_COUNT UINT32_C(2)
#define IU_PREFLIGHT_REQUIRED_COMPONENTS UINT32_C(0x3)
#define IU_PREFLIGHT_PROJECT_PATH_COUNT UINT32_C(10)
#define IU_PREFLIGHT_PROJECT_PATHS UINT32_C(0x3ff)

enum iu_compatibility_status_v1 {
    IU_COMPAT_SUPPORTED_AND_VERIFIED = 0,
    IU_COMPAT_UNVERIFIED = 1,
    IU_COMPAT_COMPONENT_MISSING = 2,
    IU_COMPAT_VERSION_MISMATCH = 3,
    IU_COMPAT_UNSUPPORTED_PLATFORM = 4,
    IU_COMPAT_INTERNAL_ERROR = 5
};

enum iu_preflight_error_v1 {
    IU_PREFLIGHT_ERROR_NONE = 0,
    IU_PREFLIGHT_ERROR_INVALID_ARGUMENT = 1,
    IU_PREFLIGHT_ERROR_ABI_MISMATCH = 2,
    IU_PREFLIGHT_ERROR_UNSUPPORTED_PLATFORM = 3,
    IU_PREFLIGHT_ERROR_COMPONENT_MISSING = 4,
    IU_PREFLIGHT_ERROR_VERSION_UNVERIFIED = 5,
    IU_PREFLIGHT_ERROR_VERSION_MISMATCH = 6,
    IU_PREFLIGHT_ERROR_IO = 7,
    IU_PREFLIGHT_ERROR_INTERNAL = 8
};

enum iu_system_family_v1 {
    IU_SYSTEM_UNKNOWN = 0,
    IU_SYSTEM_IOS = 1,
    IU_SYSTEM_DARWIN = 2,
    IU_SYSTEM_LINUX = 3,
    IU_SYSTEM_WINDOWS = 4
};

enum iu_architecture_v1 {
    IU_ARCH_UNKNOWN = 0,
    IU_ARCH_ARM64 = 1,
    IU_ARCH_X86_64 = 2,
    IU_ARCH_ARM32 = 3,
    IU_ARCH_X86 = 4
};

enum iu_match_state_v1 {
    IU_MATCH_UNKNOWN = 0,
    IU_MATCH_YES = 1,
    IU_MATCH_NO = 2
};

enum iu_rootful_layout_state_v1 {
    IU_ROOTFUL_LAYOUT_UNKNOWN = 0,
    IU_ROOTFUL_PATHS_AVAILABLE = 1,
    IU_ROOTFUL_PATHS_MISSING = 2
};

struct iu_text_v1 {
    uint32_t length;
    char value[IU_PREFLIGHT_TEXT_CAPACITY];
};

struct iu_component_metadata_v1 {
    uint32_t owner_uid;
    uint32_t group_uid;
    uint32_t mode;
    uint32_t link_count;
    uint64_t device;
    uint64_t inode;
    uint64_t size;
};

/* Input facts are collected by read-only probes or supplied by host fixtures.
 * This structure is not an Amethyst ABI and does not carry installed-version
 * proof. Unknown identity/version data must remain unknown, never guessed. */
struct iu_preflight_facts_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t system_family;
    uint32_t architecture;
    uint32_t reference_device_match;
    uint32_t reference_os_match;
    uint32_t required_component_mask;
    uint32_t component_present_mask;
    uint32_t component_regular_mask;
    uint32_t component_readable_mask;
    uint32_t rootful_path_expected_mask;
    uint32_t rootful_path_available_mask;
    uint32_t project_path_expected_mask;
    uint32_t project_path_present_mask;
    struct iu_component_metadata_v1 components[IU_PREFLIGHT_COMPONENT_COUNT];
    struct iu_text_v1 machine;
    struct iu_text_v1 product_version;
    struct iu_text_v1 system_build;
    struct iu_text_v1 kernel_release;
};

/* Fixed-layout result for a future project-owned daemon boundary. It contains
 * no pointers, private Amethyst structures, or kernel addresses. */
struct iu_preflight_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t compatibility_status;
    uint32_t error_code;
    uint32_t system_family;
    uint32_t architecture;
    uint32_t reference_device_match;
    uint32_t reference_os_match;
    uint32_t required_component_mask;
    uint32_t component_present_mask;
    uint32_t component_regular_mask;
    uint32_t component_readable_mask;
    uint32_t rootful_layout_state;
    uint32_t rootful_path_expected_mask;
    uint32_t rootful_path_available_mask;
    uint32_t project_path_expected_mask;
    uint32_t project_path_present_mask;
    struct iu_component_metadata_v1 components[IU_PREFLIGHT_COMPONENT_COUNT];
    struct iu_text_v1 machine;
    struct iu_text_v1 product_version;
    struct iu_text_v1 system_build;
    struct iu_text_v1 kernel_release;
};

int32_t iu_preflight_classify_v1(const struct iu_preflight_facts_v1 *facts,
                                 struct iu_preflight_result_v1 *result);
int32_t iu_preflight_detect_v1(struct iu_preflight_result_v1 *result);
const char *iu_compatibility_status_name_v1(uint32_t status);
const char *iu_preflight_error_name_v1(uint32_t error_code);
const char *iu_system_family_name_v1(uint32_t family);
const char *iu_architecture_name_v1(uint32_t architecture);

#endif /* IU_PREFLIGHT_H */
