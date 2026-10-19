#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "iu_preflight.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <TargetConditionals.h>
#endif

static const char *const amethyst_component_paths[IU_PREFLIGHT_COMPONENT_COUNT] = {
    "/amethyst/launchd_hook.dylib",
    "/usr/lib/base_hook.dylib"
};

static const char *const rootful_directory_paths[] = {
    "/usr/local/bin",
    "/usr/local/lib",
    "/var/lib",
    "/var/run",
    "/var/log",
    "/Library/LaunchDaemons"
};

static const char *const project_paths[IU_PREFLIGHT_PROJECT_PATH_COUNT] = {
    "/usr/local/bin/ios-unsandboxed",
    "/usr/local/bin/ios-unsandboxedd",
    "/usr/local/bin/iu",
    "/var/lib/ios-unsandboxed",
    "/var/lib/ios-unsandboxed/manager.sh",
    "/var/lib/ios-unsandboxed/install-state",
    "/usr/local/lib/ios-unsandboxed",
    "/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist",
    "/var/run/ios-unsandboxedd.sock",
    "/var/log/ios-unsandboxed"
};

static int32_t copy_text(struct iu_text_v1 *destination, const char *source)
{
    size_t length;

    if (destination == NULL) {
        return -1;
    }
    destination->length = 0;
    memset(destination->value, 0, sizeof(destination->value));
    if (source == NULL || source[0] == '\0') {
        return 0;
    }

    length = strnlen(source, sizeof(destination->value));
    if (length >= sizeof(destination->value)) {
        return -1;
    }
    memcpy(destination->value, source, length);
    destination->length = (uint32_t)length;
    return 0;
}

static int32_t validate_text(const struct iu_text_v1 *text)
{
    if (text == NULL || text->length >= IU_PREFLIGHT_TEXT_CAPACITY) {
        return 0;
    }
    if (text->value[text->length] != '\0') {
        return 0;
    }
    return memchr(text->value, '\0', text->length) == NULL;
}

static uint32_t classify_facts(const struct iu_preflight_facts_v1 *facts,
                               uint32_t *error_code)
{
    uint32_t complete_components;

    if (facts->system_family != IU_SYSTEM_IOS) {
        *error_code = IU_PREFLIGHT_ERROR_UNSUPPORTED_PLATFORM;
        return IU_COMPAT_UNSUPPORTED_PLATFORM;
    }
    if (facts->architecture != IU_ARCH_ARM64 ||
        facts->reference_device_match == IU_MATCH_NO) {
        *error_code = IU_PREFLIGHT_ERROR_UNSUPPORTED_PLATFORM;
        return IU_COMPAT_UNSUPPORTED_PLATFORM;
    }
    if (facts->reference_os_match == IU_MATCH_NO) {
        *error_code = IU_PREFLIGHT_ERROR_VERSION_MISMATCH;
        return IU_COMPAT_VERSION_MISMATCH;
    }

    complete_components = facts->component_present_mask &
                          facts->component_regular_mask &
                          facts->component_readable_mask;
    if ((complete_components & facts->required_component_mask) !=
        facts->required_component_mask) {
        *error_code = IU_PREFLIGHT_ERROR_COMPONENT_MISSING;
        return IU_COMPAT_COMPONENT_MISSING;
    }

    /* No installed Amethyst build provenance or live hook proof is available
     * through these read-only filesystem checks. Never promote this to PASS. */
    *error_code = IU_PREFLIGHT_ERROR_VERSION_UNVERIFIED;
    return IU_COMPAT_UNVERIFIED;
}

int32_t iu_preflight_classify_v1(const struct iu_preflight_facts_v1 *facts,
                                 struct iu_preflight_result_v1 *result)
{
    uint32_t error_code = IU_PREFLIGHT_ERROR_INTERNAL;

    if (result == NULL) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->abi_version = IU_PREFLIGHT_ABI_VERSION;
    result->struct_size = (uint32_t)sizeof(*result);
    result->compatibility_status = IU_COMPAT_INTERNAL_ERROR;
    result->error_code = IU_PREFLIGHT_ERROR_INVALID_ARGUMENT;

    if (facts == NULL) {
        return -1;
    }
    if (facts->abi_version != IU_PREFLIGHT_ABI_VERSION ||
        facts->struct_size < sizeof(*facts)) {
        result->error_code = IU_PREFLIGHT_ERROR_ABI_MISMATCH;
        return -1;
    }
    if (!validate_text(&facts->machine) || !validate_text(&facts->product_version) ||
        !validate_text(&facts->system_build) ||
        !validate_text(&facts->kernel_release) ||
        facts->system_family > IU_SYSTEM_WINDOWS ||
        facts->architecture > IU_ARCH_X86 ||
        facts->reference_device_match > IU_MATCH_NO ||
        facts->reference_os_match > IU_MATCH_NO ||
        facts->required_component_mask == 0 ||
        (facts->required_component_mask & ~IU_PREFLIGHT_REQUIRED_COMPONENTS) != 0 ||
        (facts->component_present_mask & ~facts->required_component_mask) != 0 ||
        (facts->component_regular_mask & ~facts->required_component_mask) != 0 ||
        (facts->component_readable_mask & ~facts->required_component_mask) != 0 ||
        facts->rootful_path_expected_mask == 0 ||
        (facts->rootful_path_expected_mask & ~UINT32_C(0x3f)) != 0 ||
        (facts->rootful_path_available_mask & ~facts->rootful_path_expected_mask) != 0 ||
        facts->project_path_expected_mask == 0 ||
        (facts->project_path_expected_mask & ~IU_PREFLIGHT_PROJECT_PATHS) != 0 ||
        (facts->project_path_present_mask & ~facts->project_path_expected_mask) != 0) {
        result->error_code = IU_PREFLIGHT_ERROR_INVALID_ARGUMENT;
        return -1;
    }

    result->system_family = facts->system_family;
    result->architecture = facts->architecture;
    result->reference_device_match = facts->reference_device_match;
    result->reference_os_match = facts->reference_os_match;
    result->required_component_mask = facts->required_component_mask;
    result->component_present_mask = facts->component_present_mask;
    result->component_regular_mask = facts->component_regular_mask;
    result->component_readable_mask = facts->component_readable_mask;
    result->rootful_path_expected_mask = facts->rootful_path_expected_mask;
    result->rootful_path_available_mask = facts->rootful_path_available_mask;
    result->project_path_expected_mask = facts->project_path_expected_mask;
    result->project_path_present_mask = facts->project_path_present_mask;
    memcpy(result->components, facts->components, sizeof(result->components));
    result->rootful_layout_state =
        facts->system_family != IU_SYSTEM_IOS ? IU_ROOTFUL_LAYOUT_UNKNOWN :
        ((facts->rootful_path_available_mask & facts->rootful_path_expected_mask) ==
         facts->rootful_path_expected_mask ? IU_ROOTFUL_PATHS_AVAILABLE :
                                              IU_ROOTFUL_PATHS_MISSING);
    result->machine = facts->machine;
    result->product_version = facts->product_version;
    result->system_build = facts->system_build;
    result->kernel_release = facts->kernel_release;

    result->compatibility_status = classify_facts(facts, &error_code);
    result->error_code = error_code;
    return 0;
}

static void probe_component(struct iu_preflight_facts_v1 *facts,
                            const char *path,
                            uint32_t bit,
                            uint32_t index)
{
    struct stat path_status;
    struct stat descriptor_status;
    struct iu_component_metadata_v1 *metadata = &facts->components[index];
    int descriptor;

    if (lstat(path, &path_status) != 0) {
        return;
    }
    facts->component_present_mask |= bit;
    metadata->owner_uid = (uint32_t)path_status.st_uid;
    metadata->group_uid = (uint32_t)path_status.st_gid;
    metadata->mode = (uint32_t)path_status.st_mode;
    metadata->link_count = (uint32_t)path_status.st_nlink;
    metadata->device = (uint64_t)path_status.st_dev;
    metadata->inode = (uint64_t)path_status.st_ino;
    metadata->size = (uint64_t)path_status.st_size;
    if (!S_ISREG(path_status.st_mode)) {
        return;
    }
    facts->component_regular_mask |= bit;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return;
    }
    if (fstat(descriptor, &descriptor_status) == 0 &&
        S_ISREG(descriptor_status.st_mode) &&
        descriptor_status.st_dev == path_status.st_dev &&
        descriptor_status.st_ino == path_status.st_ino) {
        facts->component_readable_mask |= bit;
        metadata->owner_uid = (uint32_t)descriptor_status.st_uid;
        metadata->group_uid = (uint32_t)descriptor_status.st_gid;
        metadata->mode = (uint32_t)descriptor_status.st_mode;
        metadata->link_count = (uint32_t)descriptor_status.st_nlink;
        metadata->device = (uint64_t)descriptor_status.st_dev;
        metadata->inode = (uint64_t)descriptor_status.st_ino;
        metadata->size = (uint64_t)descriptor_status.st_size;
    }
    (void)close(descriptor);
}

static void probe_rootful_paths(struct iu_preflight_facts_v1 *facts)
{
    size_t index;

    for (index = 0; index < sizeof(rootful_directory_paths) /
                                sizeof(rootful_directory_paths[0]); ++index) {
        struct stat status;
        uint32_t bit = UINT32_C(1) << index;

        facts->rootful_path_expected_mask |= bit;
        if (stat(rootful_directory_paths[index], &status) == 0 &&
            S_ISDIR(status.st_mode)) {
            facts->rootful_path_available_mask |= bit;
        }
    }
}

static void probe_project_paths(struct iu_preflight_facts_v1 *facts)
{
    size_t index;

    for (index = 0; index < IU_PREFLIGHT_PROJECT_PATH_COUNT; ++index) {
        struct stat status;
        uint32_t bit = UINT32_C(1) << index;

        facts->project_path_expected_mask |= bit;
        if (lstat(project_paths[index], &status) == 0) {
            facts->project_path_present_mask |= bit;
        }
    }
}

#if defined(__APPLE__)
static int32_t read_sysctl_string(const char *name, char *buffer, size_t capacity)
{
    size_t length = capacity;

    if (sysctlbyname(name, buffer, &length, NULL, 0) != 0 || length == 0 ||
        length > capacity) {
        return -1;
    }
    buffer[capacity - 1] = '\0';
    if (memchr(buffer, '\0', length) == NULL) {
        buffer[capacity - 1] = '\0';
    }
    return buffer[0] == '\0' ? -1 : 0;
}
#endif

int32_t iu_preflight_detect_v1(struct iu_preflight_result_v1 *result)
{
    struct iu_preflight_facts_v1 facts;
    struct utsname system_info;
#if defined(__APPLE__)
    char machine[IU_PREFLIGHT_TEXT_CAPACITY] = {0};
    char product_version[IU_PREFLIGHT_TEXT_CAPACITY] = {0};
    char system_build[IU_PREFLIGHT_TEXT_CAPACITY] = {0};
#endif
    uint32_t index;

    if (result == NULL) {
        return -1;
    }
    memset(&facts, 0, sizeof(facts));
    facts.abi_version = IU_PREFLIGHT_ABI_VERSION;
    facts.struct_size = (uint32_t)sizeof(facts);
    facts.required_component_mask = IU_PREFLIGHT_REQUIRED_COMPONENTS;
    facts.project_path_expected_mask = IU_PREFLIGHT_PROJECT_PATHS;
    facts.reference_device_match = IU_MATCH_UNKNOWN;
    facts.reference_os_match = IU_MATCH_UNKNOWN;

    if (uname(&system_info) != 0) {
        memset(result, 0, sizeof(*result));
        result->abi_version = IU_PREFLIGHT_ABI_VERSION;
        result->struct_size = (uint32_t)sizeof(*result);
        result->compatibility_status = IU_COMPAT_INTERNAL_ERROR;
        result->error_code = IU_PREFLIGHT_ERROR_IO;
        return -1;
    }

#if defined(__APPLE__)
#if TARGET_OS_IPHONE
    facts.system_family = IU_SYSTEM_IOS;
#else
    facts.system_family = IU_SYSTEM_DARWIN;
#endif
#elif defined(__linux__)
    facts.system_family = IU_SYSTEM_LINUX;
#else
    facts.system_family = IU_SYSTEM_UNKNOWN;
#endif

#if defined(__arm64__) || defined(__aarch64__)
    facts.architecture = IU_ARCH_ARM64;
#elif defined(__x86_64__)
    facts.architecture = IU_ARCH_X86_64;
#elif defined(__arm__)
    facts.architecture = IU_ARCH_ARM32;
#elif defined(__i386__)
    facts.architecture = IU_ARCH_X86;
#else
    facts.architecture = IU_ARCH_UNKNOWN;
#endif

    (void)copy_text(&facts.kernel_release, system_info.release);
    (void)copy_text(&facts.machine, system_info.machine);

#if defined(__APPLE__)
    if (read_sysctl_string("hw.machine", machine, sizeof(machine)) == 0) {
        (void)copy_text(&facts.machine, machine);
    } else if (facts.system_family == IU_SYSTEM_IOS) {
        memset(&facts.machine, 0, sizeof(facts.machine));
    }
    if (read_sysctl_string("kern.osproductversion", product_version,
                           sizeof(product_version)) == 0) {
        (void)copy_text(&facts.product_version, product_version);
    }
    if (read_sysctl_string("kern.osversion", system_build,
                           sizeof(system_build)) == 0) {
        (void)copy_text(&facts.system_build, system_build);
    }
#endif

    if (facts.system_family == IU_SYSTEM_IOS && facts.architecture == IU_ARCH_ARM64) {
#if defined(__APPLE__) && TARGET_OS_SIMULATOR
        facts.reference_device_match = IU_MATCH_NO;
#else
        if (facts.machine.length != 0) {
            facts.reference_device_match =
                strcmp(facts.machine.value, "iPad4,4") == 0 ? IU_MATCH_YES : IU_MATCH_NO;
        }
#endif
        if (facts.product_version.length != 0) {
            facts.reference_os_match =
                strcmp(facts.product_version.value, "12.5.7") == 0 ? IU_MATCH_YES : IU_MATCH_NO;
        }
    }

    for (index = 0; index < IU_PREFLIGHT_COMPONENT_COUNT; ++index) {
        probe_component(&facts, amethyst_component_paths[index], UINT32_C(1) << index,
                        index);
    }
    probe_rootful_paths(&facts);
    probe_project_paths(&facts);

    return iu_preflight_classify_v1(&facts, result);
}

const char *iu_compatibility_status_name_v1(uint32_t status)
{
    switch (status) {
    case IU_COMPAT_SUPPORTED_AND_VERIFIED:
        return "SUPPORTED_AND_VERIFIED";
    case IU_COMPAT_UNVERIFIED:
        return "UNVERIFIED";
    case IU_COMPAT_COMPONENT_MISSING:
        return "COMPONENT_MISSING";
    case IU_COMPAT_VERSION_MISMATCH:
        return "VERSION_MISMATCH";
    case IU_COMPAT_UNSUPPORTED_PLATFORM:
        return "UNSUPPORTED_PLATFORM";
    case IU_COMPAT_INTERNAL_ERROR:
        return "INTERNAL_ERROR";
    default:
        return "UNKNOWN_STATUS";
    }
}

const char *iu_preflight_error_name_v1(uint32_t error_code)
{
    switch (error_code) {
    case IU_PREFLIGHT_ERROR_NONE:
        return "NONE";
    case IU_PREFLIGHT_ERROR_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case IU_PREFLIGHT_ERROR_ABI_MISMATCH:
        return "ABI_MISMATCH";
    case IU_PREFLIGHT_ERROR_UNSUPPORTED_PLATFORM:
        return "UNSUPPORTED_PLATFORM";
    case IU_PREFLIGHT_ERROR_COMPONENT_MISSING:
        return "COMPONENT_MISSING";
    case IU_PREFLIGHT_ERROR_VERSION_UNVERIFIED:
        return "VERSION_UNVERIFIED";
    case IU_PREFLIGHT_ERROR_VERSION_MISMATCH:
        return "VERSION_MISMATCH";
    case IU_PREFLIGHT_ERROR_IO:
        return "IO";
    case IU_PREFLIGHT_ERROR_INTERNAL:
        return "INTERNAL";
    default:
        return "UNKNOWN_ERROR";
    }
}

const char *iu_system_family_name_v1(uint32_t family)
{
    switch (family) {
    case IU_SYSTEM_IOS:
        return "iOS";
    case IU_SYSTEM_DARWIN:
        return "Darwin (non-iOS target)";
    case IU_SYSTEM_LINUX:
        return "Linux";
    case IU_SYSTEM_WINDOWS:
        return "Windows";
    default:
        return "Unknown";
    }
}

const char *iu_architecture_name_v1(uint32_t architecture)
{
    switch (architecture) {
    case IU_ARCH_ARM64:
        return "ARM64";
    case IU_ARCH_X86_64:
        return "x86_64";
    case IU_ARCH_ARM32:
        return "ARM32";
    case IU_ARCH_X86:
        return "x86";
    default:
        return "Unknown";
    }
}
