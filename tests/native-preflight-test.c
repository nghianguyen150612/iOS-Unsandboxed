#define _POSIX_C_SOURCE 200809L

#include "iu_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(condition)                                                                  \
    do {                                                                                  \
        if (!(condition)) {                                                               \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                                     \
        }                                                                                 \
    } while (0)

static void initialize_compatible_facts(struct iu_preflight_facts_v1 *facts)
{
    memset(facts, 0, sizeof(*facts));
    facts->abi_version = IU_PREFLIGHT_ABI_VERSION;
    facts->struct_size = (uint32_t)sizeof(*facts);
    facts->system_family = IU_SYSTEM_IOS;
    facts->architecture = IU_ARCH_ARM64;
    facts->reference_device_match = IU_MATCH_YES;
    facts->reference_os_match = IU_MATCH_YES;
    facts->required_component_mask = IU_PREFLIGHT_REQUIRED_COMPONENTS;
    facts->component_present_mask = IU_PREFLIGHT_REQUIRED_COMPONENTS;
    facts->component_regular_mask = IU_PREFLIGHT_REQUIRED_COMPONENTS;
    facts->component_readable_mask = IU_PREFLIGHT_REQUIRED_COMPONENTS;
    facts->rootful_path_expected_mask = UINT32_C(0x3f);
    facts->rootful_path_available_mask = UINT32_C(0x3f);
    facts->project_path_expected_mask = IU_PREFLIGHT_PROJECT_PATHS;
    facts->machine.length = 7;
    memcpy(facts->machine.value, "iPad4,4", 8);
    facts->product_version.length = 6;
    memcpy(facts->product_version.value, "12.5.7", 7);
    facts->system_build.length = 5;
    memcpy(facts->system_build.value, "16H81", 6);
    facts->kernel_release.length = 6;
    memcpy(facts->kernel_release.value, "Darwin", 7);
}

static int test_compatibility_classification(void)
{
    struct iu_preflight_facts_v1 facts;
    struct iu_preflight_result_v1 result;

    initialize_compatible_facts(&facts);
    CHECK(iu_preflight_classify_v1(&facts, &result) == 0);
    /* Matching platform facts and present files still do not verify an
     * installed Amethyst build or prove live hook state. */
    CHECK(result.compatibility_status == IU_COMPAT_UNVERIFIED);
    CHECK(result.error_code == IU_PREFLIGHT_ERROR_VERSION_UNVERIFIED);
    CHECK(result.rootful_layout_state == IU_ROOTFUL_PATHS_AVAILABLE);

    facts.component_present_mask &= ~UINT32_C(0x1);
    CHECK(iu_preflight_classify_v1(&facts, &result) == 0);
    CHECK(result.compatibility_status == IU_COMPAT_COMPONENT_MISSING);

    initialize_compatible_facts(&facts);
    facts.system_family = IU_SYSTEM_LINUX;
    CHECK(iu_preflight_classify_v1(&facts, &result) == 0);
    CHECK(result.compatibility_status == IU_COMPAT_UNSUPPORTED_PLATFORM);
    CHECK(result.rootful_layout_state == IU_ROOTFUL_LAYOUT_UNKNOWN);

    initialize_compatible_facts(&facts);
    facts.reference_os_match = IU_MATCH_NO;
    CHECK(iu_preflight_classify_v1(&facts, &result) == 0);
    CHECK(result.compatibility_status == IU_COMPAT_VERSION_MISMATCH);

    initialize_compatible_facts(&facts);
    facts.reference_device_match = IU_MATCH_NO;
    CHECK(iu_preflight_classify_v1(&facts, &result) == 0);
    CHECK(result.compatibility_status == IU_COMPAT_UNSUPPORTED_PLATFORM);

    initialize_compatible_facts(&facts);
    facts.abi_version += 1;
    CHECK(iu_preflight_classify_v1(&facts, &result) != 0);
    CHECK(result.compatibility_status == IU_COMPAT_INTERNAL_ERROR);
    CHECK(result.error_code == IU_PREFLIGHT_ERROR_ABI_MISMATCH);
    return 0;
}

static int make_path(char *destination,
                     size_t capacity,
                     const char *base,
                     const char *suffix)
{
    int written = snprintf(destination, capacity, "%s/%s", base, suffix);
    return written >= 0 && (size_t)written < capacity ? 0 : -1;
}

static int inspect_path(const char *path, struct iu_policy_target_v1 *target)
{
    return iu_policy_inspect_path_v1(path, (uint32_t)strlen(path), target);
}

static void set_fake_target(struct iu_policy_target_v1 *target,
                            const char *path,
                            uint32_t owner_uid)
{
    size_t length = strlen(path);
    memset(target, 0, sizeof(*target));
    target->abi_version = IU_POLICY_ABI_VERSION;
    target->struct_size = (uint32_t)sizeof(*target);
    target->inspection_state = IU_POLICY_INSPECTION_OK;
    target->file_type = IU_POLICY_FILE_REGULAR;
    target->owner_uid = owner_uid;
    target->mode = UINT32_C(0100700);
    target->link_count = 1;
    target->canonical_path_length = (uint32_t)length;
    memcpy(target->canonical_path, path, length + 1);
    target->path_device = 1;
    target->descriptor_device = 1;
    target->path_inode = 2;
    target->descriptor_inode = 2;
}

static void initialize_policy(struct iu_policy_config_v1 *config,
                              const char *directory_path,
                              uint32_t owner_uid)
{
    size_t length = strlen(directory_path);
    memset(config, 0, sizeof(*config));
    config->abi_version = IU_POLICY_ABI_VERSION;
    config->struct_size = (uint32_t)sizeof(*config);
    config->enabled = 1;
    config->compatibility_status = IU_COMPAT_SUPPORTED_AND_VERIFIED;
    config->expected_owner_uid = owner_uid;
    config->eligible_directory_count = 1;
    config->eligible_directories[0].path_length = (uint32_t)length;
    memcpy(config->eligible_directories[0].path, directory_path, length + 1);
    config->eligible_directories[0].owner_uid = owner_uid;
    config->eligible_directories[0].mode = UINT32_C(0700);
    config->eligible_directories[0].file_type = IU_POLICY_FILE_DIRECTORY;
    config->eligible_directories[0].metadata_verified = 1;
}

static int expect_outcome(const struct iu_policy_config_v1 *config,
                          const struct iu_policy_target_v1 *target,
                          uint32_t expected)
{
    struct iu_policy_result_v1 result;

    CHECK(iu_policy_evaluate_v1(config, target, &result) == 0);
    if (result.outcome != expected) {
        (void)fprintf(stderr, "expected %s, got %s\n",
                      iu_policy_outcome_name_v1(expected),
                      iu_policy_outcome_name_v1(result.outcome));
        return 1;
    }
    return 0;
}

static int test_policy_and_file_safety(void)
{
    char fixture_root[IU_POLICY_PATH_CAPACITY];
    char fixture_template[IU_POLICY_PATH_CAPACITY];
    char safe_directory[IU_POLICY_PATH_CAPACITY];
    char executable_path[IU_POLICY_PATH_CAPACITY];
    char symlink_path[IU_POLICY_PATH_CAPACITY];
    char symlink_directory[IU_POLICY_PATH_CAPACITY];
    char symlink_directory_target[IU_POLICY_PATH_CAPACITY];
    char hardlink_path[IU_POLICY_PATH_CAPACITY];
    char fifo_path[IU_POLICY_PATH_CAPACITY];
    char boundary_path[IU_POLICY_PATH_CAPACITY];
    char current_directory[IU_POLICY_PATH_CAPACITY];
    struct iu_policy_config_v1 config;
    struct iu_policy_config_v1 default_config;
    struct iu_policy_config_v1 malformed_config;
    struct iu_policy_target_v1 target;
    struct iu_policy_target_v1 inspected;
    struct iu_policy_result_v1 result;
    uint32_t owner_uid = (uint32_t)geteuid();
    int descriptor;

    CHECK(getcwd(current_directory, sizeof(current_directory)) != NULL);
    CHECK(make_path(fixture_template, sizeof(fixture_template), current_directory,
                    "build/host/iu-p003-XXXXXX") == 0);
    CHECK(mkdtemp(fixture_template) != NULL);
    CHECK(strlen(fixture_template) < sizeof(fixture_root));
    memcpy(fixture_root, fixture_template, strlen(fixture_template) + 1);
    CHECK(make_path(safe_directory, sizeof(safe_directory), fixture_root, "safe") == 0);
    CHECK(make_path(executable_path, sizeof(executable_path), safe_directory, "tool") == 0);
    CHECK(make_path(symlink_path, sizeof(symlink_path), safe_directory, "link") == 0);
    CHECK(make_path(symlink_directory, sizeof(symlink_directory), fixture_root,
                    "safe-alias") == 0);
    CHECK(make_path(symlink_directory_target, sizeof(symlink_directory_target),
                    symlink_directory, "tool") == 0);
    CHECK(make_path(hardlink_path, sizeof(hardlink_path), safe_directory, "hardlink") == 0);
    CHECK(make_path(fifo_path, sizeof(fifo_path), safe_directory, "pipe") == 0);
    CHECK(mkdir(safe_directory, 0700) == 0);
    descriptor = open(executable_path, O_CREAT | O_WRONLY | O_EXCL, 0700);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, "x", 1) == 1);
    CHECK(close(descriptor) == 0);
    CHECK(chmod(executable_path, 0700) == 0);
    initialize_policy(&config, safe_directory, owner_uid);

    CHECK(inspect_path(executable_path, &target) == 0);
    CHECK(target.inspection_state == IU_POLICY_INSPECTION_OK);
    CHECK(target.file_type == IU_POLICY_FILE_REGULAR);
    CHECK(strcmp(target.canonical_path, executable_path) == 0);
    memset(&default_config, 0, sizeof(default_config));
    default_config.abi_version = IU_POLICY_ABI_VERSION;
    default_config.struct_size = (uint32_t)sizeof(default_config);
    CHECK(expect_outcome(&default_config, &target, IU_POLICY_DENY_DISABLED) == 0);
    CHECK(expect_outcome(&config, &target, IU_POLICY_ALLOW_ELIGIBLE) == 0);

    config.enabled = 0;
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_DISABLED) == 0);
    config.enabled = 1;
    config.compatibility_status = IU_COMPAT_UNVERIFIED;
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNVERIFIED_BACKEND) == 0);
    config.compatibility_status = IU_COMPAT_INTERNAL_ERROR;
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_INTERNAL_ERROR) == 0);
    config.compatibility_status = IU_COMPAT_SUPPORTED_AND_VERIFIED;

    set_fake_target(&target, "/System/Library/CoreServices/target", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_PROTECTED_PATH) == 0);
    set_fake_target(&target, "/amethyst/launchd_hook.dylib", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_PROTECTED_PATH) == 0);
    set_fake_target(&target, "/usr/local/bin/ios-unsandboxed", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_PROTECTED_PATH) == 0);
    set_fake_target(&target, "/var/lib/ios-unsandboxed/manager.sh", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_PROTECTED_PATH) == 0);

    set_fake_target(&target, "/tmp/example/safe-neighbour/tool", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_SKIP_NOT_TARGETED) == 0);
    set_fake_target(&target, "/tmp/example/safe/../private/tool", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSUPPORTED_TARGET) == 0);
    set_fake_target(&target, "relative/tool", owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSUPPORTED_TARGET) == 0);

    CHECK(chdir(fixture_root) == 0);
    CHECK(inspect_path("safe/tool", &inspected) == 0);
    CHECK(strcmp(inspected.canonical_path, executable_path) == 0);
    CHECK(expect_outcome(&config, &inspected, IU_POLICY_ALLOW_ELIGIBLE) == 0);
    CHECK(chdir(current_directory) == 0);

    CHECK(symlink(executable_path, symlink_path) == 0);
    CHECK(inspect_path(symlink_path, &target) == 0);
    CHECK(target.path_was_symlink == 1);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    CHECK(unlink(symlink_path) == 0);

    CHECK(symlink(safe_directory, symlink_directory) == 0);
    CHECK(inspect_path(symlink_directory_target, &target) == 0);
    CHECK(target.path_was_symlink == 1);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    CHECK(unlink(symlink_directory) == 0);

    CHECK(link(executable_path, hardlink_path) == 0);
    CHECK(inspect_path(executable_path, &target) == 0);
    CHECK(target.link_count > 1);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    CHECK(unlink(hardlink_path) == 0);

    CHECK(inspect_path(safe_directory, &target) == 0);
    CHECK(target.file_type == IU_POLICY_FILE_DIRECTORY);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);

    CHECK(mkfifo(fifo_path, 0600) == 0);
    CHECK(inspect_path(fifo_path, &target) == 0);
    CHECK(target.file_type == IU_POLICY_FILE_OTHER);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    CHECK(unlink(fifo_path) == 0);

    CHECK(inspect_path(executable_path, &target) == 0);
    target.mode |= UINT32_C(04000);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    target.mode &= ~UINT32_C(04000);
    target.mode |= UINT32_C(02000);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    target.mode &= ~UINT32_C(02000);
    target.mode |= UINT32_C(0020);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);
    target.mode &= ~UINT32_C(0020);
    target.owner_uid += 1;
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);

    CHECK(inspect_path(executable_path, &target) == 0);
    target.mode = UINT32_C(0040700);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_UNSAFE_FILE) == 0);

    CHECK(inspect_path(executable_path, &target) == 0);
    target.path_inode += 1;
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_IDENTITY_MISMATCH) == 0);

    CHECK(inspect_path("/path/that/does/not/exist", &target) != 0);
    CHECK(expect_outcome(&config, &target, IU_POLICY_DENY_INTERNAL_ERROR) == 0);
    target.inspection_error = IU_POLICY_INSPECTION_ERROR_IDENTITY;
    CHECK(expect_outcome(&config, &target,
                         IU_POLICY_DENY_IDENTITY_MISMATCH) == 0);
    CHECK(iu_policy_evaluate_v1(NULL, &target, &result) == 0);
    CHECK(result.outcome == IU_POLICY_DENY_INTERNAL_ERROR);

    malformed_config = config;
    malformed_config.abi_version += 1;
    CHECK(expect_outcome(&malformed_config, &target,
                         IU_POLICY_DENY_INTERNAL_ERROR) == 0);
    malformed_config = config;
    malformed_config.eligible_directories[0].metadata_verified = 0;
    CHECK(expect_outcome(&malformed_config, &target,
                         IU_POLICY_DENY_INTERNAL_ERROR) == 0);
    malformed_config = config;
    malformed_config.eligible_directory_count = IU_POLICY_MAX_DIRECTORIES + 1;
    CHECK(expect_outcome(&malformed_config, &target,
                         IU_POLICY_DENY_INTERNAL_ERROR) == 0);

    CHECK(make_path(boundary_path, sizeof(boundary_path), fixture_root,
                    "safe-neighbour/tool") == 0);
    set_fake_target(&target, boundary_path, owner_uid);
    CHECK(expect_outcome(&config, &target, IU_POLICY_SKIP_NOT_TARGETED) == 0);

    CHECK(unlink(executable_path) == 0);
    CHECK(rmdir(safe_directory) == 0);
    CHECK(rmdir(fixture_root) == 0);
    return 0;
}

int main(void)
{
    if (test_compatibility_classification() != 0 ||
        test_policy_and_file_safety() != 0) {
        return 1;
    }
    puts("Native C17 preflight and policy tests passed (simulated host fixtures).");
    return 0;
}
