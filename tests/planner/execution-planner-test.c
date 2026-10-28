#define _POSIX_C_SOURCE 200809L
#include "iu_execution_planner.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)

static int load_path(const char *root, const char *name, char path[1024])
{
    int n = snprintf(path, 1024, "%s/%s", root, name);
    return n > 0 && n < 1024 ? 0 : -1;
}

static void test_fixtures(const char *root)
{
    static const struct { const char *name; uint32_t state; uint32_t preparation; } cases[] = {
        {"unsigned", IU_AME_MACHO_NO_CODE_SIGNATURE, IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND},
        {"parseable", IU_AME_MACHO_PARSEABLE_CODEDIRECTORY, IU_EXECUTION_PREP_PARSEABLE_SIGNATURE},
        {"adhoc", IU_AME_MACHO_ADHOC_SIGNATURE, IU_EXECUTION_PREP_ADHOC_SIGNATURE},
        {"malformed", IU_AME_MACHO_MALFORMED_SIGNATURE, IU_EXECUTION_PREP_REQUIRES_REPAIR},
        {"empty", IU_AME_MACHO_EMPTY_SIGNATURE, IU_EXECUTION_PREP_REQUIRES_REPAIR},
        {"wrong-architecture", IU_AME_MACHO_UNSUPPORTED_FORMAT, IU_EXECUTION_PREP_UNSUPPORTED_TARGET},
        {"truncated", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"zero", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"random", IU_AME_MACHO_UNSUPPORTED_FORMAT, IU_EXECUTION_PREP_UNSUPPORTED_TARGET},
        {"bad-magic", IU_AME_MACHO_UNSUPPORTED_FORMAT, IU_EXECUTION_PREP_UNSUPPORTED_TARGET},
        {"huge-ncmds", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"huge-sizeofcmds", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"zero-cmdsize", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"overlapping-commands", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY},
        {"oob-signature", IU_AME_MACHO_EMPTY_SIGNATURE, IU_EXECUTION_PREP_REQUIRES_REPAIR},
        {"wrong-filetype", IU_AME_MACHO_PARSEABLE_CODEDIRECTORY, IU_EXECUTION_PREP_UNSUPPORTED_TARGET},
        {"bad-superblob-index", IU_AME_MACHO_MALFORMED_SIGNATURE, IU_EXECUTION_PREP_REQUIRES_REPAIR},
        {"bad-codedirectory-length", IU_AME_MACHO_MALFORMED_SIGNATURE, IU_EXECUTION_PREP_REQUIRES_REPAIR},
        {"conflicting-signatures", IU_AME_MACHO_TRUNCATED_OR_CORRUPT, IU_EXECUTION_PREP_INVALID_BINARY}
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char path[1024]; struct iu_execution_plan_v1 plan; struct stat before, after;
        CHECK(load_path(root, cases[i].name, path) == 0);
        CHECK(stat(path, &before) == 0);
        CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
        CHECK(stat(path, &after) == 0);
        CHECK(before.st_ino == after.st_ino && before.st_size == after.st_size &&
              before.st_mode == after.st_mode && before.st_mtime == after.st_mtime &&
              before.st_ctime == after.st_ctime);
        if (plan.macho_state != cases[i].state || plan.signature_preparation != cases[i].preparation)
            fprintf(stderr, "fixture %s got state=%u prep=%u expected=%u/%u\n", cases[i].name,
                    plan.macho_state, plan.signature_preparation, cases[i].state, cases[i].preparation);
        CHECK(plan.macho_state == cases[i].state);
        CHECK(plan.signature_preparation == cases[i].preparation);
        CHECK(plan.inspection_status == IU_EXECUTION_INSPECTION_COMPLETE);
        CHECK(plan.identity_status == IU_EXECUTION_IDENTITY_RECORDED);
        CHECK(plan.operational_authorization == 0 && plan.device_runtime_verified == 0);
        CHECK(plan.missing_prerequisites == UINT32_C(0x3ff));
        CHECK(plan.sha256[0] != 0 || plan.sha256[1] != 0 || plan.file_size == 0);
        if (strcmp(cases[i].name, "unsigned") == 0) {
            CHECK(plan.preview_status == IU_EXECUTION_PREVIEW_PREPARATION_NOT_IMPLEMENTED);
            CHECK(iu_execution_plan_revalidate_v1(&plan) == 0);
        }
    }
}

static void test_descriptor_and_revalidation(const char *root)
{
    char path[1024], linkpath[1024], hardpath[1024], parentlink[1024];
    struct iu_execution_plan_v1 plan;
    struct iu_ame_macho_result_v1 macho;
    struct stat st;
    int fd;
    unsigned char replacement[32];
    static const unsigned char abc_sha256[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    CHECK(load_path(root, "unsigned", path) == 0);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(lseek(fd, 7, SEEK_SET) == 7);
        CHECK(iu_ame_macho_inspect_fd_v1(fd, &macho) == 0);
        CHECK(macho.state == IU_AME_MACHO_NO_CODE_SIGNATURE);
        CHECK(lseek(fd, 0, SEEK_CUR) == 7);
        close(fd);
    }
    CHECK(load_path(root, "sha-abc", path) == 0);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    if (fd >= 0) {
        unsigned char digest[IU_EXECUTION_PLAN_SHA256_SIZE];
        CHECK(iu_ame_sha256_fd_v1(fd, digest) == 0);
        CHECK(memcmp(digest, abc_sha256, sizeof(digest)) == 0);
        close(fd);
    }
    CHECK(load_path(root, "unsigned", path) == 0);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    CHECK(iu_execution_plan_revalidate_v1(&plan) == 0);
    plan.sha256[0] ^= 1U;
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED);
    plan.sha256[0] ^= 1U;
    memset(replacement, 0x5a, sizeof(replacement));
    fd = open(path, O_WRONLY);
    CHECK(fd >= 0);
    if (fd >= 0) { CHECK(write(fd, replacement, sizeof(replacement)) == (ssize_t)sizeof(replacement)); close(fd); }
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED);

    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    CHECK(chmod(path, 0600) == 0);
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    CHECK(unlink(path) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0700);
    CHECK(fd >= 0);
    if (fd >= 0) { CHECK(write(fd, replacement, sizeof(replacement)) == (ssize_t)sizeof(replacement)); close(fd); }
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    fd = open(path, O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    if (fd >= 0) { CHECK(write(fd, "x", 1) == 1); close(fd); }
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED);

    CHECK(load_path(root, "parseable", path) == 0);
    CHECK(snprintf(linkpath, sizeof(linkpath), "%s/symlink", root) > 0);
    CHECK(snprintf(hardpath, sizeof(hardpath), "%s/hardlink", root) > 0);
    CHECK(symlink(path, linkpath) == 0);
    { int32_t link_result = iu_execution_plan_create_v1(linkpath, &plan);
      CHECK(link_result == -IU_EXECUTION_PLAN_ERROR_IO || link_result == -IU_EXECUTION_PLAN_ERROR_PATH ||
            link_result == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE); }
    CHECK(link(path, hardpath) == 0);
    CHECK(iu_execution_plan_create_v1(hardpath, &plan) == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE);
    CHECK(unlink(linkpath) == 0 && unlink(hardpath) == 0);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    CHECK(snprintf(parentlink, sizeof(parentlink), "%s/parent-link/parseable", root) > 0);
    {
        char parent[1024];
        CHECK(snprintf(parent, sizeof(parent), "%s/parent-link", root) > 0);
        CHECK(symlink(root, parent) == 0);
    }
    { int32_t parent_result = iu_execution_plan_create_v1(parentlink, &plan);
      CHECK(parent_result != 0); }
    CHECK(snprintf(parentlink, sizeof(parentlink), "%s/parent-link", root) > 0);
    CHECK(unlink(parentlink) == 0);
    CHECK(snprintf(parentlink, sizeof(parentlink), "%s/fifo", root) > 0);
    CHECK(iu_execution_plan_create_v1(parentlink, &plan) == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE);
    CHECK(snprintf(parentlink, sizeof(parentlink), "%s/socket", root) > 0);
    CHECK(iu_execution_plan_create_v1(parentlink, &plan) == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE);
    CHECK(snprintf(parentlink, sizeof(parentlink), "%s/oversized", root) > 0);
    CHECK(iu_execution_plan_create_v1(parentlink, &plan) == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE);
    CHECK(iu_execution_plan_create_v1("", &plan) == -IU_EXECUTION_PLAN_ERROR_PATH);
    CHECK(iu_execution_plan_create_v1("../etc/passwd", &plan) == -IU_EXECUTION_PLAN_ERROR_PATH);
    CHECK(iu_execution_plan_create_v1(root, &plan) == -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE);
    CHECK(iu_execution_plan_create_v1("./Cargo.toml", &plan) == 0);
    CHECK(strstr(plan.canonical_path, "/./") == NULL);

    CHECK(load_path(root, "unsigned", path) == 0);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    plan.struct_size--;
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_ABI);
    plan.struct_size = sizeof(plan); plan.signature_preparation = 999;
    CHECK(iu_execution_plan_revalidate_v1(&plan) == -IU_EXECUTION_PLAN_ERROR_ABI);
    CHECK(stat(path, &st) == 0);
}

static void make_policy(struct iu_execution_planner_test_context_v1 *context,
                        const struct iu_execution_plan_v1 *plan)
{
    struct iu_policy_config_v1 *config = &context->policy;
    size_t parent_length = plan->canonical_path_length;
    while (parent_length > 1 && plan->canonical_path[parent_length - 1] != '/') --parent_length;
    if (parent_length > 1) --parent_length;
    memset(context, 0, sizeof(*context));
    context->abi_version = IU_EXECUTION_PLAN_ABI_VERSION;
    context->struct_size = (uint32_t)sizeof(*context);
    config->abi_version = IU_POLICY_ABI_VERSION; config->struct_size = sizeof(*config);
    config->enabled = 1; config->compatibility_status = IU_COMPAT_SUPPORTED_AND_VERIFIED;
    config->expected_owner_uid = (uint32_t)geteuid(); config->eligible_directory_count = 1;
    config->eligible_directories[0].path_length = (uint32_t)parent_length;
    memcpy(config->eligible_directories[0].path, plan->canonical_path, parent_length);
    config->eligible_directories[0].path[parent_length] = '\0';
    config->eligible_directories[0].owner_uid = (uint32_t)geteuid();
    config->eligible_directories[0].mode = 0700;
    config->eligible_directories[0].file_type = IU_POLICY_FILE_DIRECTORY;
    config->eligible_directories[0].metadata_verified = 1;
}

static void test_policy_fail_closed(const char *root)
{
    char path[1024]; struct iu_execution_plan_v1 plan;
    struct iu_execution_planner_test_context_v1 context;
    struct iu_policy_target_v1 target;
    struct iu_policy_result_v1 result;
    uint32_t outcome = UINT32_MAX;
    CHECK(load_path(root, "parseable", path) == 0);
    CHECK(chmod(path, 0700) == 0);
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    make_policy(&context, &plan);
    memset(&target, 0, sizeof(target)); target.abi_version = IU_POLICY_ABI_VERSION;
    target.struct_size = sizeof(target); target.inspection_state = IU_POLICY_INSPECTION_OK;
    target.file_type = IU_POLICY_FILE_REGULAR; target.owner_uid = plan.owner_uid;
    target.group_uid = plan.owner_gid; target.mode = 0100700; target.link_count = 1;
    target.canonical_path_length = plan.canonical_path_length;
    memcpy(target.canonical_path, plan.canonical_path, plan.canonical_path_length + 1);
    target.path_device = target.descriptor_device = plan.device_number;
    target.path_inode = target.descriptor_inode = plan.inode;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0);
    CHECK(outcome == IU_POLICY_ALLOW_ELIGIBLE); /* Fixture-only hypothetical eligibility. */

    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0);
    CHECK(result.outcome == IU_POLICY_ALLOW_ELIGIBLE);
    context.policy.enabled = 0;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0 && outcome == IU_POLICY_DENY_DISABLED);
    context.policy.enabled = 1; context.policy.compatibility_status = IU_COMPAT_UNVERIFIED;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0 && outcome == IU_POLICY_DENY_UNVERIFIED_BACKEND);
    context.policy.compatibility_status = IU_COMPAT_UNSUPPORTED_PLATFORM;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0 && outcome == IU_POLICY_DENY_UNSUPPORTED_TARGET);
    context.policy.compatibility_status = IU_COMPAT_SUPPORTED_AND_VERIFIED;
    target.owner_uid++;
    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0 && result.outcome == IU_POLICY_DENY_UNSAFE_FILE);
    target.owner_uid--;
    target.mode = 0100722;
    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0 && result.outcome == IU_POLICY_DENY_UNSAFE_FILE);
    target.mode = 0100700;
    target.descriptor_inode++;
    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0 && result.outcome == IU_POLICY_DENY_IDENTITY_MISMATCH);
    target.descriptor_inode--;
    memcpy(target.canonical_path, "/System/fixture", sizeof("/System/fixture"));
    target.canonical_path_length = (uint32_t)strlen("/System/fixture");
    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0 && result.outcome == IU_POLICY_DENY_PROTECTED_PATH);
    memcpy(target.canonical_path, plan.canonical_path, plan.canonical_path_length + 1);
    target.canonical_path_length = plan.canonical_path_length;
    context.policy.eligible_directories[0].path[0] = '/';
    memcpy(context.policy.eligible_directories[0].path, "/opt/not-targeted", sizeof("/opt/not-targeted"));
    context.policy.eligible_directories[0].path_length = (uint32_t)strlen("/opt/not-targeted");
    CHECK(iu_policy_evaluate_v1(&context.policy, &target, &result) == 0 && result.outcome == IU_POLICY_SKIP_NOT_TARGETED);
    make_policy(&context, &plan);
    context.policy.eligible_directory_count = IU_POLICY_MAX_DIRECTORIES + 1;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0 && outcome == IU_POLICY_DENY_INTERNAL_ERROR);
    context.policy.eligible_directory_count = 1;
    target.abi_version = 99;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == 0 && outcome == IU_POLICY_DENY_INTERNAL_ERROR);
    target.abi_version = IU_POLICY_ABI_VERSION;

    /* Production entry point uses disabled policy and unverified adapter facts. */
    CHECK(iu_execution_plan_create_v1(path, &plan) == 0);
    CHECK(plan.policy_outcome == IU_POLICY_DENY_DISABLED);
    CHECK(plan.adapter_compatibility != IU_AME_SUPPORTED_AND_VERIFIED);
    CHECK(plan.operational_authorization == 0 && plan.device_runtime_verified == 0);
    context.struct_size--;
    CHECK(iu_execution_plan_test_evaluate_v1(&context, &target, &outcome) == -IU_EXECUTION_PLAN_ERROR_ABI);
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    test_fixtures(argv[1]);
    test_descriptor_and_revalidation(argv[1]);
    test_policy_fail_closed(argv[1]);
    if (failures != 0) return 1;
    puts("read-only execution planner fixtures passed");
    return 0;
}
