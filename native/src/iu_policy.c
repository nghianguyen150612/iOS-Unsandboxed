#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "iu_policy.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint32_t file_type_from_mode(mode_t mode);

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int32_t path_has_symlink_component(const char *path)
{
    char absolute_path[IU_POLICY_PATH_CAPACITY];
    char current_directory[IU_POLICY_PATH_CAPACITY];
    size_t path_length = strlen(path);
    size_t absolute_length;
    size_t component_start = 1;
    size_t index;

    if (path[0] == '/') {
        if (path_length >= sizeof(absolute_path)) {
            return -1;
        }
        memcpy(absolute_path, path, path_length + 1);
    } else {
        size_t current_length;
        if (getcwd(current_directory, sizeof(current_directory)) == NULL) {
            return -1;
        }
        current_length = strlen(current_directory);
        if (current_length + 1 + path_length >= sizeof(absolute_path)) {
            return -1;
        }
        memcpy(absolute_path, current_directory, current_length);
        absolute_path[current_length] = '/';
        memcpy(absolute_path + current_length + 1, path, path_length + 1);
    }

    absolute_length = strlen(absolute_path);
    for (index = 1; index <= absolute_length; ++index) {
        if (index == absolute_length || absolute_path[index] == '/') {
            struct stat status;
            char separator;

            if (index == component_start) {
                component_start = index + 1;
                continue;
            }
            separator = absolute_path[index];
            absolute_path[index] = '\0';
            if (lstat(absolute_path, &status) != 0) {
                return -1;
            }
            absolute_path[index] = separator;
            if (S_ISLNK(status.st_mode)) {
                return 1;
            }
            component_start = index + 1;
        }
    }
    return 0;
}

static const char *const protected_roots[] = {
    "/System",
    "/bin",
    "/sbin",
    "/usr",
    "/Library/Apple",
    "/Applications",
    "/Developer",
    "/private/etc",
    "/private/var/root",
    "/amethyst",
    "/var/jb"
};

static const char *const project_paths[] = {
    "/usr/local/bin/ios-unsandboxed",
    "/usr/local/bin/ios-unsandboxedd",
    "/usr/local/bin/iu",
    "/var/lib/ios-unsandboxed",
    "/usr/local/lib/ios-unsandboxed",
    "/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist",
    "/var/run/ios-unsandboxedd.sock",
    "/var/log/ios-unsandboxed"
};

static void set_result(struct iu_policy_result_v1 *result,
                       uint32_t outcome,
                       uint32_t reason)
{
    memset(result, 0, sizeof(*result));
    result->abi_version = IU_POLICY_ABI_VERSION;
    result->struct_size = (uint32_t)sizeof(*result);
    result->outcome = outcome;
    result->reason_code = reason;
}

static int32_t text_is_valid(const char *value, uint32_t length, uint32_t capacity)
{
    if (value == NULL || length == 0 || length >= capacity || value[length] != '\0') {
        return 0;
    }
    return memchr(value, '\0', length) == NULL;
}

static int32_t canonical_path_is_valid(const char *path, uint32_t length)
{
    uint32_t index;
    uint32_t component_start;

    if (!text_is_valid(path, length, IU_POLICY_PATH_CAPACITY) || path[0] != '/') {
        return 0;
    }
    if (length > 1 && path[length - 1] == '/') {
        return 0;
    }
    for (index = 1; index < length; ++index) {
        if (path[index] == '/' && path[index - 1] == '/') {
            return 0;
        }
    }

    component_start = 1;
    for (index = 1; index <= length; ++index) {
        if (index == length || path[index] == '/') {
            uint32_t component_length = index - component_start;
            if ((component_length == 1 && path[component_start] == '.') ||
                (component_length == 2 && path[component_start] == '.' &&
                 path[component_start + 1] == '.')) {
                return 0;
            }
            component_start = index + 1;
        }
    }
    return 1;
}

static int32_t path_at_or_below(const char *path, const char *root)
{
    size_t root_length = strlen(root);
    size_t path_length = strlen(path);

    if (path_length < root_length || memcmp(path, root, root_length) != 0) {
        return 0;
    }
    if (path_length == root_length) {
        return 1;
    }
    return root_length == 1 || path[root_length] == '/';
}

static int32_t is_protected_path(const char *path)
{
    size_t index;

    for (index = 0; index < sizeof(protected_roots) / sizeof(protected_roots[0]); ++index) {
        if (path_at_or_below(path, protected_roots[index])) {
            return 1;
        }
    }
    for (index = 0; index < sizeof(project_paths) / sizeof(project_paths[0]); ++index) {
        if (path_at_or_below(path, project_paths[index])) {
            return 1;
        }
    }
    return 0;
}

static int32_t directory_config_is_valid(const struct iu_policy_config_v1 *config,
                                         const struct iu_policy_directory_v1 *directory)
{
    uint32_t length = directory->path_length;

    if (!canonical_path_is_valid(directory->path, length) ||
        (length == 1 && directory->path[0] == '/') ||
        directory->owner_uid != config->expected_owner_uid ||
        directory->file_type != IU_POLICY_FILE_DIRECTORY ||
        directory->metadata_verified != 1 ||
        (directory->mode & UINT32_C(0022)) != 0 ||
        (directory->mode & UINT32_C(0500)) != UINT32_C(0500)) {
        return 0;
    }
    return 1;
}

static int32_t config_is_valid(const struct iu_policy_config_v1 *config)
{
    uint32_t index;

    if (config == NULL || config->abi_version != IU_POLICY_ABI_VERSION ||
        config->struct_size < sizeof(*config) || config->enabled > 1 ||
        config->compatibility_status > IU_COMPAT_INTERNAL_ERROR ||
        config->eligible_directory_count > IU_POLICY_MAX_DIRECTORIES) {
        return 0;
    }
    if (config->enabled == 1 && config->eligible_directory_count == 0) {
        return 0;
    }
    for (index = 0; index < config->eligible_directory_count; ++index) {
        if (!directory_config_is_valid(config, &config->eligible_directories[index])) {
            return 0;
        }
    }
    return 1;
}

static int32_t open_canonical_path_without_symlinks(const char *path)
{
    char components[IU_POLICY_PATH_CAPACITY];
    char *cursor;
    int current_descriptor;

    if (strlen(path) >= sizeof(components)) {
        return -1;
    }
    memcpy(components, path, strlen(path) + 1);
    current_descriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current_descriptor < 0) {
        return -1;
    }
    cursor = components + 1;
    while (*cursor != '\0') {
        char *component = cursor;
        char *separator = strchr(cursor, '/');
        int next_descriptor;

        if (separator != NULL) {
            *separator = '\0';
        }
        if (*component == '\0' || strcmp(component, ".") == 0 ||
            strcmp(component, "..") == 0) {
            (void)close(current_descriptor);
            return -1;
        }
        if (separator == NULL) {
            next_descriptor = openat(current_descriptor, component,
                                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        } else {
            next_descriptor = openat(current_descriptor, component,
                                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        (void)close(current_descriptor);
        if (next_descriptor < 0) {
            return -1;
        }
        if (separator == NULL) {
            return next_descriptor;
        }
        current_descriptor = next_descriptor;
        cursor = separator + 1;
    }
    (void)close(current_descriptor);
    return -1;
}

static uint32_t file_type_from_mode(mode_t mode)
{
    if (S_ISREG(mode)) {
        return IU_POLICY_FILE_REGULAR;
    }
    if (S_ISDIR(mode)) {
        return IU_POLICY_FILE_DIRECTORY;
    }
    return IU_POLICY_FILE_OTHER;
}

int32_t iu_policy_inspect_path_v1(const char *path,
                                  uint32_t path_length,
                                  struct iu_policy_target_v1 *target)
{
    char input_path[IU_POLICY_PATH_CAPACITY];
    char canonical_path[PATH_MAX];
    struct stat initial_status;
    struct stat path_status;
    struct stat descriptor_status;
    struct stat final_input_status;
    int descriptor;
    int32_t symlink_state;

    if (target == NULL) {
        return -1;
    }
    memset(target, 0, sizeof(*target));
    target->abi_version = IU_POLICY_ABI_VERSION;
    target->struct_size = (uint32_t)sizeof(*target);
    target->inspection_state = IU_POLICY_INSPECTION_ERROR;
    target->inspection_error = IU_POLICY_INSPECTION_ERROR_INVALID_ARGUMENT;

    if (path == NULL || path_length == 0 || path_length >= IU_POLICY_PATH_CAPACITY ||
        memchr(path, '\0', path_length) != NULL) {
        return -1;
    }
    memcpy(input_path, path, path_length);
    input_path[path_length] = '\0';

    symlink_state = path_has_symlink_component(input_path);
    if (symlink_state < 0) {
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_PATH;
        return -1;
    }
    if (symlink_state > 0) {
        target->inspection_state = IU_POLICY_INSPECTION_OK;
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_NONE;
        target->path_was_symlink = 1;
        return 0;
    }

    if (lstat(input_path, &initial_status) != 0) {
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_PATH;
        return -1;
    }
    if (S_ISLNK(initial_status.st_mode)) {
        target->inspection_state = IU_POLICY_INSPECTION_OK;
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_NONE;
        target->path_was_symlink = 1;
        return 0;
    }
    if (!S_ISREG(initial_status.st_mode)) {
        if (realpath(input_path, canonical_path) == NULL ||
            strlen(canonical_path) >= sizeof(target->canonical_path)) {
            target->inspection_error = IU_POLICY_INSPECTION_ERROR_PATH;
            return -1;
        }
        target->inspection_state = IU_POLICY_INSPECTION_OK;
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_NONE;
        target->file_type = file_type_from_mode(initial_status.st_mode);
        target->owner_uid = (uint32_t)initial_status.st_uid;
        target->group_uid = (uint32_t)initial_status.st_gid;
        target->mode = (uint32_t)initial_status.st_mode;
        target->link_count = (uint32_t)initial_status.st_nlink;
        target->canonical_path_length = (uint32_t)strlen(canonical_path);
        memcpy(target->canonical_path, canonical_path,
               (size_t)target->canonical_path_length + 1);
        target->path_device = (uint64_t)initial_status.st_dev;
        target->path_inode = (uint64_t)initial_status.st_ino;
        return 0;
    }
    if (realpath(input_path, canonical_path) == NULL) {
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_PATH;
        return -1;
    }
    if (strlen(canonical_path) >= sizeof(target->canonical_path)) {
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_PATH;
        return -1;
    }

    descriptor = open_canonical_path_without_symlinks(canonical_path);
    if (descriptor < 0) {
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_IO;
        return -1;
    }
    if (fstat(descriptor, &descriptor_status) != 0 ||
        stat(canonical_path, &path_status) != 0 ||
        lstat(input_path, &final_input_status) != 0) {
        (void)close(descriptor);
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_IO;
        return -1;
    }
    if (S_ISLNK(final_input_status.st_mode) ||
        !S_ISREG(path_status.st_mode) || !S_ISREG(descriptor_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino ||
        initial_status.st_dev != descriptor_status.st_dev ||
        initial_status.st_ino != descriptor_status.st_ino ||
        final_input_status.st_dev != descriptor_status.st_dev ||
        final_input_status.st_ino != descriptor_status.st_ino) {
        (void)close(descriptor);
        target->inspection_error = IU_POLICY_INSPECTION_ERROR_IDENTITY;
        return -1;
    }

    target->inspection_state = IU_POLICY_INSPECTION_OK;
    target->inspection_error = IU_POLICY_INSPECTION_ERROR_NONE;
    target->file_type = file_type_from_mode(descriptor_status.st_mode);
    target->owner_uid = (uint32_t)descriptor_status.st_uid;
    target->group_uid = (uint32_t)descriptor_status.st_gid;
    target->mode = (uint32_t)descriptor_status.st_mode;
    target->link_count = (uint32_t)descriptor_status.st_nlink;
    target->canonical_path_length = (uint32_t)strlen(canonical_path);
    memcpy(target->canonical_path, canonical_path,
           (size_t)target->canonical_path_length + 1);
    target->path_device = (uint64_t)path_status.st_dev;
    target->path_inode = (uint64_t)path_status.st_ino;
    target->descriptor_device = (uint64_t)descriptor_status.st_dev;
    target->descriptor_inode = (uint64_t)descriptor_status.st_ino;
    (void)close(descriptor);
    return 0;
}

static int32_t target_is_safe_file(const struct iu_policy_target_v1 *target)
{
    if (target->file_type != IU_POLICY_FILE_REGULAR ||
        !S_ISREG((mode_t)target->mode) ||
        target->path_was_symlink != 0 || target->link_count != 1 ||
        (target->mode & (uint32_t)(S_ISUID | S_ISGID)) != 0 ||
        (target->mode & UINT32_C(0111)) == 0 ||
        (target->mode & UINT32_C(0022)) != 0) {
        return 0;
    }
    return 1;
}

static int32_t path_is_configured(const struct iu_policy_config_v1 *config,
                                  const char *target_path)
{
    uint32_t index;

    for (index = 0; index < config->eligible_directory_count; ++index) {
        const struct iu_policy_directory_v1 *directory =
            &config->eligible_directories[index];
        const char *directory_path = directory->path;
        size_t directory_length = directory->path_length;
        size_t target_length = strlen(target_path);

        if (target_length > directory_length &&
            memcmp(target_path, directory_path, directory_length) == 0 &&
            (directory_length == 1 || target_path[directory_length] == '/')) {
            return 1;
        }
    }
    return 0;
}

int32_t iu_policy_evaluate_v1(const struct iu_policy_config_v1 *config,
                              const struct iu_policy_target_v1 *target,
                              struct iu_policy_result_v1 *result)
{
    if (result == NULL) {
        return -1;
    }
    set_result(result, IU_POLICY_DENY_INTERNAL_ERROR,
               IU_POLICY_REASON_INVALID_CONFIG);

    if (!config_is_valid(config) || target == NULL ||
        target->abi_version != IU_POLICY_ABI_VERSION ||
        target->struct_size < sizeof(*target)) {
        return 0;
    }
    if (config->enabled == 0) {
        set_result(result, IU_POLICY_DENY_DISABLED, IU_POLICY_REASON_DISABLED);
        return 0;
    }
    if (config->compatibility_status != IU_COMPAT_SUPPORTED_AND_VERIFIED) {
        if (config->compatibility_status == IU_COMPAT_UNVERIFIED) {
            set_result(result, IU_POLICY_DENY_UNVERIFIED_BACKEND,
                       IU_POLICY_REASON_BACKEND_UNVERIFIED);
        } else if (config->compatibility_status == IU_COMPAT_INTERNAL_ERROR) {
            set_result(result, IU_POLICY_DENY_INTERNAL_ERROR,
                       IU_POLICY_REASON_PREFLIGHT_ERROR);
        } else {
            set_result(result, IU_POLICY_DENY_UNSUPPORTED_TARGET,
                       IU_POLICY_REASON_UNSUPPORTED_INPUT);
        }
        return 0;
    }
    if (target->inspection_state != IU_POLICY_INSPECTION_OK) {
        if (target->inspection_error == IU_POLICY_INSPECTION_ERROR_IDENTITY) {
            set_result(result, IU_POLICY_DENY_IDENTITY_MISMATCH,
                       IU_POLICY_REASON_FILE_IDENTITY_CHANGED);
            return 0;
        }
        set_result(result, IU_POLICY_DENY_INTERNAL_ERROR,
                   IU_POLICY_REASON_INSPECTION_FAILED);
        return 0;
    }
    if (target->path_was_symlink != 0) {
        set_result(result, IU_POLICY_DENY_UNSAFE_FILE,
                   IU_POLICY_REASON_UNSAFE_PATH_OR_FILE);
        return 0;
    }
    if (!canonical_path_is_valid(target->canonical_path,
                                 target->canonical_path_length)) {
        set_result(result, IU_POLICY_DENY_UNSUPPORTED_TARGET,
                   IU_POLICY_REASON_UNSUPPORTED_INPUT);
        return 0;
    }
    if (is_protected_path(target->canonical_path)) {
        set_result(result, IU_POLICY_DENY_PROTECTED_PATH,
                   IU_POLICY_REASON_PROTECTED_PATH);
        return 0;
    }
    if (!target_is_safe_file(target) ||
        target->owner_uid != config->expected_owner_uid) {
        set_result(result, IU_POLICY_DENY_UNSAFE_FILE,
                   IU_POLICY_REASON_UNSAFE_PATH_OR_FILE);
        return 0;
    }
    if (target->path_inode == 0 || target->descriptor_inode == 0 ||
        target->path_device != target->descriptor_device ||
        target->path_inode != target->descriptor_inode) {
        set_result(result, IU_POLICY_DENY_IDENTITY_MISMATCH,
                   IU_POLICY_REASON_FILE_IDENTITY_CHANGED);
        return 0;
    }
    if (!path_is_configured(config, target->canonical_path)) {
        set_result(result, IU_POLICY_SKIP_NOT_TARGETED,
                   IU_POLICY_REASON_NOT_CONFIGURED);
        return 0;
    }

    set_result(result, IU_POLICY_ALLOW_ELIGIBLE, IU_POLICY_REASON_NONE);
    return 0;
}

const char *iu_policy_outcome_name_v1(uint32_t outcome)
{
    switch (outcome) {
    case IU_POLICY_ALLOW_ELIGIBLE:
        return "ALLOW_ELIGIBLE";
    case IU_POLICY_SKIP_NOT_TARGETED:
        return "SKIP_NOT_TARGETED";
    case IU_POLICY_DENY_DISABLED:
        return "DENY_DISABLED";
    case IU_POLICY_DENY_UNVERIFIED_BACKEND:
        return "DENY_UNVERIFIED_BACKEND";
    case IU_POLICY_DENY_PROTECTED_PATH:
        return "DENY_PROTECTED_PATH";
    case IU_POLICY_DENY_UNSAFE_FILE:
        return "DENY_UNSAFE_FILE";
    case IU_POLICY_DENY_IDENTITY_MISMATCH:
        return "DENY_IDENTITY_MISMATCH";
    case IU_POLICY_DENY_UNSUPPORTED_TARGET:
        return "DENY_UNSUPPORTED_TARGET";
    case IU_POLICY_DENY_INTERNAL_ERROR:
        return "DENY_INTERNAL_ERROR";
    default:
        return "DENY_INTERNAL_ERROR";
    }
}
