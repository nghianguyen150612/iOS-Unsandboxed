#define _GNU_SOURCE
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "iu_service_state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void init_result(struct iu_service_state_result_v1 *result)
{
    memset(result, 0, sizeof(*result));
    result->abi_version = IU_SERVICE_STATE_ABI_VERSION;
    result->struct_size = (uint32_t)sizeof(*result);
    result->state_status = IU_SERVICE_STATE_IO_ERROR;
    result->service_installation = IU_SERVICE_INSTALLATION_UNKNOWN;
    result->execution_activation = IU_EXECUTION_ACTIVATION_DISABLED;
}

static int parse_schema_version(const unsigned char *bytes, size_t length,
                                uint32_t *version, size_t *after_line)
{
    static const char prefix[] = "schema_version=";
    size_t position = sizeof(prefix) - 1U;
    uint32_t value = 0;
    size_t digits = 0;

    if (length < position || memcmp(bytes, prefix, position) != 0) return -1;
    if (position < length && bytes[position] == '0' && position + 1U < length &&
        bytes[position + 1U] >= '0' && bytes[position + 1U] <= '9') return -1;
    while (position < length && bytes[position] >= '0' && bytes[position] <= '9') {
        uint32_t digit = (uint32_t)(bytes[position] - '0');
        if (value > (UINT32_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
        ++position;
        ++digits;
    }
    if (digits == 0 || value == 0 || position >= length || bytes[position] != '\n') return -1;
    *version = value;
    *after_line = position + 1U;
    return 0;
}

static void parse_state(const unsigned char *bytes, size_t length,
                        struct iu_service_state_result_v1 *result)
{
    static const char header[] = "ios-unsandboxed-state\n";
    static const char body[] =
        "service_installation=installed\n"
        "execution_activation=disabled\n";
    size_t position = 0;
    size_t schema_line_length = 0;

    result->state_status = IU_SERVICE_STATE_CORRUPT;
    if (length < sizeof(header) - 1U ||
        memcmp(bytes, header, sizeof(header) - 1U) != 0) return;
    if (parse_schema_version(bytes + sizeof(header) - 1U,
                             length - (sizeof(header) - 1U),
                             &result->schema_version, &schema_line_length) != 0) return;
    position = (sizeof(header) - 1U) + schema_line_length;
    if (result->schema_version != IU_SERVICE_STATE_SCHEMA_VERSION) {
        result->state_status = IU_SERVICE_STATE_UNSUPPORTED_SCHEMA;
        return;
    }
    if (length - position != sizeof(body) - 1U ||
        memcmp(bytes + position, body, sizeof(body) - 1U) != 0) return;

    result->state_status = IU_SERVICE_STATE_VALID;
    result->schema_supported = 1U;
    result->service_installation = IU_SERVICE_INSTALLATION_INSTALLED;
    /* No on-disk value can enable execution in P005. */
    result->execution_activation = IU_EXECUTION_ACTIVATION_DISABLED;
}

static int split_state_path(const char *path, char *parent, size_t parent_size)
{
    const char *slash;
    size_t length;

    if (path == NULL || path[0] != '/') return -1;
    slash = strrchr(path, '/');
    if (slash == NULL || strcmp(slash + 1, "install-state") != 0) return -1;
    length = slash == path ? 1U : (size_t)(slash - path);
    if (length >= parent_size) return -1;
    memcpy(parent, path, length);
    parent[length] = '\0';
    return 0;
}

int iu_service_state_load_v1(const char *path,
                             uid_t expected_directory_uid,
                             gid_t expected_directory_gid,
                             uid_t expected_file_uid,
                             gid_t expected_file_gid,
                             struct iu_service_state_result_v1 *result)
{
    char parent[PATH_MAX];
    struct stat directory_stat;
    struct stat file_stat;
    unsigned char bytes[IU_SERVICE_STATE_MAX_BYTES];
    size_t length = 0;
    int directory_fd = -1;
    int file_fd = -1;
    int saved_errno;

    if (result == NULL) { errno = EINVAL; return -1; }
    init_result(result);
    if (split_state_path(path, parent, sizeof(parent)) != 0) {
        result->state_status = IU_SERVICE_STATE_UNSAFE;
        errno = EINVAL;
        return 0;
    }

    directory_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        result->state_status = errno == ENOENT ? IU_SERVICE_STATE_DIRECTORY_MISSING :
                                                 IU_SERVICE_STATE_IO_ERROR;
        return 0;
    }
    if (fstat(directory_fd, &directory_stat) != 0) goto io_error;
    if (!S_ISDIR(directory_stat.st_mode) ||
        directory_stat.st_uid != expected_directory_uid ||
        directory_stat.st_gid != expected_directory_gid ||
        (directory_stat.st_mode & 07777) != 0700) {
        result->state_status = IU_SERVICE_STATE_UNSAFE;
        goto done;
    }

    /* O_NONBLOCK prevents a raced FIFO replacement from hanging diagnostics. */
    file_fd = openat(directory_fd, "install-state",
                     O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file_fd < 0) {
        result->state_status = errno == ENOENT ? IU_SERVICE_STATE_FILE_MISSING :
                               errno == ELOOP ? IU_SERVICE_STATE_UNSAFE :
                                                IU_SERVICE_STATE_IO_ERROR;
        goto done;
    }
    if (fstat(file_fd, &file_stat) != 0) goto io_error;
    if (!S_ISREG(file_stat.st_mode) || file_stat.st_uid != expected_file_uid ||
        file_stat.st_gid != expected_file_gid || (file_stat.st_mode & 07777) != 0600 ||
        file_stat.st_nlink > 1 || file_stat.st_size < 0 ||
        (uint64_t)file_stat.st_size > IU_SERVICE_STATE_MAX_BYTES) {
        result->state_status = IU_SERVICE_STATE_UNSAFE;
        goto done;
    }

    while (length < sizeof(bytes)) {
        ssize_t count = read(file_fd, bytes + length, sizeof(bytes) - length);
        if (count > 0) { length += (size_t)count; continue; }
        if (count == 0) break;
        if (errno == EINTR) continue;
        goto io_error;
    }
    if (length == sizeof(bytes)) {
        unsigned char extra;
        ssize_t count;
        do { count = read(file_fd, &extra, 1); } while (count < 0 && errno == EINTR);
        if (count != 0) {
            result->state_status = IU_SERVICE_STATE_CORRUPT;
            goto done;
        }
    }
    if (fstat(file_fd, &directory_stat) != 0) goto io_error;
    if (directory_stat.st_dev != file_stat.st_dev || directory_stat.st_ino != file_stat.st_ino ||
        directory_stat.st_uid != file_stat.st_uid || directory_stat.st_gid != file_stat.st_gid ||
        directory_stat.st_mode != file_stat.st_mode || directory_stat.st_size != file_stat.st_size) {
        result->state_status = IU_SERVICE_STATE_CORRUPT;
        goto done;
    }
    parse_state(bytes, length, result);
    goto done;

io_error:
    saved_errno = errno;
    result->state_status = IU_SERVICE_STATE_IO_ERROR;
    errno = saved_errno;
done:
    if (file_fd >= 0) close(file_fd);
    if (directory_fd >= 0) close(directory_fd);
    return 0;
}

const char *iu_service_state_status_name_v1(uint32_t status)
{
    switch (status) {
        case IU_SERVICE_STATE_DIRECTORY_MISSING: return "directory missing";
        case IU_SERVICE_STATE_FILE_MISSING: return "file missing";
        case IU_SERVICE_STATE_VALID: return "valid";
        case IU_SERVICE_STATE_UNSAFE: return "unsafe";
        case IU_SERVICE_STATE_UNSUPPORTED_SCHEMA: return "unsupported schema";
        case IU_SERVICE_STATE_CORRUPT: return "corrupt";
        case IU_SERVICE_STATE_IO_ERROR: return "I/O error";
        default: return "invalid status";
    }
}
