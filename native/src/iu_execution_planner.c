#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "iu_execution_planner.h"
#include "iu_preflight.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#error "P010 requires O_NOFOLLOW for safe path traversal"
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#if defined(__APPLE__)
#define PLAN_MTIME_NS(s) ((s).st_mtimespec.tv_nsec)
#define PLAN_CTIME_NS(s) ((s).st_ctimespec.tv_nsec)
#else
#define PLAN_MTIME_NS(s) ((s).st_mtim.tv_nsec)
#define PLAN_CTIME_NS(s) ((s).st_ctim.tv_nsec)
#endif

struct opened_path { int fd; int parent_fd; char *leaf; char canonical[IU_EXECUTION_PLAN_PATH_CAPACITY]; };

static int canonicalize_input(const char *input, char out[IU_EXECUTION_PLAN_PATH_CAPACITY])
{
    char cwd[IU_EXECUTION_PLAN_PATH_CAPACITY];
    char raw[IU_EXECUTION_PLAN_PATH_CAPACITY];
    size_t n, base = 0, i, component = 1, output_length = 1;
    if (input == NULL) return -1;
    n = strnlen(input, IU_EXECUTION_PLAN_PATH_CAPACITY);
    if (n == 0 || n >= IU_EXECUTION_PLAN_PATH_CAPACITY) return -1;
    if (input[0] == '/') {
        memcpy(raw, input, n + 1);
    } else {
        if (getcwd(cwd, sizeof(cwd)) == NULL) return -1;
        base = strlen(cwd);
        if (base + n + 2 > IU_EXECUTION_PLAN_PATH_CAPACITY) return -1;
        memcpy(raw, cwd, base); raw[base] = '/'; memcpy(raw + base + 1, input, n + 1);
    }
    n = strlen(raw);
    if (n < 2 || raw[n - 1] == '/') return -1;
    out[0] = '/'; out[1] = '\0';
    for (i = 1; i <= n; ++i) {
        if (i == n || raw[i] == '/') {
            size_t len = i - component;
            if (len == 0 || (len == 2 && raw[component] == '.' && raw[component + 1] == '.')) return -1;
            if (len == 1 && raw[component] == '.') { component = i + 1; continue; }
            if (output_length + len + (output_length > 1 ? 1U : 0U) >= IU_EXECUTION_PLAN_PATH_CAPACITY)
                return -1;
            if (output_length > 1) out[output_length++] = '/';
            memcpy(out + output_length, raw + component, len);
            output_length += len; out[output_length] = '\0';
            component = i + 1;
        }
    }
    return output_length > 1 ? 0 : -1;
}

static int open_identity_path(const char *input, struct opened_path *opened, struct stat *snapshot)
{
    char *cursor;
    int dirfd;
    struct stat at_path;
    memset(opened, 0, sizeof(*opened)); opened->fd = -1; opened->parent_fd = -1;
    if (canonicalize_input(input, opened->canonical) != 0) return -IU_EXECUTION_PLAN_ERROR_PATH;
    dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return -IU_EXECUTION_PLAN_ERROR_IO;
    cursor = opened->canonical + 1;
    for (;;) {
        char *slash = strchr(cursor, '/');
        int next;
        if (slash == NULL) {
            opened->parent_fd = dirfd; opened->leaf = cursor;
            if (fstatat(dirfd, cursor, &at_path, AT_SYMLINK_NOFOLLOW) != 0) goto io_fail;
            if (!S_ISREG(at_path.st_mode) || at_path.st_nlink != 1 || at_path.st_size < 0 ||
                (uint64_t)at_path.st_size > IU_AME_MAX_FILE_SIZE) goto unsafe_fail;
            opened->fd = openat(dirfd, cursor, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (opened->fd < 0) goto io_fail;
            if (fstat(opened->fd, snapshot) != 0 || !S_ISREG(snapshot->st_mode) ||
                snapshot->st_nlink != 1 || snapshot->st_dev != at_path.st_dev ||
                snapshot->st_ino != at_path.st_ino || snapshot->st_size != at_path.st_size ||
                snapshot->st_mode != at_path.st_mode || snapshot->st_uid != at_path.st_uid ||
                snapshot->st_gid != at_path.st_gid) goto identity_fail;
            return 0;
        }
        *slash = '\0';
        if (*cursor == '\0') goto path_fail;
        next = openat(dirfd, cursor, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        *slash = '/'; close(dirfd);
        if (next < 0) goto io_fail_closed;
        dirfd = next; cursor = slash + 1;
    }
path_fail: close(dirfd); return -IU_EXECUTION_PLAN_ERROR_PATH;
unsafe_fail: close(dirfd); return -IU_EXECUTION_PLAN_ERROR_UNSAFE_FILE;
identity_fail: close(opened->fd); opened->fd = -1; close(dirfd); opened->parent_fd = -1; return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
io_fail: close(dirfd); return -IU_EXECUTION_PLAN_ERROR_IO;
io_fail_closed: return -IU_EXECUTION_PLAN_ERROR_IO;
}

static void close_opened(struct opened_path *p)
{
    if (p->fd >= 0) close(p->fd);
    if (p->parent_fd >= 0) close(p->parent_fd);
}

static int stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_mtime == b->st_mtime && PLAN_MTIME_NS(*a) == PLAN_MTIME_NS(*b) &&
        a->st_ctime == b->st_ctime && PLAN_CTIME_NS(*a) == PLAN_CTIME_NS(*b);
}

static void set_defaults(struct iu_execution_plan_v1 *r)
{
    memset(r, 0, sizeof(*r)); r->abi_version = IU_EXECUTION_PLAN_ABI_VERSION;
    r->struct_size = (uint32_t)sizeof(*r); r->error_code = IU_EXECUTION_PLAN_ERROR_NONE;
    r->inspection_status = IU_EXECUTION_INSPECTION_BLOCKED;
    r->identity_status = IU_EXECUTION_IDENTITY_UNVERIFIED;
    r->signature_preparation = IU_EXECUTION_PREP_UNVERIFIED_RUNTIME;
    r->preview_status = IU_EXECUTION_PREVIEW_INSPECTION_BLOCKED;
    r->operational_authorization = 0; r->device_runtime_verified = 0;
}

static void evaluate_policy_and_capabilities(struct iu_execution_plan_v1 *r, const struct stat *st)
{
    struct iu_policy_config_v1 config;
    struct iu_policy_target_v1 target;
    struct iu_policy_result_v1 result;
    struct iu_preflight_result_v1 preflight;
    struct iu_ame_probe_result_v1 probe;
    size_t i;
    uint32_t launchd_runtime = 0, base_runtime = 0, signed_runtime = 0, adhoc_runtime = 0;
    memset(&config, 0, sizeof(config)); config.abi_version = IU_POLICY_ABI_VERSION;
    config.struct_size = (uint32_t)sizeof(config); config.enabled = 0;
    if (iu_preflight_detect_v1(&preflight) == 0 &&
        preflight.compatibility_status <= IU_COMPAT_INTERNAL_ERROR)
        config.compatibility_status = preflight.compatibility_status;
    else
        config.compatibility_status = IU_COMPAT_INTERNAL_ERROR;
    config.expected_owner_uid = (uint32_t)geteuid();
    memset(&target, 0, sizeof(target)); target.abi_version = IU_POLICY_ABI_VERSION;
    target.struct_size = (uint32_t)sizeof(target); target.inspection_state = IU_POLICY_INSPECTION_OK;
    target.file_type = IU_POLICY_FILE_REGULAR; target.owner_uid = (uint32_t)st->st_uid;
    target.group_uid = (uint32_t)st->st_gid; target.mode = (uint32_t)st->st_mode;
    target.link_count = (uint32_t)st->st_nlink; target.canonical_path_length = r->canonical_path_length;
    memcpy(target.canonical_path, r->canonical_path, (size_t)r->canonical_path_length + 1);
    target.path_device = (uint64_t)st->st_dev; target.path_inode = (uint64_t)st->st_ino;
    target.descriptor_device = (uint64_t)st->st_dev; target.descriptor_inode = (uint64_t)st->st_ino;
    (void)iu_policy_evaluate_v1(&config, &target, &result);
    r->policy_outcome = result.outcome; r->policy_reason = result.reason_code;
    r->blocking_reason = result.reason_code;
    r->required_capabilities = (UINT32_C(1) << IU_AME_CAP_ARM64_MACHO_INSPECTION) |
        (UINT32_C(1) << IU_AME_CAP_FUTURE_EXECUTION_ADAPTER);
    r->missing_prerequisites = UINT32_C(0x3ff);
    memset(&probe, 0, sizeof(probe));
    if (iu_ame_adapter_probe_v1(&probe) == 0 &&
        probe.abi_version == IU_AME_ADAPTER_ABI_VERSION &&
        probe.struct_size == sizeof(probe) &&
        probe.capabilities.abi_version == IU_AME_CAPABILITY_ABI_VERSION &&
        probe.capabilities.struct_size == sizeof(probe.capabilities) &&
        probe.capabilities.record_count == IU_AME_CAPABILITY_COUNT) {
        for (i = 0; i < probe.capabilities.record_count; ++i) {
            const struct iu_ame_capability_record_v1 *record = &probe.capabilities.records[i];
            if (record->status != IU_AME_CAP_RUNTIME_VERIFIED) continue;
            switch (record->capability_id) {
                case IU_AME_CAP_BUILD_IDENTIFICATION:
                    r->missing_prerequisites &= ~IU_EXECUTION_MISSING_TRUSTED_BUILD_IDENTITY; break;
                case IU_AME_CAP_LAUNCHD_HOOK_DETECTION: launchd_runtime = 1; break;
                case IU_AME_CAP_BASE_HOOK_DETECTION: base_runtime = 1; break;
                case IU_AME_CAP_SSH_EXEC_PATH_COVERAGE:
                    r->missing_prerequisites &= ~IU_EXECUTION_MISSING_SSH_COVERAGE; break;
                case IU_AME_CAP_SIGNED_MACHO_PREPARATION: signed_runtime = 1; break;
                case IU_AME_CAP_ADHOC_MACHO_PREPARATION: adhoc_runtime = 1; break;
                case IU_AME_CAP_FUTURE_EXECUTION_ADAPTER:
                    r->missing_prerequisites &= ~IU_EXECUTION_MISSING_EXECUTION_ADAPTER; break;
                default: break;
            }
        }
        if (launchd_runtime != 0 && base_runtime != 0)
            r->missing_prerequisites &= ~IU_EXECUTION_MISSING_HOOK_RUNTIME_EVIDENCE;
        if (signed_runtime != 0 && adhoc_runtime != 0)
            r->missing_prerequisites &= ~IU_EXECUTION_MISSING_SIGNATURE_PREPARATION;
        r->adapter_compatibility = probe.compatibility;
    } else {
        r->adapter_compatibility = IU_AME_INTERNAL_ERROR;
    }
    if (result.outcome == IU_POLICY_DENY_DISABLED) r->preview_status = IU_EXECUTION_PREVIEW_POLICY_DISABLED;
    else if (result.outcome == IU_POLICY_SKIP_NOT_TARGETED) r->preview_status = IU_EXECUTION_PREVIEW_NOT_TARGETED;
    else if (r->adapter_compatibility != IU_AME_SUPPORTED_AND_VERIFIED) r->preview_status = IU_EXECUTION_PREVIEW_BACKEND_UNVERIFIED;
    else r->preview_status = IU_EXECUTION_PREVIEW_RUNTIME_NOT_VERIFIED;
}

static int32_t execution_plan_create(const char *path, int borrowed_fd,
                                    struct iu_execution_plan_v1 *r)
{
    struct opened_path opened;
    struct opened_path rebound;
    struct stat before, after, path_after;
    struct stat rebound_status;
    struct iu_ame_macho_result_v1 macho;
    int rc, parser_rc, hash_rc, inspection_fd;
    if (r == NULL) return -IU_EXECUTION_PLAN_ERROR_INVALID_ARGUMENT;
    set_defaults(r);
    rc = open_identity_path(path, &opened, &before);
    if (rc != 0) { r->error_code = (uint32_t)-rc; return rc; }
    inspection_fd = borrowed_fd >= 0 ? borrowed_fd : opened.fd;
    if (borrowed_fd >= 0) {
        struct stat descriptor_before;
        if (fstat(borrowed_fd, &descriptor_before) != 0) {
            close_opened(&opened); r->error_code = IU_EXECUTION_PLAN_ERROR_IO;
            return -IU_EXECUTION_PLAN_ERROR_IO;
        }
        if (!stat_same(&before, &descriptor_before)) {
            close_opened(&opened); r->error_code = IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
            r->identity_status = IU_EXECUTION_IDENTITY_CHANGED;
            r->preview_status = IU_EXECUTION_PREVIEW_IDENTITY_CHANGED;
            return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
        }
    }
    parser_rc = iu_ame_macho_inspect_fd_v1(inspection_fd, &macho);
    if (parser_rc != 0) {
        rc = parser_rc == -IU_AME_ERROR_IDENTITY_MISMATCH ? IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED : IU_EXECUTION_PLAN_ERROR_IO;
        close_opened(&opened); r->error_code = (uint32_t)rc;
        if (rc == IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED) {
            r->identity_status = IU_EXECUTION_IDENTITY_CHANGED; r->preview_status = IU_EXECUTION_PREVIEW_IDENTITY_CHANGED;
        }
        return -rc;
    }
    hash_rc = iu_ame_sha256_fd_v1(inspection_fd, r->sha256);
    if (hash_rc != 0) {
        rc = hash_rc == -IU_AME_ERROR_IDENTITY_MISMATCH ? IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED : IU_EXECUTION_PLAN_ERROR_IO;
        close_opened(&opened); r->error_code = (uint32_t)rc;
        if (rc == IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED) {
            r->identity_status = IU_EXECUTION_IDENTITY_CHANGED; r->preview_status = IU_EXECUTION_PREVIEW_IDENTITY_CHANGED;
        }
        return -rc;
    }
    if (fstat(inspection_fd, &after) != 0) {
        close_opened(&opened); r->error_code = IU_EXECUTION_PLAN_ERROR_IO;
        return -IU_EXECUTION_PLAN_ERROR_IO;
    }
    if (!stat_same(&before, &after) ||
        fstatat(opened.parent_fd, opened.leaf, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !stat_same(&before, &path_after)) {
        close_opened(&opened); r->error_code = IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
        r->identity_status = IU_EXECUTION_IDENTITY_CHANGED; r->preview_status = IU_EXECUTION_PREVIEW_IDENTITY_CHANGED;
        return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
    }
    rc = open_identity_path(opened.canonical, &rebound, &rebound_status);
    if (rc != 0 || !stat_same(&before, &rebound_status)) {
        if (rc == 0) close_opened(&rebound);
        close_opened(&opened); r->error_code = IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
        r->identity_status = IU_EXECUTION_IDENTITY_CHANGED; r->preview_status = IU_EXECUTION_PREVIEW_IDENTITY_CHANGED;
        return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
    }
    close_opened(&rebound);
    r->file_type = IU_POLICY_FILE_REGULAR; r->owner_uid = (uint32_t)before.st_uid;
    r->owner_gid = (uint32_t)before.st_gid; r->mode = (uint32_t)(before.st_mode & 07777);
    r->link_count = (uint32_t)before.st_nlink; r->device_number = (uint64_t)before.st_dev;
    r->inode = (uint64_t)before.st_ino; r->file_size = (uint64_t)before.st_size;
    r->modification_seconds = (int64_t)before.st_mtime; r->modification_nanoseconds = (uint32_t)PLAN_MTIME_NS(before);
    r->change_seconds = (int64_t)before.st_ctime; r->change_nanoseconds = (uint32_t)PLAN_CTIME_NS(before);
    r->canonical_path_length = (uint32_t)strlen(opened.canonical);
    memcpy(r->canonical_path, opened.canonical, (size_t)r->canonical_path_length + 1);
    r->macho_state = macho.state; r->architecture = macho.architecture; r->macho_filetype = macho.macho_filetype;
    r->identity_status = IU_EXECUTION_IDENTITY_RECORDED;
    r->inspection_status = IU_EXECUTION_INSPECTION_COMPLETE;
    switch (macho.state) {
        case IU_AME_MACHO_PARSEABLE_CODEDIRECTORY: r->signature_preparation = IU_EXECUTION_PREP_PARSEABLE_SIGNATURE; break;
        case IU_AME_MACHO_ADHOC_SIGNATURE: r->signature_preparation = IU_EXECUTION_PREP_ADHOC_SIGNATURE; break;
        case IU_AME_MACHO_MALFORMED_SIGNATURE: case IU_AME_MACHO_EMPTY_SIGNATURE: r->signature_preparation = IU_EXECUTION_PREP_REQUIRES_REPAIR; break;
        case IU_AME_MACHO_NO_CODE_SIGNATURE: r->signature_preparation = IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND; break;
        case IU_AME_MACHO_UNSUPPORTED_FORMAT: r->signature_preparation = IU_EXECUTION_PREP_UNSUPPORTED_TARGET; break;
        default: r->signature_preparation = IU_EXECUTION_PREP_INVALID_BINARY; break;
    }
    if (macho.architecture == IU_ARCH_ARM64 && macho.macho_filetype != UINT32_C(2))
        r->signature_preparation = IU_EXECUTION_PREP_UNSUPPORTED_TARGET;
    evaluate_policy_and_capabilities(r, &before);
    if (r->signature_preparation == IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND)
        r->preview_status = IU_EXECUTION_PREVIEW_PREPARATION_NOT_IMPLEMENTED;
    else if (r->signature_preparation == IU_EXECUTION_PREP_UNSUPPORTED_TARGET ||
             r->signature_preparation == IU_EXECUTION_PREP_INVALID_BINARY)
        r->preview_status = IU_EXECUTION_PREVIEW_UNSUPPORTED_BINARY;
    else if (r->preview_status == IU_EXECUTION_PREVIEW_RUNTIME_NOT_VERIFIED)
        r->preview_status = IU_EXECUTION_PREVIEW_INSPECTION_COMPLETE;
    r->operational_authorization = 0; r->device_runtime_verified = 0;
    close_opened(&opened);
    return 0;
}

int32_t iu_execution_plan_create_v1(const char *path, struct iu_execution_plan_v1 *r)
{
    return execution_plan_create(path, -1, r);
}

int32_t iu_execution_plan_create_fd_v2(int borrowed_fd, const char *requested_path,
                                       struct iu_execution_plan_v1 *r)
{
    if (borrowed_fd < 0) {
        if (r != NULL) {
            set_defaults(r);
            r->error_code = IU_EXECUTION_PLAN_ERROR_INVALID_ARGUMENT;
        }
        return -IU_EXECUTION_PLAN_ERROR_INVALID_ARGUMENT;
    }
    return execution_plan_create(requested_path, borrowed_fd, r);
}

static int canonical_record_path_valid(const char *path, uint32_t length)
{
    uint32_t start = 1, i;
    if (length < 2 || path[0] != '/' || path[length - 1] == '/') return 0;
    for (i = 1; i <= length; ++i) {
        if (i == length || path[i] == '/') {
            uint32_t part = i - start;
            if (part == 0 || (part == 1 && path[start] == '.') ||
                (part == 2 && path[start] == '.' && path[start + 1] == '.')) return 0;
            start = i + 1;
        }
    }
    return 1;
}

static int plan_metadata_valid(const struct iu_execution_plan_v1 *p)
{
    return p != NULL && p->abi_version == IU_EXECUTION_PLAN_ABI_VERSION &&
        p->struct_size == sizeof(*p) && p->canonical_path_length > 1 &&
        p->canonical_path_length < sizeof(p->canonical_path) &&
        canonical_record_path_valid(p->canonical_path, p->canonical_path_length) &&
        p->canonical_path[p->canonical_path_length] == '\0' &&
        memchr(p->canonical_path, '\0', p->canonical_path_length) == NULL &&
        p->identity_status == IU_EXECUTION_IDENTITY_RECORDED && p->link_count == 1 &&
        p->inspection_status == IU_EXECUTION_INSPECTION_COMPLETE &&
        p->macho_state >= IU_AME_MACHO_PARSEABLE_CODEDIRECTORY && p->macho_state <= IU_AME_MACHO_IO_ERROR &&
        p->architecture <= IU_ARCH_X86 &&
        p->signature_preparation >= IU_EXECUTION_PREP_PARSEABLE_SIGNATURE &&
        p->signature_preparation <= IU_EXECUTION_PREP_UNVERIFIED_RUNTIME &&
        p->preview_status >= IU_EXECUTION_PREVIEW_INSPECTION_COMPLETE &&
        p->preview_status <= IU_EXECUTION_PREVIEW_RUNTIME_NOT_VERIFIED &&
        p->policy_outcome <= IU_POLICY_DENY_INTERNAL_ERROR &&
        p->policy_reason <= IU_POLICY_REASON_PREFLIGHT_ERROR &&
        p->adapter_compatibility <= IU_AME_INTERNAL_ERROR &&
        p->required_capabilities == ((UINT32_C(1) << IU_AME_CAP_ARM64_MACHO_INSPECTION) |
                                     (UINT32_C(1) << IU_AME_CAP_FUTURE_EXECUTION_ADAPTER)) &&
        (p->missing_prerequisites & ~UINT32_C(0x3ff)) == 0 &&
        p->error_code == IU_EXECUTION_PLAN_ERROR_NONE &&
        p->file_type == IU_POLICY_FILE_REGULAR && p->operational_authorization == 0 &&
        p->device_runtime_verified == 0 && p->reserved0 == 0 && p->reserved1 == 0 &&
        p->reserved[0] == 0 && p->reserved[1] == 0 && p->reserved[2] == 0 && p->reserved[3] == 0;
}

int32_t iu_execution_plan_revalidate_v1(const struct iu_execution_plan_v1 *p)
{
    struct iu_execution_plan_v1 current;
    if (p == NULL) return -IU_EXECUTION_PLAN_ERROR_INVALID_ARGUMENT;
    if (!plan_metadata_valid(p)) return -IU_EXECUTION_PLAN_ERROR_ABI;
    if (iu_execution_plan_create_v1(p->canonical_path, &current) != 0) return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
    if (p->file_type != current.file_type || p->owner_uid != current.owner_uid || p->owner_gid != current.owner_gid ||
        p->mode != current.mode || p->link_count != current.link_count || p->device_number != current.device_number ||
        p->inode != current.inode || p->file_size != current.file_size ||
        p->modification_seconds != current.modification_seconds || p->modification_nanoseconds != current.modification_nanoseconds ||
        p->change_seconds != current.change_seconds || p->change_nanoseconds != current.change_nanoseconds ||
        p->macho_state != current.macho_state || p->architecture != current.architecture ||
        p->macho_filetype != current.macho_filetype || memcmp(p->sha256, current.sha256, sizeof(p->sha256)) != 0)
        return -IU_EXECUTION_PLAN_ERROR_IDENTITY_CHANGED;
    return 0;
}

const char *iu_execution_plan_preparation_name_v1(uint32_t state)
{
    switch (state) {
        case IU_EXECUTION_PREP_PARSEABLE_SIGNATURE: return "PARSEABLE_SIGNATURE";
        case IU_EXECUTION_PREP_ADHOC_SIGNATURE: return "ADHOC_SIGNATURE";
        case IU_EXECUTION_PREP_REQUIRES_REPAIR: return "REQUIRES_REPAIR";
        case IU_EXECUTION_PREP_MISSING_SIGNATURE_COMMAND: return "PREPARATION_REQUIRED_BUT_NOT_IMPLEMENTED";
        case IU_EXECUTION_PREP_UNSUPPORTED_TARGET: return "UNSUPPORTED_TARGET";
        case IU_EXECUTION_PREP_INVALID_BINARY: return "INVALID_BINARY";
        default: return "UNVERIFIED_RUNTIME";
    }
}

const char *iu_execution_plan_preview_name_v1(uint32_t status)
{
    switch (status) {
        case IU_EXECUTION_PREVIEW_INSPECTION_COMPLETE: return "INSPECTION_COMPLETE";
        case IU_EXECUTION_PREVIEW_NOT_TARGETED: return "NOT_TARGETED";
        case IU_EXECUTION_PREVIEW_POLICY_DISABLED: return "POLICY_DISABLED";
        case IU_EXECUTION_PREVIEW_BACKEND_UNVERIFIED: return "BACKEND_UNVERIFIED";
        case IU_EXECUTION_PREVIEW_PREPARATION_NOT_IMPLEMENTED: return "PREPARATION_NOT_IMPLEMENTED";
        case IU_EXECUTION_PREVIEW_IDENTITY_CHANGED: return "IDENTITY_CHANGED";
        case IU_EXECUTION_PREVIEW_UNSUPPORTED_BINARY: return "UNSUPPORTED_BINARY";
        case IU_EXECUTION_PREVIEW_RUNTIME_NOT_VERIFIED: return "RUNTIME_NOT_VERIFIED";
        default: return "INSPECTION_BLOCKED";
    }
}

#ifdef IU_EXECUTION_PLANNER_TESTING
int32_t iu_execution_plan_test_evaluate_v1(const struct iu_execution_planner_test_context_v1 *c,
                                            const struct iu_policy_target_v1 *t, uint32_t *outcome)
{
    struct iu_policy_result_v1 result;
    if (c == NULL || t == NULL || outcome == NULL || c->abi_version != IU_EXECUTION_PLAN_ABI_VERSION ||
        c->struct_size != sizeof(*c))
        return -IU_EXECUTION_PLAN_ERROR_ABI;
    if (iu_policy_evaluate_v1(&c->policy, t, &result) != 0) return -IU_EXECUTION_PLAN_ERROR_INTERNAL;
    *outcome = result.outcome;
    return 0;
}
#endif
