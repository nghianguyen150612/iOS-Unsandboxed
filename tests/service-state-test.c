#define _POSIX_C_SOURCE 200809L
#include "iu_service_state.h"

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char valid_state[] =
    "ios-unsandboxed-state\n"
    "schema_version=1\n"
    "service_installation=installed\n"
    "execution_activation=disabled\n";

struct fixture {
    char directory[64];
    char path[128];
    uid_t uid;
    gid_t gid;
};

static void write_bytes(const char *path, const char *bytes, size_t length, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    assert(fchmod(fd, mode) == 0);
    size_t done = 0;
    while (done < length) {
        ssize_t written = write(fd, bytes + done, length - done);
        assert(written > 0);
        done += (size_t)written;
    }
    assert(close(fd) == 0);
}

static void remove_state(const struct fixture *fixture)
{
    struct stat st;
    if (lstat(fixture->path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) assert(rmdir(fixture->path) == 0);
        else assert(unlink(fixture->path) == 0);
    }
}

static struct iu_service_state_result_v1 load(const struct fixture *fixture)
{
    struct iu_service_state_result_v1 result;
    assert(iu_service_state_load_v1(fixture->path, fixture->uid, fixture->gid,
                                    fixture->uid, fixture->gid, &result) == 0);
    assert(result.abi_version == IU_SERVICE_STATE_ABI_VERSION);
    assert(result.struct_size == sizeof(result));
    assert(result.execution_activation == IU_EXECUTION_ACTIVATION_DISABLED);
    return result;
}

static struct fixture make_fixture(void)
{
    struct fixture fixture = {0};
    strcpy(fixture.directory, "/tmp/iu-state-XXXXXX");
    assert(mkdtemp(fixture.directory) != NULL);
    assert(snprintf(fixture.path, sizeof(fixture.path), "%s/install-state",
                    fixture.directory) > 0);
    fixture.uid = getuid();
    fixture.gid = getgid();
    return fixture;
}

static void test_missing_and_valid(const struct fixture *fixture)
{
    struct iu_service_state_result_v1 result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_FILE_MISSING);
    assert(result.service_installation == IU_SERVICE_INSTALLATION_UNKNOWN);
    assert(result.schema_supported == 0);

    write_bytes(fixture->path, valid_state, sizeof(valid_state) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_VALID);
    assert(result.schema_version == IU_SERVICE_STATE_SCHEMA_VERSION);
    assert(result.schema_supported == 1);
    assert(result.service_installation == IU_SERVICE_INSTALLATION_INSTALLED);
    assert(result.execution_activation == IU_EXECUTION_ACTIVATION_DISABLED);
}

static void test_bad_contents(const struct fixture *fixture)
{
    struct iu_service_state_result_v1 result;
    const char unsupported[] =
        "ios-unsandboxed-state\n"
        "schema_version=2\n"
        "service_installation=installed\n"
        "execution_activation=disabled\n";
    const char malformed[] = "this is not an install-state file\n";
    const char noncanonical_version[] =
        "ios-unsandboxed-state\n"
        "schema_version=01\n"
        "service_installation=installed\n"
        "execution_activation=disabled\n";
    const char enabled[] =
        "ios-unsandboxed-state\n"
        "schema_version=1\n"
        "service_installation=installed\n"
        "execution_activation=enabled\n";
    const char truncated[] =
        "ios-unsandboxed-state\n"
        "schema_version=1\n"
        "service_installation=installed\n";

    write_bytes(fixture->path, malformed, sizeof(malformed) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_CORRUPT);
    assert(result.execution_activation == IU_EXECUTION_ACTIVATION_DISABLED);

    write_bytes(fixture->path, noncanonical_version, sizeof(noncanonical_version) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_CORRUPT);

    write_bytes(fixture->path, unsupported, sizeof(unsupported) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSUPPORTED_SCHEMA);
    assert(result.schema_version == 2);
    assert(result.schema_supported == 0);
    assert(result.execution_activation == IU_EXECUTION_ACTIVATION_DISABLED);

    write_bytes(fixture->path, truncated, sizeof(truncated) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_CORRUPT);

    write_bytes(fixture->path, enabled, sizeof(enabled) - 1, 0600);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_CORRUPT);
    assert(result.service_installation == IU_SERVICE_INSTALLATION_UNKNOWN);
    assert(result.execution_activation == IU_EXECUTION_ACTIVATION_DISABLED);
}

static void test_metadata_checks(const struct fixture *fixture)
{
    struct iu_service_state_result_v1 result;
    uid_t wrong_uid = fixture->uid == 0 ? 1 : 0;
    gid_t wrong_gid = fixture->gid == 0 ? 1 : 0;

    write_bytes(fixture->path, valid_state, sizeof(valid_state) - 1, 0644);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);

    write_bytes(fixture->path, valid_state, sizeof(valid_state) - 1, 0600);
    assert(iu_service_state_load_v1(fixture->path, fixture->uid, fixture->gid,
                                    wrong_uid, fixture->gid, &result) == 0);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);
    assert(iu_service_state_load_v1(fixture->path, fixture->uid, fixture->gid,
                                    fixture->uid, wrong_gid, &result) == 0);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);
    assert(iu_service_state_load_v1(fixture->path, wrong_uid, fixture->gid,
                                    fixture->uid, fixture->gid, &result) == 0);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);

    assert(chmod(fixture->directory, 0755) == 0);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);
    assert(chmod(fixture->directory, 0700) == 0);

    remove_state(fixture);
    assert(symlink("missing-target", fixture->path) == 0);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);

    remove_state(fixture);
    assert(mkdir(fixture->path, 0700) == 0);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);

    remove_state(fixture);
    assert(mkfifo(fixture->path, 0600) == 0);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_UNSAFE);
}

static void test_interrupted_atomic_write(const struct fixture *fixture)
{
    char temporary[160];
    const char partial[] = "ios-unsandboxed-state\nschema_version=1\n";
    struct iu_service_state_result_v1 result;

    remove_state(fixture);
    write_bytes(fixture->path, valid_state, sizeof(valid_state) - 1, 0600);
    assert(snprintf(temporary, sizeof(temporary), "%s/install-state.tmp", fixture->directory) > 0);
    write_bytes(temporary, partial, sizeof(partial) - 1, 0600);

    /* A crash before rename leaves the previous canonical state intact. */
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_VALID);
    assert(unlink(temporary) == 0);

    /* A complete replacement becomes visible only after the atomic rename. */
    write_bytes(temporary, valid_state, sizeof(valid_state) - 1, 0600);
    assert(rename(temporary, fixture->path) == 0);
    result = load(fixture);
    assert(result.state_status == IU_SERVICE_STATE_VALID);
}

struct reader_args {
    const struct fixture *fixture;
    int failed;
};

static void *concurrent_reader(void *context)
{
    struct reader_args *args = context;
    for (unsigned int i = 0; i < 300; ++i) {
        struct iu_service_state_result_v1 result = load(args->fixture);
        if (result.state_status != IU_SERVICE_STATE_VALID ||
            result.execution_activation != IU_EXECUTION_ACTIVATION_DISABLED) {
            args->failed = 1;
            break;
        }
    }
    return NULL;
}

static void test_concurrent_atomic_replacement(const struct fixture *fixture)
{
    pthread_t readers[4];
    struct reader_args arguments[4];
    char temporary[160];

    remove_state(fixture);
    write_bytes(fixture->path, valid_state, sizeof(valid_state) - 1, 0600);
    assert(snprintf(temporary, sizeof(temporary), "%s/install-state.next", fixture->directory) > 0);
    for (size_t i = 0; i < 4; ++i) {
        arguments[i].fixture = fixture;
        arguments[i].failed = 0;
        assert(pthread_create(&readers[i], NULL, concurrent_reader, &arguments[i]) == 0);
    }
    for (unsigned int i = 0; i < 100; ++i) {
        write_bytes(temporary, valid_state, sizeof(valid_state) - 1, 0600);
        assert(rename(temporary, fixture->path) == 0);
    }
    for (size_t i = 0; i < 4; ++i) {
        assert(pthread_join(readers[i], NULL) == 0);
        assert(arguments[i].failed == 0);
    }
}

int main(void)
{
    struct fixture fixture = make_fixture();
    struct iu_service_state_result_v1 result;
    char missing_directory[128];

    assert(snprintf(missing_directory, sizeof(missing_directory),
                    "%s/absent/install-state", fixture.directory) > 0);
    assert(iu_service_state_load_v1(missing_directory, fixture.uid, fixture.gid,
                                    fixture.uid, fixture.gid, &result) == 0);
    assert(result.state_status == IU_SERVICE_STATE_DIRECTORY_MISSING);

    test_missing_and_valid(&fixture);
    test_bad_contents(&fixture);
    test_metadata_checks(&fixture);
    test_interrupted_atomic_write(&fixture);
    test_concurrent_atomic_replacement(&fixture);

    remove_state(&fixture);
    assert(rmdir(fixture.directory) == 0);
    puts("service-state tests passed (temporary fixture only; read-only production API)");
    return 0;
}
