#ifndef IU_SERVICE_STATE_H
#define IU_SERVICE_STATE_H

#include <stdint.h>
#include <sys/types.h>

#define IU_SERVICE_STATE_ABI_VERSION 1U
#define IU_SERVICE_STATE_SCHEMA_VERSION 1U
#define IU_SERVICE_STATE_MAX_BYTES 256U

enum iu_service_state_status_v1 {
    IU_SERVICE_STATE_DIRECTORY_MISSING = 0,
    IU_SERVICE_STATE_FILE_MISSING = 1,
    IU_SERVICE_STATE_VALID = 2,
    IU_SERVICE_STATE_UNSAFE = 3,
    IU_SERVICE_STATE_UNSUPPORTED_SCHEMA = 4,
    IU_SERVICE_STATE_CORRUPT = 5,
    IU_SERVICE_STATE_IO_ERROR = 6
};

enum iu_service_installation_v1 {
    IU_SERVICE_INSTALLATION_UNKNOWN = 0,
    IU_SERVICE_INSTALLATION_INSTALLED = 1
};

/* P005 has no activation operation. This value is intentionally one-way. */
enum iu_execution_activation_v1 {
    IU_EXECUTION_ACTIVATION_DISABLED = 0
};

struct iu_service_state_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t state_status;
    uint32_t schema_version;
    uint32_t schema_supported;
    uint32_t service_installation;
    uint32_t execution_activation;
};

/*
 * Read a state file without following its final path component. Production
 * callers pass the canonical path and root:wheel (UID/GID 0) for both the
 * directory and file. Fixture tests may pass their temporary-directory owner
 * IDs. This interface never writes state.
 */
int iu_service_state_load_v1(const char *path,
                             uid_t expected_directory_uid,
                             gid_t expected_directory_gid,
                             uid_t expected_file_uid,
                             gid_t expected_file_gid,
                             struct iu_service_state_result_v1 *result);

const char *iu_service_state_status_name_v1(uint32_t status);

#endif /* IU_SERVICE_STATE_H */
