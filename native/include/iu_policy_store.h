#ifndef IU_POLICY_STORE_H
#define IU_POLICY_STORE_H
#include "iu_policy.h"
#include <sys/types.h>
#include <stddef.h>
#define IU_POLICY_STORE_ABI_VERSION 1U
#define IU_POLICY_STORE_MAX_BYTES 17000U
#define IU_POLICY_SCOPE_BASE "/opt/ios-unsandboxed-scopes/"
enum iu_policy_store_state { IU_STORE_MISSING, IU_STORE_VALID, IU_STORE_CORRUPT, IU_STORE_UNSAFE, IU_STORE_UNSUPPORTED, IU_STORE_IO_ERROR };
struct iu_policy_store {
    unsigned state, schema, count;
    char scopes[IU_POLICY_MAX_DIRECTORIES][IU_POLICY_PATH_CAPACITY];
    uint64_t devices[IU_POLICY_MAX_DIRECTORIES], inodes[IU_POLICY_MAX_DIRECTORIES];
};
int iu_policy_store_load(int datafd, uid_t uid, gid_t gid, struct iu_policy_store *out);
int iu_policy_store_encode(const struct iu_policy_store *store, char *out, size_t capacity, size_t *length);
int iu_policy_scope_syntax(const char *path);
int iu_policy_scope_inspect(int rootfd, const char *path, uid_t uid, gid_t gid, struct iu_policy_directory_v1 *out, uint64_t *device, uint64_t *inode, int require_empty);
const char *iu_policy_store_state_name(unsigned state);
#endif
