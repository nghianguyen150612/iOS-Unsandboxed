#ifndef IU_LAUNCH_BINDING_H
#define IU_LAUNCH_BINDING_H
#include "iu_artifact_provenance.h"
#define IU_LAUNCH_BINDING_ABI_VERSION UINT32_C(1)
#define IU_LAUNCH_RESULT_V1_SIZE UINT32_C(5472)
#define IU_LAUNCH_SUMMARY_ABI_VERSION_V2 UINT32_C(2)
#define IU_LAUNCH_SUMMARY_V2_SIZE UINT32_C(3376)
enum iu_launch_operation_v1 { IU_LAUNCH_OPERATION_PREVIEW = 1 };
enum iu_launch_scope_v1 { IU_LAUNCH_SCOPE_UNVERIFIED, IU_LAUNCH_SCOPE_NOT_CONFIGURED, IU_LAUNCH_SCOPE_MATCH };
enum iu_launch_decision_v1 { IU_LAUNCH_POLICY_DISABLED = 1, IU_LAUNCH_KNOWN_PROTECTED, IU_LAUNCH_PROVENANCE_UNKNOWN, IU_LAUNCH_ORIGIN_NOT_AUTHENTICATED, IU_LAUNCH_PROVENANCE_IDENTITY_MISMATCH, IU_LAUNCH_DECISION_SCOPE_NOT_CONFIGURED, IU_LAUNCH_UNSUPPORTED_ARTIFACT };
enum iu_launch_revalidation_v1 { IU_LAUNCH_SAME_OPEN_OBJECT = 1, IU_LAUNCH_PATH_REPLACED, IU_LAUNCH_OBJECT_MODIFIED, IU_LAUNCH_IDENTITY_UNVERIFIED, IU_LAUNCH_STALE_EVIDENCE, IU_LAUNCH_STALE_POLICY };
enum iu_launch_boundary_v1 { IU_LAUNCH_BOUNDARY_NOT_IMPLEMENTED = 1 };
struct iu_launch_request_v1 {
    uint32_t abi_version, struct_size, operation, path_length;
    char path[IU_POLICY_PATH_CAPACITY];
    const uint8_t *evidence;
    uint32_t evidence_length;
};
struct iu_launch_result_v1 {
    uint32_t abi_version, struct_size, operation, scope_state, store_state;
    uint32_t hypothetical_p003_outcome, decision, boundary_status, operational_authorization;
    uint32_t evidence_length;
    uint64_t scope_device, scope_inode, store_device, store_inode;
    uint8_t store_sha256[32];
    char scope_path[IU_POLICY_PATH_CAPACITY];
    char requested_path[IU_POLICY_PATH_CAPACITY];
    struct iu_execution_plan_v1 artifact;
    struct iu_provenance_result_v1 provenance;
    uint8_t evidence[IU_PROVENANCE_EVIDENCE_MAX];
};
_Static_assert(sizeof(struct iu_launch_result_v1)==IU_LAUNCH_RESULT_V1_SIZE, "launch result ABI changed");
/* fd is borrowed; the result is a snapshot, never a permit. Evidence is a
 * caller-supplied byte snapshot; supply the current bytes again at revalidation. */
int32_t iu_launch_binding_preview_fd_v1(int fd, const struct iu_launch_request_v1 *request, struct iu_launch_result_v1 *result);
int32_t iu_launch_binding_revalidate_fd_v1(int fd, const struct iu_launch_result_v1 *previous, const uint8_t *evidence, uint32_t evidence_length);
struct iu_launch_cli_summary_v1 { uint32_t abi_version, struct_size, scope_state, store_state, provenance_state, decision, boundary_status, operational_authorization; uint64_t device, inode; uint8_t sha256[32]; };
int32_t iu_launch_binding_path_summary_v1(const char *path, struct iu_launch_cli_summary_v1 *summary);
/* P013C projection of a P012 v1 descriptor preview. The v1 provenance result
 * is intentionally omitted: it has no production Ed25519 provider. */
struct iu_launch_cli_summary_v2 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t scope_state;
    uint32_t store_state;
    uint32_t hypothetical_p003_outcome;
    uint32_t decision;
    uint32_t boundary_status;
    uint32_t operational_authorization;
    uint64_t scope_device;
    uint64_t scope_inode;
    uint64_t store_device;
    uint64_t store_inode;
    uint8_t store_sha256[32];
    char scope_path[IU_POLICY_PATH_CAPACITY];
    char requested_path[IU_POLICY_PATH_CAPACITY];
    struct iu_execution_plan_v1 artifact;
};
_Static_assert(sizeof(struct iu_launch_cli_summary_v2)==IU_LAUNCH_SUMMARY_V2_SIZE,
               "launch summary v2 ABI size changed");
int32_t iu_launch_binding_preview_fd_summary_v2(int borrowed_fd,
    const char *requested_path, struct iu_launch_cli_summary_v2 *summary);
int32_t iu_launch_binding_revalidate_fd_summary_v2(int borrowed_fd,
    const struct iu_launch_cli_summary_v2 *previous);
#ifdef IU_LAUNCH_BINDING_TESTING
/* Test roots are injected only into test binaries; no runtime production switch. */
int32_t iu_launch_binding_test_scope_v1(int rootfd, int datafd, uint32_t uid, uint32_t gid, const char *logical_path, struct iu_launch_result_v1 *result);
#endif
#endif
