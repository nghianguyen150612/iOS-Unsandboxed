#ifndef IU_BUILDER_TRUST_MANAGER_H
#define IU_BUILDER_TRUST_MANAGER_H
#include <stdint.h>
#include <sys/types.h>
/* Scalar, versioned ABI. C owns platform/install checks and the shared P007
 * lock. Rust borrows argv strings and the held datafd; it never trusts plans. */
struct iu_builder_admin_request_v1 {
    uint32_t abi_version, struct_size;
    int32_t datafd;
    uint32_t uid, gid, apply;
    const char *action, *first, *second, *identity;
    uint64_t reserved;
};
_Static_assert(sizeof(struct iu_builder_admin_request_v1)==64,"builder admin ABI v1");
int32_t iu_builder_admin_v1(const struct iu_builder_admin_request_v1 *request);
int32_t iu_builder_admin_settled_v1(int32_t datafd,uint32_t uid,uint32_t gid);
#if defined(IU_INSTALLER_TESTING)
int32_t iu_builder_admin_test_v1(const struct iu_builder_admin_request_v1 *request,const char *fault);
#endif
int iu_builder_trust_manager_run(int datafd,uid_t uid,gid_t gid,const char *action,
    const char *first,const char *second,const char *identity,int apply,const char *fault);
#endif
