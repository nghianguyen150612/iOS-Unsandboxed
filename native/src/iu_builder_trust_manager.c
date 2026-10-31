#include "iu_builder_trust_manager.h"
#include <stddef.h>
_Static_assert(offsetof(struct iu_builder_admin_request_v1,action)==24,"builder argv ABI");
_Static_assert(offsetof(struct iu_builder_admin_request_v1,reserved)==56,"builder reserved ABI");
int iu_builder_trust_manager_run(int datafd,uid_t uid,gid_t gid,const char *action,
    const char *first,const char *second,const char *identity,int apply,const char *fault)
{
    const struct iu_builder_admin_request_v1 request={1,sizeof(request),datafd,uid,gid,
        (uint32_t)apply,action,first,second,identity,0};
#if defined(IU_INSTALLER_TESTING)
    if(fault)return iu_builder_admin_test_v1(&request,fault);
#else
    (void)fault;
#endif
    return iu_builder_admin_v1(&request);
}
