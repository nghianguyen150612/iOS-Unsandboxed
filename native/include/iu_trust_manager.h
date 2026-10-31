#ifndef IU_TRUST_MANAGER_H
#define IU_TRUST_MANAGER_H
#include <sys/types.h>
/* Caller holds the shared installer lock and has verified installation for apply.
 * No execution authorization is produced. */
int iu_trust_manager_run(int datafd,uid_t uid,gid_t gid,const char *action,
    const char *first,const char *second,const char *publisher,int apply,
    const char *interrupt_phase);
#endif
