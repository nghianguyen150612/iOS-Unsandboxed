#ifndef IU_POLICY_MANAGER_H
#define IU_POLICY_MANAGER_H
#include "iu_policy_store.h"
int iu_policy_preview(const struct iu_policy_store *store, int rootfd, const char *root,
                      int fixture, uid_t uid, gid_t gid, const char *target);
#endif
