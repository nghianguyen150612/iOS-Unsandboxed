#ifndef IU_PEER_AUTH_H
#define IU_PEER_AUTH_H
#include <sys/types.h>
struct iu_peer_identity { uid_t uid; gid_t gid; };
int iu_peer_authenticate(int fd, struct iu_peer_identity *identity);
int iu_peer_authorize_readonly(const struct iu_peer_identity *identity);
int iu_peer_authorize_management(const struct iu_peer_identity *identity);
#endif
