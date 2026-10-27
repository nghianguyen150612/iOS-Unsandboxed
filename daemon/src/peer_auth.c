#define _GNU_SOURCE
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "iu_peer_auth.h"
#include <sys/socket.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

int iu_peer_authenticate(int fd, struct iu_peer_identity *identity)
{
    if (identity == NULL) { errno = EINVAL; return -1; }
#if defined(__APPLE__)
    if (getpeereid(fd, &identity->uid, &identity->gid) != 0) return -1;
    return 0;
#elif defined(__linux__)
    struct ucred credentials;
    socklen_t length = (socklen_t)sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) return -1;
    identity->uid = credentials.uid;
    identity->gid = credentials.gid;
    return 0;
#else
    (void)fd; errno = ENOTSUP; return -1;
#endif
}

int iu_peer_authorize_readonly(const struct iu_peer_identity *identity)
{ return identity != NULL; }

int iu_peer_authorize_management(const struct iu_peer_identity *identity)
{ return identity != NULL && identity->uid == 0; }
