#include "iu_peer_auth.h"
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int pair[2]; struct iu_peer_identity peer;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(iu_peer_authenticate(pair[0], &peer) == 0);
    assert(peer.uid == geteuid());
    assert(iu_peer_authorize_readonly(&peer));
    assert(!iu_peer_authorize_management(NULL));
    peer.uid = 501;
    assert(!iu_peer_authorize_management(&peer));
    peer.uid = 0;
    assert(iu_peer_authorize_management(&peer));
    assert(iu_peer_authenticate(-1, &peer) != 0);
    close(pair[0]); close(pair[1]);
    return 0;
}
