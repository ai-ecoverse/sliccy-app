#ifndef SLICCY_EXEC_LANE_H
#define SLICCY_EXEC_LANE_H
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Diagnostic local-descriptor check, never a peer verifier or grant gate.
// An exec watcher may already have closed the remote endpoint. Darwin then
// returns ENOTCONN for LOCAL_PEERPID; this is unavailable identity, not a match.
static const char *inspect_exec_lane(int fd, pid_t child, uid_t expected_uid,
                                     int *peer_disconnected) {
    *peer_disconnected = 0;
    int type = 0; socklen_t size = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) ||
        size != sizeof(type) || type != SOCK_STREAM) return "socket-type";
    struct sockaddr_un address = {0}; size = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &size) ||
        address.sun_family != AF_UNIX) return "socket-family";
    pid_t peer = 0; size = sizeof(peer);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &size)) {
        if (errno != ENOTCONN) return "peer-pid-query";
        *peer_disconnected = 1;
    } else if (size != sizeof(peer) || peer != child) {
        return "peer-pid-mismatch";
    }
    uid_t uid; gid_t gid;
    if (getpeereid(fd, &uid, &gid)) return "peer-uid-query";
    if (uid != expected_uid) return "peer-uid-mismatch";
    return NULL;
}
#endif
