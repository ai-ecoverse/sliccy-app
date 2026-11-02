#include "exec-lane.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int main(void) {
    alarm(5);
    char root[] = "/private/tmp/sliccy-exec-lane.XXXXXX";
    assert(mkdtemp(root));
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/lane", root);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener >= 0);
    assert(!bind(listener, (struct sockaddr *)&address, sizeof(address)));
    assert(!listen(listener, 1));
    int sync[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, sync));
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(sync[0]); close(listener);
        int endpoint = socket(AF_UNIX, SOCK_STREAM, 0); assert(endpoint >= 0);
        assert(!connect(endpoint, (struct sockaddr *)&address, sizeof(address)));
        char byte; assert(read(sync[1], &byte, 1) == 1);
        close(endpoint);
        assert(write(sync[1], "x", 1) == 1);
        assert(read(sync[1], &byte, 1) == 1); // Stay alive after closing lane.
        _exit(0);
    }
    close(sync[1]);
    int lane = accept(listener, NULL, NULL); assert(lane >= 0);
    int disconnected = -1;
    assert(!inspect_exec_lane(lane, child, getuid(), &disconnected) && !disconnected);
    assert(!strcmp(inspect_exec_lane(lane, getpid(), getuid(), &disconnected), "peer-pid-mismatch"));
    assert(!strcmp(inspect_exec_lane(lane, child, getuid() + 1, &disconnected), "peer-uid-mismatch"));
    assert(write(sync[0], "x", 1) == 1);
    char byte; assert(read(sync[0], &byte, 1) == 1);
    assert(!inspect_exec_lane(lane, child, getuid(), &disconnected) && disconnected);
    // A disconnected identity is explicitly unavailable; UID must still match.
    assert(!strcmp(inspect_exec_lane(lane, child, getuid() + 1, &disconnected), "peer-uid-mismatch"));
    int pipe_fds[2]; assert(!pipe(pipe_fds));
    assert(!strcmp(inspect_exec_lane(pipe_fds[0], child, getuid(), &disconnected), "socket-type"));
    int internet = socket(AF_INET, SOCK_STREAM, 0); assert(internet >= 0);
    assert(!strcmp(inspect_exec_lane(internet, child, getuid(), &disconnected), "socket-family"));
    int datagram = socket(AF_UNIX, SOCK_DGRAM, 0); assert(datagram >= 0);
    assert(!strcmp(inspect_exec_lane(datagram, child, getuid(), &disconnected), "socket-type"));
    assert(!strcmp(inspect_exec_lane(-1, child, getuid(), &disconnected), "socket-type"));
    assert(write(sync[0], "x", 1) == 1);
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(lane); close(listener); close(sync[0]); close(internet); close(datagram);
    close(pipe_fds[0]); close(pipe_fds[1]); unlink(address.sun_path); rmdir(root);
    puts("PASS: retained Unix lane distinguishes connected peer from ENOTCONN; wrong peer/UID and malformed descriptors refused");
}
