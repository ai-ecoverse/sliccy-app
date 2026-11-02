#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argv; alarm(3);
    assert(argc == 1);
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) >= 0) count++;
    assert(count == 6); // Exactly stdio, bootstrap, safety, frames.
    assert(getenv("SLICCY_FIXTURE_SECRET") == NULL);
    unsigned char header[24];
    assert(read(3, header, sizeof(header)) == sizeof(header));
    uint32_t words[4]; memcpy(words, header, 16);
    assert(ntohl(words[0]) == 0x53505831 && (pid_t)ntohl(words[1]) == getpid());
    assert(ntohl(words[3]) == 4);
    char record[4]; assert(read(3, record, 4) == 4 && !memcmp(record, "test", 4));
    for (int fd = 4; fd <= 5; fd++) {
        int type = 0; socklen_t size = sizeof(type);
        assert(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_STREAM);
    }
    pid_t child = (pid_t)ntohl(words[2]); int status = 0;
    assert(waitpid(child, &status, WNOHANG) == 0); // Actual same-PID child ownership survived exec.
    assert(kill(child, SIGTERM) == 0);
    assert(waitpid(child, &status, 0) == child);
    return 0;
}
