#include "ScreenSystem.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) >= 0) count++;
    return count;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "child")) {
        // Exactly stdio + bootstrap, even when the parent has open descriptors.
        assert(descriptors() == 4);
        assert(getenv("SLICCY_FIXTURE_SECRET") == NULL);
        char input[4], bootstrap[4];
        assert(read(0, input, 4) == 4 && !memcmp(input, "join", 4));
        assert(read(3, bootstrap, 4) == 4 && !memcmp(bootstrap, "boot", 4));
        assert(write(1, "PASS", 4) == 4);
        return 0;
    }
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int sent = open("/dev/null", O_RDONLY); assert(sent >= 0);
    char payload = 'x';
    struct iovec iov = {.iov_base = &payload, .iov_len = 1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct msghdr message = {0}; message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &sent, sizeof(sent));
    assert(sendmsg(pair[0], &message, 0) == 1);
    int before = descriptors();
    assert(sliccy_screen_recv(pair[1], &payload, 1) == -1 && errno == EPROTO);
    assert(descriptors() == before); // Received rights were closed, not merely rejected.
    assert(fcntl(sent, F_GETFD) >= 0); // Sender's original remains intact.
    char *arguments[] = {argv[0], "child", NULL};
    char *environment[] = {"PATH=/usr/bin:/bin", NULL};
    setenv("SLICCY_FIXTURE_SECRET", "never-inherited", 1);
    pid_t child = 0; int input = -1, output = -1, bootstrap = -1;
    assert(sliccy_screen_spawn(argv[0], arguments, environment, &child, &input, &output, &bootstrap) == 0);
    assert(write(input, "join", 4) == 4); close(input);
    assert(write(bootstrap, "boot", 4) == 4); close(bootstrap);
    assert(kill(child, SIGCONT) == 0);
    char response[4]; assert(read(output, response, 4) == 4 && !memcmp(response, "PASS", 4)); close(output);
    int status = 0; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(sent); close(pair[0]); close(pair[1]);
    puts("PASS: ancillary rights refused and closed; suspended child inherits only stdio/bootstrap and explicit environment");
}
