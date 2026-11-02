#include "ScreenSystem.h"

OSStatus sliccy_screen_dynamic_status(SecCodeRef code, uint32_t *status) {
    CFDictionaryRef information = NULL;
    OSStatus result = SecCodeCopySigningInformation((SecStaticCodeRef)code,
        kSecCSDynamicInformation, &information);
    if (result != errSecSuccess) return result;
    CFNumberRef number = information ? CFDictionaryGetValue(information, kSecCodeInfoStatus) : NULL;
    if (!number || CFGetTypeID(number) != CFNumberGetTypeID() ||
        !CFNumberGetValue(number, kCFNumberSInt32Type, status)) result = errSecParam;
    if (information) CFRelease(information);
    return result;
}
#include <sys/socket.h>
#include <spawn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

ssize_t sliccy_screen_recv(int fd, void *buffer, size_t size) {
    union { struct cmsghdr aligned; unsigned char bytes[CMSG_SPACE(sizeof(int) * 256)]; } control;
    struct iovec iov = { .iov_base = buffer, .iov_len = size };
    struct msghdr message = {0};
    message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    ssize_t result = recvmsg(fd, &message, 0);
    if (result < 0) return result;
    int refused = (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        refused = 1;
        if (header->cmsg_len < CMSG_LEN(0)) break;
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS) {
            size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < count; i++) {
                int received;
                memcpy(&received, (unsigned char *)CMSG_DATA(header) + i * sizeof(int), sizeof(int));
                close(received);
            }
        }
    }
    if (refused) { errno = EPROTO; return -1; }
    return result;
}

static int private_pipe(int pair[2]) {
    int raw[2];
    if (pipe(raw)) return errno;
    pair[0] = fcntl(raw[0], F_DUPFD_CLOEXEC, 4);
    pair[1] = fcntl(raw[1], F_DUPFD_CLOEXEC, 4);
    int failure = errno;
    close(raw[0]); close(raw[1]);
    if (pair[0] < 0 || pair[1] < 0) {
        if (pair[0] >= 0) close(pair[0]);
        if (pair[1] >= 0) close(pair[1]);
        pair[0] = pair[1] = -1;
        return failure;
    }
    return 0;
}

int sliccy_screen_spawn(const char *executable, char *const argv[], char *const env[], pid_t *pid, int *input, int *output, int *bootstrap) {
    int in[2] = {-1,-1}, out[2] = {-1,-1}, boot[2] = {-1,-1};
    int nullfd = -1, failure = 0, actions_ready = 0, attr_ready = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    if ((failure = private_pipe(in)) || (failure = private_pipe(out)) || (failure = private_pipe(boot))) goto cleanup;
    nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd < 0) { failure = errno; goto cleanup; }
    if ((failure = posix_spawn_file_actions_init(&actions))) goto cleanup;
    actions_ready = 1;
    if ((failure = posix_spawnattr_init(&attr))) goto cleanup;
    attr_ready = 1;
    sigset_t empty, defaults;
    sigemptyset(&empty); sigfillset(&defaults);
    if ((failure = posix_spawnattr_setsigmask(&attr, &empty)) ||
        (failure = posix_spawnattr_setsigdefault(&attr, &defaults)) ||
        (failure = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, in[0], 0)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, out[1], 1)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, nullfd, 2)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, boot[0], 3))) goto cleanup;
    failure = posix_spawn(pid, executable, &actions, &attr, argv, env);
    if (!failure) {
        *input = in[1]; in[1] = -1;
        *output = out[0]; out[0] = -1;
        *bootstrap = boot[1]; boot[1] = -1;
    }
cleanup:
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) posix_spawnattr_destroy(&attr);
    if (nullfd >= 0) close(nullfd);
    for (int i = 0; i < 2; i++) {
        if (in[i] >= 0) close(in[i]);
        if (out[i] >= 0) close(out[i]);
        if (boot[i] >= 0) close(boot[i]);
    }
    return failure;
}
