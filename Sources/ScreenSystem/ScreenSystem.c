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
#include <arpa/inet.h>
#include <libkern/OSByteOrder.h>

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

int sliccy_screen_proof_exec(const char *helper, pid_t child, int safety, int frames,
                            const void *record, size_t size, uint64_t elapsed_ns) {
    if (!helper || child <= 0 || size == 0 || size > 4104) return EINVAL;
    int boot[2] = {-1,-1}, s = -1, f = -1, failure = 0, ar = 0, pr = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    if ((failure = private_pipe(boot))) goto done;
    // Stage above the fixed destination range so file actions cannot alias.
    s = fcntl(safety, F_DUPFD_CLOEXEC, 10);
    f = fcntl(frames, F_DUPFD_CLOEXEC, 10);
    int reader = fcntl(boot[0], F_DUPFD_CLOEXEC, 10);
    close(boot[0]); boot[0] = reader;
    if (s < 0 || f < 0 || reader < 0) { failure = errno; goto done; }
    unsigned char buffer[24 + 4104];
    uint32_t words[4] = { htonl(0x53505831), htonl((uint32_t)getpid()), htonl((uint32_t)child), htonl((uint32_t)size) };
    uint64_t elapsed = OSSwapHostToBigInt64(elapsed_ns);
    memcpy(buffer, words, 16); memcpy(buffer + 16, &elapsed, 8); memcpy(buffer + 24, record, size);
    size_t offset = 0;
    while (offset < 24 + size) {
        ssize_t n = write(boot[1], buffer + offset, 24 + size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { failure = errno ? errno : EIO; goto done; }
        offset += (size_t)n;
    }
    close(boot[1]); boot[1] = -1;
    if ((failure = posix_spawn_file_actions_init(&actions))) goto done;
    ar = 1;
    if ((failure = posix_spawnattr_init(&attr))) goto done;
    pr = 1;
    if ((failure = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT)) ||
        (failure = posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO)) ||
        (failure = posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO)) ||
        (failure = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, boot[0], 3)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, s, 4)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, f, 5))) goto done;
    char *const args[] = { (char *)helper, NULL };
    char *const env[] = { "PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", NULL };
    // Darwin SETEXEC consumes file-action sources after its close-on-exec pass.
    // Only these staged copies lose CLOEXEC; CLOEXEC_DEFAULT closes them after
    // dup2. The component test asserts exactly descriptors 0...5 survive.
    if (fcntl(boot[0], F_SETFD, 0) || fcntl(s, F_SETFD, 0) || fcntl(f, F_SETFD, 0)) {
        failure = errno; goto done;
    }
    pid_t same = 0;
    failure = posix_spawn(&same, helper, &actions, &attr, args, env);
    // SETEXEC never returns on success.
    if (!failure) failure = EIO;
done:
    if (ar) posix_spawn_file_actions_destroy(&actions);
    if (pr) posix_spawnattr_destroy(&attr);
    if (s >= 0) close(s);
    if (f >= 0) close(f);
    if (boot[0] >= 0) close(boot[0]);
    if (boot[1] >= 0) close(boot[1]);
    return failure;
}
