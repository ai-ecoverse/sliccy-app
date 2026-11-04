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
#include <libproc.h>
#include <sys/proc_info.h>

int sliccy_screen_proof_process_identity(pid_t pid, struct sliccy_screen_process_identity *identity) {
    struct proc_bsdinfo info = {0};
    if (pid <= 0 || !identity || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != (int)sizeof(info)) return EINVAL;
    if (info.pbi_pid != (uint32_t)pid || !info.pbi_start_tvsec || info.pbi_start_tvusec >= 1000000) return EINVAL;
    identity->pid = (int32_t)info.pbi_pid;
    identity->parent = (int32_t)info.pbi_ppid;
    identity->uid = info.pbi_uid;
    identity->seconds = info.pbi_start_tvsec;
    identity->microseconds = info.pbi_start_tvusec;
    return 0;
}

int sliccy_screen_proof_self_arch(int32_t *cpu, int32_t *subtype) {
    struct proc_archinfo info = {0};
    _Static_assert(sizeof(info) == 8, "Unexpected proc_archinfo layout");
    if (!cpu || !subtype || proc_pidinfo(getpid(), PROC_PIDARCHINFO, 0, &info, sizeof(info)) != (int)sizeof(info)) return EINVAL;
    *cpu = info.p_cputype; *subtype = info.p_cpusubtype;
    return 0;
}

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

int sliccy_screen_proof_ancillary(int safety, const void *record, size_t size) {
    if (!record || size == 0 || size > 4104) return EINVAL;
    int sentinel = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (sentinel < 0) return errno;
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec iov = {.iov_base = (void *)record, .iov_len = size};
    struct msghdr message = {0};
    message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &sentinel, sizeof(sentinel));
    ssize_t sent = sendmsg(safety, &message, MSG_DONTWAIT);
    int result = sent == (ssize_t)size ? 0 : (sent < 0 ? errno : EIO);
    close(sentinel);
    return result;
}

int sliccy_screen_proof_helper_spawn(const char *helper, pid_t *pid, int *channel, int *output) {
    int pair[2] = {-1,-1}, out[2] = {-1,-1}, staged = -1, nullfd = -1;
    int failure = 0, ar = 0, pr = 0;
    posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return errno;
    staged = fcntl(pair[1], F_DUPFD_CLOEXEC, 10);
    if (staged < 0 || fcntl(pair[0], F_SETFD, FD_CLOEXEC)) { failure = errno; goto done; }
    close(pair[1]); pair[1] = -1;
    if ((failure = private_pipe(out))) goto done;
    nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd < 0) { failure = errno; goto done; }
    if ((failure = posix_spawn_file_actions_init(&actions))) goto done;
    ar = 1;
    if ((failure = posix_spawnattr_init(&attr))) goto done;
    pr = 1;
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    if ((failure = posix_spawnattr_setsigmask(&attr, &empty)) ||
        (failure = posix_spawnattr_setsigdefault(&attr, &defaults)) ||
        (failure = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, nullfd, 0)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, out[1], 1)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, nullfd, 2)) ||
        (failure = posix_spawn_file_actions_adddup2(&actions, staged, 3))) goto done;
    char *const args[] = {(char *)helper, NULL};
    char *const env[] = {"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", NULL};
    failure = posix_spawn(pid, helper, &actions, &attr, args, env);
    if (!failure) { *channel = pair[0]; pair[0] = -1; *output = out[0]; out[0] = -1; }
done:
    if (ar) posix_spawn_file_actions_destroy(&actions);
    if (pr) posix_spawnattr_destroy(&attr);
    if (staged >= 0) close(staged);
    if (nullfd >= 0) close(nullfd);
    for (int i = 0; i < 2; i++) { if (pair[i] >= 0) close(pair[i]); if (out[i] >= 0) close(out[i]); }
    return failure;
}

int sliccy_screen_proof_handoff(int channel, int safety, pid_t cli, const void *record, size_t size) {
    if (!record || !size || size > 4104 || cli <= 0) return EINVAL;
    unsigned char buffer[12 + 4104];
    uint32_t header[3] = {htonl(0x484e4431), htonl((uint32_t)cli), htonl((uint32_t)size)};
    memcpy(buffer, header, 12); memcpy(buffer + 12, record, size);
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec iov = {.iov_base = buffer, .iov_len = size + 12};
    struct msghdr message = {0}; message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET; rights->cmsg_type = SCM_RIGHTS; rights->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(rights), &safety, sizeof(safety));
    ssize_t sent = sendmsg(channel, &message, MSG_DONTWAIT);
    return sent == (ssize_t)(size + 12) ? 0 : (sent < 0 ? errno : EIO);
}

#if defined(SLICCY_CAPTURE_RUNNER_PROOF)
#include <sys/acl.h>
#include <sys/wait.h>
extern int csops(pid_t, unsigned int, void *, size_t);
#include <sys/sysctl.h>
static struct sliccy_runner_bsd_read runner_bsd_sysctl(pid_t pid) {
    struct kinfo_proc info = {0}; size_t length = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    errno = 0; int status = sysctl(mib, 4, &info, &length, NULL, 0), error = errno;
    struct sliccy_runner_bsd_read result = {.status = status == 0 ? 0 : (error ? error : EINVAL),
        .count = length, .expected = sizeof(info)};
    if (status == 0 && length == sizeof(info) && info.kp_proc.p_starttime.tv_sec > 0 && info.kp_proc.p_starttime.tv_usec >= 0) {
        result.value = (struct sliccy_runner_bsd_value){info.kp_proc.p_pid, info.kp_eproc.e_ppid,
            info.kp_eproc.e_ucred.cr_uid, info.kp_eproc.e_pcred.p_ruid, info.kp_eproc.e_pcred.p_svuid,
            (uint64_t)info.kp_proc.p_starttime.tv_sec, (uint64_t)info.kp_proc.p_starttime.tv_usec};
    }
    return result;
}
static struct sliccy_runner_bsd_read runner_bsd_proc(pid_t pid) {
    struct proc_bsdinfo info = {0}; errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)), error = errno;
    struct sliccy_runner_bsd_read result = {.status = count == (int)sizeof(info) ? 0 : (error ? error : EINVAL),
        .count = count > 0 ? (size_t)count : 0, .expected = sizeof(info)};
    if (count == (int)sizeof(info) && info.pbi_pid <= INT32_MAX && info.pbi_ppid <= INT32_MAX) {
        result.value = (struct sliccy_runner_bsd_value){(int32_t)info.pbi_pid, (int32_t)info.pbi_ppid,
            info.pbi_uid, info.pbi_ruid, info.pbi_svuid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    }
    return result;
}
static struct sliccy_runner_bsd_bracket runner_bsd_bracket(pid_t pid) {
    struct sliccy_runner_bsd_bracket value;
    value.before = runner_bsd_sysctl(pid); value.proc = runner_bsd_proc(pid); value.after = runner_bsd_sysctl(pid);
    return value;
}
int sliccy_runner_bsd_observe(int32_t pid, struct sliccy_runner_bsd_observation *value) {
    if (!value || pid <= 0 || geteuid() == 0) return EINVAL;
    *value = (struct sliccy_runner_bsd_observation){0};
    value->self_pid = getpid(); value->parent_pid = getppid();
    value->controls[0] = runner_bsd_bracket(value->self_pid);
    value->controls[1] = runner_bsd_bracket(value->parent_pid);
    value->target = runner_bsd_bracket(pid);
    return getpid() == value->self_pid && getppid() == value->parent_pid ? 0 : EINVAL;
}
int sliccy_runner_bsd_select(const struct sliccy_runner_bsd_observation *observation, int32_t pid,
                            struct sliccy_runner_bsd_value *value, int *used_sysctl) {
    return observation ? sliccy_bsd_select(*observation, pid, value, used_sysctl) : EINVAL;
}
int sliccy_runner_bsd_windowserver(const struct sliccy_runner_bsd_value *a, const struct sliccy_runner_bsd_value *b) {
    return a && b && sliccy_bsd_windowserver(*a, *b);
}
int sliccy_runner_identity(pid_t pid, struct sliccy_screen_process_identity *identity) {
    if (!identity || pid <= 0) return EINVAL;
    struct proc_bsdinfo value = {0};
    errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, sizeof(value));
    if (count < 0 || (size_t)count != sizeof(value)) return errno ? errno : EINVAL;
    if (value.pbi_pid != (uint32_t)pid || !value.pbi_start_tvsec || value.pbi_start_tvusec >= 1000000) return EINVAL;
    identity->pid = pid; identity->parent = value.pbi_ppid; identity->uid = value.pbi_uid;
    identity->seconds = value.pbi_start_tvsec; identity->microseconds = value.pbi_start_tvusec;
    return 0;
}
int sliccy_runner_path(pid_t pid, char *path, uint32_t size) {
    if (!path || size < PROC_PIDPATHINFO_MAXSIZE) return EINVAL;
    errno = 0;
    int count = proc_pidpath(pid, path, size);
    return count > 0 && (uint32_t)count < size ? 0 : (errno ? errno : EINVAL);
}
int sliccy_runner_hash(pid_t pid, unsigned char *hash) {
    errno = 0;
    return hash && csops(pid, 5, hash, 20) == 0 ? 0 : (errno ? errno : EINVAL);
}
int sliccy_runner_no_acl(const char *path) {
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT ? 0 : EINVAL;
    if (acl_valid(acl) != 0) { acl_free(acl); return EINVAL; }
    acl_entry_t entry;
    errno = 0;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    int absent = result == -1 && errno == EINVAL;
    acl_free(acl);
    return absent ? 0 : EINVAL;
}

#endif
