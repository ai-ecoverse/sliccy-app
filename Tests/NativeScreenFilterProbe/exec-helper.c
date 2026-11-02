#include <Security/Security.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "exec-lane.h"

// Immutable proof-only same-PID replacement. No target arguments, capture,
// listening sockets, filesystem access or grant generation.
static uint64_t began, offset_ns;
static volatile sig_atomic_t interrupted;
static uint64_t now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static void row(const char *stage, const char *reason) {
    double ms = (double)(offset_ns + now_ns() - began) / 1000000.0;
    printf("{\"schema\":2,\"case\":\"parent-exec\",\"capture\":false,\"stage\":\"%s\",\"elapsedMs\":%.6f", stage, ms);
    if (reason) printf(",\"reason\":\"%s\"", reason);
    puts("}"); fflush(stdout);
}
static void stop_signal(int value) { (void)value; interrupted = 1; }
static int read_exact(int fd, void *bytes, size_t size) {
    size_t offset = 0; uint64_t deadline = now_ns() + 1000000000ULL;
    while (offset < size && now_ns() < deadline) {
        struct pollfd p = {.fd=fd, .events=POLLIN};
        if (poll(&p, 1, 25) <= 0) continue;
        ssize_t n = read(fd, (char *)bytes + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return offset == size ? 0 : -1;
}
static int wait_owned(pid_t child, uint64_t deadline, int *status) {
    while (now_ns() < deadline) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 1;
        if (result < 0 && errno != EINTR) return -1;
        struct timespec step = {.tv_nsec=10000000}; nanosleep(&step, NULL);
    }
    return 0;
}
int main(int argc, char **argv) {
    (void)argv; began = now_ns();
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal);
    if (argc != 1) return 2;
    unsigned char header[24], record[4104];
    if (read_exact(3, header, sizeof(header))) return 2;
    uint32_t words[4]; uint64_t elapsed;
    memcpy(words, header, 16); memcpy(&elapsed, header + 16, 8);
    pid_t expected = (pid_t)ntohl(words[1]), child = (pid_t)ntohl(words[2]);
    size_t length = ntohl(words[3]); offset_ns = OSSwapBigToHostInt64(elapsed);
    if (ntohl(words[0]) != 0x53505831 || expected != getpid() || child <= 0 || child == getpid() || !length || length > sizeof(record)) return 2;
    int status = 0;
    pid_t owned;
    do { owned = waitpid(child, &status, WNOHANG); } while (owned < 0 && errno == EINTR);
    if (owned != 0) {
        row(owned == child ? "helper-child-already-reaped" : "helper-ownership-refused", NULL);
        return 1; // ECHILD/unexpected ownership never signals a PID.
    }
    row("helper-child-owned", NULL);
    int valid = read_exact(3, record, length) == 0;
    row(valid ? "helper-bootstrap-record-read" : "helper-bootstrap-record-refused", NULL);
    close(3);
    for (int fd = 4; fd <= 5; fd++) {
        int disconnected = 0;
        const char *failure = inspect_exec_lane(fd, child, getuid(), &disconnected);
        if (failure) {
            valid = 0;
            row(fd == 4 ? "helper-safety-refused" : "helper-frames-refused", failure);
        } else {
            row(fd == 4 ? "helper-safety-retained" : "helper-frames-retained",
                disconnected ? "peer-disconnected" : "peer-matched");
        }
    }
    SecCodeRef code = NULL; SecRequirementRef requirement = NULL;
    OSStatus role = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (!role) role = SecRequirementCreateWithString(CFSTR("anchor apple generic and identifier \"ai.sliccy.mac\" and certificate leaf[subject.OU] = \"S8LB56P782\""), kSecCSDefaultFlags, &requirement);
    if (!role) role = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    if (role == errSecCSReqFailed) { row("helper-app-role-refused", NULL); }
    else { valid = 0; row("helper-app-role-check-failed", NULL); }
    if (valid) {
        row("helper-lanes-retained", NULL);
        // Otherwise-current heartbeat, provided by the real transport snapshot.
        // An exec monitor may close first; that is not verifier-branch evidence.
        size_t position = 0; uint64_t deadline = now_ns() + 100000000ULL;
        while (position < length && now_ns() < deadline) {
            struct pollfd p = {.fd=4, .events=POLLOUT};
            if (poll(&p, 1, 5) <= 0) continue;
            ssize_t n = write(4, record + position, length - position);
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) break;
            position += (size_t)n;
        }
        row(position == length ? "helper-control-written" : "helper-control-write-refused", NULL);
        while (!interrupted && now_ns() - began < 2000000000ULL) {
            struct timespec step = {.tv_nsec=10000000}; nanosleep(&step, NULL);
        }
        row("helper-observation-ended", interrupted ? "interrupted" : "elapsed");
    }
    close(4); close(5);
    do { owned = waitpid(child, &status, WNOHANG); } while (owned < 0 && errno == EINTR);
    if (owned == 0) {
        // Only this process can reap its retained child; its PID cannot be reused.
        (void)kill(child, SIGTERM);
        int reaped = wait_owned(child, now_ns() + 2000000000ULL, &status);
        if (reaped == 0) { (void)kill(child, SIGKILL); reaped = wait_owned(child, now_ns() + 1000000000ULL, &status); }
        owned = reaped == 1 ? child : -1;
    }
    if (owned == child) row("helper-child-exit-reaped", NULL);
    else { valid = 0; row("helper-cleanup-failed", NULL); }
    row("helper-terminal", valid && !interrupted ? "cleanup-complete" : "failed");
    return valid && !interrupted ? 0 : 1;
}
