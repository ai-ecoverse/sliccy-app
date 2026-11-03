#include "ScreenSystem.h"
#include "exec-lane.h"
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t interrupted;
static void stop(int value) { (void)value; interrupted = 1; }
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC_RAW, &t); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
static void row(const char *stage) { printf("{\"stage\":\"%s\"}\n", stage); fflush(stdout); }
static int read_record(void *data, size_t size, uint64_t deadline) {
    size_t offset = 0;
    while (offset < size && !interrupted && now() < deadline) {
        struct pollfd p = {.fd=3, .events=POLLIN};
        if (poll(&p, 1, 10) <= 0) continue;
        ssize_t n = sliccy_screen_recv(3, (char *)data + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return offset == size ? 0 : -1;
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 2;
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, stop); signal(SIGINT, stop);
    pid_t parent = getppid();
    row("ready");
    uint64_t deadline = now() + 2000000000ULL;
    unsigned char header[12] = {0}, record[4104]; int endpoint = -1, valid = 1;
    // Receive exactly the first byte with its rights. All subsequent reads reject
    // ancillary data, and any extra delivered rights are closed before failure.
    struct pollfd p = {.fd=3, .events=POLLIN};
    if (poll(&p, 1, 2000) <= 0) return 1;
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int)*16)]; } control = {0};
    struct iovec iov = {.iov_base=header, .iov_len=1};
    struct msghdr msg = {0}; msg.msg_iov=&iov; msg.msg_iovlen=1;
    msg.msg_control=control.bytes; msg.msg_controllen=sizeof(control.bytes);
    if (recvmsg(3, &msg, 0) != 1 || (msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC))) valid=0;
    int count=0;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(&msg); c; c=CMSG_NXTHDR(&msg,c)) {
        if (c->cmsg_len < CMSG_LEN(0)) {valid=0; break;}
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) {valid=0; continue;}
        size_t n=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        for (size_t i=0;i<n;i++) {int fd;memcpy(&fd,(char*)CMSG_DATA(c)+i*sizeof(int),sizeof(fd)); if(!count++) endpoint=fd; else close(fd);}
    }
    if (count != 1 || !valid || read_record(header+1,11,deadline)) valid=0;
    uint32_t words[3]={0}; memcpy(words,header,12);
    size_t length=ntohl(words[2]); pid_t cli=(pid_t)ntohl(words[1]);
    if (ntohl(words[0])!=0x484e4431 || cli<=0 || !length || length>sizeof(record)) valid=0;
    if (valid && read_record(record,length,deadline)) valid=0;
    int disconnected=0;
    if (valid && (inspect_exec_lane(endpoint,cli,getuid(),&disconnected) || disconnected)) valid=0;
    close(3);
    if (valid && getppid()==parent) {
        row("received"); row("write-started");
        ssize_t n=send(endpoint,record,length,MSG_DONTWAIT);
        if (n != (ssize_t)length) valid=0;
        else row("written");
    } else valid=0;
    if (valid) {
        uint64_t end=now()+2000000000ULL;
        while (!interrupted && now()<end && getppid()==parent) {struct timespec t={.tv_nsec=10000000};nanosleep(&t,NULL);}
        valid=!interrupted && getppid()==parent;
        if(valid) row("held");
    }
    if(endpoint>=0)close(endpoint);
    row(valid ? "complete" : "failed");
    return valid ? 0 : 1;
}
