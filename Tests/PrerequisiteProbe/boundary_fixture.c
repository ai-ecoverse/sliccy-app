#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define PROC_PIDTBSDINFO 3
#define PROC_PIDPATHINFO_MAXSIZE 4096
struct proc_bsdinfo { uint32_t pbi_pid, pbi_ppid, pbi_uid; uint64_t pbi_start_tvsec, pbi_start_tvusec; };
static struct proc_bsdinfo fake;
static int count, failure, pathCount;
static int fake_info(int pid, int flavor, uint64_t arg, void *buffer, int size) {
    assert(pid == 42 && flavor == PROC_PIDTBSDINFO && arg == 0 && size == sizeof(fake));
    memcpy(buffer, &fake, sizeof(fake)); errno = failure; return count;
}
static int fake_path(int pid, void *buffer, uint32_t size) {
    assert(pid == 42 && size == PROC_PIDPATHINFO_MAXSIZE);
    memcpy(buffer, "/bin/sleep", 11); errno = failure; return pathCount;
}
#define proc_pidinfo fake_info
#define proc_pidpath fake_path
#include "prerequisite_bsd_boundary.h"
int main(void) {
    struct sliccy_screen_process_identity result = {0};
    fake = (struct proc_bsdinfo){42, 11, 0, 100, 123}; count = sizeof(fake);
    assert(sliccy_runner_identity(42, &result) == 0);
    assert(result.pid == 42 && result.parent == 11 && result.uid == 0 && result.seconds == 100 && result.microseconds == 123);
    count = 0; failure = EPERM; assert(sliccy_runner_identity(42, &result) == EPERM);
    failure = 0; assert(sliccy_runner_identity(42, &result) == EINVAL);
    count = sizeof(fake) - 1; assert(sliccy_runner_identity(42, &result) == EINVAL);
    count = sizeof(fake); fake.pbi_pid = 43; assert(sliccy_runner_identity(42, &result) == EINVAL);
    fake.pbi_pid = 42; fake.pbi_start_tvsec = 0; assert(sliccy_runner_identity(42, &result) == EINVAL);
    fake.pbi_start_tvsec = 100; fake.pbi_start_tvusec = 1000000; assert(sliccy_runner_identity(42, &result) == EINVAL);
    assert(sliccy_runner_identity(0, &result) == EINVAL);
    assert(sliccy_runner_identity(42, NULL) == EINVAL);
    char path[4096] = {0}; pathCount = 10;
    assert(sliccy_runner_path(42, path, sizeof(path)) == 0 && strcmp(path, "/bin/sleep") == 0);
    pathCount = 0; failure = EPERM; assert(sliccy_runner_path(42, path, sizeof(path)) == EPERM);
    failure = 0; assert(sliccy_runner_path(42, path, sizeof(path)) == EINVAL);
    pathCount = 4096; assert(sliccy_runner_path(42, path, sizeof(path)) == EINVAL);
    assert(sliccy_runner_path(42, path, 10) == EINVAL);
    assert(sliccy_runner_path(42, NULL, 4096) == EINVAL);
    puts("synthetic production boundary PASS");
    return 0;
}
