#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "prerequisite_bsd_boundary.h"

static uint64_t sequence;
static double began;
static double clockNow(void) { return NSProcessInfo.processInfo.systemUptime; }
static void emit(NSString *phase, NSString *state, NSDictionary *facts) {
    if (++sequence > 1500) @throw [NSException exceptionWithName:@"bound" reason:@"record-count" userInfo:nil];
    NSDictionary *row = @{@"schema": @1, @"seq": @(sequence), @"phase": phase, @"state": state,
        @"elapsedMs": @((clockNow() - began) * 1000), @"facts": facts};
    NSMutableData *data = [[NSJSONSerialization dataWithJSONObject:row options:NSJSONWritingSortedKeys error:NULL] mutableCopy];
    [data appendBytes:"\n" length:1];
    if (data.length > 16384 || write(1, data.bytes, data.length) != (ssize_t)data.length)
        @throw [NSException exceptionWithName:@"delivery" reason:@"record-write" userInfo:nil];
}
static NSDictionary *sample(pid_t pid) {
    struct sliccy_screen_process_identity value = {0};
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    emit(@"bsd", @"entered", @{@"pid": @(pid)});
    int status = sliccy_runner_identity(pid, &value);
    NSDictionary *bsd = status ? (id)NSNull.null : @{@"pid": @(value.pid), @"parent": @(value.parent), @"uid": @(value.uid),
        @"seconds": [NSString stringWithFormat:@"%llu", value.seconds], @"microseconds": @(value.microseconds)};
    emit(@"bsd", @"completed", @{@"pid": @(pid), @"status": @(status), @"value": bsd});
    emit(@"pidpath", @"entered", @{@"pid": @(pid)});
    int pathStatus = sliccy_runner_path(pid, path, sizeof(path));
    id name = pathStatus ? NSNull.null : [NSString stringWithUTF8String:path];
    emit(@"pidpath", @"completed", @{@"pid": @(pid), @"status": @(pathStatus), @"value": name ?: NSNull.null});
    return @{@"pid": @(pid), @"bsdStatus": @(status), @"pathStatus": @(pathStatus), @"bsd": bsd, @"path": name ?: NSNull.null};
}
static NSDictionary *code(pid_t pid) {
    SecRequirementRef requirement = NULL;
    SecCodeRef guest = NULL;
    SecStaticCodeRef live = NULL, file = NULL;
    CFDictionaryRef liveInfo = NULL, fileInfo = NULL;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    @try {
        emit(@"requirement", @"entered", @{});
        OSStatus status = SecRequirementCreateWithString(CFSTR("anchor apple"), 0, &requirement);
        emit(@"requirement", @"completed", @{@"status": @(status)}); if (status || !requirement) return result;
        emit(@"guest", @"entered", @{@"pid": @(pid)});
        status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributePid: @(pid)}, 0, &guest);
        emit(@"guest", @"completed", @{@"status": @(status)}); if (status || !guest) return result;
        emit(@"dynamic-validity", @"entered", @{});
        status = SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement);
        emit(@"dynamic-validity", @"completed", @{@"status": @(status)}); if (status) return result;
        emit(@"guest-static", @"entered", @{});
        status = SecCodeCopyStaticCode(guest, 0, &live);
        emit(@"guest-static", @"completed", @{@"status": @(status)}); if (status || !live) return result;
        emit(@"live-info", @"entered", @{});
        status = SecCodeCopySigningInformation(live, kSecCSSigningInformation, &liveInfo);
        emit(@"live-info", @"completed", @{@"status": @(status)}); if (status || !liveInfo) return result;
        emit(@"file-static", @"entered", @{});
        status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:@"/bin/sleep"], 0, &file);
        emit(@"file-static", @"completed", @{@"status": @(status)}); if (status || !file) return result;
        emit(@"static-validity", @"entered", @{});
        status = SecStaticCodeCheckValidity(file, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement);
        emit(@"static-validity", @"completed", @{@"status": @(status)}); if (status) return result;
        emit(@"file-info", @"entered", @{});
        status = SecCodeCopySigningInformation(file, kSecCSSigningInformation, &fileInfo);
        emit(@"file-info", @"completed", @{@"status": @(status)}); if (status || !fileInfo) return result;
        NSDictionary *a = (__bridge NSDictionary *)liveInfo, *b = (__bridge NSDictionary *)fileInfo;
        NSData *ah = a[(__bridge NSString *)kSecCodeInfoUnique], *bh = b[(__bridge NSString *)kSecCodeInfoUnique];
        NSString *ai = a[(__bridge NSString *)kSecCodeInfoIdentifier], *bi = b[(__bridge NSString *)kSecCodeInfoIdentifier];
        NSURL *path = a[(__bridge NSString *)kSecCodeInfoMainExecutable];
        BOOL matched = [ah isKindOfClass:NSData.class] && ah.length == 20 && [ah isEqual:bh] &&
            [ai isKindOfClass:NSString.class] && ai.length && [ai isEqual:bi] && [path.path isEqual:@"/bin/sleep"];
        result[@"matched"] = matched ? @YES : @NO;
        result[@"identifier"] = [ai isKindOfClass:NSString.class] ? ai : (id)NSNull.null;
        result[@"cdHashBase64"] = [ah isKindOfClass:NSData.class] ? [ah base64EncodedStringWithOptions:0] : (id)NSNull.null;
    } @finally {
        if (fileInfo) CFRelease(fileInfo); if (liveInfo) CFRelease(liveInfo);
        if (file) CFRelease(file); if (live) CFRelease(live); if (guest) CFRelease(guest); if (requirement) CFRelease(requirement);
    }
    return result;
}
static BOOL hosted(void) {
#if !defined(__arm64__)
    return NO;
#endif
    NSDictionary *env = NSProcessInfo.processInfo.environment;
    NSDictionary *fixed = @{@"GITHUB_ACTIONS": @"true", @"GITHUB_REPOSITORY": @"ai-ecoverse/sliccy-app",
        @"GITHUB_EVENT_NAME": @"workflow_dispatch", @"GITHUB_REF": @"refs/heads/proof/runner-capture-v1",
        @"SLICCY_RUNNER_ENVIRONMENT": @"github-hosted", @"RUNNER_ENVIRONMENT": @"github-hosted"};
    for (NSString *key in fixed) if (![fixed[key] isEqual:env[key]]) return NO;
    return geteuid() != 0 && NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 27;
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        (void)argv;
        began = clockNow(); signal(SIGPIPE, SIG_IGN); alarm(8);
        if (fcntl(1, F_SETFL, O_NONBLOCK) < 0) return 2;
        pid_t child = 0; BOOL success = NO, reaped = NO;
        double launchWall = NSDate.date.timeIntervalSince1970;
        @try {
            emit(@"placement", @"entered", @{});
            BOOL placed = argc == 1 && hosted();
            emit(@"placement", @"completed", @{@"accepted": placed ? @YES : @NO});
            if (!placed) @throw [NSException exceptionWithName:@"placement" reason:@"host-or-arguments" userInfo:nil];
            emit(@"spawn", @"entered", @{@"tool": @"/usr/bin/sudo", @"arguments": @[@"-n", @"--", @"/bin/sleep", @"2"]});
            posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
            int error = posix_spawn_file_actions_init(&actions);
            if (error) @throw [NSException exceptionWithName:@"spawn" reason:@"actions" userInfo:nil];
            error = posix_spawnattr_init(&attr);
            if (error) { posix_spawn_file_actions_destroy(&actions); @throw [NSException exceptionWithName:@"spawn" reason:@"attributes" userInfo:nil]; }
            error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
            if (!error) error = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
            if (!error) error = posix_spawn_file_actions_adddup2(&actions, 1, 1);
            if (!error) error = posix_spawn_file_actions_adddup2(&actions, 2, 2);
            char *args[] = {"/usr/bin/sudo", "-n", "--", "/bin/sleep", "2", NULL};
            char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", NULL};
            if (!error) error = posix_spawn(&child, args[0], &actions, &attr, args, env);
            posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr);
            emit(@"spawn", @"completed", @{@"status": @(error), @"pid": @(child), @"launchWall": @(launchWall)});
            if (error || child <= 0) @throw [NSException exceptionWithName:@"spawn" reason:@"failed" userInfo:nil];
            double observationEnd = began + 2;
            for (int round = 0; round < 16 && clockNow() < observationEnd && !success; round++) {
                NSMutableArray *pending = [NSMutableArray arrayWithObject:@[@(child), @0]];
                NSMutableSet *seen = [NSMutableSet set];
                NSMutableArray *samples = [NSMutableArray array];
                for (NSUInteger i = 0; i < pending.count && i < 8 && clockNow() < observationEnd; i++) {
                    pid_t pid = [pending[i][0] intValue]; int depth = [pending[i][1] intValue];
                    if ([seen containsObject:@(pid)]) continue;
                    [seen addObject:@(pid)];
                    NSDictionary *before = sample(pid); [samples addObject:before];
                    if ([before[@"path"] isEqual:@"/bin/sleep"] && [before[@"bsdStatus"] intValue] == 0) {
                        NSDictionary *identity = code(pid), *after = sample(pid);
                        NSMutableArray *rechecked = [NSMutableArray array];
                        for (NSDictionary *item in samples) [rechecked addObject:sample([item[@"pid"] intValue])];
                        emit(@"candidate", @"completed", @{@"sudoPID": @(child), @"launchWall": @(launchWall),
                            @"before": before, @"after": after, @"code": identity, @"chain": samples, @"chainAfter": rechecked});
                        success = [identity[@"matched"] boolValue] && [before isEqual:after] && [samples isEqual:rechecked] && clockNow() < observationEnd;
                    }
                    if (depth >= 4 || success) continue;
                    pid_t kids[9] = {0};
                    emit(@"children", @"entered", @{@"parent": @(pid)});
                    errno = 0; int count = proc_listchildpids(pid, kids, sizeof(kids)); int err = errno;
                    NSMutableArray *list = [NSMutableArray array];
                    if (count >= 0 && count <= 8) for (int j = 0; j < count; j++) {
                        if (kids[j] <= 0) @throw [NSException exceptionWithName:@"children" reason:@"invalid-pid" userInfo:nil];
                        [list addObject:@(kids[j])]; [pending addObject:@[@(kids[j]), @(depth + 1)]];
                    }
                    emit(@"children", @"completed", @{@"parent": @(pid), @"count": @(count), @"errno": @(err), @"pids": list});
                    if (count < 0 || (count == 0 && err != 0) || count > 8 || pending.count > 8) @throw [NSException exceptionWithName:@"children" reason:@"bound-or-unavailable" userInfo:nil];
                }
                if (!success && clockNow() < observationEnd) usleep(100000);
            }
        } @catch (NSException *error) {
            @try { emit(@"failure", @"completed", @{@"class": error.name, @"reason": error.reason ?: @"unknown"}); } @catch (NSException *ignored) { (void)ignored; }
            success = NO;
        } @finally {
            if (child > 0) {
                double cleanupEnd = clockNow() + 5; int status = 0, error = 0;
                @try { emit(@"reap", @"entered", @{@"pid": @(child)}); } @catch (NSException *ignored) { (void)ignored; success = NO; }
                do {
                    pid_t value = waitpid(child, &status, WNOHANG);
                    if (value == child) { reaped = YES; break; }
                    if (value < 0 && errno != EINTR) { error = errno; break; }
                    usleep(10000);
                } while (clockNow() < cleanupEnd);
                @try { emit(@"reap", @"completed", @{@"pid": @(child), @"reaped": reaped ? @YES : @NO,
                    @"waitStatus": @(status), @"errno": @(error)}); } @catch (NSException *ignored) { (void)ignored; success = NO; }
                success = success && reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            }
        }
        @try { emit(@"result", @"completed", @{@"candidateObserved": success ? @YES : @NO, @"reaped": reaped ? @YES : @NO}); }
        @catch (NSException *ignored) { (void)ignored; return 2; }
        return success ? 0 : 2;
    }
}
