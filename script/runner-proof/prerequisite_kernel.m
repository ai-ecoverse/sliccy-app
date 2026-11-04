#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <spawn.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "prerequisite_bsd_boundary.h"
#include "prerequisite_launch_boundary.h"
#include "prerequisite_binding_record.h"
extern int csops(pid_t, unsigned int, void *, size_t);

static uint64_t sequence;
static double began;
static double clockNow(void) { return NSProcessInfo.processInfo.systemUptime; }
static void require(BOOL value, NSString *reason) {
    if (!value) @throw [NSException exceptionWithName:@"prerequisite" reason:reason userInfo:nil];
}
static void emit(NSString *phase, NSString *state, NSDictionary *facts) {
    require(++sequence <= 512, @"record-count");
    NSDictionary *row = @{@"schema": @2, @"seq": @(sequence), @"phase": phase, @"state": state,
        @"elapsedMs": @((clockNow() - began) * 1000), @"facts": facts};
    NSMutableData *data = [[NSJSONSerialization dataWithJSONObject:row options:NSJSONWritingSortedKeys error:NULL] mutableCopy];
    [data appendBytes:"\n" length:1];
    require(data && data.length <= 32768 && write(1, data.bytes, data.length) == (ssize_t)data.length, @"record-write");
}
static NSDictionary *sample(pid_t pid) {
    struct sliccy_screen_process_identity value = {0};
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    emit(@"bsd", @"entered", @{@"pid": @(pid)});
    int status = sliccy_runner_identity(pid, &value);
    id bsd = status ? (id)NSNull.null : @{@"pid": @(value.pid), @"parent": @(value.parent), @"uid": @(value.uid),
        @"seconds": [NSString stringWithFormat:@"%llu", value.seconds], @"microseconds": @(value.microseconds)};
    emit(@"bsd", @"completed", @{@"pid": @(pid), @"status": @(status), @"value": bsd});
    emit(@"pidpath", @"entered", @{@"pid": @(pid)});
    int pathStatus = sliccy_runner_path(pid, path, sizeof(path));
    id name = pathStatus ? NSNull.null : [NSString stringWithUTF8String:path];
    emit(@"pidpath", @"completed", @{@"pid": @(pid), @"status": @(pathStatus), @"value": name ?: NSNull.null});
    return @{@"pid": @(pid), @"bsdStatus": @(status), @"pathStatus": @(pathStatus), @"bsd": bsd, @"path": name ?: NSNull.null};
}
static void completed(NSString *phase, OSStatus status) {
    emit(phase, @"completed", @{@"status": @(status)});
    require(status == errSecSuccess, phase);
}
static NSDictionary *pathFacts(NSString *label, NSString *path) {
    if (![path isKindOfClass:NSString.class] || !path.length || path.length > 4096)
        return @{@"label": label, @"path": sliccy_binding_value(path), @"resolveStatus": NSNull.null,
                 @"resolved": NSNull.null, @"statStatus": NSNull.null, @"device": NSNull.null, @"inode": NSNull.null};
    emit(@"binding-path-resolve", @"entered", @{@"label": label, @"path": path});
    char resolved[PATH_MAX] = {0}; errno = 0;
    char *result = realpath(path.fileSystemRepresentation, resolved); int resolutionError = errno;
    id real = result ? [NSString stringWithUTF8String:resolved] : (id)NSNull.null;
    emit(@"binding-path-resolve", @"completed", @{@"label": label, @"status": result ? @0 : @(-1), @"errno": @(resolutionError), @"resolved": real});
    emit(@"binding-path-stat", @"entered", @{@"label": label, @"path": path});
    struct stat value = {0}; errno = 0;
    int status = stat(path.fileSystemRepresentation, &value), error = errno;
    NSDictionary *facts = @{@"label": label, @"path": path, @"resolveStatus": result ? @0 : @(-1),
        @"resolved": real, @"resolveErrno": @(resolutionError), @"statStatus": @(status), @"statErrno": @(error),
        @"device": status ? (id)NSNull.null : @(value.st_dev), @"inode": status ? (id)NSNull.null : @(value.st_ino)};
    emit(@"binding-path-stat", @"completed", facts);
    return facts;
}
static void bindingMetadata(pid_t pid, SecCodeRef guest, SecRequirementRef requirement,
                            NSDictionary *liveInfo, NSDictionary *staticInfo, NSString *path) {
    CFStringRef text = NULL;
    emit(@"binding-requirement-text", @"entered", @{});
    OSStatus status = SecRequirementCopyString(requirement, 0, &text);
    emit(@"binding-requirement-text", @"completed", @{@"status": @(status), @"value": sliccy_binding_value((__bridge id)text)});
    if (text) CFRelease(text);
    for (NSString *lane in @[@"live", @"static"]) {
        NSDictionary *info = [lane isEqual:@"live"] ? liveInfo : staticInfo;
        id image = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
        emit(@"binding-code-info", @"completed", @{@"lane": lane,
            @"identifier": sliccy_binding_value(info[(__bridge NSString *)kSecCodeInfoIdentifier]),
            @"cdhash": sliccy_binding_value(info[(__bridge NSString *)kSecCodeInfoUnique]),
            @"imagePath": sliccy_binding_value([image isKindOfClass:NSURL.class] ? [image path] : nil)});
    }
    SecRequirementRef apple = NULL;
    emit(@"binding-apple-requirement", @"entered", @{@"rule": @"anchor apple"});
    status = SecRequirementCreateWithString(CFSTR("anchor apple"), 0, &apple);
    emit(@"binding-apple-requirement", @"completed", @{@"status": @(status), @"available": apple ? @YES : @NO});
    emit(@"binding-live-apple-anchor", @"entered", @{@"flags": @16, @"affectsVerdict": @NO});
    BOOL queried = status == errSecSuccess && apple != NULL;
    OSStatus anchorStatus = queried ? SecCodeCheckValidity(guest, kSecCSStrictValidate, apple) : status;
    emit(@"binding-live-apple-anchor", @"completed", sliccy_anchor_record(queried, anchorStatus));
    if (apple) CFRelease(apple);
    uint32_t flags = 0;
    emit(@"binding-kernel-flags", @"entered", @{@"pid": @(pid), @"operation": @0});
    errno = 0; int kernelStatus = csops(pid, 0, &flags, sizeof(flags)), kernelError = errno;
    emit(@"binding-kernel-flags", @"completed", sliccy_platform_record(kernelStatus, kernelError, flags));
    id liveImage = liveInfo[(__bridge NSString *)kSecCodeInfoMainExecutable];
    id staticImage = staticInfo[(__bridge NSString *)kSecCodeInfoMainExecutable];
    NSDictionary *input = pathFacts(@"static-input", path);
    NSDictionary *live = pathFacts(@"live-image", [liveImage isKindOfClass:NSURL.class] ? [liveImage path] : nil);
    NSDictionary *file = pathFacts(@"static-image", [staticImage isKindOfClass:NSURL.class] ? [staticImage path] : nil);
    emit(@"binding-comparison", @"completed", sliccy_inode_row(@"filesystem-input-live-inode", input, live));
    emit(@"binding-comparison", @"completed", sliccy_inode_row(@"filesystem-input-static-inode", input, file));
    emit(@"binding-comparison", @"completed", sliccy_inode_row(@"filesystem-live-static-inode", live, file));
}
#include "prerequisite_image_native.h"
#include "prerequisite_slice_native.h"
static NSDictionary *code(pid_t pid, NSString *path, NSString *rule, NSString *identifier, NSData *expected, BOOL designated) {
    SecRequirementRef requirement = NULL;
    SecCodeRef guest = NULL;
    SecStaticCodeRef live = NULL, file = NULL;
    CFDictionaryRef liveInfo = NULL, fileInfo = NULL;
    NSDictionary *result = nil;
    @try {
        emit(@"file-static", @"entered", @{@"path": path});
        completed(@"file-static", SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], 0, &file)); require(file != NULL, @"file-null");
        emit(@"requirement", @"entered", @{@"designated": designated ? @YES : @NO, @"rule": rule});
        OSStatus status = designated ? SecCodeCopyDesignatedRequirement(file, 0, &requirement) :
            SecRequirementCreateWithString((__bridge CFStringRef)rule, 0, &requirement);
        completed(@"requirement", status); require(requirement != NULL, @"requirement-null");
        sliccy_static_diagnostics(^int32_t(uint32_t flags) {
            return SecStaticCodeCheckValidity(file, flags, requirement);
        }, ^(NSString *state, NSDictionary *facts) {
            emit(@"binding-static-validity", state, facts);
        });
        emit(@"static-validity", @"entered", @{@"flags": @25});
        completed(@"static-validity", SecStaticCodeCheckValidity(file, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement));
        emit(@"file-info", @"entered", @{});
        completed(@"file-info", SecCodeCopySigningInformation(file, kSecCSSigningInformation, &fileInfo)); require(fileInfo != NULL, @"file-info-null");
        emit(@"guest", @"entered", @{@"pid": @(pid)});
        completed(@"guest", SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributePid: @(pid)}, 0, &guest)); require(guest != NULL, @"guest-null");
        emit(@"dynamic-validity", @"entered", @{@"flags": @16});
        completed(@"dynamic-validity", SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement));
        emit(@"guest-static", @"entered", @{});
        completed(@"guest-static", SecCodeCopyStaticCode(guest, 0, &live)); require(live != NULL, @"live-null");
        emit(@"live-info", @"entered", @{});
        completed(@"live-info", SecCodeCopySigningInformation(live, kSecCSSigningInformation, &liveInfo)); require(liveInfo != NULL, @"live-info-null");
        NSDictionary *a = (__bridge NSDictionary *)liveInfo, *b = (__bridge NSDictionary *)fileInfo;
        NSData *ah = a[(__bridge NSString *)kSecCodeInfoUnique], *bh = b[(__bridge NSString *)kSecCodeInfoUnique];
        NSString *ai = a[(__bridge NSString *)kSecCodeInfoIdentifier], *bi = b[(__bridge NSString *)kSecCodeInfoIdentifier];
        NSURL *image = a[(__bridge NSString *)kSecCodeInfoMainExecutable];
        uint8_t hash[20] = {0};
        emit(@"kernel-hash", @"entered", @{@"pid": @(pid)});
        errno = 0; int kernelStatus = csops(pid, 5, hash, sizeof(hash)), kernelError = errno;
        NSData *kernelHash = [NSData dataWithBytes:hash length:sizeof(hash)];
        emit(@"kernel-hash", @"completed", @{@"status": @(kernelStatus), @"errno": @(kernelError), @"hash": [kernelHash base64EncodedStringWithOptions:0]});
        for (NSDictionary *comparison in sliccy_binding_rows(kernelStatus, ah, bh, kernelHash, expected, ai, bi, identifier, image, path))
            emit(@"binding-comparison", @"completed", comparison);
        bindingMetadata(pid, guest, requirement, a, b, path);
        if (!expected) imageDiagnostics(pid, requirement, a, b, path, kernelHash);
        BOOL sliceBound=bindUniqueSlice(pid,guest,requirement,a,path,identifier,kernelHash);
        require(kernelStatus == 0 && [ah isKindOfClass:NSData.class] && ah.length == 20 && sliceBound &&
            [ah isEqual:kernelHash] && (!expected || [ah isEqual:expected]) && [ai isEqual:identifier] && [bi isEqual:identifier] &&
            [image.path isEqual:path], @"code-binding");
        result = @{@"identifier": ai, @"path": path, @"hash": [ah base64EncodedStringWithOptions:0], @"matched": @YES};
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
static NSData *line(int fd, double deadline) {
    NSMutableData *data = [NSMutableData data];
    while (data.length < 4096 && clockNow() < deadline) {
        struct pollfd item = {.fd = fd, .events = POLLIN};
        int count = poll(&item, 1, 10);
        if (count == 0 || (count < 0 && errno == EINTR)) continue;
        uint8_t value = 0;
        require(count > 0 && read(fd, &value, 1) == 1, @"child-line-read");
        if (value == 10) return data;
        [data appendBytes:&value length:1];
    }
    require(NO, @"child-line-deadline"); return nil;
}
static NSDictionary *object(NSData *data) {
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    require([value isKindOfClass:NSDictionary.class], @"child-object");
    return value;
}
static BOOL integer(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
        strcmp([value objCType], @encode(double)) != 0 && strcmp([value objCType], @encode(float)) != 0;
}
static void keys(NSDictionary *value, NSArray *expected) {
    require([[NSSet setWithArray:value.allKeys] isEqual:[NSSet setWithArray:expected]], @"child-keys");
}
static NSArray *chain(pid_t root, pid_t sudoPID) {
    NSMutableArray *records = [NSMutableArray array]; NSMutableSet *seen = [NSMutableSet set];
    pid_t next = root;
    for (int i = 0; i < 5; i++) {
        require(next > 0 && ![seen containsObject:@(next)], @"ancestry-cycle");
        [seen addObject:@(next)]; NSDictionary *value = sample(next); [records addObject:value];
        require([value[@"bsdStatus"] intValue] == 0 && [value[@"pathStatus"] intValue] == 0, @"ancestry-unavailable");
        if (next == sudoPID) return records;
        next = [value[@"bsd"][@"parent"] intValue];
    }
    require(NO, @"ancestry-depth"); return nil;
}
static int spawnChild(const struct sliccy_prerequisite_launch *launch, pid_t *child, int *input, int *output) {
    int in[2] = {-1, -1}, out[2] = {-1, -1};
    if (pipe(in)) return errno;
    if (pipe(out)) { int error = errno; close(in[0]); close(in[1]); return error; }
    for (int i = 0; i < 2; i++) { fcntl(in[i], F_SETFD, FD_CLOEXEC); fcntl(out[i], F_SETFD, FD_CLOEXEC); }
    posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
    int error = posix_spawn_file_actions_init(&actions);
    BOOL haveActions = error == 0, haveAttr = NO;
    if (!error) { error = posix_spawnattr_init(&attr); haveAttr = error == 0; }
    if (!error) error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, in[0], 0);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, 2, 2);
    if (!error) error = posix_spawn(child, launch->arguments[0], &actions, &attr, launch->arguments, launch->environment);
    if (haveActions) posix_spawn_file_actions_destroy(&actions);
    if (haveAttr) posix_spawnattr_destroy(&attr);
    close(in[0]); close(out[1]);
    if (error) { close(in[1]); close(out[0]); }
    else { *input = in[1]; *output = out[0]; }
    return error;
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        began = clockNow(); signal(SIGPIPE, SIG_IGN); alarm(8);
        if (fcntl(1, F_SETFL, O_NONBLOCK) < 0) return 2;
        pid_t child = 0, rootPID = 0; int input = -1, output = -1;
        BOOL success = NO, reaped = NO, rootGone = NO;
        @try {
            emit(@"placement", @"entered", @{});
            require(argc == 3 && hosted(), @"placement");
            struct sliccy_prerequisite_launch launch;
            require(sliccy_prerequisite_launch_arguments(argc, argv, &launch) == 0, @"arguments");
            NSString *run = [NSString stringWithUTF8String:launch.run];
            pid_t target = launch.target_pid;
            NSString *executable = [NSString stringWithUTF8String:launch.executable];
            emit(@"placement", @"completed", @{@"run": run, @"target": @(target), @"executable": executable});
            NSDictionary *targetBefore = sample(target);
            require([targetBefore[@"pathStatus"] intValue] == 0, @"target-path");
            NSDictionary *targetCode = code(target, targetBefore[@"path"], @"anchor apple and identifier \"com.apple.WindowServer\"", @"com.apple.WindowServer", nil, NO);
            NSDictionary *targetAfter = sample(target);
            require([targetBefore isEqual:targetAfter], @"target-prelaunch-change");
            emit(@"target-before", @"completed", @{@"sample": targetBefore, @"code": targetCode});
            NSData *expected = [[NSData alloc] initWithBase64EncodedString:@"stPyiHVvDcejjgvo90frsO5TZ2c=" options:0];
            emit(@"spawn", @"entered", @{@"tool": @"/usr/bin/sudo", @"executable": executable, @"target": @(target)});
            double launchWall = NSDate.date.timeIntervalSince1970, end = clockNow() + 2;
            int error = spawnChild(&launch, &child, &input, &output);
            emit(@"spawn", @"completed", @{@"status": @(error), @"pid": @(child), @"launchWall": @(launchWall)});
            require(!error && child > 0, @"spawn");
            emit(@"hello", @"entered", @{});
            NSData *helloBytes = line(output, end); NSDictionary *hello = object(helloBytes);
            emit(@"hello", @"completed", @{@"rawBase64": [helloBytes base64EncodedStringWithOptions:0]});
            keys(hello, @[@"schema", @"pid"]);
            require(integer(hello[@"schema"]) && [hello[@"schema"] intValue] == 1 && integer(hello[@"pid"]) && [hello[@"pid"] longLongValue] > 0 && [hello[@"pid"] longLongValue] <= INT32_MAX, @"hello-types");
            rootPID = [hello[@"pid"] intValue];
            NSDictionary *rootBefore = sample(rootPID);
            require([rootBefore[@"bsdStatus"] intValue] == 0 && [rootBefore[@"bsd"][@"uid"] intValue] == 0 && [rootBefore[@"path"] isEqual:executable], @"root-identity");
            double start = [rootBefore[@"bsd"][@"seconds"] doubleValue] + [rootBefore[@"bsd"][@"microseconds"] doubleValue] / 1000000;
            require(start >= launchWall && start <= NSDate.date.timeIntervalSince1970, @"root-start");
            NSArray *beforeChain = chain(rootPID, child);
            NSDictionary *rootCode = code(rootPID, executable, @"staged-build12-designated-requirement", @"ai.sliccy.mac", expected, YES);
            NSDictionary *rootAfter = sample(rootPID); NSArray *afterChain = chain(rootPID, child);
            require([rootBefore isEqual:rootAfter] && [beforeChain isEqual:afterChain], @"root-changed");
            emit(@"candidate", @"completed", @{@"sudoPID": @(child), @"launchWall": @(launchWall), @"before": rootBefore, @"after": rootAfter,
                @"chain": beforeChain, @"chainAfter": afterChain, @"code": rootCode});
            uint8_t ack = 1; require(clockNow() < end && write(input, &ack, 1) == 1, @"ack-deadline");
            close(input); input = -1;
            emit(@"ack", @"completed", @{@"rootPID": @(rootPID)});
            emit(@"facts", @"entered", @{});
            NSData *factBytes = line(output, end); NSDictionary *facts = object(factBytes);
            emit(@"facts", @"completed", @{@"rawBase64": [factBytes base64EncodedStringWithOptions:0]});
            keys(facts, @[@"schema", @"sample", @"path", @"hash"]);
            require(integer(facts[@"schema"]) && [facts[@"schema"] intValue] == 1 && [facts[@"path"] isEqual:targetCode[@"path"]] && [facts[@"hash"] isEqual:targetCode[@"hash"]], @"target-facts-code");
            NSDictionary *targetRecheck = sample(target);
            NSDictionary *targetCodeAfter = code(target, targetCode[@"path"], @"anchor apple and identifier \"com.apple.WindowServer\"", @"com.apple.WindowServer", nil, NO);
            require([targetCode isEqual:targetCodeAfter] && [targetBefore isEqual:targetRecheck], @"target-after-change");
            emit(@"target-after", @"completed", @{@"sample": targetRecheck, @"code": targetCodeAfter});
            success = YES;
        } @catch (NSException *error) {
            @try { emit(@"failure", @"completed", @{@"class": error.name, @"reason": error.reason ?: @"unknown"}); } @catch (NSException *ignored) { (void)ignored; }
            success = NO;
        } @finally {
            if (input >= 0) close(input);
            if (child > 0) {
                double cleanupEnd = clockNow() + 5; int status = 0, error = 0;
                @try { emit(@"reap", @"entered", @{@"pid": @(child)}); } @catch (NSException *ignored) { (void)ignored; success = NO; }
                do {
                    pid_t value = waitpid(child, &status, WNOHANG);
                    if (value == child) { reaped = YES; break; }
                    if (value < 0 && errno != EINTR) { error = errno; break; }
                    usleep(10000);
                } while (clockNow() < cleanupEnd);
                if (reaped && rootPID > 0) {
                    if (rootPID == child) rootGone = YES;
                    else {
                        @try {
                            emit(@"root-exit-bsd", @"entered", @{@"pid": @(rootPID)});
                            struct sliccy_screen_process_identity value; int result = sliccy_runner_identity(rootPID, &value);
                            emit(@"root-exit-bsd", @"completed", @{@"pid": @(rootPID), @"status": @(result)});
                            rootGone = result == ESRCH;
                        } @catch (NSException *ignored) { (void)ignored; success = NO; }
                    }
                }
                @try { emit(@"reap", @"completed", @{@"pid": @(child), @"reaped": reaped ? @YES : @NO, @"rootGone": rootGone ? @YES : @NO,
                    @"rootPID": @(rootPID), @"waitStatus": @(status), @"errno": @(error)}); } @catch (NSException *ignored) { (void)ignored; success = NO; }
                success = success && reaped && rootGone && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            }
            if (output >= 0) {
                int flags = fcntl(output, F_GETFL, 0); uint8_t extra = 0;
                success = success && flags >= 0 && fcntl(output, F_SETFL, flags | O_NONBLOCK) == 0 && read(output, &extra, 1) == 0;
                close(output);
            }
        }
        @try { emit(@"result", @"completed", @{@"observed": success ? @YES : @NO, @"reaped": reaped ? @YES : @NO, @"rootGone": rootGone ? @YES : @NO}); }
        @catch (NSException *ignored) { (void)ignored; return 2; }
        return success ? 0 : 2;
    }
}
