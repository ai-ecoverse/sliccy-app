#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern int csops(pid_t, unsigned int, void *, size_t);

static id absent(void) { return [NSNull null]; }
static BOOL hosted(void) {
    NSDictionary *env = NSProcessInfo.processInfo.environment;
    struct utsname machine;
    return uname(&machine) == 0 && strcmp(machine.machine, "arm64") == 0 &&
        NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 27 &&
        [env[@"GITHUB_ACTIONS"] isEqual:@"true"] &&
        [env[@"GITHUB_REPOSITORY"] isEqual:@"ai-ecoverse/sliccy-app"] &&
        [env[@"GITHUB_EVENT_NAME"] isEqual:@"workflow_dispatch"] &&
        [env[@"GITHUB_REF"] isEqual:@"refs/heads/proof/runner-capture-v1"] &&
        [env[@"RUNNER_ENVIRONMENT"] isEqual:@"github-hosted"] &&
        [env[@"SLICCY_RUNNER_ENVIRONMENT"] isEqual:@"github-hosted"];
}
static NSString *hex(const unsigned char *bytes, size_t count) {
    NSMutableString *value = [NSMutableString stringWithCapacity:count * 2];
    for (size_t i = 0; i < count; i++) [value appendFormat:@"%02x", bytes[i]];
    return value;
}
static NSDictionary *kernel(pid_t pid) {
    struct proc_bsdinfo info = {0};
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    int infoError = size == (int)sizeof(info) ? 0 : errno;
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int pathSize = proc_pidpath(pid, path, sizeof(path));
    int pathError = pathSize > 0 ? 0 : errno;
    uint32_t flags = 0;
    int status = csops(pid, 0, &flags, sizeof(flags));
    int statusError = status == 0 ? 0 : errno;
    unsigned char hash[20] = {0};
    int hashStatus = csops(pid, 5, hash, sizeof(hash));
    int hashError = hashStatus == 0 ? 0 : errno;
    BOOL valid = size == (int)sizeof(info) && info.pbi_pid == (uint32_t)pid && info.pbi_start_tvsec > 0 && info.pbi_start_tvusec < 1000000;
    return @{@"pid": @(pid), @"processInfoAvailable": @(valid), @"processInfoError": @(infoError),
        @"parent": valid ? @(info.pbi_ppid) : absent(), @"uid": valid ? @(info.pbi_uid) : absent(),
        @"startSeconds": valid ? [NSString stringWithFormat:@"%llu", info.pbi_start_tvsec] : absent(),
        @"startMicroseconds": valid ? @(info.pbi_start_tvusec) : absent(),
        @"path": pathSize > 0 ? ([NSString stringWithUTF8String:path] ?: absent()) : absent(), @"pathError": @(pathError),
        @"codeStatus": status == 0 ? @(flags) : absent(), @"codeStatusError": @(statusError),
        @"platformBinary": status == 0 ? @((flags & 0x04000000) != 0) : absent(),
        @"cdHash": hashStatus == 0 ? hex(hash, sizeof(hash)) : absent(), @"cdHashError": @(hashError)};
}
static NSDictionary *owner(pid_t pid) {
    NSDictionary *before = kernel(pid);
    SecCodeRef guest = NULL;
    SecStaticCodeRef code = NULL;
    SecRequirementRef anchor = NULL;
    CFDictionaryRef raw = NULL;
    OSStatus lookup = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributePid: @(pid)}, kSecCSDefaultFlags, &guest);
    OSStatus live = errSecParam, apple = errSecParam, copied = errSecParam, details = errSecParam, staticStatus = errSecParam;
    NSDictionary *info = @{};
    if (lookup == errSecSuccess && guest) {
        live = SecCodeCheckValidity(guest, kSecCSStrictValidate, NULL);
        if (SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &anchor) == errSecSuccess && anchor)
            apple = SecCodeCheckValidity(guest, kSecCSStrictValidate, anchor);
        copied = SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &code);
        if (copied == errSecSuccess && code) {
            staticStatus = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
            details = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw);
            if (details == errSecSuccess && raw) info = (__bridge NSDictionary *)raw;
        }
    }
    id identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier];
    id team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    id image = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
    id digest = info[(__bridge NSString *)kSecCodeInfoUnique];
    NSString *codeHash = [digest isKindOfClass:NSData.class] ? hex([digest bytes], [digest length]) : nil;
    NSString *imagePath = [image isKindOfClass:NSURL.class] ? [image path] : nil;
    OSStatus liveAfter = guest ? SecCodeCheckValidity(guest, kSecCSStrictValidate, NULL) : errSecParam;
    NSDictionary *after = kernel(pid);
    BOOL same = [before[@"processInfoAvailable"] boolValue] && [after[@"processInfoAvailable"] boolValue];
    for (NSString *key in @[@"pid", @"parent", @"uid", @"startSeconds", @"startMicroseconds", @"path", @"cdHash", @"codeStatus"])
        same = same && before[key] != absent() && [before[key] isEqual:after[key]];
    BOOL bound = same && live == errSecSuccess && liveAfter == errSecSuccess && staticStatus == errSecSuccess &&
        codeHash && [codeHash isEqual:before[@"cdHash"]] && imagePath && [imagePath isEqual:before[@"path"]];
    NSDictionary *result = @{@"pid": @(pid), @"before": before, @"after": after,
        @"guestLookupStatus": @(lookup), @"liveValidityStatus": @(live), @"liveValidityAfterStatus": @(liveAfter),
        @"appleAnchorStatus": @(apple), @"appleAnchored": apple == errSecSuccess ? @YES : apple == errSecCSReqFailed ? @NO : absent(),
        @"staticCopyStatus": @(copied), @"staticValidityStatus": @(staticStatus), @"signingInformationStatus": @(details),
        @"signingIdentifier": [identifier isKindOfClass:NSString.class] ? identifier : absent(),
        @"teamIdentifier": [team isKindOfClass:NSString.class] ? team : absent(),
        @"securedExecutablePath": imagePath ?: absent(), @"securityCDHash": codeHash ?: absent(),
        @"stableKernelSamples": @(same), @"liveStaticKernelConsistent": @(bound)};
    if (raw) CFRelease(raw);
    if (code) CFRelease(code);
    if (anchor) CFRelease(anchor);
    if (guest) CFRelease(guest);
    return result;
}
static NSDictionary *snapshot(void) {
    CFArrayRef raw = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
    if (!raw) return @{@"schema": @1, @"available": @NO, @"reason": @"cg-unavailable"};
    NSArray *rows = CFBridgingRelease(raw);
    if (rows.count > 512) return @{@"schema": @1, @"available": @NO, @"reason": @"window-bound"};
    NSMutableArray *windows = [NSMutableArray array], *owners = [NSMutableArray array];
    NSMutableSet *pids = [NSMutableSet set];
    BOOL complete = YES;
    for (NSDictionary *row in rows) {
        id pid = row[(__bridge NSString *)kCGWindowOwnerPID];
        id wid = row[(__bridge NSString *)kCGWindowNumber];
        id layer = row[(__bridge NSString *)kCGWindowLayer];
        id name = row[(__bridge NSString *)kCGWindowOwnerName];
        id bounds = row[(__bridge NSString *)kCGWindowBounds];
        BOOL valid = [pid isKindOfClass:NSNumber.class] && [pid intValue] > 0 &&
            [wid isKindOfClass:NSNumber.class] && [layer isKindOfClass:NSNumber.class] && [bounds isKindOfClass:NSDictionary.class];
        complete = complete && valid;
        [windows addObject:@{@"pid": pid ?: absent(), @"windowID": wid ?: absent(), @"ownerName": name ?: absent(),
            @"layer": layer ?: absent(), @"bounds": bounds ?: absent(), @"validShape": @(valid)}];
        if (valid) [pids addObject:pid];
    }
    if (pids.count > 128) return @{@"schema": @1, @"available": @NO, @"reason": @"owner-bound"};
    for (NSNumber *pid in [[pids allObjects] sortedArrayUsingSelector:@selector(compare:)]) [owners addObject:owner(pid.intValue)];
    return @{@"schema": @1, @"available": @YES, @"allWindowRowsClassifiable": @(complete),
        @"windows": windows, @"owners": owners, @"capture": @NO, @"tccWrites": @NO, @"grants": @NO};
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        if (!hosted()) return 2;
        id value = nil;
        if (argc == 1) value = snapshot();
        else if (argc == 3 && strcmp(argv[1], "--owner") == 0) {
            char *end = NULL;
            long pid = strtol(argv[2], &end, 10);
            if (!end || *end || pid <= 0 || pid > INT32_MAX) return 2;
            value = owner((pid_t)pid);
        } else return 2;
        NSError *error = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:&error];
        if (!data || data.length > 4194304) return 1;
        if (fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF) return 1;
        return 0;
    }
}
