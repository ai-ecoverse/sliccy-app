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
#include <fcntl.h>
#include <time.h>

extern int csops(pid_t, unsigned int, void *, size_t);

static int failed(const char *step, int status) {
    fprintf(stderr, "{\"step\":\"%s\",\"exitStatus\":%d}\n", step, status);
    return status;
}

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
typedef NS_ENUM(unsigned, ProbePhase) {
    PhaseProcInfo, PhaseProcPath, PhaseCodeStatus, PhaseCodeHash,
    PhaseChromeCreate, PhaseChromeRequirement, PhaseChromeIdentity, PhaseChromeStrict, PhaseChromeInformation,
    PhaseGuestLookup, PhaseGuestLive, PhaseAppleRequirement, PhaseAppleLive, PhaseGuestStaticCopy,
    PhaseGuestStatic, PhaseGuestInformation, PhaseGuestChromeRequirement, PhaseGuestChromeStatic,
    PhaseGuestChromeLive, PhaseGuestLiveAfter, PhaseWindows, PhaseCount
};
static const char *phaseNames[] = {"proc-info", "proc-path", "code-status", "code-hash",
    "chrome-create", "chrome-requirement", "chrome-identity", "chrome-strict", "chrome-information",
    "guest-lookup", "guest-live", "apple-requirement", "apple-live", "guest-static-copy",
    "guest-static", "guest-information", "guest-chrome-requirement", "guest-chrome-static",
    "guest-chrome-live", "guest-live-after", "windows"};
static unsigned phaseSequence = 0;
static uint64_t phaseOrigin = 0;
static uint64_t monotonicNanos(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) _exit(1);
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}
static BOOL writePhase(int fd, ProbePhase phase, pid_t pid, BOOL complete, uint64_t began, long long result, int error) {
    if ((unsigned)phase >= PhaseCount || phaseSequence >= 8192) return NO;
    uint64_t now = monotonicNanos();
    char row[512];
    int count = snprintf(row, sizeof(row),
        "{\"schema\":1,\"kind\":\"identity-call\",\"seq\":%u,\"phase\":\"%s\",\"pid\":%d,\"state\":\"%s\",\"elapsedNs\":%llu,\"durationNs\":%llu,\"result\":%lld,\"error\":%d}\n",
        ++phaseSequence, phaseNames[phase], pid, complete ? "complete" : "entered",
        (unsigned long long)(now - phaseOrigin), (unsigned long long)(complete ? now - began : 0), result, error);
    return count > 0 && count < (int)sizeof(row) && write(fd, row, (size_t)count) == count;
}
static uint64_t beginPhase(ProbePhase phase, pid_t pid) {
    int saved = errno;
    uint64_t began = monotonicNanos();
    if (!writePhase(STDERR_FILENO, phase, pid, NO, began, 0, 0)) _exit(1);
    errno = saved;
    return began;
}
static void endPhase(ProbePhase phase, pid_t pid, uint64_t began, long long result, int error) {
    if (!writePhase(STDERR_FILENO, phase, pid, YES, began, result, error)) _exit(1);
    errno = error;
}
#define OBSERVE(phase, pid, expression) ({ uint64_t began = beginPhase(phase, pid); __auto_type result = (expression); int error = errno; endPhase(phase, pid, began, (long long)result, error); result; })
#define OBSERVE_POINTER(phase, pid, expression) ({ uint64_t began = beginPhase(phase, pid); __auto_type result = (expression); int error = errno; endPhase(phase, pid, began, result ? 1 : 0, error); result; })
static BOOL configurePhases(void) {
    phaseOrigin = monotonicNanos();
    int flags = fcntl(STDERR_FILENO, F_GETFL);
    return flags >= 0 && fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK) == 0;
}
static BOOL exactPID(const char *text, pid_t *pid) {
    if (!text || !*text || text[0] == '0') return NO;
    for (const char *cursor = text; *cursor; cursor++) if (*cursor < '0' || *cursor > '9') return NO;
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value <= 0 || value > INT32_MAX) return NO;
    *pid = (pid_t)value;
    return YES;
}
static BOOL modeAllowed(uid_t uid, int argc, const char **argv) {
    BOOL privileged = argc == 3 && strcmp(argv[1], "--kernel") == 0;
    return uid == 0 ? privileged : !privileged;
}
static NSDictionary *privilegedKernelRecord(pid_t pid, struct proc_bsdinfo info, int size, int infoError,
    const char *path, int pathSize, int pathError) {
    BOOL valid = size == (int)sizeof(info) && info.pbi_pid == (uint32_t)pid && info.pbi_start_tvsec > 0 && info.pbi_start_tvusec < 1000000;
    return @{@"schema": @1, @"kind": @"privileged-kernel-identity", @"pid": @(pid),
        @"processInfoAvailable": valid ? @YES : @NO, @"processInfoError": @(infoError),
        @"parent": valid ? @(info.pbi_ppid) : absent(), @"uid": valid ? @(info.pbi_uid) : absent(),
        @"startSeconds": valid ? [NSString stringWithFormat:@"%llu", info.pbi_start_tvsec] : absent(),
        @"startMicroseconds": valid ? @(info.pbi_start_tvusec) : absent(),
        @"path": pathSize > 0 ? ([NSString stringWithUTF8String:path] ?: absent()) : absent(), @"pathError": @(pathError)};
}
static NSDictionary *privilegedKernel(pid_t pid) {
    struct proc_bsdinfo info = {0};
    int size = OBSERVE(PhaseProcInfo, pid, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)));
    int infoError = size == (int)sizeof(info) ? 0 : errno;
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int pathSize = OBSERVE(PhaseProcPath, pid, proc_pidpath(pid, path, sizeof(path)));
    int pathError = pathSize > 0 ? 0 : errno;
    return privilegedKernelRecord(pid, info, size, infoError, path, pathSize, pathError);
}
static NSDictionary *kernelRecord(pid_t pid, struct proc_bsdinfo info, int size, int infoError,
    const char *path, int pathSize, int pathError, uint32_t flags, int status, int statusError,
    const unsigned char *hash, int hashStatus, int hashError) {
    BOOL valid = size == (int)sizeof(info) && info.pbi_pid == (uint32_t)pid && info.pbi_start_tvsec > 0 && info.pbi_start_tvusec < 1000000;
    return @{@"pid": @(pid), @"processInfoAvailable": @(valid), @"processInfoError": @(infoError),
        @"parent": valid ? @(info.pbi_ppid) : absent(), @"uid": valid ? @(info.pbi_uid) : absent(),
        @"startSeconds": valid ? [NSString stringWithFormat:@"%llu", info.pbi_start_tvsec] : absent(),
        @"startMicroseconds": valid ? @(info.pbi_start_tvusec) : absent(),
        @"path": pathSize > 0 ? ([NSString stringWithUTF8String:path] ?: absent()) : absent(), @"pathError": @(pathError),
        @"codeStatus": status == 0 ? @(flags) : absent(), @"codeStatusError": @(statusError),
        @"platformBinary": status == 0 ? ((flags & 0x04000000) != 0 ? @YES : @NO) : absent(),
        @"cdHash": hashStatus == 0 ? hex(hash, 20) : absent(), @"cdHashError": @(hashError)};
}
static NSDictionary *kernel(pid_t pid) {
    struct proc_bsdinfo info = {0};
    int size = OBSERVE(PhaseProcInfo, pid, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)));
    int infoError = size == (int)sizeof(info) ? 0 : errno;
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int pathSize = OBSERVE(PhaseProcPath, pid, proc_pidpath(pid, path, sizeof(path)));
    int pathError = pathSize > 0 ? 0 : errno;
    uint32_t flags = 0;
    int status = OBSERVE(PhaseCodeStatus, pid, csops(pid, 0, &flags, sizeof(flags)));
    int statusError = status == 0 ? 0 : errno;
    unsigned char hash[20] = {0};
    int hashStatus = OBSERVE(PhaseCodeHash, pid, csops(pid, 5, hash, sizeof(hash)));
    int hashError = hashStatus == 0 ? 0 : errno;
    return kernelRecord(pid, info, size, infoError, path, pathSize, pathError, flags, status, statusError, hash, hashStatus, hashError);
}
static NSString *chromeRule(void) {
    return @"anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"";
}
static BOOL chromeAccepted(OSStatus identity, OSStatus strict) {
    return identity == errSecSuccess && (strict == errSecSuccess || strict == errSecCSInvalidAssociatedFileData);
}
static NSDictionary *chromePolicyRecord(OSStatus identity, OSStatus strict, CFErrorRef error) {
    SecCSFlags flags = kSecCSCheckAllArchitectures | kSecCSCheckNestedCode;
    return @{@"requirement": chromeRule(), @"identityFlags": @(flags), @"strictFlags": @(flags | kSecCSStrictValidate), @"identityStatus": @(identity), @"strictStatus": @(strict),
        @"strictErrorDomain": error ? (__bridge NSString *)CFErrorGetDomain(error) : absent(),
        @"strictErrorCode": error ? @(CFErrorGetCode(error)) : absent(),
        @"accepted": chromeAccepted(identity, strict) ? @YES : @NO,
        @"detritusTolerated": identity == errSecSuccess && strict == errSecCSInvalidAssociatedFileData ? @YES : @NO};
}
static NSDictionary *chromeStatic(SecStaticCodeRef code, SecRequirementRef requirement, pid_t pid) {
    SecCSFlags flags = kSecCSCheckAllArchitectures | kSecCSCheckNestedCode;
    CFErrorRef error = NULL;
    OSStatus identity = OBSERVE(PhaseChromeIdentity, pid, SecStaticCodeCheckValidity(code, flags, requirement));
    OSStatus strict = OBSERVE(PhaseChromeStrict, pid, SecStaticCodeCheckValidityWithErrors(code, flags | kSecCSStrictValidate, requirement, &error));
    NSDictionary *result = chromePolicyRecord(identity, strict, error);
    if (error) CFRelease(error);
    return result;
}
static NSDictionary *chromeIdentityRecord(OSStatus created, OSStatus rule, OSStatus details, NSDictionary *policy, NSDictionary *info) {
    id digest = info[(__bridge NSString *)kSecCodeInfoUnique];
    NSString *hash = [digest isKindOfClass:NSData.class] && [digest length] == 20 ? hex([digest bytes], [digest length]) : nil;
    id identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier], team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    BOOL accepted = [policy[@"accepted"] boolValue] && details == errSecSuccess && hash &&
        [identifier isEqual:@"com.google.Chrome"] && [team isEqual:@"EQHXZ8M8AV"];
    return @{@"schema": @1, @"kind": @"chrome-static-identity", @"accepted": accepted ? @YES : @NO,
        @"createStatus": @(created), @"requirementStatus": @(rule), @"signingInformationStatus": @(details),
        @"policy": policy, @"cdHash": hash ?: absent(), @"identifier": identifier ?: absent(), @"team": team ?: absent()};
}
static NSDictionary *chromePreflight(pid_t pid) {
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef raw = NULL;
    OSStatus created = OBSERVE(PhaseChromeCreate, pid, SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:@"/Applications/Google Chrome.app"], kSecCSDefaultFlags, &code));
    OSStatus rule = OBSERVE(PhaseChromeRequirement, pid, SecRequirementCreateWithString((__bridge CFStringRef)chromeRule(), kSecCSDefaultFlags, &requirement));
    NSDictionary *policy = code && requirement && created == errSecSuccess && rule == errSecSuccess ? chromeStatic(code, requirement, pid) : @{};
    OSStatus details = code ? OBSERVE(PhaseChromeInformation, pid, SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw)) : errSecParam;
    NSDictionary *result = chromeIdentityRecord(created, rule, details, policy, raw ? (__bridge NSDictionary *)raw : @{});
    if (raw) CFRelease(raw);
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    return result;
}
static NSData *encodeRecord(id value, NSError **error) {
    return [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:error];
}
static NSDictionary *owner(pid_t pid) {
    NSDictionary *before = kernel(pid);
    SecCodeRef guest = NULL;
    SecStaticCodeRef code = NULL;
    SecRequirementRef anchor = NULL;
    CFDictionaryRef raw = NULL;
    OSStatus lookup = OBSERVE(PhaseGuestLookup, pid, SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributePid: @(pid)}, kSecCSDefaultFlags, &guest));
    OSStatus requirementStatus = errSecParam;
    OSStatus live = errSecParam, apple = errSecParam, copied = errSecParam, details = errSecParam, staticStatus = errSecParam;
    NSDictionary *info = @{};
    if (lookup == errSecSuccess && guest) {
        live = OBSERVE(PhaseGuestLive, pid, SecCodeCheckValidity(guest, kSecCSStrictValidate, NULL));
        requirementStatus = OBSERVE(PhaseAppleRequirement, pid, SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &anchor));
        if (requirementStatus == errSecSuccess && anchor)
            apple = OBSERVE(PhaseAppleLive, pid, SecCodeCheckValidity(guest, kSecCSStrictValidate, anchor));
        copied = OBSERVE(PhaseGuestStaticCopy, pid, SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &code));
        if (copied == errSecSuccess && code) {
            staticStatus = OBSERVE(PhaseGuestStatic, pid, SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL));
            details = OBSERVE(PhaseGuestInformation, pid, SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw));
            if (details == errSecSuccess && raw) info = (__bridge NSDictionary *)raw;
        }
    }
    id identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier];
    id team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    id image = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
    id digest = info[(__bridge NSString *)kSecCodeInfoUnique];
    NSString *codeHash = [digest isKindOfClass:NSData.class] ? hex([digest bytes], [digest length]) : nil;
    NSString *imagePath = [image isKindOfClass:NSURL.class] ? [image path] : nil;
    OSStatus guestStrictStatus = staticStatus;
    NSDictionary *chromePolicy = nil;
    SecRequirementRef chromeRequirement = NULL;
    OSStatus chromeRequirementStatus = errSecParam;
    BOOL isChrome = [identifier isEqual:@"com.google.Chrome"];
    if (isChrome && code && guest) {
        chromeRequirementStatus = OBSERVE(PhaseGuestChromeRequirement, pid, SecRequirementCreateWithString((__bridge CFStringRef)chromeRule(), kSecCSDefaultFlags, &chromeRequirement));
        if (chromeRequirementStatus == errSecSuccess && chromeRequirement) {
            chromePolicy = chromePreflight(pid);
            staticStatus = OBSERVE(PhaseGuestChromeStatic, pid, SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, chromeRequirement));
            live = OBSERVE(PhaseGuestChromeLive, pid, SecCodeCheckValidity(guest, kSecCSDefaultFlags, chromeRequirement));
        } else {
            staticStatus = errSecCSReqFailed;
            live = errSecCSReqFailed;
        }
    }
    OSStatus liveAfter = guest ? OBSERVE(PhaseGuestLiveAfter, pid, SecCodeCheckValidity(guest, isChrome ? kSecCSDefaultFlags : kSecCSStrictValidate, isChrome ? chromeRequirement : NULL)) : errSecParam;
    NSDictionary *after = kernel(pid);
    BOOL same = [before[@"processInfoAvailable"] boolValue] && [after[@"processInfoAvailable"] boolValue];
    for (NSString *key in @[@"pid", @"parent", @"uid", @"startSeconds", @"startMicroseconds", @"path", @"cdHash", @"codeStatus"])
        same = same && before[key] != absent() && [before[key] isEqual:after[key]];
    BOOL bound = same && live == errSecSuccess && liveAfter == errSecSuccess && staticStatus == errSecSuccess &&
        codeHash && [codeHash isEqual:before[@"cdHash"]] && imagePath && [imagePath isEqual:before[@"path"]] &&
        (!isChrome || ([chromePolicy[@"accepted"] boolValue] && [chromePolicy[@"cdHash"] isEqual:codeHash] &&
            [team isEqual:@"EQHXZ8M8AV"] && chromeAccepted(staticStatus, guestStrictStatus)));
    NSDictionary *result = @{@"pid": @(pid), @"before": before, @"after": after,
        @"guestLookupStatus": @(lookup), @"liveValidityStatus": @(live), @"liveValidityAfterStatus": @(liveAfter),
        @"appleRequirementStatus": @(requirementStatus), @"appleAnchorStatus": @(apple), @"appleAnchored": apple == errSecSuccess ? @YES : apple == errSecCSReqFailed ? @NO : absent(),
        @"staticCopyStatus": @(copied), @"staticValidityStatus": @(staticStatus), @"signingInformationStatus": @(details),
        @"signingIdentifier": [identifier isKindOfClass:NSString.class] ? identifier : absent(),
        @"teamIdentifier": [team isKindOfClass:NSString.class] ? team : absent(),
        @"securedExecutablePath": imagePath ?: absent(), @"securityCDHash": codeHash ?: absent(),
        @"guestStrictStatus": @(guestStrictStatus), @"chromePolicy": chromePolicy ?: absent(), @"chromeRequirementStatus": @(chromeRequirementStatus), @"stableKernelSamples": @(same), @"liveStaticKernelConsistent": @(bound)};
    if (chromeRequirement) CFRelease(chromeRequirement);
    if (raw) CFRelease(raw);
    if (code) CFRelease(code);
    if (anchor) CFRelease(anchor);
    if (guest) CFRelease(guest);
    return result;
}
static NSDictionary *snapshot(void) {
    CFArrayRef raw = OBSERVE_POINTER(PhaseWindows, 0, CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID));
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
        if (!hosted()) return failed("observer-host-preflight", 2);
        if (!modeAllowed(geteuid(), argc, argv)) return failed("observer-privilege-mode", 2);
        if (!configurePhases()) return failed("observer-phase-output", 1);
        id value = nil;
        BOOL staticMode = argc == 2 && strcmp(argv[1], "--chrome-static") == 0;
        if (staticMode) value = chromePreflight(0);
        else if (argc == 1) value = snapshot();
        else if (argc == 3 && (strcmp(argv[1], "--owner") == 0 || strcmp(argv[1], "--kernel") == 0)) {
            pid_t pid;
            if (!exactPID(argv[2], &pid)) return failed("observer-owner-argument", 2);
            if (strcmp(argv[1], "--kernel") == 0) {
                alarm(2);
                value = privilegedKernel(pid);
            } else value = owner(pid);
        } else return failed("observer-mode-argument", 2);
        NSError *error = nil;
        NSData *data = encodeRecord(value, &error);
        if (!data) return failed("observer-json-serialization", 1);
        if (data.length > 4194304) return failed("observer-json-bound", 1);
        if (fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF || fflush(stdout) == EOF) return failed("observer-output-write", 1);
        return staticMode && ![value[@"accepted"] boolValue] ? 1 : 0;
    }
}
