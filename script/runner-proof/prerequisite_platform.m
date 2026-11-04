#import <Foundation/Foundation.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void require(BOOL value, NSString *reason) {
    if (!value) @throw [NSException exceptionWithName:@"platform" reason:reason userInfo:nil];
}
static void phase(NSString *name, NSString *state, NSString *path, int status, int error) {
    NSDictionary *row = @{@"phase": name, @"state": state, @"path": path, @"status": @(status), @"errno": @(error)};
    NSMutableData *data = [[NSJSONSerialization dataWithJSONObject:row options:NSJSONWritingSortedKeys error:NULL] mutableCopy];
    [data appendBytes:"\n" length:1];
    require(data && data.length < 1024 && write(2, data.bytes, data.length) == (ssize_t)data.length, @"phase-delivery");
}
static NSDictionary *fact(NSString *path) {
    struct stat value;
    phase(@"lstat", @"entered", path, 0, 0);
    errno = 0;
    int status = lstat(path.fileSystemRepresentation, &value), error = errno;
    phase(@"lstat", @"completed", path, status, error);
    require(status == 0, @"tool-lstat");
    return @{@"path": path, @"device": @(value.st_dev), @"inode": @(value.st_ino),
        @"uid": @(value.st_uid), @"gid": @(value.st_gid), @"mode": @(value.st_mode)};
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
        signal(SIGPIPE, SIG_IGN); alarm(2);
        if (fcntl(2, F_SETFL, O_NONBLOCK) < 0) return 2;
        NSMutableDictionary *result = [@{@"schema": @1, @"accepted": @NO} mutableCopy];
        int exitCode = 2;
        @try {
            require(argc == 1 && hosted(), @"placement");
            struct statfs volume = {0};
            phase(@"statfs", @"entered", @"/", 0, 0);
            errno = 0;
            int status = statfs("/", &volume), error = errno;
            phase(@"statfs", @"completed", @"/", status, error);
            result[@"statfs"] = @{@"status": @(status), @"errno": @(error), @"flags": @(volume.f_flags),
                @"mountPoint": [NSString stringWithUTF8String:volume.f_mntonname],
                @"mountedFrom": [NSString stringWithUTF8String:volume.f_mntfromname],
                @"filesystem": [NSString stringWithUTF8String:volume.f_fstypename]};
            require(status == 0, @"root-statfs");
            struct attrlist attributes = { .bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES };
            struct { uint32_t length; vol_capabilities_attr_t value; } capabilities = {0};
            phase(@"getattrlist", @"entered", @"/", 0, 0);
            errno = 0;
            status = getattrlist("/", &attributes, &capabilities, sizeof(capabilities), FSOPT_REPORT_FULLSIZE);
            error = errno;
            phase(@"getattrlist", @"completed", @"/", status, error);
            result[@"capabilities"] = @{@"status": @(status), @"errno": @(error), @"length": @(capabilities.length),
                @"expectedLength": @(sizeof(capabilities)), @"validFormat": @(capabilities.value.valid[VOL_CAPABILITIES_FORMAT]),
                @"format": @(capabilities.value.capabilities[VOL_CAPABILITIES_FORMAT])};
            require(status == 0 && capabilities.length == sizeof(capabilities), @"root-capabilities");
            require((volume.f_flags & (MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT)) == (MNT_RDONLY | MNT_ROOTFS | MNT_SNAPSHOT), @"root-readonly-snapshot");
            require((capabilities.value.valid[VOL_CAPABILITIES_FORMAT] & VOL_CAP_FMT_SEALED) &&
                    (capabilities.value.capabilities[VOL_CAPABILITIES_FORMAT] & VOL_CAP_FMT_SEALED), @"root-seal");
            NSDictionary *root = fact(@"/"); result[@"root"] = root;
            NSArray *paths = @[@"/", @"/usr", @"/usr/bin", @"/usr/bin/sudo", @"/bin", @"/bin/mkdir", @"/bin/cp", @"/bin/rm"];
            NSMutableArray *records = [NSMutableArray array]; result[@"paths"] = records;
            for (NSString *path in paths) {
                NSDictionary *value = fact(path); [records addObject:value];
                mode_t mode = [value[@"mode"] unsignedShortValue];
                BOOL tool = [@[@"/usr/bin/sudo", @"/bin/mkdir", @"/bin/cp", @"/bin/rm"] containsObject:path];
                require([value[@"device"] isEqual:root[@"device"]] && [value[@"uid"] unsignedIntValue] == 0 &&
                    (tool ? S_ISREG(mode) && (mode & 0111) != 0 : S_ISDIR(mode)), @"tool-root-volume-identity");
            }
            result[@"accepted"] = @YES; exitCode = 0;
        } @catch (NSException *error) {
            result[@"failure"] = @{@"class": error.name, @"reason": error.reason ?: @"unknown"};
        }
        NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:NULL];
        if (!data || data.length > 16384 || fcntl(1, F_SETFL, O_NONBLOCK) < 0 ||
            write(1, data.bytes, data.length) != (ssize_t)data.length || write(1, "\n", 1) != 1) return 2;
        return exitCode;
    }
}
