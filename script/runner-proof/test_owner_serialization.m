#define main owner_probe_main_not_invoked
#include "owner_identity_probe.m"
#undef main

int main(void) {
    @autoreleasepool {
        unsigned char digest[20]; memset(digest, 0xAA, sizeof(digest));
        NSDictionary *info = @{(__bridge NSString *)kSecCodeInfoUnique: [NSData dataWithBytes:digest length:sizeof(digest)],
            (__bridge NSString *)kSecCodeInfoIdentifier: @"com.google.Chrome", (__bridge NSString *)kSecCodeInfoTeamIdentifier: @"EQHXZ8M8AV"};
        CFErrorRef detritus = CFErrorCreate(NULL, kCFErrorDomainOSStatus, errSecCSInvalidAssociatedFileData, NULL);
        CFErrorRef broken = CFErrorCreate(NULL, kCFErrorDomainOSStatus, errSecCSBadResource, NULL);
        NSMutableArray *records = [NSMutableArray array];
        NSArray *cases = @[
            @{@"name": @"clean", @"identity": @0, @"strict": @0},
            @{@"name": @"detritus", @"identity": @0, @"strict": @(errSecCSInvalidAssociatedFileData)},
            @{@"name": @"wrong-identity", @"identity": @(errSecCSReqFailed), @"strict": @(errSecCSInvalidAssociatedFileData)},
            @{@"name": @"broken-seal", @"identity": @0, @"strict": @(errSecCSBadResource)}
        ];
        for (NSDictionary *row in cases) {
            OSStatus identity = [row[@"identity"] intValue], strict = [row[@"strict"] intValue];
            CFErrorRef error = strict == errSecCSInvalidAssociatedFileData ? detritus : strict == errSecCSBadResource ? broken : NULL;
            NSDictionary *policy = chromePolicyRecord(identity, strict, error);
            [records addObject:@{@"name": row[@"name"], @"record": chromeIdentityRecord(0, 0, 0, policy, info)}];
        }
        NSDictionary *clean = chromePolicyRecord(0, 0, NULL);
        [records addObject:@{@"name": @"missing-metadata", @"record": chromeIdentityRecord(0, 0, errSecParam, clean, @{})}];
        [records addObject:@{@"name": @"missing-code", @"record": chromeIdentityRecord(errSecParam, errSecParam, errSecParam, @{}, @{})}];
        NSMutableDictionary *wrong = [info mutableCopy]; wrong[(__bridge NSString *)kSecCodeInfoTeamIdentifier] = @"WRONGTEAM";
        [records addObject:@{@"name": @"wrong-team", @"record": chromeIdentityRecord(0, 0, 0, clean, wrong)}];
        wrong = [info mutableCopy]; wrong[(__bridge NSString *)kSecCodeInfoUnique] = [NSData dataWithBytes:digest length:19];
        [records addObject:@{@"name": @"wrong-digest-length", @"record": chromeIdentityRecord(0, 0, 0, clean, wrong)}];
        NSError *error = nil;
        NSData *data = encodeRecord(records, &error);
        CFRelease(detritus); CFRelease(broken);
        if (!data || data.length > 65536) return 1;
        if (fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF || fflush(stdout) == EOF) return 1;
        return 0;
    }
}
