#define main owner_probe_main_not_invoked
#include "owner_identity_probe.m"
#undef main

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc == 2) {
            phaseOrigin = monotonicNanos();
            if (strcmp(argv[1], "--phase-loss-full") == 0) {
                int descriptors[2];
                if (pipe(descriptors) != 0 || fcntl(descriptors[1], F_SETFL, O_NONBLOCK) != 0) return 9;
                char padding[4096] = {0};
                for (unsigned i = 0; i < 1024 && write(descriptors[1], padding, sizeof(padding)) > 0; i++) {}
                if (errno != EAGAIN || dup2(descriptors[1], STDERR_FILENO) < 0) return 9;
            } else if (strcmp(argv[1], "--phase-loss-closed") == 0) {
                close(STDERR_FILENO);
            } else if (strcmp(argv[1], "--phase-loss-bound") == 0) {
                phaseSequence = 8192;
            } else return 9;
            beginPhase(PhaseProcInfo, 42);
            return 9;
        }
        if (argc != 1) return 9;
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
        struct proc_bsdinfo sample = {0};
        sample.pbi_pid = 42; sample.pbi_ppid = 10; sample.pbi_uid = 501;
        sample.pbi_start_tvsec = 123; sample.pbi_start_tvusec = 456;
        NSMutableArray *kernels = [NSMutableArray array];
        for (NSNumber *flags in @[@0, @0x04000000]) {
            [kernels addObject:kernelRecord(42, sample, sizeof(sample), 0, "/synthetic", 10, 0,
                flags.unsignedIntValue, 0, 0, digest, 0, 0)];
        }
        [kernels addObject:kernelRecord(42, sample, 0, ESRCH, "", 0, ESRCH, 0, -1, ESRCH, digest, -1, ESRCH)];
        sample.pbi_pid = 43;
        [kernels addObject:kernelRecord(42, sample, sizeof(sample), 0, "/synthetic", 10, 0,
            0, 0, 0, digest, 0, 0)];
        sample.pbi_pid = 42;
        NSArray *privileged = @[
            privilegedKernelRecord(42, sample, sizeof(sample), 0, "/synthetic", 10, 0),
            privilegedKernelRecord(42, sample, 0, ESRCH, "", 0, ESRCH)
        ];
        const char *kernelArgs[] = {"fixed", "--kernel", "42"};
        const char *ownerArgs[] = {"fixed", "--owner", "42"};
        const char *staticArgs[] = {"fixed", "--chrome-static"};
        if (!modeAllowed(0, 3, kernelArgs) || modeAllowed(501, 3, kernelArgs) ||
            modeAllowed(0, 3, ownerArgs) || modeAllowed(0, 2, staticArgs) || modeAllowed(0, 1, ownerArgs)) return 2;
        pid_t syntheticPID = 0;
        if (!exactPID("42", &syntheticPID) || syntheticPID != 42) return 2;
        for (NSString *bad in @[@"", @"0", @"01", @"+42", @"-1", @" 42", @"42x", @"2147483648"])
            if (exactPID(bad.UTF8String, &syntheticPID)) return 2;
        FILE *phaseFile = tmpfile();
        if (!phaseFile) return 2;
        phaseOrigin = monotonicNanos();
        for (unsigned phase = 0; phase < PhaseCount; phase++) {
            uint64_t began = monotonicNanos();
            if (!writePhase(fileno(phaseFile), phase, 42, NO, began, 0, 0) ||
                !writePhase(fileno(phaseFile), phase, 42, YES, began, -1, EACCES)) return 2;
        }
        rewind(phaseFile);
        NSMutableArray *phases = [NSMutableArray array];
        char phaseRow[512];
        while (fgets(phaseRow, sizeof(phaseRow), phaseFile)) {
            NSData *row = [NSData dataWithBytes:phaseRow length:strlen(phaseRow)];
            id value = [NSJSONSerialization JSONObjectWithData:row options:0 error:NULL];
            if (!value) return 2;
            [phases addObject:value];
        }
        fclose(phaseFile);
        int descriptors[2];
        if (pipe(descriptors) != 0 || fcntl(descriptors[1], F_SETFL, O_NONBLOCK) != 0) return 2;
        char padding[4096] = {0};
        for (unsigned i = 0; i < 1024 && write(descriptors[1], padding, sizeof(padding)) > 0; i++) {}
        if (errno != EAGAIN || writePhase(descriptors[1], PhaseProcInfo, 42, NO, monotonicNanos(), 0, 0)) return 2;
        close(descriptors[0]); close(descriptors[1]);
        if (writePhase(-1, PhaseProcInfo, 42, NO, monotonicNanos(), 0, 0)) return 2;
        phaseSequence = 8192;
        if (writePhase(-1, PhaseProcInfo, 42, NO, monotonicNanos(), 0, 0)) return 2;
        NSError *error = nil;
        NSData *data = encodeRecord(@{@"staticRecords": records, @"kernelRecords": kernels, @"privilegedRecords": privileged, @"phases": phases}, &error);
        CFRelease(detritus); CFRelease(broken);
        if (!data || data.length > 65536) return 1;
        if (fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF || fflush(stdout) == EOF) return 1;
        return 0;
    }
}
