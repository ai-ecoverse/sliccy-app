#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "prerequisite_binding_record.h"

static void check(BOOL value, NSString *name) {
    if (!value) { fprintf(stderr, "binding runtime assertion: %s\n", name.UTF8String); exit(1); }
}
int main(void) {
    @autoreleasepool {
        NSData *good = [@"aaaaaaaaaaaaaaaaaaaa" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *bad = [@"bbbbbbbbbbbbbbbbbbbb" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *identifier = @"com.apple.WindowServer", *path = @"/System/WindowServer";
        NSArray *names = @[@"kernel-status-zero", @"live-cdhash-type", @"live-cdhash-length", @"live-static-cdhash", @"live-kernel-cdhash", @"live-expected-cdhash", @"live-identifier", @"static-identifier", @"live-input-path"];
        NSMutableArray *cases = [NSMutableArray array];
        for (NSInteger fault = -1; fault < 9; fault++) {
            id live = fault == 1 ? (id)@"wrong-type" : fault == 2 ? [@"short" dataUsingEncoding:NSUTF8StringEncoding] : good;
            NSArray *rows = sliccy_binding_rows(fault == 0 ? -1 : 0, live, fault == 3 ? bad : good, fault == 4 ? bad : good,
                fault == 5 ? bad : good, fault == 6 ? @"wrong-live" : identifier, fault == 7 ? @"wrong-static" : identifier,
                identifier, [NSURL fileURLWithPath:fault == 8 ? @"/other" : path], path);
            check(rows.count == names.count, @"row-count");
            for (NSUInteger i = 0; i < names.count; i++) {
                check([rows[i][@"comparison"] isEqual:names[i]], @"comparison-name");
                if (fault == -1) check([rows[i][@"matched"] isEqual:@YES], names[i]);
                if ((NSInteger)i == fault) check([rows[i][@"matched"] isEqual:@NO], names[i]);
            }
            [cases addObject:@{@"fault": @(fault), @"rows": rows}];
        }
        NSArray *optional = sliccy_binding_rows(0, good, good, good, nil, identifier, identifier, identifier, [NSURL fileURLWithPath:path], path);
        check([optional[5][@"matched"] isEqual:@YES] && [optional[5][@"affectsVerdict"] isEqual:@NO], @"optional-expected-hash");
        NSMutableArray *files = [NSMutableArray array];
        NSArray *fileNames = @[@"filesystem-input-live-inode", @"filesystem-input-static-inode", @"filesystem-live-static-inode"];
        for (NSString *name in fileNames) {
            NSDictionary *left = @{@"statStatus": @0, @"device": @1, @"inode": @2};
            for (int fault = 0; fault < 4; fault++) {
                NSDictionary *right = fault == 3 ? @{@"statStatus": @(-1), @"device": NSNull.null, @"inode": NSNull.null} :
                    @{@"statStatus": @0, @"device": fault == 1 ? @3 : @1, @"inode": fault == 2 ? @4 : @2};
                NSDictionary *row = sliccy_inode_row(name, left, right);
                check([row[@"matched"] isEqual:fault == 0 ? @YES : fault == 3 ? (id)NSNull.null : @NO], name);
                [files addObject:row];
            }
        }
        NSArray *platform = @[sliccy_platform_record(0, 0, 0x04000000), sliccy_platform_record(0, 0, 0), sliccy_platform_record(-1, 1, 0)];
        NSArray *anchor = @[sliccy_anchor_record(YES, 0), sliccy_anchor_record(YES, -67050), sliccy_anchor_record(NO, -1)];
        NSArray *values = @[sliccy_binding_value(nil), sliccy_binding_value(@"string"), sliccy_binding_value(@123),
            sliccy_binding_value([NSObject new]), sliccy_binding_value([NSMutableData dataWithLength:4097])];
        NSDictionary *output = @{@"cases": cases, @"optional": optional, @"filesystem": files, @"platform": platform, @"anchor": anchor, @"values": values};
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:output options:NSJSONWritingSortedKeys error:NULL];
        check(encoded != nil, @"encoder");
        fwrite(encoded.bytes, 1, encoded.length, stdout); fputc('\n', stdout);
        return 0;
    }
}
