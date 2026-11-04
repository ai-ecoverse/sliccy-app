#import <Foundation/Foundation.h>

static NSDictionary *sliccy_binding_value(id value) {
    if (!value || value == NSNull.null) return @{@"type": @"null", @"value": NSNull.null};
    if ([value isKindOfClass:NSData.class]) {
        NSData *data = value;
        return @{@"type": @"data", @"length": @(data.length), @"value": data.length <= 4096 ? [data base64EncodedStringWithOptions:0] : (id)NSNull.null};
    }
    if ([value isKindOfClass:NSString.class]) {
        NSString *text = value;
        return @{@"type": @"string", @"length": @(text.length), @"value": text.length <= 4096 ? text : (id)NSNull.null};
    }
    if ([value isKindOfClass:NSNumber.class]) return @{@"type": @"number", @"value": value};
    return @{@"type": @"other", @"value": NSNull.null};
}
static NSDictionary *sliccy_binding_row(NSString *name, id left, id right, BOOL matched, BOOL required) {
    return @{@"comparison": name, @"left": sliccy_binding_value(left), @"right": sliccy_binding_value(right),
             @"matched": matched ? @YES : @NO, @"affectsVerdict": required ? @YES : @NO,
             @"status": @"compared"};
}
static NSArray *sliccy_binding_rows(int kernelStatus, id liveHash, id staticHash, NSData *kernelHash,
                                   NSData *expectedHash, id liveIdentifier, id staticIdentifier,
                                   NSString *expectedIdentifier, id liveImage, NSString *inputPath) {
    BOOL data = [liveHash isKindOfClass:NSData.class];
    id length = data ? @([liveHash length]) : (id)NSNull.null;
    NSString *imagePath = [liveImage isKindOfClass:NSURL.class] ? [liveImage path] : nil;
    return @[
        sliccy_binding_row(@"kernel-status-zero", @(kernelStatus), @0, kernelStatus == 0, YES),
        sliccy_binding_row(@"live-cdhash-type", data ? @"data" : @"not-data", @"data", data, YES),
        sliccy_binding_row(@"live-cdhash-length", length, @20, data && [liveHash length] == 20, YES),
        sliccy_binding_row(@"live-static-cdhash", liveHash, staticHash, [liveHash isEqual:staticHash], YES),
        sliccy_binding_row(@"live-kernel-cdhash", liveHash, kernelHash, [liveHash isEqual:kernelHash], YES),
        sliccy_binding_row(@"live-expected-cdhash", liveHash, expectedHash, !expectedHash || [liveHash isEqual:expectedHash], expectedHash != nil),
        sliccy_binding_row(@"live-identifier", liveIdentifier, expectedIdentifier, [liveIdentifier isEqual:expectedIdentifier], YES),
        sliccy_binding_row(@"static-identifier", staticIdentifier, expectedIdentifier, [staticIdentifier isEqual:expectedIdentifier], YES),
        sliccy_binding_row(@"live-input-path", imagePath, inputPath, [imagePath isEqual:inputPath], YES)
    ];
}
static NSDictionary *sliccy_inode_row(NSString *name, NSDictionary *left, NSDictionary *right) {
    BOOL available = [left[@"statStatus"] isEqual:@0] && [right[@"statStatus"] isEqual:@0];
    BOOL same = available && [left[@"device"] isEqual:right[@"device"]] && [left[@"inode"] isEqual:right[@"inode"]];
    return @{@"comparison": name, @"left": left, @"right": right, @"affectsVerdict": @NO,
             @"matched": available ? (same ? @YES : @NO) : (id)NSNull.null,
             @"status": available ? @"compared" : @"unavailable"};
}
static NSDictionary *sliccy_platform_record(int status, int error, uint32_t flags) {
    return @{@"status": @(status), @"errno": @(error), @"flags": status ? (id)NSNull.null : @(flags),
             @"platformBinary": status ? (id)NSNull.null : ((flags & 0x04000000) ? @YES : @NO), @"affectsVerdict": @NO};
}
static NSDictionary *sliccy_anchor_record(BOOL queried, int32_t status) {
    return @{@"queried": queried ? @YES : @NO, @"status": queried ? @(status) : (id)NSNull.null,
             @"appleAnchored": queried ? (status == 0 ? @YES : @NO) : (id)NSNull.null, @"affectsVerdict": @NO};
}

static void sliccy_static_diagnostics(int32_t (^query)(uint32_t), void (^record)(NSString *, NSDictionary *)) {
    NSArray *names = @[@"static-default", @"static-all-architectures", @"static-nested", @"static-strict"];
    const uint32_t flags[] = {0, 1, 8, 16};
    for (NSUInteger i = 0; i < names.count; i++) {
        record(@"entered", @{@"check": names[i], @"flags": @(flags[i]), @"affectsVerdict": @NO});
        int32_t status = query(flags[i]);
        record(@"completed", @{@"check": names[i], @"flags": @(flags[i]), @"status": @(status),
            @"matched": status == 0 ? @YES : @NO, @"affectsVerdict": @NO});
    }
}
