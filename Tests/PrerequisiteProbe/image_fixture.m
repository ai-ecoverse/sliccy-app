#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "prerequisite_image_record.h"

static void check(BOOL value,NSString *name) {
    if(!value){fprintf(stderr,"image runtime assertion: %s\n",name.UTF8String);exit(1);}
}
static void put32(NSMutableData *data,NSUInteger at,uint32_t value,BOOL big) {
    uint8_t *p=data.mutableBytes;
    for(int i=0;i<4;i++)p[at+i]=(uint8_t)(value>>(8*(big?3-i:i)));
}
static NSData *thin(uint32_t cpu,uint32_t subtype) {
    NSMutableData *d=[NSMutableData dataWithLength:32];put32(d,0,0xfeedfacf,NO);put32(d,4,cpu,NO);put32(d,8,subtype,NO);return d;
}
static NSData *fat(BOOL wide,BOOL big) {
    NSMutableData *d=[NSMutableData dataWithLength:288];put32(d,0,wide?0xcafebabf:0xcafebabe,big);put32(d,4,2,big);
    for(NSUInteger i=0;i<2;i++) {
        NSUInteger at=8+i*(wide?32:20);uint32_t cpu=i?0x01000007:0x0100000c;
        put32(d,at,cpu,big);put32(d,at+4,0,big);
        if(wide){put32(d,at+(big?12:8),128+(uint32_t)i*128,big);put32(d,at+(big?20:16),32,big);put32(d,at+24,7,big);}
        else{put32(d,at+8,128+(uint32_t)i*128,big);put32(d,at+12,32,big);put32(d,at+16,7,big);}
        [d replaceBytesInRange:NSMakeRange(128+i*128,32) withBytes:thin(cpu,0).bytes];
    }
    return d;
}
int main(void) {
    @autoreleasepool {
        NSMutableArray *layouts=[NSMutableArray array];
        for(NSData *bytes in @[thin(0x0100000c,0),fat(NO,YES),fat(YES,YES),fat(NO,NO),fat(YES,NO)]) {
            NSArray *slices=sliccy_image_slices(bytes);check(slices!=nil,@"slices-valid");[layouts addObject:slices];
        }
        NSMutableArray *bad=[NSMutableArray array];
        NSMutableData *overlap=[fat(NO,YES) mutableCopy];put32(overlap,20,160,YES);[bad addObject:overlap];
        NSMutableData *range=[fat(NO,YES) mutableCopy];put32(range,16,0xfffffff0,YES);[bad addObject:range];
        NSMutableData *cpu=[fat(NO,YES) mutableCopy];put32(cpu,128+4,7,NO);[bad addObject:cpu];
        NSMutableData *count=[fat(NO,YES) mutableCopy];put32(count,4,9,YES);[bad addObject:count];
        NSMutableData *reserved=[fat(YES,YES) mutableCopy];put32(reserved,36,1,YES);[bad addObject:reserved];
        [bad addObject:[NSMutableData dataWithLength:27]];
        for(NSData *bytes in bad)check(sliccy_image_slices(bytes)==nil,@"slices-invalid");
        NSData *a=[@"aaaaaaaaaaaaaaaaaaaa" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *b=[@"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *bp=[b subdataWithRange:NSMakeRange(0,20)];
        NSDictionary *set=@{@1:a,@2:b};
        NSArray *hashes=@[sliccy_image_hashes(set,@1,a,a),sliccy_image_hashes(set,@2,bp,a),sliccy_image_hashes(nil,nil,nil,a),
            sliccy_image_hashes(@{@2:@"wrong"},@2,bp,a),sliccy_image_hashes(@{@1:a,@3:a},@3,a,a)];
        check([hashes[0][@"uniqueHashTypes"] isEqual:@[@1]],@"live-hash-type");
        check([hashes[1][@"uniqueHashTypes"] isEqual:@[@2]],@"static-hash-type");
        check([hashes[1][@"kernelHashTypes"] isEqual:@[@1]],@"kernel-hash-type");
        check([hashes[4][@"kernelHashTypes"] isEqual:@[@1,@3]],@"ambiguous-hash-types");
        NSArray *arch=@[sliccy_image_arch(8,0,8,0x0100000c,2),sliccy_image_arch(0,1,8,0,0),sliccy_image_arch(4,0,8,0,0)];
        check([arch[0][@"cpuType"] intValue]==0x0100000c,@"architecture");
        check(arch[1][@"cpuType"]==NSNull.null && arch[2][@"cpuSubtype"]==NSNull.null,@"architecture-unavailable");
        NSArray *vnodes=@[sliccy_image_relation(YES,1,2,YES,1,2),sliccy_image_relation(YES,3,2,YES,1,2),
            sliccy_image_relation(YES,1,3,YES,1,2),sliccy_image_relation(NO,0,0,YES,1,2),sliccy_image_relation(YES,1,2,NO,0,0)];
        check([vnodes[0][@"same"] isEqual:@YES],@"vnode-same");
        check([vnodes[1][@"same"] isEqual:@NO] && [vnodes[2][@"same"] isEqual:@NO],@"vnode-different");
        check(vnodes[3][@"same"]==NSNull.null && vnodes[4][@"same"]==NSNull.null,@"vnode-unavailable");
        NSDictionary *result=@{@"layouts":layouts,@"invalidLayouts":@(bad.count),@"hashes":hashes,@"architectures":arch,@"vnodes":vnodes};
        NSData *encoded=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:NULL];check(encoded!=nil,@"encoder");
        fwrite(encoded.bytes,1,encoded.length,stdout);fputc('\n',stdout);
    }
    return 0;
}
