#import <Foundation/Foundation.h>
#include <stdint.h>
#include <string.h>

static BOOL sliccy_image_integer(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
        strcmp([value objCType], @encode(float)) && strcmp([value objCType], @encode(double));
}
static uint32_t sliccy_image_u32(const uint8_t *p, BOOL big) {
    return big ? ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3] :
        ((uint32_t)p[3]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[1]<<8)|p[0];
}
static uint64_t sliccy_image_u64(const uint8_t *p, BOOL big) {
    return big ? ((uint64_t)sliccy_image_u32(p,YES)<<32)|sliccy_image_u32(p+4,YES) :
        ((uint64_t)sliccy_image_u32(p+4,NO)<<32)|sliccy_image_u32(p,NO);
}
static NSArray *sliccy_image_slices(NSData *data) {
    if (data.length < 28 || data.length > 128*1024*1024) return nil;
    const uint8_t *p=data.bytes; uint32_t magic=sliccy_image_u32(p,YES);
    BOOL fat=magic==0xcafebabe || magic==0xcafebabf || magic==0xbebafeca || magic==0xbfbafeca;
    BOOL big=magic==0xcafebabe || magic==0xcafebabf, wide=magic==0xcafebabf || magic==0xbfbafeca;
    uint32_t count=fat?sliccy_image_u32(p+4,big):1, stride=wide?32:20;
    if (!count || count>8 || (fat && 8+(uint64_t)count*stride>data.length)) return nil;
    NSMutableArray *rows=[NSMutableArray array];
    for (uint32_t i=0;i<count;i++) {
        const uint8_t *entry=fat?p+8+i*stride:p;
        uint64_t offset=fat?(wide?sliccy_image_u64(entry+8,big):sliccy_image_u32(entry+8,big)):0;
        uint64_t size=fat?(wide?sliccy_image_u64(entry+16,big):sliccy_image_u32(entry+12,big)):data.length;
        uint32_t alignment=fat?sliccy_image_u32(entry+(wide?24:16),big):0;
        if (alignment>30 || offset%((uint64_t)1<<alignment) || size<28 || offset>data.length || size>data.length-offset ||
            (fat && offset<8+(uint64_t)count*stride) || (fat && wide && sliccy_image_u32(entry+28,big))) return nil;
        uint32_t thin=sliccy_image_u32(p+offset,YES);
        BOOL thinBig=thin==0xfeedface || thin==0xfeedfacf, thin64=thin==0xfeedfacf || thin==0xcffaedfe;
        if (!thinBig && thin!=0xcefaedfe && thin!=0xcffaedfe) return nil;
        if (thin64 && size<32) return nil;
        int32_t cpu=(int32_t)sliccy_image_u32(p+offset+4,thinBig), subtype=(int32_t)sliccy_image_u32(p+offset+8,thinBig);
        if (fat && (cpu!=(int32_t)sliccy_image_u32(entry,big) || subtype!=(int32_t)sliccy_image_u32(entry+4,big))) return nil;
        for (NSDictionary *old in rows) {
            uint64_t start=[old[@"offset"] unsignedLongLongValue], length=[old[@"size"] unsignedLongLongValue];
            if ((offset<start+length && start<offset+size) || ([old[@"cpuType"] intValue]==cpu && [old[@"cpuSubtype"] intValue]==subtype)) return nil;
        }
        [rows addObject:@{@"cpuType":@(cpu),@"cpuSubtype":@(subtype),@"offset":@(offset),@"size":@(size)}];
    }
    return rows;
}
static NSDictionary *sliccy_image_hashes(id full, id selected, id unique, NSData *kernel) {
    NSMutableArray *rows=[NSMutableArray array], *uniqueTypes=[NSMutableArray array], *kernelTypes=[NSMutableArray array];
    BOOL valid=[full isKindOfClass:NSDictionary.class] && [full count]>0 && [full count]<=8;
    if (valid) for (id key in full) {
        id value=full[key];
        if (!sliccy_image_integer(key) || [key intValue]<1 || [key intValue]>255 ||
            ![value isKindOfClass:NSData.class] || [value length]<20 || [value length]>64) { valid=NO;break; }
    }
    if (valid) for (NSNumber *key in [[full allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        NSData *value=full[key], *prefix=[value subdataWithRange:NSMakeRange(0,20)];
        BOOL u=[unique isKindOfClass:NSData.class] && [prefix isEqual:unique], k=[prefix isEqual:kernel];
        [rows addObject:@{@"hashType":key,@"fullHash":[value base64EncodedStringWithOptions:0],@"length":@(value.length),
            @"cdhash20":[prefix base64EncodedStringWithOptions:0],@"matchesUnique":u?@YES:@NO,@"matchesKernel":k?@YES:@NO}];
        if(u)[uniqueTypes addObject:key];if(k)[kernelTypes addObject:key];
    }
    return @{@"status":valid?@"observed":@"unavailable",@"selectedHashType":sliccy_image_integer(selected)?selected:(id)NSNull.null,
        @"uniqueHash":[unique isKindOfClass:NSData.class] && [unique length]<=64?[unique base64EncodedStringWithOptions:0]:(id)NSNull.null,
        @"hashes":rows,@"uniqueHashTypes":uniqueTypes,@"kernelHashTypes":kernelTypes,@"affectsVerdict":@NO};
}
static NSDictionary *sliccy_image_arch(int count,int error,int expected,int32_t cpu,int32_t subtype) {
    BOOL ok=count==expected;
    return @{@"count":@(count),@"errno":@(error),@"expectedSize":@(expected),@"status":ok?@"observed":@"unavailable",
        @"cpuType":ok?@(cpu):(id)NSNull.null,@"cpuSubtype":ok?@(subtype):(id)NSNull.null,@"affectsVerdict":@NO};
}
static NSDictionary *sliccy_image_relation(BOOL available,uint64_t device,uint64_t inode,BOOL pathAvailable,uint64_t pathDevice,uint64_t pathInode) {
    BOOL compared=available && pathAvailable;
    return @{@"status":compared?@"compared":@"unavailable",@"device":available?@(device):(id)NSNull.null,
        @"inode":available?@(inode):(id)NSNull.null,@"staticDevice":pathAvailable?@(pathDevice):(id)NSNull.null,
        @"staticInode":pathAvailable?@(pathInode):(id)NSNull.null,
        @"same":compared?((device==pathDevice && inode==pathInode)?@YES:@NO):(id)NSNull.null,@"affectsVerdict":@NO};
}
