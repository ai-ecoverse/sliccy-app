#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <string.h>

static BOOL sliccy_slice_integer(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value)!=CFBooleanGetTypeID() &&
        strcmp([value objCType],@encode(float)) && strcmp([value objCType],@encode(double));
}

static NSDictionary *sliccy_slice_identity(id algorithm,id hash,id full) {
    if(!sliccy_slice_integer(algorithm) || [algorithm intValue]<1 || [algorithm intValue]>4 ||
        ![hash isKindOfClass:NSData.class] || [hash length]!=20 || ![full isKindOfClass:NSDictionary.class])return nil;
    id value=full[algorithm];
    if(![value isKindOfClass:NSData.class] || [value length]<20 || [value length]>64 ||
        ![[value subdataWithRange:NSMakeRange(0,20)] isEqual:hash])return nil;
    return @{@"hash":hash,@"hashType":algorithm};
}
static NSDictionary *sliccy_slice_selection(NSData *hash,id type,NSArray *candidates) {
    NSString *reason=@"unique-match";NSUInteger matches=0,selected=0;
    if(![hash isKindOfClass:NSData.class] || hash.length!=20)reason=@"live-hash";
    else if(!sliccy_slice_integer(type) || [type intValue]<1 || [type intValue]>4)reason=@"live-hash-type";
    else if(![candidates isKindOfClass:NSArray.class] || candidates.count<1 || candidates.count>8)reason=@"candidate-count";
    else for(NSUInteger i=0;i<candidates.count;i++) {
        id item=candidates[i];
        if(![item isKindOfClass:NSDictionary.class] || [item count]!=2 || ![item[@"hash"] isKindOfClass:NSData.class] || [item[@"hash"] length]!=20) {reason=@"candidate-hash";break;}
        id candidateType=item[@"hashType"];
        if(!sliccy_slice_integer(candidateType) || [candidateType intValue]<1 || [candidateType intValue]>4) {reason=@"candidate-hash-type";break;}
        if([candidateType isEqual:type] && [item[@"hash"] isEqual:hash]){matches++;selected=i;}
    }
    if([reason isEqual:@"unique-match"] && matches!=1)reason=matches?@"multiple-match":@"zero-match";
    BOOL accepted=[reason isEqual:@"unique-match"];
    return @{@"accepted":accepted?@YES:@NO,@"reason":reason,@"matchCount":@(matches),@"selectedIndex":accepted?@(selected):(id)NSNull.null};
}
static BOOL sliccy_slice_file_same(const struct stat *a,const struct stat *b) {
    return S_ISREG(a->st_mode) && S_ISREG(b->st_mode) && a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
