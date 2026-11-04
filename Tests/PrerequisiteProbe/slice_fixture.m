#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "prerequisite_slice_binding.h"

static void check(BOOL value,NSString *name) {if(!value){fprintf(stderr,"slice runtime assertion: %s\n",name.UTF8String);exit(1);}}
int main(void) {
    @autoreleasepool {
        NSData *hash=[@"aaaaaaaaaaaaaaaaaaaa" dataUsingEncoding:NSUTF8StringEncoding],*other=[@"bbbbbbbbbbbbbbbbbbbb" dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *good=@{@"hash":hash,@"hashType":@2},*different=@{@"hash":other,@"hashType":@2},*wrongType=@{@"hash":hash,@"hashType":@1};
        NSArray *sets=@[@[different,good],@[different],@[good,good],@[wrongType]];
        NSArray *names=@[@"unique-match",@"zero-match",@"multiple-match",@"wrong-hash-type"];
        NSMutableArray *results=[NSMutableArray array];
        for(NSUInteger i=0;i<sets.count;i++) {
            NSDictionary *row=sliccy_slice_selection(hash,@2,sets[i]);
            check([row[@"accepted"] isEqual:i==0?@YES:@NO],names[i]);
            if(i==0)check([row[@"selectedIndex"] isEqual:@1],@"unique-index");
            [results addObject:row];
        }
        NSDictionary *identity=sliccy_slice_identity(@2,hash,@{@2:hash});check([identity isEqual:good],@"identity-type-hash");
        check(sliccy_slice_identity(@YES,hash,@{@1:hash})==nil,@"identity-numeric-type");
        check(sliccy_slice_identity(@2,hash,@{@2:other})==nil,@"identity-full-prefix");
        check(sliccy_slice_identity(@2,hash,@{@1:hash})==nil,@"identity-type-missing");
        NSArray *invalid=@[sliccy_slice_selection(hash,@YES,@[good]),sliccy_slice_selection(hash,@2,@[]),
            sliccy_slice_selection(hash,@2,@[@{@"hash":hash,@"hashType":@YES}])];
        for(NSDictionary *row in invalid)check([row[@"accepted"] isEqual:@NO],@"invalid-refusal");
        struct stat original={0};original.st_mode=S_IFREG|0755;original.st_dev=1;original.st_ino=2;original.st_size=32;
        original.st_mtimespec.tv_sec=3;original.st_mtimespec.tv_nsec=4;original.st_ctimespec.tv_sec=5;original.st_ctimespec.tv_nsec=6;
        check(sliccy_slice_file_same(&original,&original),@"stable-file");
        for(int field=0;field<8;field++) {
            struct stat changed=original;
            switch(field){case 0:changed.st_dev++;break;case 1:changed.st_ino++;break;case 2:changed.st_size++;break;case 3:changed.st_mode=S_IFDIR|0755;break;
                case 4:changed.st_mtimespec.tv_sec++;break;case 5:changed.st_mtimespec.tv_nsec++;break;case 6:changed.st_ctimespec.tv_sec++;break;case 7:changed.st_ctimespec.tv_nsec++;break;}
            check(!sliccy_slice_file_same(&original,&changed),@"changed-file");
        }
        NSData *output=[NSJSONSerialization dataWithJSONObject:@{@"results":results,@"invalid":invalid,@"fileMutations":@8} options:NSJSONWritingSortedKeys error:NULL];
        check(output!=nil,@"encoder");fwrite(output.bytes,1,output.length,stdout);fputc('\n',stdout);
    }return 0;
}
