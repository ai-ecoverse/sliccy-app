#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "prerequisite_sysctl_record.h"

static void check(BOOL value,NSString *name) {if(!value){fprintf(stderr,"sysctl runtime assertion: %s\n",name.UTF8String);exit(1);}}
int main(void) {
    @autoreleasepool {
        struct kinfo_proc info={0};info.kp_proc.p_pid=42;info.kp_eproc.e_ppid=11;
        info.kp_eproc.e_ucred.cr_uid=501;info.kp_eproc.e_pcred.p_ruid=502;info.kp_eproc.e_pcred.p_svuid=503;
        info.kp_proc.p_starttime.tv_sec=123;info.kp_proc.p_starttime.tv_usec=456;
        struct proc_bsdinfo bsd={0};bsd.pbi_pid=42;bsd.pbi_ppid=11;bsd.pbi_uid=501;bsd.pbi_ruid=502;bsd.pbi_svuid=503;
        bsd.pbi_start_tvsec=123;bsd.pbi_start_tvusec=456;
        NSDictionary *expected=@{@"pid":@42,@"parent":@11,@"effectiveUID":@501,@"realUID":@502,@"savedUID":@503,@"startSeconds":@"123",@"startMicroseconds":@456};
        NSDictionary *before=sliccy_sysctl_record(42,0,0,sizeof(info),&info),*proc=sliccy_sysctl_proc_record(42,sizeof(bsd),0,&bsd);
        for(NSString *field in expected) {
            check([before[@"value"][field] isEqual:expected[field]],[@"sysctl-field-" stringByAppendingString:field]);
            check([proc[@"value"][field] isEqual:expected[field]],[@"proc-field-" stringByAppendingString:field]);
        }
        check([before[@"available"] isEqual:@YES] && [proc[@"available"] isEqual:@YES],@"available");
        NSMutableArray *unavailable=[NSMutableArray arrayWithArray:@[sliccy_sysctl_record(42,-1,EPERM,sizeof(info),&info),sliccy_sysctl_record(42,0,0,0,&info),
            sliccy_sysctl_record(42,0,0,sizeof(info)-1,&info),sliccy_sysctl_record(43,0,0,sizeof(info),&info)]];
        struct kinfo_proc invalid=info;invalid.kp_proc.p_starttime.tv_usec=1000000;
        [unavailable addObject:sliccy_sysctl_record(42,0,0,sizeof(invalid),&invalid)];
        invalid=info;invalid.kp_proc.p_starttime.tv_sec=0;[unavailable addObject:sliccy_sysctl_record(42,0,0,sizeof(invalid),&invalid)];
        for(NSDictionary *row in unavailable)check([row[@"available"] isEqual:@NO] && row[@"value"]==NSNull.null,@"unavailable");
        NSDictionary *original=@{@"pid":@42,@"bsdStatus":@0,@"pathStatus":@0,@"path":@"/fixed",@"bsd":@{@"pid":@42,@"parent":@11,@"uid":@501,@"seconds":@"123",@"microseconds":@456}};
        NSDictionary *summary=sliccy_sysctl_summary(@"observer-control",before,proc,before,original,0);
        check([summary[@"sysctlStable"] isEqual:@YES],@"stable");
        NSMutableArray *mutations=[NSMutableArray array];
        for(NSString *field in expected) {
            NSMutableDictionary *changed=[expected mutableCopy];changed[field]=[field isEqual:@"startSeconds"]?@"124":@([changed[field] unsignedLongLongValue]+1);
            NSMutableDictionary *record=[proc mutableCopy];record[@"value"]=changed;
            NSDictionary *comparison=sliccy_sysctl_summary(@"observer-control",before,record,before,original,0);
            for(NSString *other in expected)check([comparison[@"beforeVsProc"][other] isEqual:[field isEqual:other]?@NO:@YES],[@"compare-" stringByAppendingString:field]);
            [mutations addObject:@{@"field":field,@"summary":comparison}];
        }
        NSDictionary *root=sliccy_sysctl_summary(@"root-before",before,proc,before,original,11);
        check([root[@"semanticContext"][@"parentMatches"] isEqual:@YES] && [root[@"semanticContext"][@"effectiveUIDMatches"] isEqual:@NO],@"semantic-only");
        check([root[@"affectsVerdict"] isEqual:@NO] && [root[@"semanticContext"][@"crossRunIncarnationCompared"] isEqual:@NO],@"no-authority");
        NSDictionary *deniedOriginal=@{@"pid":@42,@"bsdStatus":@1,@"pathStatus":@0,@"path":@"/fixed",@"bsd":NSNull.null};
        NSDictionary *denied=sliccy_sysctl_summary(@"observer-control",before,sliccy_sysctl_proc_record(42,0,EPERM,&bsd),before,deniedOriginal,0);
        check(denied[@"beforeVsProc"][@"pid"]==NSNull.null && denied[@"beforeVsOriginalBSD"][@"effectiveUID"]==NSNull.null,@"no-inferred-agreement");
        NSData *encoded=[NSJSONSerialization dataWithJSONObject:@{@"before":before,@"proc":proc,@"unavailable":unavailable,@"summary":summary,@"mutations":mutations,@"root":root,@"denied":denied} options:NSJSONWritingSortedKeys error:NULL];
        check(encoded!=nil,@"encoder");fwrite(encoded.bytes,1,encoded.length,stdout);fputc('\n',stdout);
    }return 0;
}
