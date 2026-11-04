#import <Foundation/Foundation.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>

static NSDictionary *sliccy_sysctl_value(pid_t pid,pid_t parent,uid_t effective,uid_t real,uid_t saved,uint64_t seconds,uint64_t microseconds) {
    return @{@"pid":@(pid),@"parent":@(parent),@"effectiveUID":@(effective),@"realUID":@(real),@"savedUID":@(saved),
        @"startSeconds":[NSString stringWithFormat:@"%llu",(unsigned long long)seconds],@"startMicroseconds":@(microseconds)};
}
static NSDictionary *sliccy_sysctl_record(pid_t requested,int status,int error,size_t count,const struct kinfo_proc *info) {
    BOOL available=status==0 && count==sizeof(*info) && info && info->kp_proc.p_pid==requested && requested>0 &&
        info->kp_eproc.e_ppid>=0 && info->kp_proc.p_starttime.tv_sec>0 && info->kp_proc.p_starttime.tv_usec>=0 && info->kp_proc.p_starttime.tv_usec<1000000;
    id value=available?sliccy_sysctl_value(info->kp_proc.p_pid,info->kp_eproc.e_ppid,info->kp_eproc.e_ucred.cr_uid,
        info->kp_eproc.e_pcred.p_ruid,info->kp_eproc.e_pcred.p_svuid,(uint64_t)info->kp_proc.p_starttime.tv_sec,(uint64_t)info->kp_proc.p_starttime.tv_usec):(id)NSNull.null;
    return @{@"requestedPID":@(requested),@"status":@(status),@"errno":@(error),@"returnedBytes":@(count),@"expectedBytes":@(sizeof(*info)),
        @"available":available?@YES:@NO,@"value":value,@"affectsVerdict":@NO};
}
static NSDictionary *sliccy_sysctl_proc_record(pid_t requested,int count,int error,const struct proc_bsdinfo *info) {
    BOOL available=count==(int)sizeof(*info) && info && info->pbi_pid==(uint32_t)requested && requested>0 && info->pbi_ppid<=INT32_MAX &&
        info->pbi_start_tvsec>0 && info->pbi_start_tvusec<1000000;
    id value=available?sliccy_sysctl_value((pid_t)info->pbi_pid,(pid_t)info->pbi_ppid,info->pbi_uid,info->pbi_ruid,info->pbi_svuid,
        info->pbi_start_tvsec,info->pbi_start_tvusec):(id)NSNull.null;
    return @{@"requestedPID":@(requested),@"count":@(count),@"errno":@(error),@"expectedBytes":@(sizeof(*info)),
        @"available":available?@YES:@NO,@"value":value,@"affectsVerdict":@NO};
}
static NSDictionary *sliccy_sysctl_compare(id a,id b) {
    NSMutableDictionary *result=[NSMutableDictionary dictionary];
    for(NSString *field in @[@"pid",@"parent",@"effectiveUID",@"realUID",@"savedUID",@"startSeconds",@"startMicroseconds"])
        result[field]=[a isKindOfClass:NSDictionary.class] && [b isKindOfClass:NSDictionary.class]?([a[field] isEqual:b[field]]?@YES:@NO):(id)NSNull.null;
    return result;
}
static NSDictionary *sliccy_sysctl_summary(NSString *context,NSDictionary *before,NSDictionary *bsd,NSDictionary *after,NSDictionary *original,pid_t sudoPID) {
    id a=before[@"value"],b=bsd[@"value"],c=after[@"value"];
    BOOL readable=[a isKindOfClass:NSDictionary.class] && [c isKindOfClass:NSDictionary.class];
    id originalValue=NSNull.null;
    if([original[@"bsdStatus"] isEqual:@0] && [original[@"bsd"] isKindOfClass:NSDictionary.class]) {
        NSDictionary *o=original[@"bsd"];
        originalValue=@{@"pid":o[@"pid"],@"parent":o[@"parent"],@"effectiveUID":o[@"uid"],@"realUID":NSNull.null,@"savedUID":NSNull.null,
            @"startSeconds":o[@"seconds"],@"startMicroseconds":o[@"microseconds"]};
    }
    NSMutableDictionary *originalComparison=[sliccy_sysctl_compare(a,originalValue) mutableCopy];
    originalComparison[@"realUID"]=NSNull.null;originalComparison[@"savedUID"]=NSNull.null;
    BOOL window=[context hasPrefix:@"windowserver-"];
    BOOL root=[context hasPrefix:@"root-"];
    id expectedParent=window?@1:root?@(sudoPID):(id)NSNull.null;
    id expectedUID=window?@88:root?@0:(id)NSNull.null;
    id parentMatch=[a isKindOfClass:NSDictionary.class] && (window || root)?([a[@"parent"] isEqual:expectedParent]?@YES:@NO):(id)NSNull.null;
    id uidMatch=[a isKindOfClass:NSDictionary.class] && (window || root)?([a[@"effectiveUID"] isEqual:expectedUID]?@YES:@NO):(id)NSNull.null;
    return @{@"context":context,@"pid":before[@"requestedPID"],@"beforeVsProc":sliccy_sysctl_compare(a,b),@"afterVsProc":sliccy_sysctl_compare(c,b),
        @"sysctlStable":readable?([a isEqual:c]?@YES:@NO):(id)NSNull.null,@"originalBSD":original,@"beforeVsOriginalBSD":originalComparison,
        @"semanticContext":@{@"expectedParent":expectedParent,@"expectedEffectiveUID":expectedUID,@"parentMatches":parentMatch,@"effectiveUIDMatches":uidMatch,
            @"crossRunIncarnationCompared":@NO},@"affectsVerdict":@NO};
}
