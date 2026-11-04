#include "prerequisite_sysctl_record.h"

static NSDictionary *sysctlIdentity(pid_t pid,NSString *context,NSString *position) {
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,pid};struct kinfo_proc value={0};size_t length=sizeof(value);
    emit(@"diagnostic-sysctl",@"entered",@{@"pid":@(pid),@"context":context,@"position":position,@"mib":@[@(CTL_KERN),@(KERN_PROC),@(KERN_PROC_PID),@(pid)],@"newValue":NSNull.null,@"newLength":@0});
    errno=0;int status=sysctl(mib,4,&value,&length,NULL,0),error=errno;
    NSDictionary *record=sliccy_sysctl_record(pid,status,error,length,&value);
    emit(@"diagnostic-sysctl",@"completed",@{@"context":context,@"position":position,@"result":record});return record;
}
static void sysctlDiagnostics(pid_t pid,NSString *context,NSDictionary *original,pid_t sudoPID) {
    NSDictionary *before=sysctlIdentity(pid,context,@"before");
    struct proc_bsdinfo value={0};
    emit(@"diagnostic-sysctl-proc",@"entered",@{@"pid":@(pid),@"context":context,@"flavor":@(PROC_PIDTBSDINFO)});
    errno=0;int count=proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&value,sizeof(value)),error=errno;
    NSDictionary *bsd=sliccy_sysctl_proc_record(pid,count,error,&value);
    emit(@"diagnostic-sysctl-proc",@"completed",@{@"context":context,@"result":bsd});
    NSDictionary *after=sysctlIdentity(pid,context,@"after");
    emit(@"diagnostic-sysctl-comparison",@"completed",sliccy_sysctl_summary(context,before,bsd,after,original,sudoPID));
}
