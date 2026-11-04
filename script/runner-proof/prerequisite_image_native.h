#include <sys/mount.h>
#include "prerequisite_image_record.h"

static NSDictionary *imageArchitecture(pid_t pid,NSString *bracket) {
    struct proc_archinfo info={0};
    emit(@"image-architecture",@"entered",@{@"pid":@(pid),@"bracket":bracket,@"flavor":@(PROC_PIDARCHINFO)});
    errno=0;int count=proc_pidinfo(pid,PROC_PIDARCHINFO,0,&info,sizeof(info)),error=errno;
    NSDictionary *record=sliccy_image_arch(count,error,sizeof(info),info.p_cputype,info.p_cpusubtype);
    emit(@"image-architecture",@"completed",record);return record;
}
static void imageHashInfo(NSDictionary *info,NSString *origin,NSDictionary *slice,NSData *kernel) {
    NSDictionary *hashes=sliccy_image_hashes(info[@"cdhashes-full"],info[(__bridge NSString *)kSecCodeInfoDigestAlgorithm],
        info[(__bridge NSString *)kSecCodeInfoUnique],kernel);
    emit(@"image-hash-set",@"completed",@{@"origin":origin,@"slice":slice?: (id)NSNull.null,@"value":hashes,
        @"codeOffset":sliccy_binding_value(info[@"CodeOffset"]),@"affectsVerdict":@NO});
}
static void imageSlices(NSString *path,SecRequirementRef requirement,NSData *kernel) {
    emit(@"image-file-read",@"entered",@{@"path":path,@"maximumBytes":@(128*1024*1024)});
    errno=0;int fd=open(path.fileSystemRepresentation,O_RDONLY|O_CLOEXEC),openError=errno;
    struct stat before={0},after={0};int beforeStatus=-1,afterStatus=-1,readError=0;ssize_t count=-1;NSMutableData *bytes=nil;
    if(fd>=0) {
        beforeStatus=fstat(fd,&before);
        if(!beforeStatus && S_ISREG(before.st_mode) && before.st_size>=28 && before.st_size<=128*1024*1024) {
            bytes=[NSMutableData dataWithLength:(NSUInteger)before.st_size];errno=0;
            count=pread(fd,bytes.mutableBytes,bytes.length,0);readError=errno;
        }
        afterStatus=fstat(fd,&after);close(fd);
    }
    BOOL stable=bytes && count==(ssize_t)bytes.length && !afterStatus && before.st_dev==after.st_dev && before.st_ino==after.st_ino &&
        before.st_size==after.st_size && before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec &&
        before.st_ctimespec.tv_sec==after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec==after.st_ctimespec.tv_nsec;
    NSArray *slices=stable?sliccy_image_slices(bytes):nil;
    emit(@"image-file-read",@"completed",@{@"openStatus":fd<0?@(-1):@0,@"openErrno":@(openError),@"beforeStatStatus":@(beforeStatus),
        @"afterStatStatus":@(afterStatus),@"readCount":@(count),@"readErrno":@(readError),@"stableFileSample":stable?@YES:@NO,
        @"device":beforeStatus?(id)NSNull.null:@(before.st_dev),@"inode":beforeStatus?(id)NSNull.null:@(before.st_ino),
        @"status":slices?@"observed":@"unavailable",@"slices":slices?:@[],@"affectsVerdict":@NO});
    for(NSDictionary *slice in slices) {
        SecStaticCodeRef code=NULL;CFDictionaryRef info=NULL;
        NSDictionary *attributes=@{(__bridge NSString *)kSecCodeAttributeArchitecture:slice[@"cpuType"],
            (__bridge NSString *)kSecCodeAttributeSubarchitecture:slice[@"cpuSubtype"]};
        emit(@"image-slice-create",@"entered",@{@"slice":slice,@"path":path,@"attributes":@[@"architecture",@"subarchitecture"]});
        OSStatus status=SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:path],0,(__bridge CFDictionaryRef)attributes,&code);
        emit(@"image-slice-create",@"completed",@{@"status":@(status),@"available":code?@YES:@NO});
        if(status==errSecSuccess && code) {
            emit(@"image-slice-validity",@"entered",@{@"slice":slice,@"flags":@16,@"affectsVerdict":@NO});
            status=SecStaticCodeCheckValidity(code,kSecCSStrictValidate,requirement);
            emit(@"image-slice-validity",@"completed",@{@"status":@(status),@"affectsVerdict":@NO});
            emit(@"image-slice-info",@"entered",@{@"slice":slice,@"flags":@(kSecCSSigningInformation|kSecCSInternalInformation)});
            status=SecCodeCopySigningInformation(code,kSecCSSigningInformation|kSecCSInternalInformation,&info);
            emit(@"image-slice-info",@"completed",@{@"status":@(status),@"available":info?@YES:@NO});
            if(status==errSecSuccess && info)imageHashInfo((__bridge NSDictionary *)info,@"pathname-slice",slice,kernel);
        }
        if(info)CFRelease(info);if(code)CFRelease(code);
    }
}
static void imageMounts(NSString *path) {
    NSArray *parts=path.pathComponents;NSString *prefix=@"/";
    NSUInteger maximum=MIN(parts.count,(NSUInteger)16);
    for(NSUInteger i=0;i<maximum;i++) {
        if(i)prefix=[prefix stringByAppendingPathComponent:parts[i]];
        struct stat metadata={0};struct statfs mount={0};char link[4096]={0};
        emit(@"image-mount-component",@"entered",@{@"path":prefix});
        errno=0;int status=lstat(prefix.fileSystemRepresentation,&metadata),error=errno;
        errno=0;int mountStatus=statfs(prefix.fileSystemRepresentation,&mount),mountError=errno;
        ssize_t linkCount=-1;int linkError=0;
        if(!status && S_ISLNK(metadata.st_mode)) {errno=0;linkCount=readlink(prefix.fileSystemRepresentation,link,sizeof(link)-1);linkError=errno;}
        NSString *target=linkCount>=0?[[NSString alloc]initWithBytes:link length:(NSUInteger)linkCount encoding:NSUTF8StringEncoding]:nil;
        emit(@"image-mount-component",@"completed",@{@"path":prefix,@"lstatStatus":@(status),@"lstatErrno":@(error),
            @"device":status?(id)NSNull.null:@(metadata.st_dev),@"inode":status?(id)NSNull.null:@(metadata.st_ino),
            @"fileFlags":status?(id)NSNull.null:@(metadata.st_flags),@"firmlinkMarker":status?(id)NSNull.null:((metadata.st_flags&SF_FIRMLINK)?@YES:@NO),
            @"symlink":status?(id)NSNull.null:(S_ISLNK(metadata.st_mode)?@YES:@NO),@"linkCount":@(linkCount),@"linkErrno":@(linkError),@"linkTarget":target?: (id)NSNull.null,
            @"statfsStatus":@(mountStatus),@"statfsErrno":@(mountError),@"mountFlags":mountStatus?(id)NSNull.null:@(mount.f_flags),
            @"mountPoint":mountStatus?(id)NSNull.null:([NSString stringWithUTF8String:mount.f_mntonname]?: (id)NSNull.null),
            @"mountSource":mountStatus?(id)NSNull.null:([NSString stringWithUTF8String:mount.f_mntfromname]?: (id)NSNull.null),
            @"filesystem":mountStatus?(id)NSNull.null:([NSString stringWithUTF8String:mount.f_fstypename]?: (id)NSNull.null),
            @"cryptexMountProven":NSNull.null,@"affectsVerdict":@NO});
    }
    emit(@"image-mount-summary",@"completed",@{@"path":path,@"components":@(parts.count),@"observed":@(maximum),
        @"complete":parts.count<=16?@YES:@NO,@"firmlinkTraversalProven":NSNull.null,@"cryptexTraversalProven":NSNull.null,@"affectsVerdict":@NO});
}
static void imageRegions(pid_t pid,NSString *path) {
    struct stat file={0};emit(@"image-region-static-stat",@"entered",@{@"path":path});errno=0;int fileStatus=stat(path.fileSystemRepresentation,&file),fileError=errno;
    emit(@"image-region-static-stat",@"completed",@{@"status":@(fileStatus),@"errno":@(fileError),@"device":fileStatus?(id)NSNull.null:@(file.st_dev),@"inode":fileStatus?(id)NSNull.null:@(file.st_ino)});
    uint64_t address=0;NSUInteger observed=0;NSString *end=@"bound";
    for(NSUInteger i=0;i<8;i++) {
        struct proc_regionwithpathinfo region={0};
        emit(@"image-region",@"entered",@{@"pid":@(pid),@"flavor":@22,@"address":@(address),@"expectedSize":@(sizeof(region))});
        errno=0;int count=proc_pidinfo(pid,22,address,&region,sizeof(region)),error=errno;
        BOOL available=count==(int)sizeof(region);struct proc_regioninfo *r=&region.prp_prinfo;struct vinfo_stat *v=&region.prp_vip.vip_vi.vi_stat;
        NSString *regionPath=available?[[NSString alloc]initWithBytes:region.prp_vip.vip_path length:strnlen(region.prp_vip.vip_path,sizeof(region.prp_vip.vip_path)) encoding:NSUTF8StringEncoding]:nil;
        BOOL vnode=available && v->vst_ino!=0 && regionPath.length;
        emit(@"image-region",@"completed",@{@"status":available?@"observed":@"unavailable",@"count":@(count),@"errno":@(error),@"expectedSize":@(sizeof(region)),
            @"address":available?@(r->pri_address):(id)NSNull.null,@"size":available?@(r->pri_size):(id)NSNull.null,@"fileOffset":available?@(r->pri_offset):(id)NSNull.null,
            @"protection":available?@(r->pri_protection):(id)NSNull.null,@"path":regionPath?: (id)NSNull.null,
            @"sameExecutablePath":regionPath?[regionPath isEqual:path]?@YES:@NO:(id)NSNull.null,
            @"vnodeComparison":sliccy_image_relation(vnode,(uint32_t)v->vst_dev,v->vst_ino,!fileStatus,(uint32_t)file.st_dev,file.st_ino),
            @"executableTextIdentityProven":@NO,@"affectsVerdict":@NO});
        if(!available){end=@"unavailable";break;}observed++;
        if(!r->pri_size || r->pri_address<address || r->pri_address>UINT64_MAX-r->pri_size){end=@"invalid-range";break;}
        address=r->pri_address+r->pri_size;
    }
    emit(@"image-region-summary",@"completed",@{@"observed":@(observed),@"end":end,@"executableTextIdentityProven":@NO,@"affectsVerdict":@NO});
}
static void imageDiagnostics(pid_t pid,SecRequirementRef requirement,NSDictionary *live,NSDictionary *file,NSString *path,NSData *kernel) {
    imageArchitecture(pid,@"before");
    emit(@"image-live-path",@"entered",@{@"pid":@(pid)});char name[PROC_PIDPATHINFO_MAXSIZE]={0};errno=0;int count=proc_pidpath(pid,name,sizeof(name)),error=errno;
    NSString *livePath=count>0?[NSString stringWithUTF8String:name]:nil;
    emit(@"image-live-path",@"completed",@{@"count":@(count),@"errno":@(error),@"path":livePath?: (id)NSNull.null,
        @"matchesInput":livePath?([livePath isEqual:path]?@YES:@NO):(id)NSNull.null,@"affectsVerdict":@NO});
    off_t offset=0;emit(@"image-kernel-offset",@"entered",@{@"pid":@(pid),@"operation":@6});errno=0;int status=csops(pid,6,&offset,sizeof(offset));error=errno;
    emit(@"image-kernel-offset",@"completed",@{@"status":@(status),@"errno":@(error),@"offset":status?(id)NSNull.null:@(offset),@"affectsVerdict":@NO});
    imageHashInfo(live,@"guest-derived-static",nil,kernel);imageHashInfo(file,@"pathname-default",nil,kernel);
    imageSlices(path,requirement,kernel);imageRegions(pid,path);imageMounts(path);
    if(livePath && ![livePath isEqual:path])imageMounts(livePath);
    imageArchitecture(pid,@"after");
}
