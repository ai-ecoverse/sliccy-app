#include "prerequisite_slice_binding.h"

static NSDictionary *sliceIdentityInfo(NSDictionary *info) {
    return sliccy_slice_identity(info[(__bridge NSString *)kSecCodeInfoDigestAlgorithm],info[(__bridge NSString *)kSecCodeInfoUnique],info[@"cdhashes-full"]);
}
static NSDictionary *sliceFileRecord(const struct stat *v) {
    return @{@"device":@(v->st_dev),@"inode":@(v->st_ino),@"size":@(v->st_size),@"mode":@(v->st_mode),
        @"mtimeSeconds":@(v->st_mtimespec.tv_sec),@"mtimeNanos":@(v->st_mtimespec.tv_nsec),
        @"ctimeSeconds":@(v->st_ctimespec.tv_sec),@"ctimeNanos":@(v->st_ctimespec.tv_nsec)};
}
static BOOL bindUniqueSlice(pid_t pid,SecCodeRef guest,SecRequirementRef requirement,NSDictionary *liveInfo,
                            NSString *path,NSString *identifier,NSData *kernelHash) {
    int fd=-1;SecStaticCodeRef references[8]={0};NSUInteger referenceCount=0;
    CFDictionaryRef raw=NULL;SecRequirementRef apple=NULL;SecStaticCodeRef fresh=NULL;
    @try {
        NSDictionary *live=sliceIdentityInfo(liveInfo);
        require(live && [live[@"hash"] isEqual:kernelHash],@"slice-live-kernel-type");
        emit(@"slice-live-identity",@"completed",@{@"identifier":identifier,@"hash":[live[@"hash"] base64EncodedStringWithOptions:0],@"hashType":live[@"hashType"],@"kernelHash":[kernelHash base64EncodedStringWithOptions:0]});
        BOOL system=[identifier isEqual:@"com.apple.WindowServer"];
        require(system || [identifier isEqual:@"ai.sliccy.mac"],@"slice-role");
        if(system) {
            emit(@"slice-apple-requirement",@"entered",@{@"rule":@"anchor apple"});
            OSStatus status=SecRequirementCreateWithString(CFSTR("anchor apple"),0,&apple);
            completed(@"slice-apple-requirement",status);require(apple!=NULL,@"slice-apple-null");
            emit(@"slice-apple-validity",@"entered",@{@"flags":@16});
            completed(@"slice-apple-validity",SecCodeCheckValidity(guest,kSecCSStrictValidate,apple));
            uint32_t flags=0;emit(@"slice-platform",@"entered",@{@"pid":@(pid),@"operation":@0});errno=0;
            int statusFlags=csops(pid,0,&flags,sizeof(flags)),error=errno;
            emit(@"slice-platform",@"completed",@{@"status":@(statusFlags),@"errno":@(error),@"flags":@(flags),@"platformBinary":(flags&0x04000000)?@YES:@NO});
            require(statusFlags==0 && (flags&0x04000000),@"slice-platform-required");
        }
        emit(@"slice-path-resolve",@"entered",@{@"path":path});char resolved[PATH_MAX]={0};errno=0;
        char *resolvedResult=realpath(path.fileSystemRepresentation,resolved);int resolveError=errno;
        NSString *canonical=resolvedResult?[NSString stringWithUTF8String:resolved]:nil;
        emit(@"slice-path-resolve",@"completed",@{@"status":resolvedResult?@0:@(-1),@"errno":@(resolveError),@"resolved":canonical?: (id)NSNull.null,@"matchesInput":[canonical isEqual:path]?@YES:@NO});
        require([canonical isEqual:path],@"slice-path-canonical");
        emit(@"slice-file-open",@"entered",@{@"path":path,@"maximumBytes":@(128*1024*1024)});errno=0;
        fd=open(path.fileSystemRepresentation,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);int openError=errno;
        emit(@"slice-file-open",@"completed",@{@"status":fd<0?@(-1):@0,@"errno":@(openError)});require(fd>=0,@"slice-open");
        struct stat first={0},afterRead={0},pathBefore={0},last={0},pathAfter={0};
        emit(@"slice-file-before",@"entered",@{});errno=0;int fstatus=fstat(fd,&first),ferror=errno;errno=0;int pstatus=stat(path.fileSystemRepresentation,&pathBefore),perror=errno;
        BOOL before=fstatus==0 && pstatus==0 && sliccy_slice_file_same(&first,&pathBefore);
        emit(@"slice-file-before",@"completed",@{@"fdStatus":@(fstatus),@"fdErrno":@(ferror),@"pathStatus":@(pstatus),@"pathErrno":@(perror),@"fd":sliceFileRecord(&first),@"path":sliceFileRecord(&pathBefore),@"same":before?@YES:@NO});
        require(before && first.st_size>=28 && first.st_size<=128*1024*1024,@"slice-file-before");
        NSMutableData *bytes=[NSMutableData dataWithLength:(NSUInteger)first.st_size];
        emit(@"slice-file-read",@"entered",@{@"size":@(bytes.length)});errno=0;ssize_t readCount=pread(fd,bytes.mutableBytes,bytes.length,0);int readError=errno;
        emit(@"slice-file-read",@"completed",@{@"count":@(readCount),@"errno":@(readError)});require(readCount==(ssize_t)bytes.length,@"slice-read");
        emit(@"slice-file-after-read",@"entered",@{});errno=0;fstatus=fstat(fd,&afterRead);ferror=errno;BOOL readSame=fstatus==0 && sliccy_slice_file_same(&first,&afterRead);
        emit(@"slice-file-after-read",@"completed",@{@"status":@(fstatus),@"errno":@(ferror),@"value":sliceFileRecord(&afterRead),@"same":readSame?@YES:@NO});require(readSame,@"slice-read-change");
        NSArray *slices=sliccy_image_slices(bytes);require(slices!=nil,@"slice-layout");
        emit(@"slice-layout",@"completed",@{@"slices":slices});NSMutableArray *identities=[NSMutableArray array];
        for(NSDictionary *slice in slices) {
            NSDictionary *attributes=@{(__bridge NSString *)kSecCodeAttributeArchitecture:slice[@"cpuType"],(__bridge NSString *)kSecCodeAttributeSubarchitecture:slice[@"cpuSubtype"]};
            SecStaticCodeRef object=NULL;
            emit(@"slice-create",@"entered",@{@"slice":slice,@"attributes":@[@"architecture",@"subarchitecture"]});
            OSStatus status=SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:path],0,(__bridge CFDictionaryRef)attributes,&object);
            if(object)references[referenceCount++]=object;
            completed(@"slice-create",status);require(object!=NULL,@"slice-create-null");
            emit(@"slice-info",@"entered",@{@"slice":slice,@"flags":@(kSecCSSigningInformation|kSecCSInternalInformation)});
            status=SecCodeCopySigningInformation(object,kSecCSSigningInformation|kSecCSInternalInformation,&raw);completed(@"slice-info",status);require(raw!=NULL,@"slice-info-null");
            NSDictionary *info=(__bridge NSDictionary *)raw,*identity=sliceIdentityInfo(info);id image=info[(__bridge NSString *)kSecCodeInfoMainExecutable];
            require(identity && [info[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:identifier] && [image isKindOfClass:NSURL.class] && [[image path] isEqual:path],@"slice-info-binding");
            id codeOffset=info[@"CodeOffset"];
            require(sliccy_image_integer(codeOffset) && [codeOffset isEqual:slice[@"offset"]],@"slice-offset-binding");
            [identities addObject:identity];
            emit(@"slice-candidate",@"completed",@{@"slice":slice,@"hash":[identity[@"hash"] base64EncodedStringWithOptions:0],@"hashType":identity[@"hashType"],@"codeOffset":codeOffset});
            CFRelease(raw);raw=NULL;
        }
        NSDictionary *selection=sliccy_slice_selection(live[@"hash"],live[@"hashType"],identities);
        emit(@"slice-selection",@"completed",selection);require([selection[@"accepted"] isEqual:@YES],@"slice-unique-match");
        NSUInteger index=[selection[@"selectedIndex"] unsignedIntegerValue];require(index<referenceCount,@"slice-selected-index");
        emit(@"slice-selected-validity",@"entered",@{@"index":@(index),@"slice":slices[index],@"flags":@25});
        completed(@"slice-selected-validity",SecStaticCodeCheckValidity(references[index],kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode,requirement));
        emit(@"slice-selected-recheck",@"entered",@{@"index":@(index)});
        completed(@"slice-selected-recheck",SecCodeCopySigningInformation(references[index],kSecCSSigningInformation|kSecCSInternalInformation,&raw));require(raw!=NULL,@"slice-recheck-null");
        require([sliceIdentityInfo((__bridge NSDictionary *)raw) isEqual:live] && [((__bridge NSDictionary *)raw)[@"CodeOffset"] isEqual:slices[index][@"offset"]],@"slice-recheck-identity");CFRelease(raw);raw=NULL;
        emit(@"slice-file-after",@"entered",@{});errno=0;fstatus=fstat(fd,&last);ferror=errno;errno=0;pstatus=stat(path.fileSystemRepresentation,&pathAfter);perror=errno;
        BOOL finalSame=fstatus==0 && pstatus==0 && sliccy_slice_file_same(&first,&last) && sliccy_slice_file_same(&first,&pathAfter);
        emit(@"slice-file-after",@"completed",@{@"fdStatus":@(fstatus),@"fdErrno":@(ferror),@"pathStatus":@(pstatus),@"pathErrno":@(perror),@"fd":sliceFileRecord(&last),@"path":sliceFileRecord(&pathAfter),@"same":finalSame?@YES:@NO});require(finalSame,@"slice-path-changed");
        emit(@"slice-live-recheck",@"entered",@{@"flags":@16});completed(@"slice-live-recheck",SecCodeCheckValidity(guest,kSecCSStrictValidate,requirement));
        emit(@"slice-live-copy",@"entered",@{});completed(@"slice-live-copy",SecCodeCopyStaticCode(guest,0,&fresh));require(fresh!=NULL,@"slice-fresh-null");
        emit(@"slice-live-info",@"entered",@{});completed(@"slice-live-info",SecCodeCopySigningInformation(fresh,kSecCSSigningInformation,&raw));require(raw!=NULL,@"slice-fresh-info-null");
        NSDictionary *current=(__bridge NSDictionary *)raw;id image=current[(__bridge NSString *)kSecCodeInfoMainExecutable];
        require([sliceIdentityInfo(current) isEqual:live] && [current[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:identifier] && [image isKindOfClass:NSURL.class] && [[image path] isEqual:path],@"slice-live-changed");
        uint8_t hash[20]={0};char currentPath[PROC_PIDPATHINFO_MAXSIZE]={0};emit(@"slice-kernel-recheck",@"entered",@{@"pid":@(pid)});errno=0;int hashStatus=csops(pid,5,hash,sizeof(hash)),hashError=errno;errno=0;int pathCount=proc_pidpath(pid,currentPath,sizeof(currentPath)),pathError=errno;
        NSData *freshHash=[NSData dataWithBytes:hash length:20];NSString *freshPath=pathCount>0?[NSString stringWithUTF8String:currentPath]:nil;
        BOOL kernelSame=hashStatus==0 && [freshHash isEqual:kernelHash] && [freshPath isEqual:path];
        emit(@"slice-kernel-recheck",@"completed",@{@"hashStatus":@(hashStatus),@"hashErrno":@(hashError),@"hash":[freshHash base64EncodedStringWithOptions:0],@"pathCount":@(pathCount),@"pathErrno":@(pathError),@"path":freshPath?: (id)NSNull.null,@"same":kernelSame?@YES:@NO});require(kernelSame,@"slice-kernel-changed");
        return YES;
    } @finally {
        if(raw)CFRelease(raw);if(apple)CFRelease(apple);if(fresh)CFRelease(fresh);
        for(NSUInteger i=0;i<referenceCount;i++)CFRelease(references[i]);
        if(fd>=0)close(fd);
    }
}
