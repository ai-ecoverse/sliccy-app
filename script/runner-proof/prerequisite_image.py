import base64
from prerequisite_binding import typed

PAIRED = {'image-architecture', 'image-live-path', 'image-kernel-offset', 'image-file-read', 'image-slice-create',
          'image-slice-validity', 'image-slice-info', 'image-region-static-stat', 'image-region', 'image-mount-component'}
SINGLES = {'image-hash-set', 'image-region-summary', 'image-mount-summary'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def integer(value):
    return type(value) is int


def data(value, minimum, maximum):
    require(type(value) is str, 'image-hash-type')
    decoded = base64.b64decode(value, validate=True)
    require(minimum <= len(decoded) <= maximum, 'image-hash-size')
    return decoded


def slice_row(row):
    require(type(row) is dict and set(row) == {'cpuType', 'cpuSubtype', 'offset', 'size'} and
            all(integer(v) for v in row.values()) and 0 <= row['offset'] < 128*1024*1024 and 28 <= row['size'] <= 128*1024*1024,
            'image-slice-shape')


def hashes(row):
    require(set(row) == {'status', 'selectedHashType', 'uniqueHash', 'hashes', 'uniqueHashTypes', 'kernelHashTypes', 'affectsVerdict'}
            and row['affectsVerdict'] is False and row['status'] in ('observed','unavailable'), 'image-hashes-shape')
    require(row['selectedHashType'] is None or integer(row['selectedHashType']), 'image-selected-type')
    unique = None if row['uniqueHash'] is None else data(row['uniqueHash'],0,64)
    require(type(row['hashes']) is list and len(row['hashes']) <= 8, 'image-hashes-bound')
    types=[]; unique_types=[]; kernel_types=[]
    for item in row['hashes']:
        require(set(item) == {'hashType','fullHash','length','cdhash20','matchesUnique','matchesKernel'}, 'image-hash-row')
        require(integer(item['hashType']) and 1 <= item['hashType'] <= 255 and integer(item['length']), 'image-hash-numbers')
        full=data(item['fullHash'],20,64); short=data(item['cdhash20'],20,20)
        require(len(full)==item['length'] and full[:20]==short, 'image-hash-prefix')
        require(type(item['matchesUnique']) is bool and type(item['matchesKernel']) is bool
                and item['matchesUnique']==(unique==short), 'image-hash-match')
        types.append(item['hashType'])
        if item['matchesUnique']:unique_types.append(item['hashType'])
        if item['matchesKernel']:kernel_types.append(item['hashType'])
    require(all(type(row[k]) is list and all(integer(v) for v in row[k]) for k in ('uniqueHashTypes','kernelHashTypes')), 'image-hash-index-types')
    require(types==sorted(set(types)) and row['uniqueHashTypes']==unique_types and row['kernelHashTypes']==kernel_types,'image-hash-index')
    require(bool(types) if row['status']=='observed' else not types,'image-hash-availability')


def relation(row):
    require(set(row)=={'status','device','inode','staticDevice','staticInode','same','affectsVerdict'}
            and row['affectsVerdict'] is False and row['status'] in ('compared','unavailable'),'image-vnode-shape')
    for k in ('device','inode','staticDevice','staticInode'):
        require(row[k] is None or integer(row[k]) and row[k]>=0,'image-vnode-value')
    if row['status']=='compared':
        require(all(integer(row[k]) for k in ('device','inode','staticDevice','staticInode')) and type(row['same']) is bool
                and row['same']==((row['device'],row['inode'])==(row['staticDevice'],row['staticInode'])),'image-vnode-comparison')
    else:require(row['same'] is None,'image-vnode-unavailable')


def record(phase,row):
    require(type(row) is dict,'image-record')
    if phase=='image-hash-set':
        require(set(row)=={'origin','slice','value','codeOffset','affectsVerdict'} and row['affectsVerdict'] is False
                and row['origin'] in ('guest-derived-static','pathname-default','pathname-slice'),'image-set-origin')
        if row['origin']=='pathname-slice':slice_row(row['slice'])
        else:require(row['slice'] is None,'image-set-slice')
        hashes(row['value']);typed(row['codeOffset'])
    elif phase=='image-architecture':
        require(set(row)=={'count','errno','expectedSize','status','cpuType','cpuSubtype','affectsVerdict'}
                and all(integer(row[k]) for k in ('count','errno','expectedSize')) and row['expectedSize']==8 and row['affectsVerdict'] is False,'image-arch-shape')
        ok=row['count']==8
        require(row['status']==('observed' if ok else 'unavailable') and
                (all(integer(row[k]) for k in ('cpuType','cpuSubtype')) if ok else row['cpuType'] is None and row['cpuSubtype'] is None),'image-arch-availability')
    elif phase=='image-kernel-offset':
        require(set(row)=={'status','errno','offset','affectsVerdict'} and integer(row['status']) and integer(row['errno'])
                and row['affectsVerdict'] is False and (integer(row['offset']) and row['offset']>=0 if row['status']==0 else row['offset'] is None),'image-offset')
    elif phase=='image-live-path':
        require(set(row)=={'count','errno','path','matchesInput','affectsVerdict'} and integer(row['count']) and integer(row['errno'])
                and row['affectsVerdict'] is False and (type(row['path']) is str and 0<len(row['path'])<4096 and type(row['matchesInput']) is bool
                    if row['count']>0 else row['path'] is None and row['matchesInput'] is None),'image-live-path')
    elif phase=='image-file-read':
        require(set(row)=={'openStatus','openErrno','beforeStatStatus','afterStatStatus','readCount','readErrno','stableFileSample','device','inode','status','slices','affectsVerdict'}
                and all(integer(row[k]) for k in ('openStatus','openErrno','beforeStatStatus','afterStatStatus','readCount','readErrno'))
                and row.get('affectsVerdict') is False and type(row.get('stableFileSample')) is bool and row.get('status') in ('observed','unavailable')
                and type(row.get('slices')) is list and len(row['slices'])<=8,'image-file-record')
        for item in row['slices']:slice_row(item)
        require(row['stableFileSample'] and bool(row['slices']) if row['status']=='observed' else not row['slices'],'image-file-available')
    elif phase=='image-region':
        require(set(row)=={'status','count','errno','expectedSize','address','size','fileOffset','protection','path','sameExecutablePath','vnodeComparison','executableTextIdentityProven','affectsVerdict'}
                and row.get('affectsVerdict') is False and row.get('executableTextIdentityProven') is False and integer(row.get('count'))
                and integer(row.get('expectedSize')) and integer(row.get('errno')) and row.get('status') in ('observed','unavailable'),'image-region-record')
        available=row['count']==row['expectedSize'];require((row['status']=='observed')==available,'image-region-available')
        for key in ('address','size','fileOffset','protection'):
            require(integer(row[key]) if available else row[key] is None,'image-region-field')
        require(row['sameExecutablePath'] is None or type(row['sameExecutablePath']) is bool,'image-region-path')
        relation(row['vnodeComparison'])
    elif phase=='image-region-summary':
        require(set(row)=={'observed','end','executableTextIdentityProven','affectsVerdict'} and integer(row['observed']) and 0<=row['observed']<=8
                and row['end'] in ('bound','unavailable','invalid-range') and row['executableTextIdentityProven'] is False and row['affectsVerdict'] is False,'image-region-summary')
    elif phase=='image-mount-component':
        require(set(row)=={'path','lstatStatus','lstatErrno','device','inode','fileFlags','firmlinkMarker','symlink','linkCount','linkErrno','linkTarget','statfsStatus','statfsErrno','mountFlags','mountPoint','mountSource','filesystem','cryptexMountProven','affectsVerdict'}
                and type(row['path']) is str and all(integer(row[k]) for k in ('lstatErrno','statfsErrno','linkCount','linkErrno'))
                and row.get('affectsVerdict') is False and row.get('cryptexMountProven') is None and integer(row.get('lstatStatus')) and integer(row.get('statfsStatus')),'image-mount-record')
        for key in ('firmlinkMarker','symlink'):
            require(type(row[key]) is bool if row['lstatStatus']==0 else row[key] is None,'image-mount-boolean')
    elif phase=='image-mount-summary':
        require(set(row)=={'path','components','observed','complete','firmlinkTraversalProven','cryptexTraversalProven','affectsVerdict'}
                and type(row['path']) is str and integer(row['components']) and integer(row['observed']) and row['observed']==min(row['components'],16)
                and type(row['complete']) is bool and row['complete']==(row['components']<=16) and row['firmlinkTraversalProven'] is None
                and row['cryptexTraversalProven'] is None and row['affectsVerdict'] is False,'image-mount-summary')
    elif phase in ('image-slice-create','image-slice-info'):
        require(set(row)=={'status','available'} and integer(row['status']) and type(row['available']) is bool,'image-slice-status')
    elif phase=='image-slice-validity':
        require(set(row)=={'status','affectsVerdict'} and integer(row['status']) and row['affectsVerdict'] is False,'image-slice-validity')
    elif phase=='image-region-static-stat':
        require(set(row)=={'status','errno','device','inode'} and integer(row['status']) and integer(row['errno']),'image-static-stat')
        for key in ('device','inode'):require(integer(row[key]) if row['status']==0 else row[key] is None,'image-static-stat-value')
