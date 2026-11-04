import re
from prerequisite_image import require,integer

CONTEXTS={'observer-control','wrapper-control','windowserver-before','windowserver-after','root-before','root-after','windowserver-final'}
FIELDS={'pid','parent','effectiveUID','realUID','savedUID','startSeconds','startMicroseconds'}
PAIRED={'diagnostic-sysctl','diagnostic-sysctl-proc'}
SINGLES={'diagnostic-sysctl-comparison'}


def value(row,pid):
    require(type(row) is dict and set(row)==FIELDS,'sysctl-value-shape')
    require(integer(row['pid']) and row['pid']==pid and 0<pid<=2147483647,'sysctl-pid')
    require(integer(row['parent']) and 0<=row['parent']<=2147483647,'sysctl-parent')
    for key in ('effectiveUID','realUID','savedUID'):
        require(integer(row[key]) and 0<=row[key]<=4294967295,'sysctl-'+key)
    require(type(row['startSeconds']) is str and re.fullmatch('[1-9][0-9]{0,19}',row['startSeconds']) and int(row['startSeconds'])<=18446744073709551615,'sysctl-seconds')
    require(integer(row['startMicroseconds']) and 0<=row['startMicroseconds']<1000000,'sysctl-microseconds')


def result(row,proc=False):
    keys={'requestedPID','errno','expectedBytes','available','value','affectsVerdict'}|({'count'} if proc else {'status','returnedBytes'})
    require(type(row) is dict and set(row)==keys,'sysctl-result-shape')
    require(row['affectsVerdict'] is False and type(row['available']) is bool,'sysctl-no-authority')
    require(integer(row['requestedPID']) and 0<row['requestedPID']<=2147483647 and integer(row['errno']) and 0<=row['errno']<=4096,'sysctl-result-pid-error')
    require(integer(row['expectedBytes']) and 0<row['expectedBytes']<=4096,'sysctl-layout-size')
    if proc:
        require(integer(row['count']) and -1<=row['count']<=4096,'sysctl-proc-count')
        complete=row['count']==row['expectedBytes']
    else:
        require(integer(row['status']) and row['status'] in (-1,0) and integer(row['returnedBytes']) and 0<=row['returnedBytes']<=4096,'sysctl-status-size')
        complete=row['status']==0 and row['returnedBytes']==row['expectedBytes']
    if row['available']:
        require(complete and row['errno']==0,'sysctl-available-status')
        value(row['value'],row['requestedPID'])
    else:require(row['value'] is None,'sysctl-unavailable-value')


def comparisons(a,b):
    return {key:a[key]==b[key] if a is not None and b is not None else None for key in FIELDS}


class Records:
    def __init__(self):
        self.records={}
        self.pending=None

    def accept(self,phase,state,row):
        require(type(row) is dict and row.get('context') in CONTEXTS,'sysctl-context')
        context=row['context']
        if phase in PAIRED and state=='entered':
            expected={'pid','context','position','mib','newValue','newLength'} if phase=='diagnostic-sysctl' else {'pid','context','flavor'}
            require(set(row)==expected and integer(row['pid']) and 0<row['pid']<=2147483647,'sysctl-entered-shape')
            if phase=='diagnostic-sysctl':
                require(row['position'] in ('before','after') and row['mib']==[1,14,1,row['pid']] and all(integer(x) for x in row['mib']) and row['newValue'] is None and type(row['newLength']) is int and row['newLength']==0,'sysctl-read-only-mib')
            else:require(type(row['flavor']) is int and row['flavor']==3,'sysctl-proc-flavor')
            require(self.pending is None,'sysctl-overlapping-query')
            self.pending=(phase,context,row.get('position','proc'),row['pid'])
            return
        if phase in PAIRED:
            require(state=='completed' and set(row)==({'context','position','result'} if phase=='diagnostic-sysctl' else {'context','result'}),'sysctl-completed-shape')
            position=row.get('position','proc');require(position in ('before','after','proc'),'sysctl-position')
            require((phase=='diagnostic-sysctl-proc')==(position=='proc'),'sysctl-position-phase')
            result(row['result'],position=='proc')
            require(self.pending==(phase,context,position,row['result']['requestedPID']),'sysctl-query-binding')
            self.pending=None
            previous=self.records.setdefault(context,{})
            require(position not in previous and set(previous)==({'before','proc'} if position=='after' else {'before'} if position=='proc' else set()),'sysctl-bracket-order')
            previous[position]=row['result'];return
        require(phase=='diagnostic-sysctl-comparison' and state=='completed','sysctl-comparison-phase')
        require(set(row)=={'context','pid','beforeVsProc','afterVsProc','sysctlStable','originalBSD','beforeVsOriginalBSD','semanticContext','affectsVerdict'} and row['affectsVerdict'] is False,'sysctl-comparison-shape')
        samples=self.records.get(context,{});require(set(samples)=={'before','proc','after'},'sysctl-comparison-bracket')
        pid=samples['before']['requestedPID'];require(type(row['pid']) is int and row['pid']==pid and all(item['requestedPID']==pid for item in samples.values()),'sysctl-bracket-pid')
        a,b,c=(samples[key]['value'] for key in ('before','proc','after'))
        expected={'beforeVsProc':comparisons(a,b),'afterVsProc':comparisons(c,b)}
        original=row['originalBSD'];require(type(original) is dict and set(original)=={'pid','bsdStatus','pathStatus','bsd','path'} and type(original['pid']) is int and original['pid']==pid,'sysctl-original-shape')
        require(integer(original['bsdStatus']) and integer(original['pathStatus']),'sysctl-original-status')
        mapped=None
        if original['bsdStatus']==0:
            o=original['bsd'];require(type(o) is dict and set(o)=={'pid','parent','uid','seconds','microseconds'},'sysctl-original-bsd')
            mapped={'pid':o['pid'],'parent':o['parent'],'effectiveUID':o['uid'],'realUID':0,'savedUID':0,'startSeconds':o['seconds'],'startMicroseconds':o['microseconds']};value(mapped,pid)
        else:require(original['bsd'] is None,'sysctl-original-unavailable')
        expected['beforeVsOriginalBSD']=comparisons(a,mapped);expected['beforeVsOriginalBSD'].update(realUID=None,savedUID=None)
        for key,item in expected.items():
            require(type(row[key]) is dict and set(row[key])==FIELDS and all(v is None or type(v) is bool for v in row[key].values()) and row[key]==item,'sysctl-comparison-'+key)
        stable=(a==c) if a is not None and c is not None else None
        require((row['sysctlStable'] is None or type(row['sysctlStable']) is bool) and row['sysctlStable']==stable,'sysctl-stability')
        semantic=row['semanticContext'];require(type(semantic) is dict and set(semantic)=={'expectedParent','expectedEffectiveUID','parentMatches','effectiveUIDMatches','crossRunIncarnationCompared'} and semantic['crossRunIncarnationCompared'] is False,'sysctl-semantic-shape')
        if context.startswith('windowserver-'):require(type(semantic['expectedParent']) is int and semantic['expectedParent']==1 and type(semantic['expectedEffectiveUID']) is int and semantic['expectedEffectiveUID']==88,'sysctl-windowserver-context')
        elif context.startswith('root-'):require(integer(semantic['expectedParent']) and 0<semantic['expectedParent']<=2147483647 and type(semantic['expectedEffectiveUID']) is int and semantic['expectedEffectiveUID']==0,'sysctl-root-context')
        else:require(semantic['expectedParent'] is None and semantic['expectedEffectiveUID'] is None,'sysctl-control-context')
        for key,field,expect in [('parentMatches','parent','expectedParent'),('effectiveUIDMatches','effectiveUID','expectedEffectiveUID')]:
            match=a[field]==semantic[expect] if a is not None and semantic[expect] is not None else None
            require((semantic[key] is None or type(semantic[key]) is bool) and semantic[key]==match,'sysctl-semantic-'+key)
        samples['complete']=True
