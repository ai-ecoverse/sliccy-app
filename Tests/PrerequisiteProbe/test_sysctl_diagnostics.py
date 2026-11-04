from pathlib import Path
from unittest import TestCase
import copy
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'script/runner-proof'))
import prerequisite_sysctl as diagnostic
import prerequisite_kernel as kernel


def values(pid=42):
    return dict(pid=pid,parent=11,effectiveUID=501,realUID=502,savedUID=503,startSeconds='123',startMicroseconds=456)


def sample(proc=False,available=True):
    row=dict(requestedPID=42,errno=0 if available else 1,expectedBytes=648 if not proc else 136,
             available=available,value=values() if available else None,affectsVerdict=False)
    row.update(count=136 if available else 0) if proc else row.update(status=0 if available else -1,returnedBytes=648)
    return row


def original():
    v=values()
    return dict(pid=42,bsdStatus=0,pathStatus=0,path='/fixed',bsd=dict(pid=42,parent=v['parent'],uid=v['effectiveUID'],seconds=v['startSeconds'],microseconds=v['startMicroseconds']))


def comparison(a,b,c,context='observer-control'):
    o=original();mapped=values();mapped.update(realUID=0,savedUID=0)
    prior=diagnostic.comparisons(a,mapped);prior.update(realUID=None,savedUID=None)
    return dict(context=context,pid=42,beforeVsProc=diagnostic.comparisons(a,b),afterVsProc=diagnostic.comparisons(c,b),
                sysctlStable=a==c if a is not None and c is not None else None,originalBSD=o,beforeVsOriginalBSD=prior,
                semanticContext=dict(expectedParent=None,expectedEffectiveUID=None,parentMatches=None,effectiveUIDMatches=None,crossRunIncarnationCompared=False),affectsVerdict=False)


def rows(before=None,proc=None,after=None,summary=None):
    before=before if before is not None else sample();proc=proc if proc is not None else sample(True);after=after if after is not None else copy.deepcopy(before)
    summary=summary if summary is not None else comparison(before['value'],proc['value'],after['value'])
    context=summary['context'];result=[]
    def add(phase,state,facts):result.append(dict(schema=2,seq=len(result)+1,phase=phase,state=state,elapsedMs=len(result),facts=facts))
    for phase,position,value in [('diagnostic-sysctl','before',before),('diagnostic-sysctl-proc','proc',proc),('diagnostic-sysctl','after',after)]:
        entry=dict(pid=42,context=context)
        entry.update(position=position,mib=[1,14,1,42],newValue=None,newLength=0) if position!='proc' else entry.update(flavor=3)
        add(phase,'entered',entry)
        output=dict(context=context,result=value)
        if position!='proc':output['position']=position
        add(phase,'completed',output)
    add('diagnostic-sysctl-comparison','completed',summary)
    add('result','completed',dict(observed=False,reaped=False,rootGone=False))
    return result


def parse(value):
    return kernel.parse(b''.join((json.dumps(row)+'\n').encode() for row in value))


class SysctlDiagnosticsTests(TestCase):
    def test_same_run_field_comparisons(self):
        raw=rows();self.assertEqual(parse(raw),raw)
        for field in diagnostic.FIELDS:
            b=sample(True);b['value'][field]=str(int(b['value'][field])+1) if field=='startSeconds' else b['value'][field]+1
            if field=='pid':
                with self.assertRaises(ValueError):parse(rows(proc=b))
                continue
            item=rows(proc=b);self.assertIs(item[-2]['facts']['beforeVsProc'][field],False);parse(item)
            item[-2]['facts']['beforeVsProc'][field]=True
            with self.assertRaisesRegex(ValueError,'sysctl-comparison-beforeVsProc'):parse(item)

    def test_status_sizes_unavailable_and_numeric_boolean_refuse(self):
        for proc in (False,True):
            for available in (False,True):
                row=sample(proc,available);diagnostic.result(row,proc)
                for key in ('available','affectsVerdict'):
                    bad=copy.deepcopy(row);bad[key]=int(bad[key])
                    with self.assertRaises(ValueError):diagnostic.result(bad,proc)
            for field,new in [('errno',1),('expectedBytes',0),('requestedPID',99),('count' if proc else 'returnedBytes',0)]:
                bad=sample(proc);bad[field]=new
                with self.assertRaises(ValueError):diagnostic.result(bad,proc)
        a=sample(False,False);b=sample(True,False);raw=rows(a,b);parse(raw)
        self.assertIsNone(raw[-2]['facts']['sysctlStable']);self.assertTrue(all(v is None for v in raw[-2]['facts']['beforeVsProc'].values()))

    def test_entered_completed_pid_context_and_readonly_mib(self):
        for index,field,new in [(0,'pid',99),(0,'mib',[1,14,1,99]),(0,'newLength',1),(0,'newValue',{}),(1,'context','wrapper-control'),(2,'flavor',13)]:
            raw=rows();raw[index]['facts'][field]=new
            with self.assertRaises(ValueError):parse(raw)

    def test_stability_and_semantic_checks_are_diagnostic_only(self):
        a=sample();c=sample();c['value']['parent']=12
        raw=rows(after=c);parse(raw);self.assertIs(raw[-2]['facts']['sysctlStable'],False)
        raw[-2]['facts']['sysctlStable']=True
        with self.assertRaisesRegex(ValueError,'sysctl-stability'):parse(raw)
        for context,parent,uid in [('windowserver-before',1,88),('root-before',11,0)]:
            s=comparison(a['value'],a['value'],a['value'],context)
            s['semanticContext'].update(expectedParent=parent,expectedEffectiveUID=uid,parentMatches=a['value']['parent']==parent,effectiveUIDMatches=False)
            raw=rows(summary=s);parse(raw)
            for key in ('affectsVerdict',):
                bad=copy.deepcopy(raw);bad[-2]['facts'][key]=True
                with self.assertRaises(ValueError):parse(bad)
            bad=copy.deepcopy(raw);bad[-2]['facts']['semanticContext']['crossRunIncarnationCompared']=True
            with self.assertRaises(ValueError):parse(bad)

    def test_original_bsd_uses_only_available_fields(self):
        s=comparison(values(),values(),values());s['originalBSD'].update(bsdStatus=1,bsd=None)
        s['beforeVsOriginalBSD']={key:None for key in diagnostic.FIELDS};parse(rows(summary=s))
        s['beforeVsOriginalBSD']['effectiveUID']=True
        with self.assertRaises(ValueError):parse(rows(summary=s))

    def test_partial_diagnostic_failure_stays_failed_without_comparison(self):
        r=rows()[:1]
        r.extend([dict(schema=2,seq=2,phase='failure',state='completed',elapsedMs=1,facts=dict(reason='record-write',**{'class':'prerequisite'})),
                  dict(schema=2,seq=3,phase='result',state='completed',elapsedMs=2,facts=dict(observed=False,reaped=False,rootGone=False))])
        parse(r)
        with self.assertRaises(ValueError):kernel.outcome(r,2,'1',42)

    def test_source_keeps_eperm_guard_and_fixed_sysctl_readonly(self):
        source=(ROOT/'script/runner-proof/prerequisite_kernel.m').read_text();native=(ROOT/'script/runner-proof/prerequisite_sysctl_native.h').read_text()
        self.assertIn('sysctl(mib,4,&value,&length,NULL,0)',native)
        self.assertIn('int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,pid}',native)
        self.assertIn('require([rootBefore[@"bsdStatus"] intValue] == 0 && [rootBefore[@"bsd"][@"uid"] intValue] == 0 && [rootBefore[@"path"] isEqual:executable], @"root-identity");',source)
        self.assertLess(source.index('sysctlDiagnostics(rootPID,@"root-before"'),source.index('@"root-identity"'))
        self.assertNotIn('require(',native);self.assertNotIn('posix_spawn',native);self.assertNotIn('/usr/bin/sudo',native)

    def test_original_native_body_byte_identical_without_diagnostic_insertions(self):
        source=(ROOT/'script/runner-proof/prerequisite_kernel.m').read_text()
        stripped=''.join(line for line in source.splitlines(keepends=True) if '#include "prerequisite_sysctl_native.h"' not in line and 'sysctlDiagnostics(' not in line and 'pid_t observerPID=getpid(),wrapperPID=getppid();' not in line)
        self.assertEqual(hashlib.sha256(stripped.encode()).hexdigest(),'0349ccd98d3e8394f56ee412f64a9c1220943a44a2707afd33788b32684ddf9b')
