from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
HEADER=ROOT/'Sources/ScreenSystem/include/ScreenRunnerBSD.h'
FIXTURE=ROOT/'Tests/RunnerBSD/fixture.c'
MUTATIONS={
    'controls':('!sliccy_bsd_controls(o)','0'),
    'control-after':('sliccy_bsd_equal(b.after.value, b.proc.value)','(1 || sliccy_bsd_equal(b.after.value, b.proc.value))'),
    'unstable':('!sliccy_bsd_equal(b.before.value, b.after.value)','0'),
    'eperm-only':('b.proc.status != EPERM','0'),
    'short':('r.count == r.expected','(1 || r.count == r.expected)'),
    'effective':('a.effective_uid == 88','(1 || a.effective_uid == 88)'),
    'real':('a.real_uid == 0','(1 || a.real_uid == 0)'),
    'saved':('a.saved_uid == 0','(1 || a.saved_uid == 0)'),
    'binding':('return sliccy_bsd_equal(a, b) &&','return (1 || sliccy_bsd_equal(a, b)) &&'),
    'parent':('a.parent == 1','(1 || a.parent == 1)'),
    'eperm-bytes':('b.proc.count != 0','0'),
    'pid-bound':('r.value.pid == pid','(1 || r.value.pid == pid)'),
    'start-bound':('r.value.seconds > 0','(1 || r.value.seconds > 0)'),
    'microsecond-bound':('r.value.microseconds < 1000000','(1 || r.value.microseconds < 1000000)'),
}

for index,field in enumerate(['pid','parent','effective_uid','real_uid','saved_uid','seconds','microseconds']):
    old='a.'+field+' == b.'+field
    pairs=[(old,'(1 || '+old+')')]
    if field=='pid':pairs.append(('r.value.pid == pid','(1 || r.value.pid == pid)'))
    MUTATIONS['control-field-'+str(index)]=pairs

def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise RuntimeError('hosted-only')
    output=ROOT/'bsd-results';output.mkdir(mode=0o700)
    original=HEADER.read_bytes();results=[]
    def run(label,args):
        value=subprocess.run(args,capture_output=True,timeout=60)
        for stream in ('stdout','stderr'):(output/(label+'.'+stream)).write_bytes(getattr(value,stream))
        results.append({'label':label,'args':args,'exit':value.returncode,'stdout':hashlib.sha256(value.stdout).hexdigest(),'stderr':hashlib.sha256(value.stderr).hexdigest()})
        (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        return value
    with tempfile.TemporaryDirectory() as directory:
        temp=Path(directory);header=temp/HEADER.name;exe=temp/'fixture'
        header.write_bytes(original)
        args=['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-DSLICCY_CAPTURE_RUNNER_PROOF','-I',str(temp),str(FIXTURE),'-o',str(exe)]
        assert run('baseline-compile',args).returncode==0
        for name in [*MUTATIONS,'fields']:assert run('baseline-'+name,[str(exe),name]).returncode==0
        for name,changes in MUTATIONS.items():
            if isinstance(changes,tuple):changes=[changes]
            mutant=original.decode()
            for old,new in changes:
                assert mutant.count(old)==1
                mutant=mutant.replace(old,new)
            header.write_text(mutant)
            assert run(name+'-compile',args).returncode==0
            value=run(name+'-mutant',[str(exe),name])
            assert value.returncode==1 and value.stdout==b'' and value.stderr==('ASSERTION:'+name+'\n').encode()
            header.write_bytes(original)
            assert run(name+'-restored-compile',args).returncode==0
            assert run(name+'-restored',[str(exe),name]).returncode==0
    assert HEADER.read_bytes()==original
    (output/'summary.json').write_text(json.dumps({'source':os.environ['GITHUB_SHA'],'headerSHA256':hashlib.sha256(original).hexdigest(),'fixtureSHA256':hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),'mutations':len(MUTATIONS),'allRuntimeRedRestoredGreen':True,'scope':'fabricated structs and assertions only; no identity queries'},indent=2)+'\n')

if __name__=='__main__':main()
