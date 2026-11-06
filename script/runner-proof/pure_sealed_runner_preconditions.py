#!/usr/bin/env python3
"""Pure gate: sealed_runner preconditions before network/subprocess/Go/app download."""
from __future__ import annotations
import hashlib, json, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load_constants():
    text=(ROOT/'sealed_runner.py').read_text()
    ns={}
    # evaluate only assignment preamble through INPUTS
    head=text.split('PREFIX =',1)[0]
    exec(head, ns)
    prefix=text.split('PREFIX = ',1)[1].split('\n',1)[0].strip().strip("'\"")
    ns['PREFIX']=prefix
    return ns

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def catalog():
    return [
        {'line':59,'assert':'sha(inputs/name)==INPUTS[name]','file':'script/runner-proof/inputs/*','preHeavy':True},
        {'line':82,'assert':'capture-driver-files.json contract == expected','file':'capture-driver-files.json','preHeavy':True},
        {'line':94,'assert':'len(files)==101 single-component .go','file':'capture-driver-files.json','preHeavy':True},
        {'line':101,'assert':'tar member digests == files map','file':'capture-driver.tar.gz','preHeavy':True},
        {'line':115,'assert':'app zip == APP_ZIP_SHA','file':'Sliccy-0.1.0.zip','preHeavy':False},
        {'line':220,'assert':'outer == APP_OUTER_SHA','file':'artifact.zip','preHeavy':False},
        {'line':238,'assert':'manifest == APP_MANIFEST_SHA','file':'capture-manifest.json','preHeavy':False},
    ]

def run(inputs: Path):
    c=load_constants()
    rows=[]
    def check(line, name, file, fn):
        row={'line':line,'assert':name,'file':file,'ok':False}
        try:
            fn(); row['ok']=True; rows.append(row)
        except Exception as e:
            row['detail']=f'{type(e).__name__}: {e}'; rows.append(row)
            raise AssertionError(json.dumps(row)) from e
    for name, digest in c['INPUTS'].items():
        def make(n=name,d=digest):
            def fn():
                got=sha(inputs/n); assert got==d, f'{n}: {got} != {d}'
            return fn
        check(59, f'INPUTS[{name}]', f'inputs/{name}', make())
    metadata=json.loads((inputs/'capture-driver-files.json').read_text())
    contract={k:v for k,v in metadata.items() if k!='files'}
    expected={
        'schema': 1, 'sourceTag': 'v1.59.0', 'sourceArchiveSHA256': c['INPUTS']['slicc-v1.59.0.tar.gz'],
        'sourceArchiveRoot': c['PREFIX'], 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local',
        'entryTests': ['TestSignedRunnerCapture'],
        'entryCommand': ['go', 'test', '-mod=readonly', './test/nativeproof', '-run', '^TestSignedRunnerCapture$', '-count=1', '-timeout=980s'],
        'fixtureSource': c['APP_SOURCE'], 'signedRun': int(c['APP_RUN']), 'artifactID': c['APP_ARTIFACT'],
        'appBuild': '17', 'driverTimeoutSeconds': 960, 'goTestTimeoutSeconds': 980,
        'caseTotalSeconds': 150, 'caseExecutionSeconds': 120, 'caseCaptureSeconds': 10,
        'helperBuild': '12', 'goCommandTimeoutSeconds': 990,
        'chromeStaticIdentitySeconds': 30, 'baselineIdentityAndWindowsTotalSeconds': 2,
    }
    def c82():
        assert contract==expected, {k:(contract.get(k),expected.get(k)) for k in set(contract)|set(expected) if contract.get(k)!=expected.get(k)}
    check(82,'driver-files contract','capture-driver-files.json', c82)
    expected_files=metadata['files']
    def c94():
        assert len(expected_files)==101
        from pathlib import PurePosixPath
        for n in expected_files:
            v=PurePosixPath(n)
            assert not v.is_absolute() and '..' not in v.parts and len(v.parts)==1 and n.endswith('.go')
    check(94,'file set','capture-driver-files.json', c94)
    def c101():
        with tarfile.open(inputs/'capture-driver.tar.gz') as archive:
            seen=set()
            for entry in archive.getmembers():
                assert entry.name in expected_files and entry.isfile()
                seen.add(entry.name)
                data=archive.extractfile(entry).read()
                assert hashlib.sha256(data).hexdigest()==expected_files[entry.name]
            assert seen==set(expected_files)
    check(101,'tar digests','capture-driver.tar.gz', c101)
    return rows

def main(argv):
    try:
        rows=run(Path(argv[1]) if len(argv)>1 else ROOT/'inputs')
        print(json.dumps({'ok':True,'checks':len(rows),'rows':rows,'catalog':catalog()},indent=2)); return 0
    except AssertionError as e:
        try: payload=json.loads(str(e))
        except Exception: payload={'detail':str(e)}
        print(json.dumps({'ok':False,'failed':payload,'catalog':catalog()},indent=2)); return 1
if __name__=='__main__':
    raise SystemExit(main(sys.argv))
