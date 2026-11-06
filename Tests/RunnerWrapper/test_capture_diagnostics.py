from pathlib import Path
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import patch
import contextlib
import hashlib
import io
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'script/runner-proof'))
import sealed_runner as wrapper
import capture_diagnostics as diagnostic


class Pipeline:
    def __init__(self, root, fail_at=None, go_status=0):
        self.root = Path(root)
        self.evidence = self.root / 'evidence'; self.evidence.mkdir()
        self.store = self.root / 'store'; self.store.mkdir()
        self.app = self.store / 'Sliccy.app'
        self.bundle(self.app, 'ai.sliccy.mac', 'Sliccy', '17')
        self.helper = self.app / 'Contents/Helpers/ScreenProofSurface.app'
        self.bundle(self.helper, 'ai.sliccy.proof-helper', 'ScreenProofSurface', '12')
        (self.helper / 'Contents/CodeResources').write_bytes(b'fixed helper ticket')
        (self.app / 'Contents/Resources').mkdir()
        (self.app / 'Contents/Resources/slicc').write_bytes(b'fixed released fixture')
        self.helper_files = {str(p.relative_to(self.helper)): wrapper.sha(p) for p in self.helper.rglob('*') if p.is_file()}
        self.cli = self.app / 'Contents/Resources/slicc'
        self.calls, self.fail_at, self.go_status = [], fail_at, go_status
        self.req = struct.pack('>IIII', 0xfade0c00, 16, 1, 1)
        self.permissions = {}
        self.journal = diagnostic.Journal(self.evidence / 'steps.ndjson', self.root, BASE, time.monotonic(), ['SECRET-TOKEN'])
        self.trace = diagnostic.Trace(wrapper.setup.SetupTrace(self.evidence / 'stages.ndjson', time.monotonic()), self.journal)
        self.gh = self.store / 'gh'; self.gh.write_bytes(b'fake gh'); self.gh.chmod(0o700)
        self.go = self.root / 'go/bin/go'; self.go.parent.mkdir(parents=True); self.go.write_bytes(b'fake go')
        self.deadline = time.monotonic() + 1500

    @staticmethod
    def bundle(app, role, name, build):
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/_CodeSignature').mkdir()
        (app / 'Contents/MacOS' / name).write_bytes(name.encode())
        (app / 'Contents/_CodeSignature/CodeResources').write_bytes(b'fake seal')
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier=role,
            CFBundleShortVersionString='0.1.0', CFBundleVersion=build, CFBundleExecutable=name)))

    @staticmethod
    def fullhash(path):
        name = Path(path).name
        if name == 'ScreenProofSurface.app': name = 'ScreenProofSurface'
        if name == 'Sliccy.app': name = 'Sliccy'
        return hashlib.sha256(name.encode()).hexdigest()

    def output(self, args):
        name = Path(args[0]).name
        if name == 'gh':
            if args[-1].endswith('/zip'): return 0, (self.store / 'outer.zip').read_bytes(), b''
            return 0, json.dumps({'id': wrapper.APP_ARTIFACT, 'name': 'Sliccy-Capture-Proof-0.1.0-arm64-' + wrapper.APP_SOURCE,
                'expired': False, 'digest': 'sha256:' + wrapper.APP_OUTER_SHA,
                'workflow_run': {'id': int(wrapper.APP_RUN), 'head_sha': wrapper.APP_SOURCE}}).encode(), b''
        if name == 'ditto':
            shutil.copytree(self.app, Path(args[-1]) / 'Sliccy.app')
        if name == 'codesign':
            if '--entitlements' in args: return 0, plistlib.dumps({}), b''
            if '-r-' in args: return 0, b'', b'designated => fixed fixture requirement\n'
            if '--verify' in args:
                wrong = args[-1].endswith('ScreenProofSurface.app') and 'identifier "ai.sliccy.mac"' in args[-2]
                return (3, b'', b'expected role refusal') if wrong else (0, b'', b'static verified')
            full = self.fullhash(args[-1])
            return 0, b'', ('CDHash=' + full[:40] + '\nCandidateCDHashFull sha256=' + full + '\nTeamIdentifier=S8LB56P782\nflags=0x10000(runtime)\n').encode()
        if name == 'lipo': return 0, b'arm64\n', b''
        if name == 'sw_vers': return 0, b'27.0.1\n', b''
        if name == 'csreq': Path(args[-1]).write_bytes(self.req)
        if name == 'sudo':
            if args[2] == '/usr/bin/find': return 0, (wrapper.capture_tcc.USER_BASE + '/a/b/c/Data/Library/Application Support/com.apple.TCC/TCC.db\n').encode(), b''
            if args[2] == '/usr/bin/sqlite3':
                db, sql = args[-2:]
                if sql == 'PRAGMA table_info(access);':
                    rows = [{'cid': i, 'name': n, 'type': 'TEXT' if n in ('service','client','indirect_object_identifier','boot_uuid') else 'BLOB' if n in ('csreq','indirect_object_code_identity') else 'INTEGER'} for i, n in enumerate(wrapper.capture_tcc.COLUMNS)]
                    return 0, json.dumps(rows).encode(), b''
                if sql.startswith('BEGIN'): self.permissions[db] = True
                elif sql.startswith('DELETE'): self.permissions[db] = False
                elif sql.startswith('SELECT') and self.permissions.get(db):
                    rows = [{'service': s, 'client': 'ai.sliccy.mac', 'client_type': 0, 'auth_value': 2, 'auth_reason': 4, 'auth_version': 1, 'csreq': self.req.hex().upper()} for s in wrapper.capture_tcc.SERVICES]
                    return 0, json.dumps(rows).encode(), b''
                return 0, b'[]', b''
        if name == 'go':
            if args[1] == 'version': return 0, b'go version go1.26.5 darwin/arm64\n', b''
            (self.evidence / 'capture/capture-suite.json').write_text(json.dumps({'cases': [{'case': 'authorization-exclusion', 'outcome': 'FAILED_TO_DEMONSTRATE'}, {'case':'selected-window','outcome':'PASS'}]}))
            return self.go_status, b'private full Go output\n', b'private Go stderr\n'
        return 0, b'fixed stdout', b'fixed stderr'

    def invoke(self, args, kwargs):
        self.calls.append((list(args), dict(kwargs.get('env', {}))))
        if len(self.calls) == self.fail_at: code, out, err = 7, b'x' * 6000 + b'FAIL-OUT', b'y' * 6000 + b'FAIL-ERR'
        else: code, out, err = self.output(args)
        kwargs['stdout'].write(out); kwargs['stderr'].write(err)
        return code

    def run(self, args, **kwargs):
        return subprocess.CompletedProcess(args, self.invoke(args, kwargs))

    def popen(self, args, **kwargs):
        code = self.invoke(args, kwargs)
        return SimpleNamespace(pid=123, returncode=code, wait=lambda timeout: code)

    def checked(self, args):
        code, out, err = self.output(args)
        if code: raise subprocess.CalledProcessError(code, args, out, err)
        return out, err

    def execute(self):
        def synthetic_run(args, **kwargs):
            code, out, err = self.output(args)
            return subprocess.CompletedProcess(args, code, out, err)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, GH_TOKEN='SECRET-TOKEN', GITHUB_SHA=wrapper.APP_SOURCE, RUNNER_ENVIRONMENT='github-hosted'))
            stack.enter_context(patch.dict(wrapper.snapshot_manifest.RESOURCES, slicc=('arm64', wrapper.sha(self.cli), self.fullhash(self.cli)[:40])))
            stack.enter_context(patch.object(wrapper.capture_manifest.surface_pin, 'FILES', self.helper_files))
            stack.enter_context(patch.object(wrapper.capture_manifest.surface_pin, 'CDHASH', self.fullhash('ScreenProofSurface')[:40]))
            stack.enter_context(patch.object(wrapper.capture_manifest.surface_pin, 'subprocess', SimpleNamespace(run=synthetic_run)))
            stack.enter_context(patch.object(wrapper.capture_manifest, 'subprocess', SimpleNamespace(run=synthetic_run, PIPE=subprocess.PIPE)))
            stack.enter_context(patch.object(wrapper.capture_manifest, 'checked', self.checked))
            stack.enter_context(patch.object(wrapper.snapshot_manifest, 'checked', self.checked))
            stack.enter_context(patch.object(wrapper.universal_manifest, 'checked', self.checked))
            manifest = wrapper.capture_manifest.manifest(self.app)
            (self.store / 'capture-manifest.json').write_text(json.dumps(manifest))
            (self.store / 'signing.txt').write_text('fabricated fixture only')
            with zipfile.ZipFile(self.store / 'Sliccy-0.1.0.zip', 'w') as z:
                for p in self.app.rglob('*'):
                    if p.is_file(): z.write(p, str(p.relative_to(self.store)))
            inner = wrapper.sha(self.store / 'Sliccy-0.1.0.zip')
            (self.store / 'SHA256SUMS').write_text(inner + '  Sliccy-0.1.0.zip\n')
            with zipfile.ZipFile(self.store / 'outer.zip', 'w') as z:
                for name in ['Sliccy-0.1.0.zip','SHA256SUMS','capture-manifest.json','signing.txt']: z.write(self.store / name, name)
            for name, value in [('APP_ZIP_SHA',inner),('APP_OUTER_SHA',wrapper.sha(self.store / 'outer.zip')),('APP_MANIFEST_SHA',wrapper.sha(self.store / 'capture-manifest.json'))]:
                stack.enter_context(patch.object(wrapper, name, value))
            stack.enter_context(patch.object(wrapper, 'require_host'))
            stack.enter_context(patch.object(wrapper.capture_tcc.placement, 'require_host'))
            stack.enter_context(patch.object(wrapper.setup, 'discover_gh', return_value=str(self.gh)))
            stack.enter_context(patch.object(wrapper.setup, 'unpack_go', return_value=self.go))
            stack.enter_context(patch.object(wrapper.capture_evidence, 'crash_baseline', return_value={}))
            stack.enter_context(patch.object(wrapper.capture_evidence, 'collect_crashes'))
            stack.enter_context(patch.object(diagnostic.subprocess, 'run', side_effect=self.run))
            stack.enter_context(patch.object(diagnostic.subprocess, 'Popen', side_effect=self.popen))
            stack.enter_context(self.journal.bind(wrapper))
            with (self.evidence / 'runner.log').open('xb') as log:
                return wrapper.suite(self.root, self.evidence, log, {'PATH':wrapper.PATH}, self.deadline, BASE, self.trace)


class CaptureDiagnosticTests(unittest.TestCase):
    def test_every_actual_pipeline_command_failure_is_named_and_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            p = Pipeline(root); self.assertEqual(p.execute(), 0); count = len(p.calls)
            type(self).pipeline_command_count = count
            self.assertGreater(count, 50)
            self.assertIn('private full Go output', (p.evidence / 'go-test.log').read_text())
            self.assertFalse(any(p.permissions.values()))
            for args, env in p.calls:
                self.assertEqual('GH_TOKEN' in env, Path(args[0]).name == 'gh')
                self.assertNotIn('GITHUB_TOKEN', env)
        for index in range(1, count + 1):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as root:
                p = Pipeline(root, index)
                try: self.assertEqual(p.execute(), 1)
                except (ValueError, subprocess.CalledProcessError, wrapper.setup.SetupFailure): pass
                rows = [json.loads(l) for l in p.journal.path.read_text().splitlines()]
                failed = [r for r in rows if r['kind']=='command' and r.get('exitStatus')==7]
                self.assertEqual(len(failed),1)
                row=failed[0]
                self.assertTrue(row['step']);self.assertTrue(row['tool']);self.assertTrue(row['arguments'])
                self.assertTrue(row['stdoutTail'].endswith('FAIL-OUT'));self.assertTrue(row['stderrTail'].endswith('FAIL-ERR'))
                self.assertLessEqual(len(row['stdoutTail'].encode()),4096);self.assertLessEqual(len(row['stderrTail'].encode()),4096)

    def test_nonzero_retains_all_cases_and_cleanup_and_package(self):
        with tempfile.TemporaryDirectory() as root:
            p=Pipeline(root,go_status=1);self.assertEqual(p.execute(),1)
            self.assertFalse(any(p.permissions.values()))
            original=(p.evidence/'capture/capture-suite.json').read_bytes()
            payload=p.root/'sealed-input.tar'
            wrapper.package_evidence(p.evidence,payload,p.root/'absent-bootstrap')
            with tarfile.open(payload) as t:
                self.assertEqual(t.extractfile('capture/capture-suite.json').read(),original)
                self.assertIn(b'private Go stderr',t.extractfile('go-test.log').read())
            self.assertEqual(json.loads(original)['cases'][0]['outcome'],'FAILED_TO_DEMONSTRATE')
            self.assertEqual(json.loads((p.evidence/'invocation.json').read_text())['result'],'DRIVER_FAILED')

    def test_main_nonzero_seals_case_records_without_public_details(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);output=p/'github-output';retained={};calls=[]
            def suite(private,evidence,*args):
                (evidence/'capture').mkdir()
                (evidence/'capture/capture-suite.json').write_text('private case verdicts')
                return 1
            def owned(args,log,env,deadline,**kwargs):
                self.assertNotIn('GH_TOKEN',env);self.assertNotIn('GITHUB_TOKEN',env)
                calls.append((args,deadline,kwargs))
                if '--encrypt' in args:
                    with tarfile.open(args[-1]) as archive:
                        retained['cases']=archive.extractfile('capture/capture-suite.json').read()
                        retained['envelope']=json.load(archive.extractfile('envelope.json'))
                    Path(args[args.index('--output')+1]).write_bytes(b'synthetic sealed fixture')
                return 0
            with patch.dict(os.environ,{'RUNNER_TEMP':str(p),'GITHUB_OUTPUT':str(output),'GH_TOKEN':'SECRET','GITHUB_SHA':'a'*40}),patch.object(wrapper,'require_host'),patch.object(wrapper,'validate_source_manifest',return_value={'files':{}}),patch.object(wrapper,'unpack_age',side_effect=lambda _,exe:exe.write_bytes(b'never executed')),patch.object(wrapper,'suite',side_effect=suite),patch.object(diagnostic.Journal,'owned',side_effect=owned),contextlib.redirect_stdout(io.StringIO()) as public:
                self.assertEqual(wrapper.main(),1)
            self.assertEqual(retained['cases'],b'private case verdicts')
            self.assertEqual(retained['envelope']['exitCode'],1)
            self.assertFalse(retained['envelope']['ciStatusIsProofVerdict'])
            self.assertEqual(output.read_text(),'sealed=true\n')
            self.assertEqual((p/'sliccy-screen-evidence.age').read_bytes(),b'synthetic sealed fixture')
            self.assertEqual(calls[-1][1]-calls[0][1],60)
            self.assertEqual(public.getvalue(),'Capture diagnostic evidence sealed.\n')

    def test_cleanup_executes_despite_diagnostic_sink_loss(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);journal=diagnostic.Journal(p/'rows',p,BASE,time.monotonic())
            trace=diagnostic.Trace(wrapper.setup.SetupTrace(p/'stages',time.monotonic()),journal)
            journal.path.unlink();journal.path.mkdir()
            calls=[]
            def command(args,**kwargs):
                calls.append(args);kwargs['stdout'].write(b'[]');return subprocess.CompletedProcess(args,0)
            def cleanup():
                journal.run(['/usr/bin/sudo','-n','/usr/bin/sqlite3','owned','DELETE scoped'],capture_output=True,check=True)
            with patch.object(diagnostic.subprocess,'run',side_effect=command),self.assertRaisesRegex(ValueError,'diagnostic loss'):
                trace.cleanup(cleanup)
            self.assertEqual(len(calls),1);self.assertTrue(journal.loss)

    def test_every_validation_step_records_failure_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);j=diagnostic.Journal(p/'rows',p,BASE,time.monotonic(),['SECRET'])
            for stage in diagnostic.STEPS:
                with self.assertRaisesRegex(ValueError,'SECRET'):
                    with j.step(stage): raise ValueError('SECRET')
            rows=[json.loads(l) for l in j.path.read_text().splitlines()]
            failed=[r for r in rows if r['status']=='failed']
            self.assertEqual({r['step'] for r in failed},set(diagnostic.STEPS))
            self.assertNotIn('SECRET',j.path.read_text())
            self.assertTrue(all(r['exceptionClass']=='ValueError' for r in failed))

    def test_owned_expiry_refuses_spawn_and_timeout_keeps_tails(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);j=diagnostic.Journal(p/'rows',p,BASE,time.monotonic())
            with patch.object(diagnostic.subprocess,'Popen') as spawn,self.assertRaises(subprocess.TimeoutExpired):
                j.call('native-driver',j.owned,['/fixed/go'],io.BytesIO(),{},time.monotonic()-1)
            spawn.assert_not_called()
            def fail(args,**kwargs):
                kwargs['stdout'].write(b'partial out');kwargs['stderr'].write(b'partial err')
                raise subprocess.TimeoutExpired(args,1)
            with patch.object(diagnostic.subprocess,'run',side_effect=fail),self.assertRaises(subprocess.TimeoutExpired):
                j.call('artifact-signature',j.run,['/usr/bin/codesign','--verify'],capture_output=True)
            rows=[json.loads(l) for l in j.path.read_text().splitlines()]
            last=[r for r in rows if r['kind']=='command' and r['status']=='failed'][-1]
            self.assertEqual(last['stdoutTail'],'partial out');self.assertEqual(last['stderrTail'],'partial err')


if __name__=='__main__':unittest.main(verbosity=2)
