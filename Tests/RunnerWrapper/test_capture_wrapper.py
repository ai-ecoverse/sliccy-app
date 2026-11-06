from pathlib import Path
import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'script/runner-proof'))
import sealed_runner as subject
import capture_tcc as tcc
import capture_evidence as evidence_module
SIGNED = Path('/Users/trieloff/.bb/thread-storage/thr_desfnajij8/signed/42217144755-capture-proof')


class WrapperTests(unittest.TestCase):
    def test_exact_driver_and_release_archive(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'source'
            m = subject.extract_sources(BASE / 'script/runner-proof/inputs', target)
            self.assertEqual(len(m['files']), 99)
            self.assertEqual({p.name for p in (target / 'test/nativeproof').iterdir()}, set(m['files']))
            self.assertIn('go 1.26.5', (target / 'go.mod').read_text())

    def test_manifest_and_paths_refuse_tampering(self):
        manifest = subject.validate_source_manifest(BASE)
        for name in ['../escape', '/absolute', 'a/../../escape', '', 'a//b', 'a/./b']:
            with self.assertRaises(ValueError): subject.safe_parts(name)
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            for name in manifest['files']:
                out = repo / name; out.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(BASE / name, out)
            shutil.copy2(BASE / 'script/runner-proof/capture-reviewed-sources.json', repo / 'script/runner-proof/capture-reviewed-sources.json')
            target = repo / 'script/runner-proof/capture_tcc.py'
            target.chmod(0o600)
            target.write_text('changed')
            with self.assertRaises(ValueError): subject.validate_source_manifest(repo)

    def exercise_suite(self, exit_code):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); evidence = root / 'evidence'; evidence.mkdir()
            env = {'PATH': subject.PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/', 'LANG': 'C', 'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
            manifest = json.loads((SIGNED / 'capture-manifest.json').read_text())
            journal = subject.diagnostics.Journal(evidence / 'steps', root, BASE, time.monotonic())
            trace = subject.diagnostics.Trace(subject.setup.SetupTrace(evidence / 'trace', time.monotonic()), journal)
            calls = []; order = []
            def run(args, log, child_env, deadline, **kwargs):
                calls.append((args, dict(child_env), deadline, kwargs))
                if len(args) > 2 and args[1] == 'api':
                    if args[-1].endswith('/zip'):
                        log.write((SIGNED / 'artifact.zip').read_bytes())
                    else:
                        log.write(json.dumps({'id': subject.APP_ARTIFACT, 'name': 'Sliccy-Capture-Proof-0.1.0-arm64-' + subject.APP_SOURCE,
                            'expired': False, 'digest': 'sha256:' + subject.APP_OUTER_SHA,
                            'workflow_run': {'id': int(subject.APP_RUN), 'head_sha': subject.APP_SOURCE}}).encode())
                if args[0] == '/usr/bin/ditto': (Path(args[-1]) / 'Sliccy.app').mkdir()
                if 'test' in args:
                    order.append('driver')
                    (evidence / 'capture/capture-suite.json').write_text('case evidence preserved')
                    return exit_code
                return 0
            class Grants:
                def __init__(self, *args): pass
                def install(self, app): order.append('install')
                def remove(self): order.append('remove')
            def static(args, **kwargs):
                self.assertNotIn('GH_TOKEN', kwargs['env'])
                return subprocess.CompletedProcess(args, 0, b'27.0\n', b'')
            deadline = time.monotonic() + 1500
            with patch.dict(os.environ, {'GH_TOKEN': 'SECRET-SENTINEL', 'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'run_owned', side_effect=run), patch.object(subject, 'require_host'), patch.object(subject.setup, 'discover_gh', return_value='/trusted/gh'), patch.object(subject.setup, 'unpack_go', return_value=root / 'go/bin/go'), patch.object(subject.setup, 'check_go'), patch.object(subject.capture_manifest, 'manifest', return_value=manifest), patch.object(subject.capture_tcc, 'ScopedGrants', Grants), patch.object(subject.capture_evidence, 'crash_baseline', return_value={}), patch.object(subject.capture_evidence, 'collect_crashes'), patch.object(subject.subprocess, 'run', side_effect=static):
                with (evidence / 'log').open('wb') as log: result = subject.suite(root, evidence, log, env, deadline, BASE, trace)
            self.assertEqual(order, ['install', 'driver', 'remove'])
            driver = [c for c in calls if 'test' in c[0]]; self.assertEqual(len(driver), 1)
            args, child_env, actual_deadline, opts = driver[0]
            self.assertEqual(args[1:], ['test', '-mod=readonly', './test/nativeproof', '-run', '^TestSignedRunnerCapture$', '-count=1', '-timeout=980s'])
            self.assertEqual(opts['maximum'], 990); self.assertEqual(actual_deadline, deadline)
            self.assertEqual(child_env['SLICCY_RUNNER_OS_VERSION'], '27.0')
            self.assertEqual(child_env['RUNNER_ENVIRONMENT'], 'github-hosted')
            self.assertEqual(child_env['SLICC_RUNNER_PROOF_ROOT'], str(evidence / 'capture'))
            self.assertEqual(child_env['GOTOOLCHAIN'], 'local'); self.assertEqual(child_env['CGO_ENABLED'], '0')
            invocation=json.loads((evidence/'invocation.json').read_text())
            self.assertEqual({key:invocation[key] for key in ['driverTimeoutSeconds','goTestTimeoutSeconds','goCommandSeconds','caseSeconds','captureSeconds']},
                             {'driverTimeoutSeconds':960,'goTestTimeoutSeconds':980,'goCommandSeconds':990,'caseSeconds':150,'captureSeconds':10})
            for args, child_env, _, _ in calls:
                self.assertEqual('GH_TOKEN' in child_env, len(args) > 1 and args[1] == 'api')
                self.assertNotIn('GITHUB_TOKEN', child_env)
            self.assertEqual((evidence / 'capture/capture-suite.json').read_text(), 'case evidence preserved')
            self.assertEqual(result, 0 if exit_code == 0 else 1)
            self.assertEqual(json.loads((evidence / 'suite-outcomes.json').read_text())['capture'], 'DRIVER_EXIT_0' if exit_code == 0 else 'DRIVER_FAILED')

    def test_driver_contract_token_isolation_and_cleanup(self): self.exercise_suite(0)
    def test_driver_failure_is_retained(self): self.exercise_suite(1)

    def test_local_host_refuses_before_any_command(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(subject, 'run_owned') as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(subject.main(), 1); run.assert_not_called()
        self.assertEqual(output.getvalue(), 'Capture diagnostic evidence unavailable.\n')

    def test_encryption_failure_uploads_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); output_path = p / 'output'; calls = []
            def unpack(_, executable): executable.write_bytes(b'not executed')
            def run(args, log, env, deadline, **kwargs):
                calls.append((args, deadline))
                if '--encrypt' in args: raise RuntimeError('PRIVATE-ERROR')
                return 0
            with patch.dict(os.environ, {'RUNNER_TEMP': str(p), 'GITHUB_OUTPUT': str(output_path), 'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'require_host'), patch.object(subject, 'validate_source_manifest', return_value={'files': {}}), patch.object(subject, 'unpack_age', side_effect=unpack), patch.object(subject, 'suite', return_value=1), patch.object(subject.diagnostics.Journal, 'owned', side_effect=run), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(subject.main(), 1)
            self.assertEqual(calls[-1][1] - calls[0][1], 60)
            self.assertFalse(output_path.exists()); self.assertFalse((p / 'sliccy-screen-evidence.age').exists())
            self.assertEqual(output.getvalue(), 'Capture diagnostic evidence unavailable.\n')

    def test_absolute_command_deadline(self):
        with patch.object(subject.time, 'monotonic', return_value=100), patch.object(subject.subprocess, 'Popen') as popen:
            child = popen.return_value; child.wait.return_value = 0; child.returncode = 0
            subject.run_owned(['fixed'], None, {}, 102, maximum=60)
            child.wait.assert_called_once_with(timeout=2)
            popen.reset_mock()
            with self.assertRaises(subprocess.TimeoutExpired): subject.run_owned(['fixed'], None, {}, 99)
            popen.assert_not_called()

    def test_actual_outer_deadlines_and_sealed_envelope(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);calls=[];observed={}
            def unpack(_,path):path.write_bytes(b'never executed')
            def run(args,log,env,deadline,**kwargs):
                calls.append((args,deadline,kwargs))
                if '--encrypt' in args:Path(args[args.index('--output')+1]).write_bytes(b'ciphertext fixture')
                return 0
            def suite(private,evidence,log,env,deadline,workspace,trace):
                observed['workDeadline']=deadline
                return 1
            def package(evidence,*args):observed['envelope']=json.loads((evidence/'envelope.json').read_text())
            with patch.dict(os.environ,{'RUNNER_TEMP':str(root),'GITHUB_OUTPUT':str(root/'output'),'GITHUB_SHA':'a'*40}),patch.object(subject.time,'monotonic',return_value=1000),patch.object(subject,'require_host'),patch.object(subject,'validate_source_manifest',return_value={'files':{}}),patch.object(subject,'unpack_age',side_effect=unpack),patch.object(subject,'suite',side_effect=suite),patch.object(subject,'package_evidence',side_effect=package),patch.object(subject.diagnostics.Journal,'owned',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(subject.main(),1)
            self.assertEqual(observed['workDeadline'],2500)
            self.assertEqual(calls[0][1],2500)
            self.assertEqual(calls[-1][1],2560)
            self.assertEqual(observed['envelope']['workDeadlineSeconds'],1500)
            self.assertEqual(observed['envelope']['sealDeadlineSeconds'],1560)
            self.assertEqual(observed['envelope']['exitCode'],1)
            self.assertFalse(observed['envelope']['ciStatusIsProofVerdict'])
            self.assertTrue((root/'sliccy-screen-evidence.age').is_file())
            self.assertFalse(list(root.glob('sliccy-capture-private-*')))

    def test_capture_only_workflow_has_no_secret_or_other_dispatch(self):
        text = (BASE / '.github/workflows/runner-proof.yml').read_text()
        for job in ['hosted-pid', 'universal', 'owner-identity', 'prerequisite', 'setup-read-only']:
            self.assertIn('  ' + job + ':\n    if: false', text)
        self.assertIn("github.ref == 'refs/heads/proof/runner-capture-v1'", text.split('  universal:')[0])
        self.assertNotIn('secrets.', text); self.assertNotIn('id-token:', text)
        self.assertIn('> "$RUNNER_TEMP/sliccy-screen-bootstrap.log" 2>&1', text)
        block=text.split('  diagnostic:')[1].split('  universal:')[0]
        self.assertIn('timeout-minutes: 30',block)


class TCCTests(unittest.TestCase):
    def test_resolution_refuses_ambiguous_database(self):
        a = tcc.USER_BASE + '/a/b/c/Data/Library/Application Support/com.apple.TCC/TCC.db'
        b = a.replace('/a/', '/x/')
        self.assertEqual(tcc.user_database([a], []), a)
        self.assertEqual(tcc.user_database([a, b], [b]), b)
        for active in [[], [a, b]]:
            with self.assertRaises(ValueError): tcc.user_database([a, b], active)
        with self.assertRaises(ValueError): tcc.user_database(['/tmp/other.db'], [])

    def test_exact_scoped_sql_and_schema(self):
        db = sqlite3.connect(':memory:')
        text = {'service', 'client', 'indirect_object_identifier', 'boot_uuid'}; blob = {'csreq', 'indirect_object_code_identity'}
        db.execute('CREATE TABLE access (' + ','.join(n + (' TEXT' if n in text else ' BLOB' if n in blob else ' INTEGER') for n in tcc.COLUMNS) + ')')
        rows = [dict(zip(['cid', 'name', 'type', 'notnull', 'dflt_value', 'pk'], row)) for row in db.execute('PRAGMA table_info(access)')]
        tcc.schema_supported(rows)
        with self.assertRaises(ValueError): tcc.schema_supported(rows[:-1])
        req = struct.pack('>IIII', 0xfade0c00, 16, 1, 1)
        self.assertEqual(tcc.compiled_requirement(req), req.hex())
        with self.assertRaises(ValueError): tcc.compiled_requirement(b'invalid')
        db.executescript(tcc.insert_sql(req.hex(), 123))
        records = db.execute('SELECT service,client,client_type,hex(csreq) FROM access').fetchall()
        self.assertEqual({r[0] for r in records}, set(tcc.SERVICES))
        self.assertTrue(all(r[1:] == ('ai.sliccy.mac', 0, req.hex().upper()) for r in records))
        db.execute("INSERT INTO access(service,client) VALUES ('kTCCServiceScreenCapture','unrelated')")
        db.execute('DELETE FROM access WHERE ' + tcc.predicates() + " AND csreq=X'" + req.hex() + "'")
        self.assertEqual(db.execute('SELECT client FROM access').fetchall(), [('unrelated',)])
        db.close()

    def test_tcc_local_guard_precedes_any_command(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {}, clear=True):
            obj = tcc.ScopedGrants(Path(root), Path(root), {}, time.monotonic() + 10)
            with patch.object(obj, 'command') as command:
                with self.assertRaises(ValueError): obj.install(Path(root) / 'app')
                command.assert_not_called()

    def test_cleanup_continues_after_first_failure(self):
        with tempfile.TemporaryDirectory() as root:
            obj = tcc.ScopedGrants(Path(root), Path(root), {}, time.monotonic() + 10)
            obj.touched = ['one', 'two']; obj.hex = 'aaaa'; calls = []
            def query(db, sql, cleanup=False):
                self.assertTrue(cleanup); calls.append(db)
                if db == 'two': raise ValueError('blocked')
                return []
            with patch.object(obj, 'query', side_effect=query):
                with self.assertRaises(ValueError): obj.remove()
            self.assertIn('one', calls); self.assertIn('two', calls)


class EvidenceTests(unittest.TestCase):
    def test_only_new_scoped_regular_crash_files_are_collected(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); reports = p / 'reports'; reports.mkdir(); evidence = p / 'evidence'; evidence.mkdir()
            (reports / 'Sliccy-old.ips').write_text('old')
            with patch.object(evidence_module, 'crash_directories', return_value=[reports]):
                baseline = evidence_module.crash_baseline()
                (reports / 'Sliccy-new.ips').write_text('new'); (reports / 'unrelated.ips').write_text('private')
                evidence_module.collect_crashes(baseline, evidence)
                self.assertEqual([f.read_text() for f in (evidence / 'crashes').iterdir()], ['new'])

    def test_crash_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root); reports = p / 'reports'; reports.mkdir(); evidence = p / 'evidence'; evidence.mkdir()
            (reports / 'Sliccy-new.ips').symlink_to(p / 'outside')
            with patch.object(evidence_module, 'crash_directories', return_value=[reports]):
                with self.assertRaises(ValueError): evidence_module.collect_crashes({}, evidence)


if __name__ == '__main__': unittest.main(verbosity=2)
