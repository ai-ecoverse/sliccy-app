from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import time
import unittest
import zipfile
import owner_diagnostics as diagnostics
import owner_identity_setup as identity
import sealed_owner_identity as wrapper


def chrome_record():
    return {'schema': 1, 'kind': 'chrome-static-identity', 'accepted': True,
        'createStatus': 0, 'requirementStatus': 0, 'signingInformationStatus': 0,
        'identifier': 'com.google.Chrome', 'team': 'EQHXZ8M8AV', 'cdHash': 'a' * 40,
        'policy': {'requirement': wrapper.CHROME_REQUIREMENT, 'identityFlags': 9, 'strictFlags': 25,
            'identityStatus': 0, 'strictStatus': -66999, 'accepted': True, 'detritusTolerated': True}}


class Pipeline:
    def __init__(self, directory, fail_at=None):
        self.root = Path(directory)
        self.workspace = Path(wrapper.__file__).resolve().parents[2]
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.journal = diagnostics.Journal(self.evidence / 'steps.ndjson', self.root, self.workspace, time.monotonic())
        self.trace = diagnostics.Trace(wrapper.shared.setup.SetupTrace(self.evidence / 'old.ndjson', time.monotonic()), self.journal)
        self.calls, self.fail_at = [], fail_at
        self.store = self.root / 'fixtures'; self.store.mkdir()
        self.capture = self.fixture('capture', '11', True)
        self.preview = self.fixture('preview', '1', False)
        self.expected = {}
        self.resources = self.root / 'test-tools'; self.resources.mkdir()
        self.gh = self.resources / 'gh'; self.gh.write_bytes(b'fixed test tool')
        self.gh.chmod(0o700)

    def fixture(self, kind, build, helper):
        base = self.store / kind; base.mkdir()
        app = base / 'Sliccy.app'
        self.bundle(app, 'ai.sliccy.mac', 'Sliccy', build)
        (app / 'Contents/Resources').mkdir()
        (app / 'Contents/Resources/slicc').write_bytes(b'fixed CLI bytes')
        if helper:
            self.bundle(app / 'Contents/Helpers/ScreenProofSurface.app', 'ai.sliccy.proof-helper', 'ScreenProofSurface', build)
        with zipfile.ZipFile(base / 'Sliccy-0.1.0.zip', 'w') as out:
            for path in app.rglob('*'):
                if path.is_file():
                    out.write(path, str(path.relative_to(base)))
        digest = wrapper.shared.sha(base / 'Sliccy-0.1.0.zip')
        (base / 'SHA256SUMS').write_text(digest + '  Sliccy-0.1.0.zip\n')
        (base / 'signing.txt').write_text('fixed test fixture')
        return base

    @staticmethod
    def bundle(app, role, name, build):
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/_CodeSignature').mkdir()
        (app / 'Contents/MacOS' / name).write_bytes(name.encode())
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier=role,
            CFBundleShortVersionString='0.1.0', CFBundleVersion=build, CFBundleExecutable=name)))

    @staticmethod
    def fullhash(path):
        return hashlib.sha256(Path(path).name.encode()).hexdigest()

    def output(self, args):
        name = Path(args[0]).name
        if name == 'gh':
            if '--version' in args:
                return 0, b'gh version fixture\n', b''
            src = self.capture if args[3] == wrapper.shared.APP_RUN else self.preview
            dest = Path(args[-1])
            for file in src.iterdir():
                if file.is_file():
                    shutil.copyfile(file, dest / file.name)
            return 0, b'downloaded\n', b''
        if name == 'ditto':
            src = self.capture if Path(args[-1]).name == 'artifact' else self.preview
            shutil.copytree(src / 'Sliccy.app', Path(args[-1]) / 'Sliccy.app')
            return 0, b'extracted\n', b''
        if name == 'lipo':
            return 0, b'arm64\n', b''
        if name == 'codesign':
            if '--entitlements' in args:
                return 0, plistlib.dumps({}), b''
            if '--verify' in args:
                mismatch = args[-1].endswith('ScreenProofSurface.app') and 'identifier "ai.sliccy.mac"' in args[-2]
                return (3, b'', b'app role refused') if mismatch else (0, b'', b'valid signature')
            full = self.fullhash(args[-1])
            return 0, b'', ('CDHash=' + full[:40] + '\nCandidateCDHashFull sha256=' + full + '\nTeamIdentifier=S8LB56P782\nflags=0x10000(runtime)\n').encode()
        if name == 'owner-identity-probe' and args[1:] == ['--chrome-static']:
            return 0, json.dumps(chrome_record()).encode(), b''
        if name == 'xcrun' and args[1] == 'clang':
            Path(args[-1]).write_bytes(b'fixed observer')
        return 0, b'fixed stdout', b'fixed stderr'

    def invoke(self, args, stdout, stderr):
        self.calls.append(args)
        if len(self.calls) == self.fail_at:
            code, out, err = 7, b'x' * 6000 + b'FAILED-STDOUT', b'y' * 6000 + b'FAILED-STDERR'
        else:
            code, out, err = self.output(args)
        stdout.write(out); stderr.write(err)
        return code

    def run(self, args, **kwargs):
        return subprocess.CompletedProcess(args, self.invoke(args, kwargs['stdout'], kwargs['stderr']))

    def popen(self, args, **kwargs):
        code = self.invoke(args, kwargs['stdout'], kwargs['stderr'])
        return SimpleNamespace(pid=123, returncode=code, wait=lambda timeout: code)

    def execute(self):
        shared = wrapper.shared
        def checked(args):
            code, out, err = self.output(args)
            if code: raise subprocess.CalledProcessError(code, args, out, err)
            return out, err
        cli = self.capture / 'Sliccy.app/Contents/Resources/slicc'
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, GITHUB_SHA=shared.APP_SOURCE, GH_TOKEN='test-secret'))
            stack.enter_context(patch.dict(shared.snapshot_manifest.RESOURCES, slicc=('arm64', shared.sha(cli), self.fullhash(cli)[:40])))
            stack.enter_context(patch.object(shared.capture_manifest, 'checked', checked))
            stack.enter_context(patch.object(shared.snapshot_manifest, 'checked', checked))
            stack.enter_context(patch.object(shared.capture_manifest, 'subprocess', SimpleNamespace(PIPE=subprocess.PIPE, run=lambda args, **kw: subprocess.CompletedProcess(args, self.output(args)[0]))))
            manifest = shared.capture_manifest.manifest(self.capture / 'Sliccy.app')
            (self.capture / 'capture-manifest.json').write_text(json.dumps(manifest))
            for module, key, val in [(shared, 'APP_ZIP_SHA', shared.sha(self.capture / 'Sliccy-0.1.0.zip')),
                (shared, 'APP_MANIFEST_SHA', shared.sha(self.capture / 'capture-manifest.json')),
                (wrapper, 'PREVIEW_ZIP', shared.sha(self.preview / 'Sliccy-0.1.0.zip')),
                (wrapper, 'PREVIEW_EXECUTABLE', shared.sha(self.preview / 'Sliccy.app/Contents/MacOS/Sliccy')),
                (wrapper, 'PREVIEW_CDHASH', self.fullhash('Sliccy')[:40])]:
                stack.enter_context(patch.object(module, key, val))
            stack.enter_context(patch.object(shared.setup.shutil, 'which', return_value=str(self.gh)))
            stack.enter_context(patch.object(shared.setup.Path, 'is_relative_to', return_value=False))
            stack.enter_context(patch.object(diagnostics.subprocess, 'run', side_effect=self.run))
            stack.enter_context(patch.object(diagnostics.subprocess, 'Popen', side_effect=self.popen))
            stack.enter_context(patch.object(identity, 'run', return_value=True))
            stack.enter_context(self.journal.bind(shared))
            with self.journal.step('identity-setup'):
                return wrapper.suite(self.root, self.evidence, io.BytesIO(), {}, time.monotonic() + 240, self.workspace, self.trace, self.journal)


class DiagnosticsTests(unittest.TestCase):
    def rows(self, journal):
        return [json.loads(line) for line in journal.path.read_text().splitlines()]

    def assert_complete(self, row):
        for name in ['step', 'tool', 'arguments', 'exitStatus', 'stdoutTail', 'stderrTail', 'exceptionClass', 'message']:
            self.assertIn(name, row)
        self.assertLessEqual(len(row['stdoutTail'].encode()), 4096)
        self.assertLessEqual(len(row['stderrTail'].encode()), 4096)

    def test_every_actual_static_pipeline_command_failure_keeps_both_tails(self):
        with tempfile.TemporaryDirectory() as name:
            baseline = Pipeline(name)
            self.assertEqual(baseline.execute(), 0)
            count = len(baseline.calls)
            self.assertGreater(count, 30)
        for position in range(1, count + 1):
            with self.subTest(position=position), tempfile.TemporaryDirectory() as name:
                pipeline = Pipeline(name, position)
                with self.assertRaises(Exception):
                    pipeline.execute()
                rows = [r for r in self.rows(pipeline.journal) if r['kind'] == 'command' and r.get('exitStatus') == 7]
                self.assertEqual(len(rows), 1)
                self.assert_complete(rows[0])
                self.assertTrue(rows[0]['stdoutTail'].endswith('FAILED-STDOUT'))
                self.assertTrue(rows[0]['stderrTail'].endswith('FAILED-STDERR'))
                self.assertEqual(len(pipeline.calls), position)

    def test_timeout_missing_tool_and_nonzero_all_name_the_actual_command(self):
        for error in [FileNotFoundError('missing fixed tool'), subprocess.TimeoutExpired(['/usr/bin/codesign'], 10)]:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as name:
                journal = diagnostics.Journal(Path(name) / 'rows', name, name, time.monotonic())
                def fail(args, **kwargs):
                    kwargs['stdout'].write(b'out-before-failure'); kwargs['stderr'].write(b'err-before-failure')
                    raise error
                with patch.object(diagnostics.subprocess, 'run', side_effect=fail), self.assertRaises(type(error)):
                    journal.call('chrome-signature', journal.run, ['/usr/bin/codesign', '--verify'], capture_output=True)
                row = [r for r in self.rows(journal) if r['kind'] == 'command' and r['status'] == 'failed'][0]
                self.assert_complete(row)
                self.assertEqual(row['stdoutTail'], 'out-before-failure')
                self.assertEqual(row['stderrTail'], 'err-before-failure')
                self.assertEqual(row['exceptionClass'], type(error).__name__)

    def test_expired_owned_deadline_does_not_spawn(self):
        with tempfile.TemporaryDirectory() as name:
            journal = diagnostics.Journal(Path(name) / 'rows', name, name, time.monotonic())
            with patch.object(diagnostics.subprocess, 'Popen') as spawn, self.assertRaises(subprocess.TimeoutExpired):
                journal.call('observer-build', journal.owned, ['/usr/bin/xcrun', 'clang'], None, {}, time.monotonic() - 1)
            spawn.assert_not_called()
            row = [r for r in self.rows(journal) if r['kind'] == 'command' and r['status'] == 'failed'][0]
            self.assert_complete(row)
            self.assertIsNone(row['exitStatus'])

    def test_redaction_byte_bounds_and_fixed_argument_tokens(self):
        with tempfile.TemporaryDirectory() as name:
            journal = diagnostics.Journal(Path(name) / 'rows', name, '/reviewed', time.monotonic(), ['secret-value'])
            self.assertNotIn('secret-value', journal.text('secret-value'))
            self.assertLessEqual(len(journal.text('é' * 5000).encode()), 4096)
            self.assertEqual(journal.tokens([name + '/app', '12', '--app=http://127.0.0.1:1234/screen-proof/host-a-1']),
                ['<private-root>/app', '12', '--app=<loopback-origin>/screen-proof/host-a-1'])

    def test_each_observer_phase_failure_has_tool_hash_exit_and_output(self):
        phases = ['initial', 'app-helper', 'chrome-launched', 'authorization-requested', 'final-setup', 'after-owned-cleanup']
        for label in ['app-preview', 'surface', 'host-a-1', 'host-a-2', 'host-b-1', 'host-b-2', 'authorization-requester']:
            phases += ['spawn-' + label, 'cleanup-' + label]
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                binary = root / 'owner-identity-probe'; binary.write_bytes(b'fixed observer')
                journal = diagnostics.Journal(root / 'rows', root, root, time.monotonic())
                observer = identity.Observer(binary, root, {}, time.monotonic() + 15, journal)
                def fail(args, **kwargs):
                    kwargs['stdout'].write(b'partial observer output')
                    kwargs['stderr'].write(b'{"step":"observer-host-preflight","exitStatus":2}')
                    return subprocess.CompletedProcess(args, 2)
                with patch.object(diagnostics.subprocess, 'run', side_effect=fail), self.assertRaisesRegex(ValueError, 'observer-failed'):
                    observer.read(phase, 12 if phase.startswith(('spawn-', 'cleanup-')) else None)
                row = [r for r in self.rows(journal) if r['kind'] == 'command' and r.get('exitStatus') == 2][0]
                self.assert_complete(row)
                self.assertEqual(row['step'], phase)
                self.assertEqual(row['tool']['sha256'], hashlib.sha256(b'fixed observer').hexdigest())
                self.assertIn('observer-host-preflight', row['stderrTail'])

    def test_each_fixed_launch_failure_and_child_exit_keeps_its_own_streams(self):
        labels = ['app-preview', 'surface', 'host-a-1', 'host-a-2', 'host-b-1', 'host-b-2', 'authorization-requester']
        for label in labels:
            for missing in [True, False]:
                with self.subTest(label=label, missing=missing), tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    binary = root / 'fixed-owned-helper'; binary.write_bytes(b'fixed helper')
                    journal = diagnostics.Journal(root / 'rows', root, root, time.monotonic())
                    observer = SimpleNamespace(journal=journal)
                    def spawn(args, **kwargs):
                        if missing: raise FileNotFoundError('fixed launch missing')
                        kwargs['stdout'].write(b'child stdout')
                        kwargs['stderr'].write(b'child stderr')
                        return SimpleNamespace(pid=123, returncode=7, wait=lambda timeout: 7)
                    with patch.object(identity.subprocess, 'Popen', side_effect=spawn):
                        if missing:
                            with self.assertRaises(FileNotFoundError):
                                journal.call(label, identity.Owned, label, [str(binary)], 'fixed.role', 'a' * 40, observer, {}, io.BytesIO())
                        else:
                            child = journal.call(label, identity.Owned, label, [str(binary)], 'fixed.role', 'a' * 40, observer, {}, io.BytesIO())
                            self.assertTrue(child.reap(0))
                    row = [r for r in self.rows(journal) if r['kind'] == 'command' and r['status'] == 'failed'][0]
                    self.assert_complete(row)
                    self.assertEqual(row['step'], label)
                    self.assertEqual(row['exitStatus'], None if missing else 7)
                    if not missing:
                        self.assertEqual(row['stdoutTail'], 'child stdout')
                        self.assertEqual(row['stderrTail'], 'child stderr')

    def test_owned_timeout_retains_actual_kill_status_and_tails(self):
        with tempfile.TemporaryDirectory() as name:
            journal = diagnostics.Journal(Path(name) / 'rows', name, name, time.monotonic())
            class Child:
                pid, returncode = 123, None
                def wait(self, timeout):
                    if self.returncode is None:
                        self.returncode = -15
                        raise subprocess.TimeoutExpired(['fixed'], timeout)
                    return self.returncode
            def spawn(args, **kwargs):
                kwargs['stdout'].write(b'last stdout')
                kwargs['stderr'].write(b'last stderr')
                return Child()
            with patch.object(diagnostics.subprocess, 'Popen', side_effect=spawn), self.assertRaises(subprocess.TimeoutExpired):
                journal.call('observer-build', journal.owned, ['/usr/bin/xcrun', 'clang'], None, {}, time.monotonic() + 1)
            row = [r for r in self.rows(journal) if r['kind'] == 'command' and r['status'] == 'failed'][0]
            self.assert_complete(row)
            self.assertEqual(row['exitStatus'], -15)
            self.assertEqual(row['stderrTail'], 'last stderr')

    def test_expected_refusal_is_recorded_without_changing_manifest_semantics(self):
        with tempfile.TemporaryDirectory() as name:
            pipeline = Pipeline(name)
            self.assertEqual(pipeline.execute(), 0)
            rows = self.rows(pipeline.journal)
            refused = [r for r in rows if r['kind'] == 'command' and r.get('exitStatus') == 3]
            self.assertEqual(len(refused), 1)
            self.assertEqual(refused[0]['stderrTail'], 'app role refused')
            self.assertNotIn('test-secret', pipeline.journal.path.read_text())

    def test_age_download_and_seal_failure_are_named_and_never_success(self):
        for stage, args in [('age-download', ['/usr/bin/curl', '--output', 'fixed-archive']),
                            ('evidence-seal', ['/fixed/age', '--encrypt', '--recipient', 'fixed-public-recipient'])]:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as name:
                journal = diagnostics.Journal(Path(name) / 'rows', name, name, time.monotonic())
                def spawn(args, **kwargs):
                    kwargs['stdout'].write(b'download-or-seal-output')
                    kwargs['stderr'].write(b'download-or-seal-error')
                    return SimpleNamespace(pid=123, returncode=1, wait=lambda timeout: 1)
                with patch.object(diagnostics.subprocess, 'Popen', side_effect=spawn), self.assertRaises(subprocess.CalledProcessError):
                    journal.call(stage, journal.owned, args, None, {}, time.monotonic() + 10)
                row = [r for r in self.rows(journal) if r['kind'] == 'command' and r.get('exitStatus') == 1][0]
                self.assert_complete(row)
                self.assertEqual(row['step'], stage)
                self.assertEqual(row['stderrTail'], 'download-or-seal-error')

    def test_chrome_typed_policy_accepts_only_valid_identity_and_exact_detritus(self):
        import copy
        cases = [(chrome_record(), 0, True)]
        clean = chrome_record(); clean['policy'].update(strictStatus=0, detritusTolerated=False)
        cases.append((clean, 0, True))
        for key, value in [('identityStatus', -67050), ('strictStatus', -67054), ('strictStatus', -67055),
                           ('strictStatus', -67050), ('strictStatus', -50), ('identityFlags', 0), ('strictFlags', 16),
                           ('requirement', 'identifier "com.google.Chrome"'), ('detritusTolerated', False)]:
            bad = copy.deepcopy(chrome_record()); bad['policy'][key] = value
            cases.append((bad, 0, False))
        for key, value in [('team', 'WRONGTEAM'), ('identifier', 'other'), ('cdHash', 'bad'), ('accepted', False), ('createStatus', -50)]:
            bad = copy.deepcopy(chrome_record()); bad[key] = value
            cases.append((bad, 0, False))
        cases.append((chrome_record(), 1, False))
        for record, code, accepted in cases:
            with self.subTest(record=record, code=code), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                journal = diagnostics.Journal(root / 'rows', root, root, time.monotonic())
                def run(args, **kwargs):
                    kwargs['stdout'].write(json.dumps(record).encode())
                    kwargs['stderr'].write(b'fixed typed verifier output')
                    return subprocess.CompletedProcess(args, code)
                with patch.object(diagnostics.subprocess, 'run', side_effect=run):
                    if accepted:
                        self.assertEqual(journal.call('chrome-signature', wrapper.chrome_identity, root / 'owner-identity-probe', root, {}, time.monotonic() + 10, journal), 'a' * 40)
                    else:
                        with self.assertRaises(ValueError):
                            journal.call('chrome-signature', wrapper.chrome_identity, root / 'owner-identity-probe', root, {}, time.monotonic() + 10, journal)
                self.assertEqual(json.loads((root / 'chrome-static-identity.json').read_text()), record)

    def test_every_closed_validation_stage_preserves_failure_cause(self):
        for stage in diagnostics.STEPS:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as name:
                journal = diagnostics.Journal(Path(name) / 'rows', name, name, time.monotonic())
                def fail(): raise ValueError('fixed validation failure')
                with self.assertRaises(ValueError): journal.call(stage, fail)
                row = self.rows(journal)[-1]
                self.assertEqual(row['step'], stage)
                self.assertEqual(row['message'], 'fixed validation failure')
                self.assertEqual(row['exceptionClass'], 'ValueError')
                for field in ['tool', 'arguments', 'exitStatus', 'stdoutTail', 'stderrTail']:
                    self.assertIn(field, row)


if __name__ == '__main__':
    unittest.main()
