from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest

BASE = Path(__file__).resolve().parents[2] / 'script/runner-proof'
sys.path.insert(0, str(BASE))
import prerequisite_stage as stage
import prerequisite_artifact as artifact
import prerequisite_kernel as kernel


def platform_record():
    paths = [{'path': p, 'device': 1, 'inode': i + 1, 'uid': 0, 'gid': 0,
              'mode': stat.S_IFREG | (0o4511 if p.endswith('sudo') else 0o755) if p in stage.TOOLS else stat.S_IFDIR | 0o755}
             for i, p in enumerate(stage.PATHS)]
    return {'schema': 1, 'accepted': True, 'statfs': {'status': 0, 'errno': 0, 'flags': stage.FLAGS,
            'mountPoint': '/', 'mountedFrom': 'snapshot', 'filesystem': 'apfs'},
            'capabilities': {'status': 0, 'errno': 0, 'length': 36, 'expectedLength': 36, 'validFormat': stage.SEALED, 'format': stage.SEALED},
            'root': copy.deepcopy(paths[0]), 'paths': paths}


def wire(value):
    return (json.dumps(value) + '\n').encode()


def sample(pid=7, parent=4, uid=0, seconds='100', path='/Library/SliccyProof-5/Sliccy.app/Contents/MacOS/Sliccy'):
    return {'pid': pid, 'bsdStatus': 0, 'pathStatus': 0, 'path': path,
            'bsd': {'pid': pid, 'parent': parent, 'uid': uid, 'seconds': seconds, 'microseconds': 0}}


def candidate():
    root = sample()
    return {'sudoPID': 4, 'launchWall': 99.5, 'before': root, 'after': copy.deepcopy(root),
            'chain': [copy.deepcopy(root), sample(pid=4, parent=2, path='/usr/bin/sudo')],
            'chainAfter': [copy.deepcopy(root), sample(pid=4, parent=2, path='/usr/bin/sudo')],
            'code': {'identifier': 'ai.sliccy.mac', 'path': root['path'], 'hash': kernel.APP_HASH, 'matched': True}}


class PlatformTests(unittest.TestCase):
    def test_exact_flags_valid_capability_and_execute_only_sudo(self):
        row = platform_record()
        self.assertEqual(stage.platform(wire(row), 0), row)
        for field, bit in [('flags', 1), ('flags', 0x4000), ('flags', 0x40000000), ('validFormat', stage.SEALED), ('format', stage.SEALED)]:
            bad = copy.deepcopy(row)
            bad['statfs' if field == 'flags' else 'capabilities'][field] &= ~bit
            with self.subTest(field=field, bit=bit), self.assertRaises(ValueError):
                stage.platform(wire(bad), 0)

    def test_tool_no_links_root_device_owner_set(self):
        row = platform_record()
        for index in range(len(row['paths'])):
            for field, value in [('uid', 501), ('device', 2), ('mode', stat.S_IFLNK | 0o777), ('inode', 0)]:
                bad = copy.deepcopy(row); bad['paths'][index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    stage.platform(wire(bad), 0)
        for field, value in [('schema', True), ('accepted', 1)]:
            bad = copy.deepcopy(row); bad[field] = value
            with self.assertRaises(ValueError): stage.platform(wire(bad), 0)
        bad = copy.deepcopy(row); bad['paths'].append(bad['paths'][-1])
        with self.assertRaises(ValueError): stage.platform(wire(bad), 0)

    def test_native_has_fixed_readonly_entry_without_content_open(self):
        source = (BASE / 'prerequisite_platform.m').read_text()
        self.assertIn('VOL_CAP_FMT_SEALED', source)
        self.assertIn('FSOPT_REPORT_FULLSIZE', source)
        self.assertNotIn(' open(', source)
        self.assertNotIn('posix_spawn', source)


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / 'source/Sliccy.app'
        self.source.mkdir(parents=True)
        (self.source / 'Contents').mkdir()
        self.data = b'approved fixture synthetic bytes'
        (self.source / 'Contents/data').write_bytes(self.data)
        (self.source / 'Contents/data').chmod(0o644)
        self.source.chmod(0o755); (self.source / 'Contents').chmod(0o755)
        self.expected = {'directories': ['Contents'], 'files': {'Contents/data': {'sha256': hashlib.sha256(self.data).hexdigest(), 'size': len(self.data), 'mode': 0o644}}}
        self.root = self.base / 'Library'; self.root.mkdir()
        self.calls, self.records = [], []
        self.failure = None
        self.checked = 0
        self.outside = self.base / 'sentinel'; self.outside.write_text('outside')

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self, path):
        value = path.lstat()
        if not stat.S_ISDIR(value.st_mode): raise ValueError('not-directory')
        return [value.st_dev, value.st_ino]

    def platform(self, deadline):
        self.checked += 1

    def invoke(self, name, args, deadline):
        self.calls.append((name, args))
        self.assertEqual(args[:3], ['/usr/bin/sudo', '-n', '--'])
        self.assertGreater(deadline, time.monotonic())
        if self.failure == name:
            error = ValueError('synthetic failure'); error.settled = True; raise error
        tool = args[3]
        if tool == '/bin/mkdir':
            self.assertEqual(args[4:6], ['-m', '0755'])
            Path(args[6]).mkdir(mode=0o755)
        elif tool == '/bin/cp':
            self.assertEqual(args[4], '-R'); self.assertNotIn('-p', args)
            shutil.copytree(args[5], Path(args[6]) / 'Sliccy.app')
        elif tool == '/bin/rm':
            self.assertEqual(args[4], '-rf'); shutil.rmtree(args[5])
        else: self.fail('unexpected root tool')
        return SimpleNamespace(returncode=0, settled=True, pid=123)

    def make(self, sink=None, verify=None, identify=None):
        return stage.Stage('7', self.source, self.expected, self.invoke, verify or (lambda path, end: None), self.platform,
            sink or (lambda *value: self.records.append(value)), root=self.root, inspect=self.inspect,
            tree=lambda path, expected, **kwargs: stage.validate_tree(path, expected, owner=False, deadline=kwargs['deadline']),
            identify=identify or self.inspect)

    def test_copy_validation_then_exact_removal(self):
        subject = self.make()
        app = subject.create(time.monotonic() + 70)
        self.assertTrue(subject.validated)
        self.assertEqual(app, self.root / 'SliccyProof-7/Sliccy.app')
        subject.remove(time.monotonic() + 5); self.assertTrue(subject.finish()['complete'])
        self.assertEqual([x[0] for x in self.calls], ['staging-mkdir', 'staging-copy', 'staging-removal'])
        self.assertEqual(self.checked, 3)
        self.assertEqual(self.outside.read_text(), 'outside')

    def test_copy_failure_still_removes(self):
        self.failure = 'staging-copy'
        subject = self.make()
        with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
        self.assertTrue(caught.exception.facts['removalConfirmed'])
        self.assertFalse(subject.path.exists()); subject.delivery.close()

    def test_blocked_diagnostic_does_not_block_recovery(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(*args): entered.set(); release.wait()
        self.failure = 'staging-copy'; subject = self.make(blocked)
        started = time.monotonic()
        try:
            with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
            self.assertLess(time.monotonic() - started, 1)
            self.assertTrue(caught.exception.facts['removalConfirmed'])
            self.assertFalse(subject.path.exists())
            self.assertTrue(entered.wait(.5))
            self.assertFalse(subject.delivery.snapshot()['complete'])
        finally: release.set(); subject.delivery.close()

    def test_broken_diagnostic_does_not_block_removal(self):
        def broken(*args): raise RuntimeError('sink')
        subject = self.make(broken); self.failure = 'staging-copy'
        with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
        self.assertTrue(caught.exception.facts['removalConfirmed']); subject.delivery.close()

    def test_missing_identity_never_confirmed(self):
        def missing(path): raise ValueError('identity unavailable')
        subject = self.make(identify=missing)
        with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
        self.assertFalse(caught.exception.facts['removalConfirmed'])
        self.assertEqual(caught.exception.facts['removalState'], 'unconfirmed')
        self.assertNotIn('staging-removal', [x[0] for x in self.calls]); subject.delivery.close()

    def test_unsettled_writer_never_removed(self):
        subject = self.make(); actual = subject.invoke
        def unfinished(name, args, deadline):
            if name == 'staging-copy':
                error = TimeoutError('copy'); error.settled = False; raise error
            return actual(name, args, deadline)
        subject.invoke = unfinished
        with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
        self.assertFalse(caught.exception.facts['removalConfirmed'])
        self.assertNotIn('staging-removal', [x[0] for x in self.calls]); subject.delivery.close()

    def test_reaped_sudo_with_surviving_writer_never_admits_removal(self):
        for code in (-9, -15, 1, 137):
            with self.subTest(code=code):
                subject = self.make()
                actual = subject.invoke
                writer_started, release_writer = threading.Event(), threading.Event()
                def surviving_writer():
                    writer_started.set()
                    release_writer.wait()
                writer = threading.Thread(target=surviving_writer)
                writer.start()
                self.assertTrue(writer_started.wait(.5))
                command_records = []
                child = mock.Mock(pid=777, returncode=code)
                child.wait.return_value = code
                child.poll.return_value = code
                command = stage.FixedCommand(lambda *row: command_records.append(row), spawn=mock.Mock(return_value=child))
                def invoke(name, args, deadline):
                    if name == 'staging-copy':
                        return command(name, args, deadline)
                    if name == 'staging-removal':
                        self.fail('removal raced surviving writer')
                    return actual(name, args, deadline)
                subject.invoke = invoke
                try:
                    with self.assertRaises(ValueError) as caught:
                        subject.create(time.monotonic() + 70)
                    self.assertTrue(writer.is_alive())
                    self.assertFalse(subject.settled)
                    self.assertEqual(subject.removal_state, 'unconfirmed-writer')
                    self.assertFalse(caught.exception.facts['removalConfirmed'])
                    self.assertEqual(caught.exception.facts['cleanup'], 'cleanup-writer-unsettled')
                    completed = command_records[-1][1]
                    self.assertTrue(completed['sudoReaped'])
                    self.assertFalse(completed['settled'])
                    self.assertEqual(completed['writerSettlement'], 'unconfirmed')
                    child.kill.assert_not_called(); child.terminate.assert_not_called()
                finally:
                    release_writer.set(); writer.join(.5)
                    self.assertFalse(writer.is_alive())
                    subject.delivery.close()
                    shutil.rmtree(subject.path)

    def test_abnormal_adapter_result_cannot_claim_settled(self):
        subject = self.make()
        subject.invoke = lambda *args: SimpleNamespace(returncode=-9, settled=True)
        with self.assertRaisesRegex(ValueError, 'staging-writer-unsettled'):
            subject.command('staging-copy', ['/bin/cp', '-R', '/source', '/destination'], time.monotonic()+5)
        self.assertFalse(subject.settled)
        subject.delivery.close()

    def test_timeout_with_reaped_nonzero_sudo_leaves_writer_unconfirmed(self):
        for code in (-9, 1, 137):
            child = mock.Mock(pid=777, returncode=code)
            child.wait.side_effect = TimeoutError('deadline')
            child.poll.return_value = code
            rows = []
            command = stage.FixedCommand(lambda *args: rows.append(args), spawn=mock.Mock(return_value=child))
            with self.assertRaises(TimeoutError) as caught:
                command('staging-copy', ['/usr/bin/sudo', '-n', '--', '/bin/cp', '-R', '/source', '/destination'], time.monotonic()+5)
            self.assertFalse(caught.exception.settled)
            self.assertTrue(rows[-1][1]['sudoReaped'])
            self.assertFalse(rows[-1][1]['settled'])

    def test_fixed_command_zero_exit_control(self):
        child = mock.Mock(pid=777, returncode=0)
        child.wait.return_value = 0
        rows = []
        command = stage.FixedCommand(lambda *args: rows.append(args), spawn=mock.Mock(return_value=child))
        result = command('staging-copy', ['/usr/bin/sudo', '-n', '--', '/bin/cp', '-R', '/source', '/destination'], time.monotonic()+5)
        self.assertTrue(result.settled)
        self.assertEqual(rows[-1][1]['writerSettlement'], 'normal-zero-exit')

    def test_validation_failure_removes_and_never_ready(self):
        def fail(path, end): raise ValueError('signature')
        subject = self.make(verify=fail)
        with self.assertRaises(ValueError) as caught: subject.create(time.monotonic() + 70)
        self.assertTrue(caught.exception.facts['removalConfirmed']); self.assertFalse(subject.validated)
        subject.delivery.close()

    def test_replaced_directory_or_symlink_refuses_removal(self):
        subject = self.make(); subject.create(time.monotonic() + 70)
        moved = self.root / 'retained'; subject.path.rename(moved)
        subject.path.symlink_to(self.outside)
        with self.assertRaises(ValueError): subject.remove(time.monotonic() + 5)
        self.assertEqual(self.outside.read_text(), 'outside'); subject.delivery.close()

    def test_tree_bytes_mode_links_extra_refused(self):
        target = self.source / 'Contents/data'
        for mutation in ('bytes', 'mode', 'symlink', 'extra'):
            with self.subTest(mutation=mutation):
                original = target.read_bytes(); original_mode = target.stat().st_mode
                if mutation == 'bytes': target.write_bytes(b'bad')
                if mutation == 'mode': target.chmod(0o666)
                if mutation == 'symlink': target.unlink(); target.symlink_to(self.outside)
                extra = self.source / 'extra'
                if mutation == 'extra': extra.write_text('bad')
                with self.assertRaises(ValueError): stage.validate_tree(self.source, self.expected, owner=False)
                if target.is_symlink(): target.unlink()
                target.write_bytes(original); target.chmod(stat.S_IMODE(original_mode))
                if extra.exists(): extra.unlink()

    def test_fixed_spawn_umask_no_python_or_signals_on_timeout(self):
        child = mock.Mock(pid=123, returncode=None)
        child.wait.side_effect = TimeoutError('fixed timeout'); child.poll.return_value = None
        spawn = mock.Mock(return_value=child)
        command = stage.FixedCommand(lambda *args: None, spawn=spawn)
        with self.assertRaises(TimeoutError) as caught:
            command('staging-copy', ['/usr/bin/sudo', '-n', '--', '/bin/cp', '-R', '/source', '/dest/'], time.monotonic() + 5)
        self.assertFalse(caught.exception.settled)
        self.assertEqual(spawn.call_args.kwargs['umask'], 0o022)
        self.assertEqual(spawn.call_args.kwargs['env'], {})
        child.kill.assert_not_called(); child.terminate.assert_not_called()
        self.assertEqual(command.retained, [child])


class KernelTests(unittest.TestCase):
    def test_candidate_binding_and_all_field_conflicts(self):
        value = candidate(); launch = {'pid': 4, 'launchWall': 99.5}
        self.assertEqual(kernel.root_candidate(value, launch, value['before']['path'])['pid'], 7)
        for field, replacement in [('pid', 9), ('parent', 99), ('uid', 501), ('seconds', '101'), ('microseconds', 1)]:
            bad = copy.deepcopy(value); bad['chain'][0]['bsd'][field] = replacement
            bad['chainAfter'] = copy.deepcopy(bad['chain'])
            with self.subTest(field=field), self.assertRaises(ValueError):
                kernel.root_candidate(bad, launch, value['before']['path'])
        for key, replacement in [('sudoPID', 99), ('launchWall', 1)]:
            bad = copy.deepcopy(value); bad[key] = replacement
            with self.assertRaises(ValueError): kernel.root_candidate(bad, launch, value['before']['path'])

    def test_target_available_denied_and_contradictions(self):
        identity = {'pid': 42, 'parent': 1, 'uid': 88, 'seconds': 100, 'microseconds': 4}
        code = {'identifier': 'com.apple.WindowServer', 'path': '/System/WindowServer', 'hash': base64.b64encode(b'a'*20).decode(), 'matched': True}
        facts = {'schema': 1, 'sample': identity, 'path': code['path'], 'hash': code['hash']}
        observed = {'sample': sample(pid=42, parent=1, uid=88, path=code['path']), 'code': code}
        observed['sample']['bsd']['microseconds'] = 4
        self.assertTrue(kernel.target_binding(observed, copy.deepcopy(observed), facts, 42))
        for field, replacement in [('pid', 9), ('parent', 2), ('uid', 0), ('seconds', 101), ('microseconds', 5)]:
            bad = copy.deepcopy(facts); bad['sample'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): kernel.target_binding(observed, observed, bad, 42)
        denied = copy.deepcopy(observed); denied['sample'].update(bsdStatus=1, bsd=None)
        self.assertTrue(kernel.target_binding(denied, copy.deepcopy(denied), facts, 42))
        denied['sample']['bsdStatus'] = 3
        with self.assertRaises(ValueError): kernel.target_binding(denied, denied, facts, 42)

    def test_expected_native_cdhash_matches_manifest(self):
        expected = json.loads((BASE / 'prerequisite-artifact.json').read_text())
        encoded = base64.b64encode(bytes.fromhex(expected['manifest']['executable']['CDHash'])).decode()
        self.assertEqual(encoded, kernel.APP_HASH)
        self.assertIn('@"' + encoded + '"', (BASE / 'prerequisite_kernel.m').read_text())


def protocol_rows():
    rows = []
    def add(phase, state, facts):
        rows.append({'schema': 2, 'seq': len(rows) + 1, 'phase': phase, 'state': state, 'elapsedMs': len(rows) * .1, 'facts': facts})
    def pair(phase, facts, result):
        add(phase, 'entered', facts); add(phase, 'completed', result)
    def checks(designated):
        for phase in ('file-static', 'requirement', 'static-validity', 'file-info', 'guest', 'dynamic-validity', 'guest-static', 'live-info', 'kernel-hash'):
            entry = {}
            if phase == 'requirement': entry = {'designated': designated, 'rule': 'staged-build12-designated-requirement' if designated else 'anchor apple and identifier "com.apple.WindowServer"'}
            if phase in ('static-validity', 'dynamic-validity'): entry = {'flags': 25 if phase == 'static-validity' else 16}
            pair(phase, entry, {'status': 0})
    executable = sample()['path']
    identity = {'pid': 42, 'parent': 1, 'uid': 88, 'seconds': 100, 'microseconds': 0}
    target = {'sample': {'pid': 42, 'bsdStatus': 1, 'pathStatus': 0, 'bsd': None, 'path': '/System/WindowServer'},
              'code': {'identifier': 'com.apple.WindowServer', 'path': '/System/WindowServer', 'hash': base64.b64encode(b'w'*20).decode(), 'matched': True}}
    pair('placement', {}, {'run': '5', 'target': 42, 'executable': executable})
    checks(False); add('target-before', 'completed', target)
    pair('spawn', {'tool': '/usr/bin/sudo', 'executable': executable, 'target': 42}, {'status': 0, 'pid': 4, 'launchWall': 99.5})
    pair('hello', {}, {'rawBase64': base64.b64encode(wire({'schema': 1, 'pid': 7}).rstrip()).decode()})
    checks(True); add('candidate', 'completed', candidate()); add('ack', 'completed', {'rootPID': 7})
    pair('facts', {}, {'rawBase64': base64.b64encode(wire({'schema': 1, 'sample': identity, 'path': target['code']['path'], 'hash': target['code']['hash']}).rstrip()).decode()})
    checks(False); add('target-after', 'completed', copy.deepcopy(target))
    add('reap', 'entered', {'pid': 4})
    pair('root-exit-bsd', {'pid': 7}, {'pid': 7, 'status': 3})
    add('reap', 'completed', {'pid': 4, 'reaped': True, 'rootGone': True, 'rootPID': 7, 'waitStatus': 0, 'errno': 0})
    add('result', 'completed', {'observed': True, 'reaped': True, 'rootGone': True})
    return rows


class CompleteProtocolTests(unittest.TestCase):
    def test_complete_protocol_and_named_failures(self):
        rows = protocol_rows()
        raw = b''.join(wire(x) for x in rows)
        self.assertTrue(kernel.outcome(kernel.parse(raw), 0, '5', 42)['rootVisibility'])
        for change in ('gap', 'truncated', 'cross-pid', 'hello-pid', 'ack-pid', 'root-not-gone', 'wrong-flags', 'missing-check', 'changed-target', 'numeric-boolean', 'duplicate-ack'):
            bad = copy.deepcopy(rows)
            if change == 'cross-pid': next(x for x in bad if x['phase'] == 'spawn' and x['state'] == 'completed')['facts']['pid'] = 99
            if change == 'hello-pid': next(x for x in bad if x['phase'] == 'hello' and x['state'] == 'completed')['facts']['rawBase64'] = base64.b64encode(wire({'schema': 1, 'pid': 99}).rstrip()).decode()
            if change == 'ack-pid': next(x for x in bad if x['phase'] == 'ack')['facts']['rootPID'] = 99
            if change == 'root-not-gone': next(x for x in bad if x['phase'] == 'reap' and x['state'] == 'completed')['facts']['rootGone'] = False
            if change == 'wrong-flags': next(x for x in bad if x['phase'] == 'static-validity' and x['state'] == 'entered')['facts']['flags'] = 9
            if change == 'missing-check': bad = [x for x in bad if x['phase'] != 'kernel-hash']
            if change == 'changed-target': next(x for x in bad if x['phase'] == 'target-after')['facts']['code']['hash'] = base64.b64encode(b'x'*20).decode()
            if change == 'numeric-boolean': bad[-1]['facts']['observed'] = 1
            if change == 'duplicate-ack': bad.insert(-1, copy.deepcopy(next(x for x in bad if x['phase'] == 'ack')))
            for i, row in enumerate(bad, 1): row['seq'] = i; row['elapsedMs'] = i*.1
            if change == 'gap': bad[1]['seq'] += 1
            data = b''.join(wire(x) for x in bad)
            if change == 'truncated': data = data[:-1]
            with self.subTest(change=change), self.assertRaises(ValueError): kernel.outcome(kernel.parse(data), 0, '5', 42)

    def test_failed_child_can_be_cleaned_but_not_passed(self):
        rows = protocol_rows()
        next(x for x in rows if x['phase'] == 'reap' and x['state'] == 'completed')['facts']['waitStatus'] = 512
        self.assertTrue(kernel.cleanup_confirmed(rows))
        with self.assertRaises(ValueError): kernel.outcome(rows, 2, '5', 42)

    def test_truncated_spawn_never_cleanup_confirmation(self):
        rows = protocol_rows()
        rows = [x for x in rows if x['phase'] != 'spawn' or x['state'] != 'completed']
        with self.assertRaises(ValueError): kernel.cleanup_confirmed(rows)


class DiagnosticTests(unittest.TestCase):
    def test_step_sink_blocked_cannot_block_recovery(self):
        import prerequisite_diagnostics as diagnostics
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = diagnostics.Journal(root / 'journal', root, root, time.monotonic())
            entered, release = threading.Event(), threading.Event()
            def block(row): entered.set(); release.wait()
            journal.write = block; journal.begin_async()
            try:
                with journal.step('staging'): journal.write({'status': 'entered'})
                self.assertTrue(entered.wait(.5))
                with self.assertRaises(ValueError): journal.check_async()
                self.assertFalse(journal.end_async()['complete'])
            finally: release.set()

    def test_async_command_failures_retain_status_and_tails(self):
        import prerequisite_diagnostics as diagnostics
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = diagnostics.Journal(root / 'journal', root, root, time.monotonic()); journal.begin_async()
            def run(args, stdout, stderr, **kwargs):
                stdout.write(b'o'*5000); stderr.write(b'e'*5000)
                return SimpleNamespace(returncode=1)
            with mock.patch.object(diagnostics.subprocess, 'run', side_effect=run):
                with journal.step('staged-signature'):
                    journal.run(['/usr/bin/codesign', '--verify', '/fixed'], capture_output=True)
            self.assertTrue(journal.end_async()['complete'])
            failed = next(x for x in map(json.loads, (root / 'journal').read_text().splitlines()) if x.get('exitStatus') == 1)
            self.assertEqual(len(failed['stdoutTail']), 4096); self.assertEqual(len(failed['stderrTail']), 4096)


class WrapperIntegrationTests(unittest.TestCase):
    def test_actual_suite_mocked_end_to_end_and_root_failure_cleanup(self):
        import prerequisite_diagnostics as diagnostics
        import sealed_prerequisite as wrapper
        import capture_stage as prior
        for native_failure in (False, True):
            with self.subTest(native_failure=native_failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); evidence = root / 'evidence'; evidence.mkdir()
                created = []
                expected = {'artifact': '13331283695', 'manifest': {}, 'manifestSHA256': hashlib.sha256(b'{}').hexdigest(),
                            'innerSHA256': 'inner', 'outerSHA256': 'outer', 'source': 'source', 'run': 'run'}
                def extraction(archive, destination, value, outer=False):
                    destination.mkdir()
                    if outer:
                        (destination / 'capture-manifest.json').write_bytes(b'{}')
                        (destination / 'SHA256SUMS').write_text('inner  Sliccy-0.1.0.zip')
                        (destination / 'Sliccy-0.1.0.zip').write_bytes(b'zip')
                    else: (destination / 'Sliccy.app').mkdir()
                    return destination
                def run(args, stdout, stderr, **kwargs):
                    if '-o' in args: Path(args[-1]).write_bytes(b'synthetic-binary')
                    if Path(args[0]).name == 'prerequisite-platform': stdout.write(wire(platform_record()))
                    if args[0] == '/usr/bin/pgrep': stdout.write(b'42\n')
                    if args[1:2] == ['api']:
                        self.assertEqual(kwargs['env'].get('GH_TOKEN'), 'downloader-only')
                        stdout.write(b'archive')
                    else: self.assertNotIn('GH_TOKEN', kwargs.get('env', {}))
                    return SimpleNamespace(returncode=0)
                class FakeStage:
                    def __init__(self, *args):
                        self.delivery = prior.DiagnosticDelivery(args[-1]); self.removal_state = 'unconfirmed'
                        self.identity = [1,2]; self.settled = True; self.validated = False
                        created.append(self)
                    def create(self, deadline): self.validated = True
                    def remove(self, deadline):
                        if not self.settled: raise ValueError('not settled')
                        self.removal_state = 'confirmed-by-inode'; return self.removal_state
                    def finish(self):
                        self.delivery.finish_success(); return self.delivery.close()
                def spawn(args, stdout, stderr, **kwargs):
                    self.assertEqual(Path(args[0]).name, 'prerequisite-kernel')
                    self.assertEqual(args[1:], ['5','42'])
                    self.assertNotIn('GH_TOKEN', kwargs['env'])
                    rows = protocol_rows()
                    if native_failure:
                        next(x for x in rows if x['phase'] == 'reap' and x['state'] == 'completed')['facts']['waitStatus'] = 512
                    stdout.write(b''.join(wire(x) for x in rows))
                    return mock.Mock(pid=123, returncode=2 if native_failure else 0, wait=mock.Mock(return_value=2 if native_failure else 0))
                journal = diagnostics.Journal(evidence / 'steps', root, BASE.parent.parent, time.monotonic())
                with mock.patch.dict(os.environ, {'GH_TOKEN':'downloader-only', 'GITHUB_RUN_ID':'5'}), \
                     mock.patch.object(wrapper.shared.setup, 'discover_gh', return_value='/fixed/gh'), \
                     mock.patch.object(artifact, 'expectation', return_value=expected), \
                     mock.patch.object(artifact, 'extract', side_effect=extraction), \
                     mock.patch.object(artifact, 'signature', return_value=None), \
                     mock.patch.object(artifact, 'normalized', return_value=expected), \
                     mock.patch.object(stage, 'validate_tree', return_value={}), \
                     mock.patch.object(stage, 'Stage', FakeStage), \
                     mock.patch.object(stage, 'PlatformCheck', return_value=lambda end: platform_record()), \
                     mock.patch.object(diagnostics.subprocess, 'run', side_effect=run), \
                     mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=spawn):
                    result = wrapper.suite(root, evidence, None, {}, time.monotonic()+200, BASE.parent.parent, journal)
                self.assertEqual(result, 1 if native_failure else 0)
                outcome = json.loads((evidence / 'prerequisite-outcome.json').read_text())
                self.assertTrue(outcome['removalConfirmed'])
                self.assertEqual(outcome['rootVisibility'], not native_failure)
                self.assertEqual(created[0].removal_state, 'confirmed-by-inode')


class ArtifactPreparationTests(unittest.TestCase):
    def test_normalize_only_disposable_modes_with_bytes_and_signature_recheck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'original/Sliccy.app'
            source.mkdir(parents=True); source.chmod(0o755)
            data = {'private': (b'data', 0o600), 'helper': (b'executable', 0o700)}
            files = {}
            for name, (body, mode) in data.items():
                path = source / name; path.write_bytes(body); path.chmod(mode)
                files[name] = {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'mode': mode}
            expected = {'files': files, 'directories': []}
            destination = root / 'normalized'
            with mock.patch.object(artifact, 'signature') as signature:
                changed = artifact.normalized(source, destination, expected, lambda *args: None)
                signature.assert_called_once()
                self.assertEqual(signature.call_args.args[0], destination)
            for name, (body, mode) in data.items():
                self.assertEqual((source / name).read_bytes(), body)
                self.assertEqual(stat.S_IMODE((source / name).stat().st_mode), mode)
                self.assertEqual((destination / name).read_bytes(), body)
                self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o755 if mode & 0o111 else 0o644)
            self.assertEqual(changed['files']['helper']['mode'], 0o755)

    def test_staged_tree_requires_actual_root_ownership(self):
        self.assertNotEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o755)
            (root / 'data').write_bytes(b'data'); (root / 'data').chmod(0o644)
            expected = {'directories': [], 'files': {'data': {'sha256': hashlib.sha256(b'data').hexdigest(), 'size': 4, 'mode': 0o644}}}
            with self.assertRaisesRegex(ValueError, 'staging-entry-owner'):
                stage.validate_tree(root, expected, owner=True, acl=lambda fd: None)

    def test_runtime_map_exact(self):
        import sealed_prerequisite as wrapper
        value = wrapper.validate_sources(BASE.parent.parent)
        self.assertEqual(value['callerSource'], 'fa4ad8c65d47b075bbe0b96c20f920752108d732')


if __name__ == '__main__':
    unittest.main()
