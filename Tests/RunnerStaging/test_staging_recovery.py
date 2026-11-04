from pathlib import Path
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'script/runner-proof'
sys.path.insert(0, str(SCRIPTS))
import capture_stage_root as root
import capture_stage as adapter


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.library = self.home / 'library'
        self.library.mkdir()
        self.fd = os.open(self.library, root.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        self.outside = self.home / 'outside'
        self.outside.write_bytes(b'outside sentinel')
        self.source = self.home / 'Sliccy.app'
        executable = self.source / 'Contents/MacOS/Sliccy'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'fixed subject never executed')
        executable.chmod(0o700)
        self.expected = adapter.bundle_manifest(self.source, 'a' * 40, 'identifier "ai.sliccy.mac"')
        self.rows = []
        self.journal = root.Journal(write=self.record)

    def record(self, data):
        self.rows.append(json.loads(data))
        return len(data)

    def immutable(self, fd, directory):
        value = os.fstat(fd)
        self.assertEqual(stat.S_ISDIR(value.st_mode), directory)
        self.assertEqual(value.st_mode & 0o022, 0)
        if not directory:
            self.assertTrue(stat.S_ISREG(value.st_mode))
            self.assertEqual(value.st_nlink, 1)
        return value

    def assert_removed(self):
        self.assertFalse((self.library / 'SliccyProof-1').exists())
        self.assertEqual(self.outside.read_bytes(), b'outside sentinel')

    def test_controlled_timeout_in_actual_stage_runs_owned_cleanup(self):
        control = root.StopControl()
        def stop(*args, **kwargs):
            control.handle(signal.SIGALRM, None)
        with patch.object(root, 'immutable', self.immutable), patch.object(root, 'copy_tree', stop), \
             patch.object(root.signal, 'setitimer') as timer, self.assertRaises(root.ControlledStop):
            root.stage(self.fd, 'SliccyProof-1', self.expected, self.journal, time.monotonic() + 55, control)
        self.assert_removed()
        self.assertTrue(any(row['step'] == 'staging-create' and row['phase'] == 'completed' for row in self.rows))
        self.assertTrue(any(row['step'] == 'staging-removal' and row['phase'] == 'completed' for row in self.rows))
        self.assertLessEqual(timer.call_args.args[1], 5)

    def test_actual_main_installs_controlled_alarm_and_cleans_on_its_callback(self):
        handlers = {}
        def install(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL
        def timeout(*args, **kwargs):
            self.assertTrue(callable(handlers.get(signal.SIGALRM)))
            handlers[signal.SIGALRM](signal.SIGALRM, None)
        actual_open = root.open_absolute
        def absolute(path, directory, immutable=False):
            if path == '/Library':
                return os.dup(self.fd)
            return actual_open(path, directory, immutable)
        with patch.object(root, 'Journal', return_value=self.journal), \
             patch.object(root, 'immutable', self.immutable), patch.object(root, 'copy_tree', timeout), \
             patch.object(root, 'open_absolute', absolute), \
             patch.object(root, 'command', return_value=(b'27.0.1\n', b'')), \
             patch.object(root.os, 'geteuid', return_value=0), \
             patch.object(root.os, 'uname', return_value=SimpleNamespace(machine='arm64')), \
             patch.object(root.os, 'umask'), patch.object(root.os, 'set_blocking'), \
             patch.dict(root.os.environ, root.ASSERTIONS, clear=True), \
             patch.object(root.sys, 'platform', 'darwin'), \
             patch.object(root.sys, 'argv', ['fixed-program', 'stage', '1']), \
             patch.object(root.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(self.expected).encode()))), \
             patch.object(root.signal, 'signal', side_effect=install), \
             patch.object(root.signal, 'setitimer') as timer:
            self.assertEqual(root.main(), 2)
        self.assert_removed()
        self.assertTrue(any(row.get('reason') == 'staging-timeout' for row in self.rows))
        self.assertTrue(any(row['step'] == 'staging-removal' and row['phase'] == 'completed' for row in self.rows))
        self.assertEqual(timer.call_args.args, (signal.ITIMER_REAL, 0))

    def test_cancel_at_creation_defers_until_identity_record_and_then_cleans(self):
        control = root.StopControl()
        original = root.os.stat
        def sample(name, *args, **kwargs):
            value = original(name, *args, **kwargs)
            if name == 'SliccyProof-1' and control.deferred:
                control.handle(signal.SIGTERM, None)
            return value
        with patch.object(root, 'immutable', self.immutable), patch.object(root.os, 'stat', sample), \
             patch.object(root.signal, 'setitimer'), self.assertRaises(root.ControlledStop):
            root.stage(self.fd, 'SliccyProof-1', self.expected, self.journal, time.monotonic() + 55, control)
        self.assert_removed()
        creation = [row for row in self.rows if row['step'] == 'staging-create' and row['phase'] == 'completed']
        self.assertEqual(len(creation), 1)
        self.assertEqual(len(creation[0]['identity']), 2)

    def test_post_mkdir_open_failure_is_inside_cleanup_and_retains_identity(self):
        original = root.os.open
        failed = False
        def opening(name, *args, **kwargs):
            nonlocal failed
            if name == 'SliccyProof-1' and not failed:
                failed = True
                raise OSError('synthetic post-mkdir open failure')
            return original(name, *args, **kwargs)
        with patch.object(root, 'immutable', self.immutable), patch.object(root.os, 'open', opening), self.assertRaises(OSError):
            root.stage(self.fd, 'SliccyProof-1', self.expected, self.journal, time.monotonic() + 55)
        self.assert_removed()
        self.assertTrue(any('identity' in row and row['step'] == 'staging-create' for row in self.rows))

    def test_creation_sink_loss_cannot_prevent_removal(self):
        def broken(data):
            row = json.loads(data)
            if row['step'] != 'staging-create' or row['phase'] != 'entered':
                raise BrokenPipeError('synthetic closed sink')
            return len(data)
        with patch.object(root, 'immutable', self.immutable), self.assertRaisesRegex(ValueError, 'staging-cleanup-unconfirmed'):
            root.stage(self.fd, 'SliccyProof-1', self.expected, root.Journal(write=broken), time.monotonic() + 55)
        self.assert_removed()

    def test_broken_removal_entered_record_does_not_gate_deletion(self):
        directory = self.library / 'SliccyProof-1'
        directory.mkdir(mode=0o755)
        identity = [directory.stat().st_dev, directory.stat().st_ino]
        def broken(data):
            raise BrokenPipeError('synthetic closed sink')
        with patch.object(root, 'immutable', self.immutable), self.assertRaisesRegex(ValueError, 'cleanup-diagnostic-loss'):
            root.remove_owned(self.fd, directory.name, identity, root.Journal(write=broken))
        self.assert_removed()

    def test_signal_handlers_are_controlled_and_reserve_never_extends_absolute_end(self):
        ticks = [100]
        control = root.StopControl(clock=lambda: ticks[0])
        with patch.object(root.signal, 'signal', return_value=signal.SIG_DFL) as handlers, patch.object(root.signal, 'setitimer') as timer:
            control.install()
            self.assertEqual([c.args for c in handlers.call_args_list], [(sig, control.handle) for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)])
            self.assertEqual(timer.call_args.args, (signal.ITIMER_REAL, 55))
            ticks[0] = 158
            self.assertEqual(control.cleanup(), 160)
            self.assertEqual(timer.call_args.args, (signal.ITIMER_REAL, 2))
            ticks[0] = 160
            with self.assertRaisesRegex(ValueError, 'reserve-exhausted'):
                control.cleanup()
            control.close()

    def adapter_case(self, failure, callback_fails=False, settled=True, blocked=None, release=None, prior_confirmation=False):
        calls, persisted = [], []
        directory = self.library / 'SliccyProof-1'
        state = None
        def record(name, row):
            if blocked is not None:
                blocked.set()
                release.wait()
            if callback_fails:
                raise BrokenPipeError('synthetic callback failure')
            persisted.append((name, row))
        def invoke(step, args, payload, env, bound, on_stdout):
            calls.append(step)
            self.assertEqual(bound, 60)
            self.assertEqual(env, root.ASSERTIONS)
            raw = bytearray()
            def write(data):
                raw.extend(data)
                on_stdout(data)
                return len(data)
            journal = root.Journal(write=write)
            if step == 'root-staging-stage':
                directory.mkdir(mode=0o755)
                identity = [directory.stat().st_dev, directory.stat().st_ino]
                if failure in ('no-creation', 'truncated-creation'):
                    if failure == 'truncated-creation':
                        write(json.dumps(dict(schema=1, seq=1, step='staging-create', phase='completed',
                                              elapsedMs=0, directory=directory.name, identity=identity)).encode()[:-1])
                    return SimpleNamespace(returncode=2, stdout=bytes(raw), settled=True)
                journal.emit('staging-create', 'completed', directory=directory.name, identity=identity,
                             uid=0, gid=0, mode=0o755)
                self.assertEqual(state.identity, identity)
                if blocked is not None:
                    self.assertTrue(blocked.wait(1))
                if failure in ('partial', 'timeout', 'unsettled'):
                    write(b'{"schema":1,"seq":2')
                if failure in ('timeout', 'unsettled'):
                    error = subprocess.TimeoutExpired(args, bound, output=bytes(raw))
                    error.settled = settled
                    raise error
                if failure == 'callback':
                    journal.emit('staging-validated', 'completed', executable='/Library/SliccyProof-1/Sliccy.app/Contents/MacOS/Sliccy',
                                 cdhash='a' * 40, identity=identity)
                return SimpleNamespace(returncode=0, stdout=bytes(raw), settled=settled)
            self.assertEqual(step, 'root-staging-remove')
            self.assertEqual(json.loads(payload), {'identity': state.identity})
            with patch.object(root, 'immutable', self.immutable):
                root.remove_owned(self.fd, directory.name, json.loads(payload)['identity'], journal, time.monotonic() + 5)
            return SimpleNamespace(returncode=0, stdout=bytes(raw), settled=True)
        program = SCRIPTS / 'capture_stage_root.py'
        state = adapter.Stage('1', self.outside, hashlib.sha256(self.outside.read_bytes()).hexdigest(),
                              hashlib.sha256(program.read_bytes()).hexdigest(), invoke, record)
        if prior_confirmation:
            state.removal_state = 'confirmed-by-inode'
        submit = state.diagnostics.submit
        def submitted(name, row):
            if row.get('step') == 'staging-create' and row.get('phase') == 'completed':
                self.assertEqual(state.identity, row['identity'])
            submit(name, row)
        state.diagnostics.submit = submitted
        def checked(path, directory, immutable):
            return os.open(path, os.O_RDONLY)
        with patch.object(root, 'open_absolute', checked):
            with self.assertRaises(BaseException) as raised:
                state.create(self.expected)
        self.assertFalse(state.validated)
        return state, calls, raised.exception

    def test_truncated_last_record_retains_inode_and_runs_separate_removal(self):
        state, calls, error = self.adapter_case('partial')
        self.assertEqual(calls, ['root-staging-stage', 'root-staging-remove'])
        self.assertIsNone(state.identity)
        self.assertIn('incomplete', error.facts['originalReason'])
        self.assertTrue(error.facts['removalConfirmed'])
        self.assertEqual(state.removal_state, 'confirmed-by-inode')
        self.assert_removed()

    def test_timeout_retains_streamed_identity_and_confirms_separate_removal(self):
        state, calls, error = self.adapter_case('timeout')
        self.assertEqual(calls, ['root-staging-stage', 'root-staging-remove'])
        self.assertEqual(error.facts['original'], 'TimeoutExpired')
        self.assertTrue(error.facts['removalConfirmed'])
        self.assertIsNone(state.identity)
        self.assert_removed()

    def test_callback_loss_retains_identity_before_callback_and_still_removes(self):
        state, calls, error = self.adapter_case('callback', callback_fails=True)
        self.assertEqual(calls, ['root-staging-stage', 'root-staging-remove'])
        self.assertIsNone(state.identity)
        self.assertTrue(error.facts['removalConfirmed'])
        self.assertEqual(state.removal_state, 'confirmed-by-inode')
        self.assertGreater(error.facts['diagnostics']['failed'], 0)
        self.assert_removed()

    def test_unsettled_writer_is_named_failure_not_concurrent_unsafe_removal(self):
        state, calls, error = self.adapter_case('unsettled', settled=False)
        self.assertEqual(calls, ['root-staging-stage'])
        self.assertIsNotNone(state.identity)
        self.assertEqual(error.facts['cleanupReason'], 'cleanup-writer-unsettled')
        self.assertTrue((self.library / 'SliccyProof-1').exists())
        self.assertEqual(self.outside.read_bytes(), b'outside sentinel')

    def test_settled_failure_without_creation_identity_is_never_confirmed(self):
        state, calls, error = self.adapter_case('no-creation')
        self.assertEqual(calls, ['root-staging-stage'])
        self.assertIsNone(state.identity)
        self.assertEqual(state.removal_state, 'unconfirmed')
        self.assertFalse(error.facts['removalConfirmed'])
        self.assertEqual(error.reason, 'cleanup-creation-identity-unavailable')
        self.assertEqual(error.facts['cleanupReason'], 'cleanup-creation-identity-unavailable')
        self.assertTrue((self.library / 'SliccyProof-1').exists())
        self.assertEqual(self.outside.read_bytes(), b'outside sentinel')

    def test_truncated_creation_resets_prior_confirmation_and_never_guesses_removal(self):
        state, calls, error = self.adapter_case('truncated-creation', prior_confirmation=True)
        self.assertEqual(calls, ['root-staging-stage'])
        self.assertIsNone(state.identity)
        self.assertEqual(state.removal_state, 'unconfirmed')
        self.assertFalse(error.facts['removalConfirmed'])
        self.assertEqual(error.reason, 'cleanup-creation-identity-unavailable')
        self.assertTrue((self.library / 'SliccyProof-1').exists())
        self.assertEqual(self.outside.read_bytes(), b'outside sentinel')

    def test_sink_that_never_returns_cannot_block_actual_adapter_recovery(self):
        blocked, release, finished = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        outcome = {}
        def exercise():
            try:
                outcome['result'] = self.adapter_case('callback', blocked=blocked, release=release)
            except BaseException as error:
                outcome['error'] = error
            finally:
                finished.set()
        worker = threading.Thread(target=exercise, daemon=True)
        worker.start()
        try:
            self.assertTrue(blocked.wait(1))
            self.assertTrue(finished.wait(1), 'actual recovery waited on the blocked sink')
            self.assertFalse(release.is_set())
            self.assertNotIn('error', outcome)
            state, calls, error = outcome['result']
            self.assertEqual(calls, ['root-staging-stage', 'root-staging-remove'])
            self.assertTrue(error.facts['removalConfirmed'])
            self.assertEqual(state.removal_state, 'confirmed-by-inode')
            self.assertFalse(error.facts['diagnostics']['complete'])
            self.assertEqual(error.facts['diagnostics']['active'], 1)
            self.assertGreater(error.facts['diagnostics']['dropped'], 0)
            self.assert_removed()
        finally:
            release.set()
            worker.join(1)


    def test_diagnostic_queue_is_bounded_and_overflow_counted_without_sink_progress(self):
        blocked, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def sink(name, row):
            blocked.set()
            release.wait()
        delivery = adapter.DiagnosticDelivery(sink)
        try:
            delivery.submit('fixed', {'index': 0})
            self.assertTrue(blocked.wait(1))
            for index in range(100):
                delivery.submit('fixed', {'index': index + 1})
            status = delivery.snapshot()
            self.assertEqual(status['active'], 1)
            self.assertEqual(status['pending'], 64)
            self.assertEqual(status['dropped'], 36)
            closed = delivery.close()
            self.assertFalse(closed['complete'])
            self.assertEqual(closed['dropped'], 100)
            self.assertFalse(release.is_set())
        finally:
            delivery.close()
            release.set()

    def test_segmented_stream_retains_complete_prefix_before_partial_failure(self):
        accepted = []
        stream = adapter.RecordStream(accepted.append)
        data = json.dumps(dict(schema=1, seq=1, step='staging-create', phase='completed', elapsedMs=0,
                               directory='SliccyProof-1', identity=[1, 2])).encode() + b'\n'
        for byte in data:
            stream.feed(bytes([byte]))
        self.assertEqual(accepted[0]['identity'], [1, 2])
        stream.feed(b'{"schema":1')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            stream.finish()
        self.assertEqual(accepted[0]['identity'], [1, 2])

    def test_separate_absence_confirmation_remains_bound_and_replacement_refuses(self):
        with patch.object(root, 'immutable', self.immutable):
            root.remove_owned(self.fd, 'SliccyProof-1', [1, 2], self.journal)
            self.assertTrue(self.rows[-1]['alreadyAbsent'])
            self.assertEqual(self.rows[-1]['identity'], [1, 2])
            directory = self.library / 'SliccyProof-1'
            directory.mkdir(mode=0o755)
            sentinel = directory / 'sentinel'
            sentinel.write_bytes(b'not our inode')
            with self.assertRaisesRegex(ValueError, 'root-replaced'):
                root.remove_owned(self.fd, directory.name, [1, 2], self.journal)
            self.assertEqual(sentinel.read_bytes(), b'not our inode')
        self.assertEqual(self.outside.read_bytes(), b'outside sentinel')


if __name__ == '__main__':
    unittest.main()
