from pathlib import Path
from unittest import TestCase, main, mock
import base64
import copy
import errno
import hashlib
import json
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'script/runner-proof'
sys.path.insert(0, str(SCRIPTS))
import prerequisite_probe as probe
import prerequisite_diagnostics as diagnostics
import sealed_prerequisite as wrapper


def sample(pid=12, parent=11, uid=0):
    return dict(pid=pid, bsdStatus=0, pathStatus=0, path='/bin/sleep',
                bsd=dict(pid=pid, parent=parent, uid=uid, seconds='100', microseconds=250000))


def candidate():
    child = sample()
    parent = sample(11, 10, 0)
    parent['path'] = '/usr/bin/sudo'
    return dict(sudoPID=11, launchWall=100.1, before=child, after=copy.deepcopy(child),
                code=dict(matched=True, identifier='com.apple.sleep', cdHashBase64=base64.b64encode(bytes(20)).decode()),
                chain=[parent, child], chainAfter=copy.deepcopy([parent, child]))


def records():
    rows = []
    def add(phase, state, facts):
        rows.append(dict(schema=1, seq=len(rows) + 1, phase=phase, state=state, elapsedMs=len(rows) * 20, facts=facts))
    add('spawn', 'entered', {'tool': '/usr/bin/sudo', 'arguments': ['-n', '--', '/bin/sleep', '2']})
    add('spawn', 'completed', dict(status=0, pid=11, launchWall=100.1))
    add('candidate', 'completed', candidate())
    add('reap', 'entered', {'pid': 11})
    add('reap', 'completed', dict(pid=11, reaped=True, waitStatus=0, errno=0))
    add('result', 'completed', dict(candidateObserved=True, reaped=True))
    return rows


def encode(rows):
    return b''.join(json.dumps(x).encode() + b'\n' for x in rows)


class BoundaryTests(TestCase):
    def test_candidate_bracket(self):
        self.assertTrue(probe.candidate(candidate()))
        for side in ('before', 'after'):
            for key, value in [('pid', 15), ('parent', 99), ('uid', 501), ('seconds', '102'), ('microseconds', 1)]:
                item = candidate()
                item[side]['bsd'][key] = value
                with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                    probe.candidate(item)

    def test_chain_missing_unavailable_replaced(self):
        for change in ('missing', 'unavailable', 'duplicate', 'parent', 'changed'):
            item = candidate()
            if change == 'missing': item['chain'] = item['chainAfter'] = [item['before']]
            if change == 'unavailable': item['chain'][0]['bsdStatus'] = errno.EPERM
            if change == 'duplicate': item['chain'].append(item['chain'][0])
            if change == 'parent': item['chain'][1]['bsd']['parent'] = 9
            if change == 'changed': item['chainAfter'][0]['bsd']['seconds'] = '99'
            with self.subTest(change=change), self.assertRaises(ValueError): probe.candidate(item)

    def test_numeric_booleans_refused(self):
        for value in (0, 1, None, 'true'):
            item = candidate(); item['code']['matched'] = value
            with self.assertRaises(ValueError): probe.candidate(item)

    def test_visibility_complete(self):
        self.assertEqual(probe.visibility_records(encode(records()), 0)['rootVisibility'], True)

    def test_spawn_candidate_reap_binding(self):
        self.assertTrue(probe.visibility_records(encode(records()), 0)['rootVisibility'])
        for change in ('different-spawn-reap', 'spawn-only', 'reap-only', 'entered-reap', 'launch', 'spawn-failed', 'duplicate-spawn', 'no-spawn', 'candidate-before-spawn', 'bool-pid', 'bool-launch'):
            items = records()
            if change == 'different-spawn-reap':
                items[1]['facts']['pid'] = 99
                items[3]['facts']['pid'] = items[4]['facts']['pid'] = 99
            if change == 'spawn-only': items[1]['facts']['pid'] = 99
            if change == 'reap-only': items[4]['facts']['pid'] = 99
            if change == 'entered-reap': items[3]['facts']['pid'] = 99
            if change == 'launch': items[1]['facts']['launchWall'] = 99.9
            if change == 'spawn-failed': items[1]['facts']['status'] = 1
            if change == 'duplicate-spawn': items[2:2] = copy.deepcopy(items[:2])
            if change == 'no-spawn': items = items[2:]
            if change == 'candidate-before-spawn': items = [items[2]] + items[:2] + items[3:]
            if change == 'bool-pid': items[1]['facts']['pid'] = True
            if change == 'bool-launch': items[1]['facts']['launchWall'] = True
            for index, item in enumerate(items, 1): item['seq'] = index; item['elapsedMs'] = index * 20
            with self.subTest(change=change), self.assertRaises(ValueError): probe.visibility_records(encode(items), 0)

    def test_root_sample_exact_in_both_chain_brackets(self):
        for key, value in [('uid', 501), ('parent', 99), ('seconds', '101'), ('microseconds', 1)]:
            item = candidate()
            for side in ('chain', 'chainAfter'): item[side][1]['bsd'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): probe.candidate(item)
            rows = records(); rows[2]['facts'] = item
            with self.assertRaises(ValueError): probe.visibility_records(encode(rows), 0)
        for key, value in [('path', '/wrong'), ('bsdStatus', 1), ('pathStatus', 1), ('pid', 55)]:
            item = candidate()
            for side in ('chain', 'chainAfter'): item[side][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): probe.candidate(item)
        item = candidate(); item['chain'] = [item['before']]; item['chainAfter'] = copy.deepcopy(item['chain']); item['sudoPID'] = item['before']['pid']
        self.assertTrue(probe.candidate(item))

    def test_visibility_missing_completion_and_boundaries(self):
        for change in ('pending', 'no-result', 'gap', 'late', 'failure', 'no-reap', 'truncated'):
            items = records()
            if change == 'pending': items[1]['state'] = 'entered'
            if change == 'no-result': items.pop()
            if change == 'gap': items[2]['seq'] += 1
            if change == 'late':
                for item in items: item['elapsedMs'] += 2100
            if change == 'failure': items[-1]['facts']['candidateObserved'] = False
            if change == 'no-reap': items[4]['facts']['reaped'] = False
            data = encode(items)
            if change == 'truncated': data = data[:-1]
            with self.subTest(change=change), self.assertRaises(ValueError): probe.visibility_records(data, 0)

    def test_symlink_hops(self):
        facts = []
        def inspect(path, record):
            target = '/safe/real' if str(path) == '/alias' else None
            row = dict(symlink=target is not None, target=target)
            record('fact', dict(path=str(path), **row))
            return row
        self.assertEqual(probe.path_facts('/alias/child', lambda *x: facts.append(x), inspect), Path('/safe/real/child'))
        self.assertEqual(sum(x[0] == 'symlink-hop' for x in facts), 1)
        with self.assertRaises(ValueError):
            probe.path_facts('/loop', lambda *x: None, lambda p, r: dict(symlink=str(p) == '/loop', target='/loop'))

    def test_snapshot_acl_failure_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = []
            def fail(fd): raise ValueError('acl-present')
            with self.assertRaisesRegex(ValueError, 'acl-present'):
                probe.snapshot(directory, lambda *x: rows.append(x), fail)
            self.assertEqual(rows[-1][1]['reason'], 'acl-present')
            self.assertIsNone(rows[-1][1]['aclAbsent'])

    def test_interpreter_unchanged_validator_dispatch(self):
        path = '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9'
        value = dict(executable=path + '/bin/python3', stdlib=path + '/lib/python3.9', prefix=path)
        commands, facts, validations = [], [], []
        def checked(args):
            commands.append(args)
            if args[0] == '/usr/bin/python3': return json.dumps(value).encode(), b''
            return b'', b'Identifier=com.apple.python3\nCDHash=' + b'a' * 40 + b'\n'
        def validate(discovered, verify, record):
            validations.append(discovered); verify('fixed', ['fixed-verifier']); return Path(value['executable']), 'digest'
        self.assertTrue(probe.interpreter_component(checked, lambda *x: facts.append(x), lambda p, r: Path(p), validate))
        self.assertEqual(validations, [value])
        self.assertIn(['/usr/bin/python3', '-I', '-S', '-B', '-c', probe.stage.DISCOVERY], commands)
        self.assertIn(['fixed-verifier'], commands)
        self.assertEqual(commands[0][-1], '/usr/bin/python3')

    def test_each_interpreter_command_failure(self):
        value = dict(executable='/Python3.framework/bin/python', stdlib='/Python3.framework/lib', prefix='/Python3.framework')
        for failure in range(7):
            count = 0
            def checked(args):
                nonlocal count
                index = count; count += 1
                if index == failure: raise subprocess.CalledProcessError(17, args, b'out', b'err')
                if args[0] == '/usr/bin/python3': return json.dumps(value).encode(), b''
                return b'Identifier=python\nCDHash=' + b'a' * 40 + b'\n', b''
            with self.subTest(failure=failure), self.assertRaises(subprocess.CalledProcessError):
                probe.interpreter_component(checked, lambda *x: None, lambda p, r: Path(p), lambda *x: (Path('/x'), 'hash'))

    def test_all_diagnostic_steps_failure_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, name in enumerate(sorted(diagnostics.STEPS)):
                journal = diagnostics.Journal(root / str(index), root, ROOT, time.monotonic())
                with self.assertRaisesRegex(ValueError, 'injected'):
                    with journal.step(name): raise ValueError('injected')
                rows = [json.loads(x) for x in journal.path.read_text().splitlines()]
                self.assertEqual(rows[-1]['status'], 'failed')
                self.assertEqual(rows[-1]['step'], name)
                self.assertEqual(rows[-1]['exceptionClass'], 'ValueError')
                for key in ('tool', 'arguments', 'exitStatus', 'stdoutTail', 'stderrTail'): self.assertIn(key, rows[-1])

    def test_command_failure_tail_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, error in enumerate((None, subprocess.TimeoutExpired(['fixed'], 1))):
                journal = diagnostics.Journal(root / str(index), root, ROOT, time.monotonic())
                def run(args, stdout, stderr, **kwargs):
                    stdout.write(b'a' * 5000); stderr.write(b'b' * 5000)
                    if error: raise error
                    return subprocess.CompletedProcess(args, 17)
                with mock.patch.object(diagnostics.subprocess, 'run', side_effect=run), self.assertRaises(Exception):
                    with journal.step('root-visibility'):
                        journal.run(['/bin/sleep', '2'], capture_output=True, check=True, timeout=1)
                rows = [json.loads(x) for x in journal.path.read_text().splitlines()]
                command = next(x for x in rows if x['kind'] == 'command' and x['status'] == 'failed')
                self.assertEqual(command['arguments'], ['/bin/sleep', '2'])
                self.assertEqual(len(command['stdoutTail']), 4096)
                self.assertEqual(len(command['stderrTail']), 4096)

    def test_native_timeout_never_signals_and_retains_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = diagnostics.Journal(root / 'journal', root, ROOT, time.monotonic())
            child = mock.Mock(pid=123, returncode=None)
            child.wait.side_effect = subprocess.TimeoutExpired(['fixed'], 10)
            def spawn(args, stdout, stderr, **kwargs):
                stdout.write(b'partial'); stderr.write(b'cause'); return child
            with (root / 'raw').open('wb') as raw, (root / 'err').open('wb') as err:
                with mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=spawn), self.assertRaises(subprocess.TimeoutExpired):
                    with journal.step('root-visibility'):
                        journal.read_only_native([str(root / 'prerequisite-visibility')], raw, err, {}, 10)
            child.kill.assert_not_called(); child.terminate.assert_not_called(); child.send_signal.assert_not_called()
            self.assertEqual((root / 'raw').read_bytes(), b'partial')
            row = next(x for x in map(json.loads, journal.path.read_text().splitlines()) if 'observerReaped' in x)
            self.assertFalse(row['observerReaped'])
            self.assertEqual(row['stderrTail'], 'cause')

    def test_actual_suite_all_tool_failures_named(self):
        for failure in range(7):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); evidence = root / 'evidence'; evidence.mkdir()
                journal = diagnostics.Journal(evidence / 'journal', root, ROOT, time.monotonic())
                count = 0
                def run(args, stdout, stderr, **kwargs):
                    nonlocal count
                    index = count; count += 1
                    stdout.write(b'Identifier=com.apple.test\nCDHash=' + b'a' * 40 + b'\n')
                    stderr.write(b'fixed-stderr')
                    if '-o' in args: Path(args[-1]).write_bytes(b'fake-built-observer')
                    return subprocess.CompletedProcess(args, 17 if index == failure else 0)
                def spawn(args, stdout, stderr, **kwargs):
                    nonlocal count
                    index = count; count += 1
                    stdout.write(encode(records())); stderr.write(b'native-stderr')
                    return mock.Mock(pid=22, returncode=17 if index == failure else 0,
                                     wait=mock.Mock(return_value=17 if index == failure else 0))
                with mock.patch.object(probe, 'path_facts', side_effect=lambda p, r: Path(p)), \
                     mock.patch.object(probe, 'interpreter_component', return_value=True), \
                     mock.patch.object(diagnostics.subprocess, 'run', side_effect=run), \
                     mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=spawn):
                    result = wrapper.suite(root, evidence, None, {}, time.monotonic() + 100, ROOT, journal)
                self.assertEqual(result, 0 if failure == 6 else 1)
                rows = [json.loads(x) for x in journal.path.read_text().splitlines()]
                if failure < 6:
                    row = next(x for x in rows if x['kind'] == 'command' and x['status'] == 'failed')
                    self.assertEqual(row['exitStatus'], 17)
                    for key in ('step', 'tool', 'arguments', 'stdoutTail', 'stderrTail'): self.assertTrue(row[key])

    def test_caller_boundary_exact(self):
        source = Path('/Users/trieloff/.bb/thread-storage/thr_desfnajij8/capture-fix-worktree')
        c = (source / 'Sources/ScreenSystem/ScreenSystem.c').read_text()
        h = (source / 'Sources/ScreenSystem/include/ScreenSystem.h').read_text()
        expected = h[h.index('struct sliccy_screen_process_identity {'):h.index('int sliccy_screen_proof_process_identity')]
        expected += c[c.index('int sliccy_runner_identity('):c.index('int sliccy_runner_hash(')]
        self.assertEqual((SCRIPTS / 'prerequisite_bsd_boundary.h').read_text(), expected)
        for name in ('capture_stage.py', 'capture_stage_root.py'):
            self.assertEqual((SCRIPTS / name).read_bytes(), (source / 'script/runner-proof' / name).read_bytes())

    def test_actual_c_boundary_synthetic_only(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'fixture'
            subprocess.run(['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-I', str(SCRIPTS),
                            str(Path(__file__).with_name('boundary_fixture.c')), '-o', str(executable)],
                           check=True, capture_output=True, timeout=20)
            result = subprocess.run([str(executable)], check=True, capture_output=True, timeout=2)
            self.assertIn(b'synthetic production boundary PASS', result.stdout)

    def test_no_runtime_subject_override(self):
        source = (SCRIPTS / 'prerequisite_visibility.m').read_text()
        self.assertIn('char *args[] = {"/usr/bin/sudo", "-n", "--", "/bin/sleep", "2", NULL}', source)
        self.assertIn('BOOL placed = argc == 1 && hosted()', source)
        self.assertNotIn('kill(', source)
        self.assertNotIn('proc_listallpids', source)
        self.assertNotIn('CGWindow', source)


if __name__ == '__main__':
    main()
