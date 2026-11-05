import ast
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from runtime_result import exact_test_pattern, runtime_result, suite_result


class CollectorTests(unittest.TestCase):
    def test_actual_collector_restores_and_continues_without_false_red(self):
        root = Path(__file__).parent
        tree = ast.parse((root / 'hosted.py').read_text())
        body = next(item for item in tree.body if isinstance(item, ast.Try)).body
        loop = next(item for item in body if isinstance(item, ast.For) and isinstance(item.target, ast.Name) and item.target.id == 'mutation')
        code = compile(ast.fix_missing_locations(ast.Module(body=[loop], type_ignores=[])), 'actual-collector', 'exec')
        for mode in ['compile', 'escaping', 'escaping-stderr', 'missing-assertion', 'signal', 'survived', 'valid', 'changed-other', 'extra-source', 'wrong-test', 'assertion-prefix', 'restore-no-test']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                source = workspace / 'source'
                source.mkdir()
                original = b'guard=1\n'
                (source / 'fixture.go').write_bytes(original)
                (source / 'untouched.go').write_bytes(b'other=1\n')
                mutations = [{'name': name, 'file': 'fixture.go', 'old': 'guard=1', 'new': 'guard=0', 'test': 'TestFake', 'assertion': 'ASSERTION:fake'} for name in ['first', 'second']]
                metadata = workspace / 'Tests/DriverSchema6'
                metadata.mkdir(parents=True)
                (metadata / 'mutants.json').write_text(json.dumps(mutations))
                calls = []

                def command(label, args, maximum):
                    calls.append(label)
                    if label == 'first-runtime' and mode == 'changed-other':
                        (source / 'untouched.go').write_bytes(b'other=0\n')
                    if label == 'first-runtime' and mode == 'extra-source':
                        (source / 'extra.go').write_bytes(b'unexpected=1\n')
                    if label.endswith('-restored-runtime'):
                        self.assertEqual(args[-1], '^TestFake$')
                    status, stdout, stderr = 0, b'', b''
                    if label.endswith('-restored-runtime'):
                        stdout = b'=== RUN   TestFake\n--- PASS: TestFake (0.01s)\n'
                        if mode == 'restore-no-test': stdout = b'PASS\n'
                    if label == 'first-compile' and mode == 'compile':
                        status = 1
                    elif label.endswith('-runtime') and '-restored-' not in label:
                        status, stdout = 1, b'=== RUN   TestFake\n    fake.go:1: ASSERTION:fake\n--- FAIL: TestFake (0.01s)\n'
                        if label.startswith('first-'):
                            if mode == 'escaping':
                                stdout += b' panic:'
                            elif mode == 'escaping-stderr':
                                stderr = b'panic: fabricated fixture'
                            elif mode == 'missing-assertion':
                                stdout = b'unrelated error'
                            elif mode == 'signal':
                                status = -9
                            elif mode == 'survived':
                                status = 0
                            elif mode == 'wrong-test':
                                stdout = stdout.replace(b'TestFake', b'TestOther')
                            elif mode == 'assertion-prefix':
                                stdout = stdout.replace(b'ASSERTION:fake', b'ASSERTION:fake-extra')
                    return SimpleNamespace(returncode=status, stdout=stdout, stderr=stderr)

                sha = lambda raw: hashlib.sha256(raw).hexdigest()
                namespace = {'Path': Path, 'json': json, 'os': SimpleNamespace(environ={'GITHUB_WORKSPACE': str(workspace)}), 'target': source, 'go': 'never-executed-go', 'binary': 'never-executed-binary', 'selected': '^TestFake$', 'command': command, 'selected_mutations': mutations, 'mutation_results': [], 'restoration_gates': [], 'results': workspace, 'exact_test_pattern': exact_test_pattern, 'runtime_result': runtime_result, 'sha': sha, 'manifest': {'files': {'fixture.go': sha(original), 'untouched.go': sha(b'other=1\n')}}}
                if mode == 'extra-source':
                    with self.assertRaises(AssertionError):
                        exec(code, namespace)
                    self.assertNotIn('first-restored-compile', calls)
                    continue
                if mode == 'restore-no-test':
                    with self.assertRaises(AssertionError): exec(code, namespace)
                    self.assertNotIn('second-compile', calls)
                    continue
                exec(code, namespace)
                self.assertEqual((source / 'untouched.go').read_bytes(), b'other=1\n')
                results = namespace['mutation_results']
                self.assertEqual([item['validRed'] for item in results], [mode in ('valid', 'changed-other'), True])
                self.assertEqual((source / 'fixture.go').read_bytes(), original)
                self.assertIn('second-restored-runtime', calls)
                for gate in namespace['restoration_gates']:
                    self.assertEqual(gate['beforeOwnTest'], namespace['manifest']['files'])
                    self.assertEqual(gate['afterOwnTest'], namespace['manifest']['files'])
                if mode == 'compile':
                    self.assertNotIn('first-runtime', calls)


    def test_runtime_and_suite_require_exact_executed_tests(self):
        self.assertEqual(exact_test_pattern('TestParent/fixture.answer'), '^TestParent$/^fixture\\.answer$')
        red = SimpleNamespace(returncode=1, stdout=b'=== RUN   TestParent/fixture.answer\n    file.go:1: ASSERTION:expected detail\n    --- FAIL: TestParent/fixture.answer (0.01s)\n', stderr=b'')
        self.assertTrue(runtime_result(red, 'TestParent/fixture.answer', 'ASSERTION:expected'))
        self.assertFalse(runtime_result(red, 'TestParent/fixture', 'ASSERTION:expected'))
        self.assertFalse(runtime_result(red, 'TestParent/fixture.answer', 'ASSERTION:expect'))
        green = SimpleNamespace(returncode=0, stdout=b'=== RUN   TestA\n--- PASS: TestA (0.01s)\n=== RUN   TestB\n--- PASS: TestB (0.02s)\n', stderr=b'')
        self.assertTrue(suite_result(green, ['TestA', 'TestB']))
        self.assertFalse(suite_result(green, ['TestA']))
        self.assertFalse(suite_result(green, ['TestA', 'TestB', 'TestC']))
        green.stdout += b'=== RUN   TestA\n--- PASS: TestA (0.01s)\n'
        self.assertFalse(suite_result(green, ['TestA', 'TestB']))


class PartitionTests(unittest.TestCase):
    def test_actual_partition_is_disjoint_exhaustive_and_fixed(self):
        from partition import select_mutations
        rows = json.loads((Path(__file__).parent / 'mutants.json').read_text())
        sets = []
        for index in range(4):
            selected, names, universe = select_mutations(rows, index, 4)
            self.assertEqual(names, sorted(names))
            self.assertEqual({r['name'] for r in selected}, set(names))
            self.assertTrue(all(not set(names) & previous for previous in sets))
            sets.append(set(names))
        self.assertEqual(set.union(*sets), set(universe))
        self.assertEqual(sum(map(len, sets)), 135)
        self.assertIn('v83-nominal-volume-gate-bypassed', sets[0])
        self.assertIn('v83-overflow-loss-blocker-removed', sets[1])
        for index, count in [(-1, 4), (4, 4), (0, 1), (0, 2), (0, 3), (True, 4), (0, True)]:
            with self.assertRaises(ValueError):
                select_mutations(rows, index, count)
        with self.assertRaises(ValueError):
            select_mutations(rows[:-1], 0, 4)
        with self.assertRaises(ValueError):
            select_mutations(rows[:-1] + [rows[0]], 0, 4)


if __name__ == '__main__':
    unittest.main()
