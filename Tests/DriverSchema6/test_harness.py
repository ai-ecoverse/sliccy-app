import ast
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from runtime_result import exact_test_pattern, runtime_result, suite_result
from suite_schedule import mutation_test_seconds, checked_suite_groups, run_full_suite


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
                namespace = {'Path': Path, 'json': json, 'os': SimpleNamespace(environ={'GITHUB_WORKSPACE': str(workspace)}), 'target': source, 'go': 'never-executed-go', 'binary': 'never-executed-binary', 'selected': '^TestFake$', 'command': command, 'selected_mutations': mutations, 'mutation_results': [], 'restoration_gates': [], 'results': workspace, 'exact_test_pattern': exact_test_pattern, 'mutation_test_seconds': mutation_test_seconds, 'runtime_result': runtime_result, 'sha': sha, 'manifest': {'files': {'fixture.go': sha(original), 'untouched.go': sha(b'other=1\n')}}}
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

    def test_driver_mutant_plan_old_strings_once(self):
        """Pure dry-run of the hosted mutation plan: no Go compile/subprocess."""
        import ast
        import tarfile
        root = Path(__file__).parent
        hosted = (root / 'hosted.py').read_text()
        self.assertIn('mutants.json', hosted)
        self.assertTrue(any(isinstance(n, ast.Call) and getattr(getattr(n, 'func', None), 'attr', None) == 'loads' for n in ast.walk(ast.parse(hosted))))
        mutants = json.loads((root / 'mutants.json').read_text())
        self.assertGreaterEqual(len(mutants), 146)
        texts = {}
        with tarfile.open(root / 'inputs' / 'driver-source.tar.gz') as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith('.go'):
                    texts[member.name] = tar.extractfile(member).read().decode()
        names = set()
        for mutant in mutants:
            self.assertNotIn(mutant['name'], names)
            names.add(mutant['name'])
            self.assertEqual(texts[mutant['file']].count(mutant['old']), 1, mutant['name'])


class PartitionTests(unittest.TestCase):
    def test_actual_partition_is_disjoint_exhaustive_and_fixed(self):
        from partition import select_mutations
        rows = json.loads((Path(__file__).parent / 'mutants.json').read_text())
        sets = []
        for index in range(6):
            selected, names, universe = select_mutations(rows, index, 6)
            self.assertEqual(names, sorted(names))
            self.assertEqual({r['name'] for r in selected}, set(names))
            self.assertTrue(all(not set(names) & previous for previous in sets))
            sets.append(set(names))
        self.assertEqual(set.union(*sets), set(universe))
        self.assertEqual(sum(map(len, sets)), 146)
        self.assertIn('v83-nominal-volume-gate-bypassed', sets[0])
        self.assertIn('v83-overflow-loss-blocker-removed', sets[1])
        for index, count in [(-1, 6), (6, 6), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (True, 6), (0, True)]:
            with self.assertRaises(ValueError):
                select_mutations(rows, index, count)
        with self.assertRaises(ValueError):
            select_mutations(rows[:-1], 0, 6)
        with self.assertRaises(ValueError):
            select_mutations(rows[:-1] + [rows[0]], 0, 6)


class SuiteScheduleTests(unittest.TestCase):
    def ledger(self):
        return json.loads((Path(__file__).parent / 'shards.json').read_text())

    def test_fixed_invocation_partition_rejects_missing_duplicate_and_widened(self):
        ledger = self.ledger()
        self.assertEqual([len(g['tests']) for g in checked_suite_groups(ledger)], [108, 1, 1])
        for mode in ('missing', 'duplicate', 'unknown', 'nonheavy-limit', 'overflow-limit', 'nominal-limit', 'universe-duplicate'):
            with self.subTest(mode=mode):
                changed = json.loads(json.dumps(ledger))
                if mode == 'missing': changed['suiteInvocations'][0]['tests'].pop()
                if mode == 'duplicate': changed['suiteInvocations'][0]['tests'].append(changed['suiteInvocations'][1]['tests'][0])
                if mode == 'unknown': changed['suiteInvocations'][0]['tests'][0] = 'TestUnknown'
                if mode == 'nonheavy-limit': changed['suiteInvocations'][0]['testSeconds'] = 60
                if mode == 'overflow-limit': changed['suiteInvocations'][2]['testSeconds'] = 60
                if mode == 'nominal-limit': changed['suiteInvocations'][1]['testSeconds'] = 61
                if mode == 'universe-duplicate': changed['baselineTests'][-1] = changed['baselineTests'][0]
                with self.assertRaises(ValueError): checked_suite_groups(changed)

    def test_actual_split_invocations_require_every_exact_runtime_pass(self):
        ledger = self.ledger()
        for mode in ('valid', 'missing', 'duplicate', 'wrong', 'skip', 'signal', 'timeout'):
            with self.subTest(mode=mode):
                calls, reports = [], []
                def command(label, args, maximum):
                    group = ledger['suiteInvocations'][len(calls)]
                    self.assertEqual(args[2], '-test.timeout=' + str(group['testSeconds']) + 's')
                    self.assertEqual(maximum, group['testSeconds'] + 15)
                    import re
                    actual = [n for n in ledger['baselineTests'] if re.fullmatch(args[-1], n)]
                    self.assertEqual(actual, group['tests'])
                    names = list(group['tests'])
                    calls.append(label)
                    if mode == 'missing': names.pop()
                    if mode == 'duplicate': names.append(names[0])
                    if mode == 'wrong': names[0] = 'TestUnknown'
                    text = ''.join('=== RUN   ' + n + '\n--- PASS: ' + n + ' (0.01s)\n' for n in names)
                    if mode == 'skip': text += '--- SKIP: TestSkipped (0.01s)\n'
                    return SimpleNamespace(returncode=-9 if mode == 'signal' else 2 if mode == 'timeout' else 0, stdout=text.encode(), stderr=b'panic: test timed out' if mode == 'timeout' else b'')
                if mode == 'valid':
                    run_full_suite('fake', 'never-native', command, ledger, reports.append)
                    self.assertEqual(len(calls), 3)
                    self.assertEqual(sum(len(r['tests']) for r in reports), 110)
                    self.assertTrue(all(r['exactTestsPassed'] for r in reports))
                else:
                    with self.assertRaises(AssertionError): run_full_suite('fake', 'never-native', command, ledger, reports.append)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse(reports[-1]['exactTestsPassed'])

    def test_only_exact_nominal_overlay_gets_sixty_seconds(self):
        from suite_schedule import NOMINAL, OVERFLOW
        self.assertEqual(mutation_test_seconds(NOMINAL), 60)
        self.assertEqual(mutation_test_seconds(OVERFLOW), 30)
        self.assertEqual(mutation_test_seconds(NOMINAL + 'Other'), 30)
        self.assertEqual(mutation_test_seconds('TestOther'), 30)


if __name__ == '__main__':
    unittest.main()
