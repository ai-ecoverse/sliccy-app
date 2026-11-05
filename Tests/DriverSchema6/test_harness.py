import ast
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


class CollectorTests(unittest.TestCase):
    def test_actual_collector_restores_and_continues_without_false_red(self):
        root = Path(__file__).parent
        tree = ast.parse((root / 'hosted.py').read_text())
        body = next(item for item in tree.body if isinstance(item, ast.Try)).body
        loop = next(item for item in body if isinstance(item, ast.For) and isinstance(item.target, ast.Name) and item.target.id == 'mutation')
        code = compile(ast.fix_missing_locations(ast.Module(body=[loop], type_ignores=[])), 'actual-collector', 'exec')
        for mode in ['compile', 'escaping', 'escaping-stderr', 'missing-assertion', 'signal', 'survived', 'valid']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                source = workspace / 'source'
                source.mkdir()
                original = b'guard=1\n'
                (source / 'fixture.go').write_bytes(original)
                mutations = [{'name': name, 'file': 'fixture.go', 'old': 'guard=1', 'new': 'guard=0', 'test': 'TestFake', 'assertion': 'ASSERTION:fake'} for name in ['first', 'second']]
                metadata = workspace / 'Tests/DriverSchema6'
                metadata.mkdir(parents=True)
                (metadata / 'mutants.json').write_text(json.dumps(mutations))
                calls = []

                def command(label, args, maximum):
                    calls.append(label)
                    status, stdout, stderr = 0, b'', b''
                    if label == 'first-compile' and mode == 'compile':
                        status = 1
                    elif label.endswith('-runtime') and '-restored-' not in label:
                        status, stdout = 1, b'ASSERTION:fake'
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
                    return SimpleNamespace(returncode=status, stdout=stdout, stderr=stderr)

                sha = lambda raw: hashlib.sha256(raw).hexdigest()
                namespace = {'Path': Path, 'json': json, 'os': SimpleNamespace(environ={'GITHUB_WORKSPACE': str(workspace)}), 'target': source, 'go': 'never-executed-go', 'binary': 'never-executed-binary', 'selected': '^TestFake$', 'command': command, 'selected_mutations': mutations, 'mutation_results': [], 'sha': sha, 'manifest': {'files': {'fixture.go': sha(original)}}}
                exec(code, namespace)
                results = namespace['mutation_results']
                self.assertEqual([item['validRed'] for item in results], [mode == 'valid', True])
                self.assertEqual((source / 'fixture.go').read_bytes(), original)
                self.assertIn('second-restored-runtime', calls)
                if mode == 'compile':
                    self.assertNotIn('first-runtime', calls)


class PartitionTests(unittest.TestCase):
    def test_actual_partition_is_disjoint_exhaustive_and_fixed(self):
        from partition import select_mutations
        rows = json.loads((Path(__file__).parent / 'mutants.json').read_text())
        first, a, universe = select_mutations(rows,0,2)
        second, b, same = select_mutations(rows,1,2)
        self.assertEqual(universe,same)
        self.assertEqual(set(a)|set(b),set(universe))
        self.assertFalse(set(a)&set(b))
        self.assertEqual(len(a)+len(b),110)
        self.assertEqual(a,sorted(a))
        self.assertEqual(b,sorted(b))
        self.assertEqual({r['name'] for r in first},set(a))
        self.assertEqual({r['name'] for r in second},set(b))
        for index,count in [(-1,2),(2,2),(0,1),(0,3),(True,2),(0,True)]:
            with self.assertRaises(ValueError): select_mutations(rows,index,count)
        with self.assertRaises(ValueError): select_mutations(rows[:-1],0,2)
        with self.assertRaises(ValueError): select_mutations(rows[:-1]+[rows[0]],0,2)

if __name__ == '__main__':
    unittest.main()
