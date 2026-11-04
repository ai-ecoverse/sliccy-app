from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('runner_slice_hosted', Path(__file__).with_name('hosted.py'))
HOSTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOSTED)

class HarnessTests(unittest.TestCase):
    def result(self, code, output=b''):
        return subprocess.CompletedProcess([], code, output, b'')

    def assertion(self, name='selected'):
        return ('Test ' + name + '() recorded an issue at Fixture.swift:1:1: Expectation failed: synthetic\n').encode()

    def test_only_exact_named_runtime_assertion_counts(self):
        self.assertTrue(HOSTED.named_assertions(self.result(1, self.assertion()), 'selected'))
        for code, output in [(0, self.assertion()), (-9, self.assertion()), (137, self.assertion()),
                             (1, self.assertion('wrong')), (1, b'Caught error: .peerUntrusted'),
                             (1, self.assertion() + b'Caught error: .peerUntrusted'),
                             (1, self.assertion() + b'error: Exited with unexpected signal code 9'),
                             (1, self.assertion() + b'SIGKILL'), (1, b'Expectation failed: unnamed')]:
            with self.subTest(code=code, output=output):
                self.assertEqual(HOSTED.named_assertions(self.result(code, output), 'selected'), [])

    def test_each_invalid_overlay_restores_and_next_overlay_runs(self):
        for failure in ['compile', 'escaping', 'signal', 'survived', 'restored-build', 'restored-runtime']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); target = root / 'source.swift'; target.write_text('old')
                calls = []
                def run(name, args, limit):
                    calls.append(name)
                    if name == 'first-build' and failure == 'compile':return self.result(1, b'compiler error')
                    if name == 'first-runtime':
                        if failure == 'escaping':return self.result(1, b'Caught error: .peerUntrusted')
                        if failure == 'signal':return self.result(-9)
                        if failure == 'survived':return self.result(0)
                    if name == 'first-restored-build' and failure == 'restored-build':return self.result(1)
                    if name == 'first-restored-runtime' and failure == 'restored-runtime':return self.result(1)
                    if name.endswith('-runtime') and '-restored-' not in name:return self.result(1, self.assertion())
                    return self.result(0)
                results = [HOSTED.overlay(root, (name, 'source.swift', 'old', 'new', 'selected'), run, [], []) for name in ['first', 'second']]
                self.assertFalse(results[0]['valid'])
                self.assertTrue(results[1]['valid'])
                self.assertEqual(target.read_text(), 'old')
                self.assertIn('first-restored-build', calls)
                self.assertIn('second-runtime', calls)
                self.assertEqual(results[0]['originalSHA256'], results[0]['restoredSHA256'])

if __name__ == '__main__':
    unittest.main()
