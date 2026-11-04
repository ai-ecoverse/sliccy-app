from pathlib import Path
from unittest import TestCase, mock
import importlib.util
import json
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('hosted_slice_overlays', Path(__file__).with_name('hosted_slice_overlays.py'))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class HostedHarnessTests(TestCase):
    def test_non_hosted_refuses_before_any_subprocess(self):
        with mock.patch.dict(HARNESS.os.environ, {}, clear=True), mock.patch.object(HARNESS.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'hosted-synthetic-test-placement'):
                HARNESS.main()
            run.assert_not_called()

    def test_actual_harness_requires_assertion_not_signal_or_compile_error(self):
        environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app', 'GITHUB_EVENT_NAME': 'push',
                       'GITHUB_REF': 'refs/heads/proof/slice-binding-tests-v1', 'RUNNER_ENVIRONMENT': 'github-hosted',
                       'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64', 'GITHUB_SHA': 'a'*40, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}
        for failure in (None, 'signal', 'compile'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                header = root/'header.h'
                header.write_bytes(HARNESS.HEADER.read_bytes())
                fixture = root/'fixture.m'
                fixture.write_bytes(HARNESS.FIXTURE.read_bytes())

                def run(args, **kwargs):
                    self.assertNotIn('GITHUB_TOKEN', kwargs['env'])
                    self.assertNotIn('GH_TOKEN', kwargs['env'])
                    status, out, err = 0, b'', b''
                    if args[0] == '/usr/bin/clang':
                        if failure == 'compile' and Path(args[-1]).parent.name == 'unique-match':
                            status, err = 1, b'compile error'
                    elif len(args) == 1:
                        label = Path(args[0]).parent.name
                        if label not in ('baseline', 'restored'):
                            status, err = 1, ('slice runtime assertion: '+label+'\n').encode()
                            if label == 'unique-match' and failure == 'signal':
                                status, err = -9, b''
                    return subprocess.CompletedProcess(args, status, out, err)

                with mock.patch.dict(HARNESS.os.environ, environment, clear=True), mock.patch.object(HARNESS.sys, 'platform', 'darwin'), \
                     mock.patch.object(HARNESS.platform, 'machine', return_value='arm64'), mock.patch.object(HARNESS, 'ROOT', root), \
                     mock.patch.object(HARNESS, 'HEADER', header), mock.patch.object(HARNESS, 'FIXTURE', fixture), \
                     mock.patch.object(HARNESS.subprocess, 'run', side_effect=run):
                    self.assertEqual(HARNESS.main(), int(failure is not None))
                evidence = json.loads((root/'slice-test-results/summary.json').read_text())
                self.assertEqual(len(evidence['overlays']), 6)
                self.assertEqual(evidence['overlays'][0]['runtimeRed'], failure is None)
                self.assertEqual(evidence['passed'], failure is None)
                self.assertFalse((root/'slice-test-results/scratch').exists())
