from pathlib import Path
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'script'))
import capture_manifest as subject


class CaptureManifestTests(unittest.TestCase):
    def setUp(self):
        pin = patch.object(subject.surface_pin, 'verify')
        self.pin = pin.start()
        self.addCleanup(pin.stop)

    def fixture(self, root):
        app = Path(root) / 'Sliccy.app'
        helper = app / 'Contents/Helpers/ScreenProofSurface.app'
        for bundle, role, name in [(app, 'ai.sliccy.mac', 'Sliccy'), (helper, 'ai.sliccy.proof-helper', 'ScreenProofSurface')]:
            for part in ['MacOS', '_CodeSignature']:
                (bundle / 'Contents' / part).mkdir(parents=True)
            (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': role, 'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '14' if role == 'ai.sliccy.mac' else '12', 'CFBundleExecutable': name}))
            (bundle / 'Contents/MacOS' / name).write_bytes(b'not executable')
        (helper / 'Contents/CodeResources').write_bytes(b'not a real ticket')
        (app / 'Contents/Resources').mkdir()
        (app / 'Contents/Resources/slicc').write_bytes(b'not executable')
        return app

    def signature(self, path, role, architecture):
        digest, cdhash = (subject.RESOURCES['slicc'][1], subject.RESOURCES['slicc'][2]) if path.name == 'slicc' else ('0' * 64, '1' * 40)
        return {'architecture': architecture, 'sha256': digest, 'CDHash': cdhash}, 'flags=0x10000(runtime)'

    def checked(self, args):
        if '-r-' in args:
            role = 'ai.sliccy.proof-helper' if str(args[-1]).endswith('ScreenProofSurface.app') else 'ai.sliccy.mac'
            return ('designated => identifier "' + role + '"\n').encode(), b''
        return (plistlib.dumps({}), b'') if '--entitlements' in args else (b'', b'')

    def test_signed_roles_release_binding_and_closed_cases_with_mocked_verifiers(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'signature', side_effect=self.signature), patch.object(subject, 'checked', side_effect=self.checked), patch.object(subject.subprocess, 'run', return_value=subprocess.CompletedProcess([], 3)):
            record = subject.manifest(self.fixture(root))
            self.assertEqual(record['build'], '14')
            self.assertEqual(len(record['cases']), 6)
            self.assertEqual(set(record['helpers']), {'ScreenProofSurface.app'})
            self.assertTrue(record['helpers']['ScreenProofSurface.app']['appRoleRefused'])
            self.assertFalse(record['productionEnabled'])
            self.assertFalse(record['nativeTrialsPerformed'])

    def test_helper_app_role_acceptance_and_nonempty_entitlements_refuse(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'signature', side_effect=self.signature):
            app = self.fixture(root)
            with patch.object(subject, 'checked', side_effect=self.checked), patch.object(subject.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaises(ValueError): subject.manifest(app)
            with patch.object(subject, 'checked', return_value=(plistlib.dumps({'com.apple.security.get-task-allow': True}), b'')):
                with self.assertRaises(ValueError): subject.manifest(app)

    def test_helper11_or_missing_ticket_refuses(self):
        for change in ['build11','missing-ticket']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as root,patch.object(subject,'signature',side_effect=self.signature),patch.object(subject,'checked',side_effect=self.checked),patch.object(subject.subprocess,'run',return_value=subprocess.CompletedProcess([],3)):
                app=self.fixture(root)
                helper=app/'Contents/Helpers/ScreenProofSurface.app'
                if change=='build11':
                    path=helper/'Contents/Info.plist';info=plistlib.loads(path.read_bytes());info['CFBundleVersion']='11';path.write_bytes(plistlib.dumps(info))
                else:
                    (helper/'Contents/CodeResources').unlink()
                with self.assertRaisesRegex(ValueError,'wrong fixture identity|unexpected helper contents'):
                    subject.manifest(app)

    def test_only_documented_requirement_failure_is_role_refusal(self):
        for status in [0, 1, 2, -9, 4, 127]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'signature', side_effect=self.signature), patch.object(subject, 'checked', side_effect=self.checked), patch.object(subject.subprocess, 'run', return_value=subprocess.CompletedProcess([], status)) as run:
                app = self.fixture(root)
                with self.assertRaisesRegex(ValueError, 'helper app-role refusal absent'):
                    subject.manifest(app)
                run.assert_called_once_with(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + subject.REQUIREMENT, str(app / 'Contents/Helpers/ScreenProofSurface.app')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def test_requirement_timeout_or_missing_tool_cannot_be_refusal(self):
        for error in [subprocess.TimeoutExpired('codesign', 15), FileNotFoundError('codesign')]:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'signature', side_effect=self.signature), patch.object(subject, 'checked', side_effect=self.checked), patch.object(subject.subprocess, 'run', side_effect=error):
                with self.assertRaises(type(error)):
                    subject.manifest(self.fixture(root))

    def test_extra_helper_and_symlink_refuse_before_verifier(self):
        for change in ['helper', 'symlink']:
            with tempfile.TemporaryDirectory() as root, patch.object(subject, 'checked') as check:
                app = self.fixture(root)
                if change == 'helper': (app / 'Contents/Helpers/extra').write_bytes(b'x')
                else: (app / 'Contents/Resources/link').symlink_to('/tmp')
                with self.assertRaises(ValueError): subject.manifest(app)
                check.assert_not_called()

    def test_build14_has_exact_guarded_packaging_and_preserves_signed_surface_without_execution(self):
        root = Path(__file__).resolve().parents[2]
        script = (root / 'script/sign_and_notarize.sh').read_text().splitlines()
        indexes = [i for i, line in enumerate(script) if '/capture_manifest.py"' in line]
        self.assertEqual(len(indexes), 1)
        self.assertTrue(script[indexes[0] - 2].endswith('== 14 ]]; then'))
        self.assertEqual(script[indexes[0] + 1], 'fi')
        self.assertIn('/surface_pin.py', script[indexes[0] - 1])
        build = (root / 'script/build_and_run.sh').read_text()
        self.assertIn('BUILD_NUMBER=14', build)
        self.assertIn('.build/pinned-surface/ScreenProofSurface.app', build)
        self.assertNotIn('Tests/NativeCaptureSurface/surface-app.swift', build)
        self.assertNotIn('--identifier ai.sliccy.proof-helper --entitlements \"$artifact_dir/entitlements.plist\" \"$surface_app\"', '\n'.join(script))
        self.assertIn('SLICCY_CAPTURE_RUNNER_PROOF:-0', build)
        self.assertIn('Contents/Helpers/ScreenProofSurface.app', build)
        workflow = (root / '.github/workflows/signing.yml').read_text()
        self.assertIn('dist-capture-proof/Sliccy.app artifacts/signed', workflow)
        self.assertIn('artifacts/signed/capture-manifest.json', workflow)
        self.assertNotIn('workflow_dispatch', workflow)
        self.assertNotIn('pull_request', workflow)
