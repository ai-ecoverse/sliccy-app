from pathlib import Path
import os
import plistlib
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'script'))
import hosted_pid_manifest as subject


class HostedManifestTests(unittest.TestCase):
    def fixture(self, root):
        app = Path(root) / 'Sliccy.app'
        for name in ['MacOS', 'Resources']:
            (app / 'Contents' / name).mkdir(parents=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'ai.sliccy.mac', 'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '10'}))
        (app / 'Contents/Resources/slicc').write_bytes(b'non-executed fixture')
        return app

    def signature(self, path, role, architecture):
        if path.name == 'slicc':
            return {'architecture': architecture, 'sha256': subject.RESOURCES['slicc'][1], 'CDHash': subject.RESOURCES['slicc'][2]}, ''
        return {'architecture': architecture, 'sha256': '0' * 64, 'CDHash': '1' * 40}, 'flags=0x10000(runtime)'

    def checked(self, args):
        return (plistlib.dumps({}), b'') if '--entitlements' in args else (b'', b'')

    def test_closed_artifact_contract_and_unexecuted_subject(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(subject, 'signature', side_effect=self.signature), patch.object(subject, 'checked', side_effect=self.checked):
            record = subject.manifest(self.fixture(root))
            self.assertEqual(record['build'], '10')
            self.assertEqual(record['case'], 'pid-reuse-hosted')
            self.assertEqual(set(record['resources']), {'slicc'})
            self.assertFalse(record['capture'])
            self.assertFalse(record['productionEnabled'])
            self.assertFalse(record['nativeTrialsPerformed'])

    def test_extra_resources_helpers_and_wrong_version_refuse(self):
        for change in ['extra', 'helpers', 'version']:
            with tempfile.TemporaryDirectory() as root:
                app = self.fixture(root)
                if change == 'extra': (app / 'Contents/Resources/other').write_bytes(b'x')
                if change == 'helpers': (app / 'Contents/Helpers').mkdir()
                if change == 'version': (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'ai.sliccy.mac', 'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '8'}))
                with self.assertRaises(ValueError): subject.manifest(app)

    def test_release_byte_hash_and_empty_entitlements_are_required(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
            app = self.fixture(root)
            def changed(path, role, architecture):
                value, text = self.signature(path, role, architecture)
                if path.name == 'slicc': value['sha256'] = '0' * 64
                return value, text
            with patch.object(subject, 'signature', side_effect=changed), patch.object(subject, 'checked', side_effect=self.checked):
                with self.assertRaises(ValueError): subject.manifest(app)
            with patch.object(subject, 'signature', side_effect=self.signature), patch.object(subject, 'checked', return_value=(plistlib.dumps({'com.apple.security.get-task-allow': True}), b'')):
                with self.assertRaises(ValueError): subject.manifest(app)

    def test_build10_packaging_selects_fixed_hosted_manifest_without_execution(self):
        root = Path(__file__).resolve().parents[2]
        lines = (root / 'script/sign_and_notarize.sh').read_text().splitlines()
        matches = [index for index, line in enumerate(lines) if '/hosted_pid_manifest.py"' in line]
        self.assertEqual(len(matches), 1)
        index = matches[0]
        self.assertEqual(lines[index], '  python3 "$(dirname "$0")/hosted_pid_manifest.py" "$signed_app" "$artifact_dir/hosted-pid-manifest.json"')
        self.assertEqual(lines[index + 1], 'fi')
        expected_prefix = 'if [[ "$(/usr/libexec/PlistBuddy -c \'Print :CFBundleVersion\' "$plist")" == '
        condition = lines[index - 1]
        self.assertTrue(condition.startswith(expected_prefix))
        version = re.fullmatch(r'([0-9]+) \]\]; then', condition[len(expected_prefix):])
        self.assertIsNotNone(version)
        selected = [build for build in ('7', '8', '9', '10') if build == version.group(1)]
        self.assertEqual(selected, ['10'])
        build_script = (root / 'script/build_and_run.sh').read_text()
        hosted = build_script.split('if [[ "${SLICCY_HOSTED_PID_PROOF:-0}" == 1 ]]; then', 1)[1].split('elif', 1)[0]
        self.assertIn('BUILD_NUMBER=10', hosted)
