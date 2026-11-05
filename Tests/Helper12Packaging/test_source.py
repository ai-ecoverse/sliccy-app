from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('helper12_manifest',ROOT/'script/helper12_manifest.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Helper12Tests(unittest.TestCase):
    def test_exact_source_lifetime_only_and_no_new_control_behavior(self):
        for name, expected in module.SOURCES.items():
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),expected)
        source=(ROOT/'Tests/NativeCaptureSurface/surface-app.swift').read_text()
        self.assertEqual(source.count('let deadline = began.advanced(by: .seconds(150))'),1)
        original=source.replace('let deadline = began.advanced(by: .seconds(150))','let deadline = began.advanced(by: .seconds(50))')
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),'668dfa14f2fc171a7bc51da7eea167bcf0e0140e9c42000dbd76cd0d7d821c60')
        self.assertIn('if count == 0 { code = 0; reason = "control-eof"; break }',source)
        self.assertIn('if offset == expected.count { code = 0; reason = "control-stop"; break }',source)

    def test_certificate_import_body_matches_existing_route(self):
        original=(ROOT/'script/ci_sign.sh').read_text().replace('refs/heads/main','refs/heads/proof/helper12-signing-v1').replace('push to the upstream main branch','push to the reviewed helper12 signing branch').replace('/sign_and_notarize.sh','/sign_helper12.sh').replace('== push','== workflow_dispatch').replace('refs/heads/proof/helper12-signing-v1','refs/heads/main')
        original='\n'.join(line for line in original.splitlines() if not line.startswith('#') or line.startswith('#!'))+'\n'
        self.assertEqual((ROOT/'script/ci_sign_helper12.sh').read_text(),original)

    def test_fixed_hosted_recipe_never_launches_subject_and_preserves_roles(self):
        build=(ROOT/'script/build_helper12.sh').read_text();sign=(ROOT/'script/sign_helper12.sh').read_text()
        self.assertIn("'CFBundleVersion':'12'",build)
        self.assertIn('swiftc -parse-as-library -target arm64-apple-macos27.0 Tests/NativeCaptureSurface/surface-presence.swift Tests/NativeCaptureSurface/surface-app.swift',build)
        self.assertIn('./script/test_surface_presence.sh',build)
        self.assertNotIn('open -',build+sign);self.assertNotIn('sudo',build+sign)
        self.assertIn('--verify --all-architectures --deep --strict',sign)
        self.assertIn('[[ "$role_status" == 3 ]]',sign)
        self.assertIn("'=identifier \"ai.sliccy.mac\"'",sign)
        self.assertIn('stapler validate',sign);self.assertIn('spctl --assess --type execute',sign)
        self.assertNotIn('SLICCY_RUNNER_ENVIRONMENT',build+sign)
        workflow=(ROOT/'.github/workflows/helper12-signing.yml').read_text()
        self.assertIn('  workflow_dispatch:',workflow)
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",workflow)
        self.assertIn('timeout-minutes: 45',workflow)
        self.assertIn('environment: signing',workflow)
        self.assertNotIn('script/build_and_run.sh',workflow)

    def fixture(self,root):
        app=root/'ScreenProofSurface.app'
        (app/'Contents/MacOS').mkdir(parents=True);(app/'Contents/_CodeSignature').mkdir()
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'ai.sliccy.proof-helper','CFBundleVersion':'12','CFBundleShortVersionString':'0.1.0','CFBundleExecutable':'ScreenProofSurface'}))
        (app/'Contents/MacOS/ScreenProofSurface').write_bytes(b'fabricated');(app/'Contents/_CodeSignature/CodeResources').write_bytes(b'fabricated-seal')
        (app/'Contents/CodeResources').write_bytes(b'fabricated-ticket')
        (app/'Contents/CodeResources').chmod(0o600)
        (root/'entitlements.plist').write_bytes(plistlib.dumps({}))
        (root/'notarization.json').write_text(json.dumps({'status':'Accepted'}))
        (root/'signing.txt').write_text('Identifier=ai.sliccy.proof-helper\nTeamIdentifier=S8LB56P782\nCDHash='+'a'*40+'\nCodeDirectory v=20500 size=500 flags=0x10000(runtime) hashes=1+7\n')
        (root/'ScreenProofSurface-0.1.0.zip').write_bytes(b'fabricated-archive')
        return app

    def test_manifest_exact_build_role_and_regular_file_set(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);app=self.fixture(root)
            result=module.manifest(root,'b'*40,'1','1')
            self.assertEqual(result['build'],'12');self.assertEqual(result['appRoleRefusalExit'],3)
            self.assertEqual(len(result['files']),4)
            info=app/'Contents/Info.plist';data=plistlib.loads(info.read_bytes());data['CFBundleVersion']='11';info.write_bytes(plistlib.dumps(data))
            with self.assertRaisesRegex(ValueError,'helper12-plist'):module.manifest(root,'b'*40,'1','1')
            data['CFBundleVersion']='12';info.write_bytes(plistlib.dumps(data))
            (app/'Contents/extra').symlink_to(info)
            with self.assertRaisesRegex(ValueError,'helper12-non-regular'):module.manifest(root,'b'*40,'1','1')

    def test_manifest_refuses_wrong_role_team_entitlement_and_attempt(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);self.fixture(root)
            sign=root/'signing.txt';original=sign.read_text()
            for replacement in [original.replace('ai.sliccy.proof-helper','ai.sliccy.mac'),original.replace('S8LB56P782','wrong'),original.replace('(runtime)','(other)')]:
                sign.write_text(replacement)
                with self.assertRaisesRegex(ValueError,'helper12-signing-metadata'):module.manifest(root,'b'*40,'1','1')
            sign.write_text(original)
            with self.assertRaisesRegex(ValueError,'helper12-run-source'):module.manifest(root,'b'*40,'1','2')
            (root/'entitlements.plist').write_bytes(plistlib.dumps({'debug':True}))
            with self.assertRaisesRegex(ValueError,'helper12-entitlements'):module.manifest(root,'b'*40,'1','1')

    def test_host_guard_refuses_before_any_artifact_read(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ValueError,'helper12-hosted-guard'):module.main()

if __name__=='__main__':
    suite=unittest.defaultTestLoader.discover(str(Path(__file__).parent))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
