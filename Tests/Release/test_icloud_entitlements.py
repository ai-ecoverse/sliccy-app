import datetime
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'script'))
from icloud_entitlements import entitlements


def profile(**changes):
    granted = {
        'com.apple.application-identifier': 'S8LB56P782.ai.sliccy.mac',
        'com.apple.developer.team-identifier': 'S8LB56P782',
        'com.apple.developer.ubiquity-kvstore-identifier': 'S8LB56P782.*',
        'keychain-access-groups': ['S8LB56P782.*'],
    }
    granted.update(changes.pop('granted', {}))
    value = {
        'TeamIdentifier': ['S8LB56P782'],
        'ProvisionsAllDevices': True,
        'ExpirationDate': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=300),
        'Entitlements': granted,
    }
    value.update(changes)
    return value


class ICloudEntitlementTests(unittest.TestCase):
    def test_developer_id_profile_yields_only_the_shared_key_value_container(self):
        expected = {
            'com.apple.application-identifier': 'S8LB56P782.ai.sliccy.mac',
            'com.apple.developer.team-identifier': 'S8LB56P782',
            'com.apple.developer.ubiquity-kvstore-identifier': 'S8LB56P782.ai.sliccy.trays',
        }
        self.assertEqual(entitlements(profile()), expected)
        exact = profile(granted={'com.apple.developer.ubiquity-kvstore-identifier': 'S8LB56P782.ai.sliccy.trays'})
        self.assertEqual(entitlements(exact), expected)

    def test_other_apps_teams_debug_development_or_expired_profiles_are_refused(self):
        refused = [
            profile(granted={'com.apple.application-identifier': 'S8LB56P782.com.slicc.sliccstart'}),
            profile(TeamIdentifier=['OTHERTEAM1']),
            profile(granted={'com.apple.developer.team-identifier': 'OTHERTEAM1'}),
            profile(granted={'com.apple.security.get-task-allow': True}),
            profile(ProvisionsAllDevices=False),
            profile(ExpirationDate=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)),
            profile(granted={'com.apple.developer.ubiquity-kvstore-identifier': 'S8LB56P782.ai.sliccy.mac'}),
            profile(granted={'com.apple.developer.ubiquity-kvstore-identifier': '*'}),
            profile(Entitlements=None),
        ]
        for value in refused:
            with self.subTest(value=value), self.assertRaises(ValueError):
                entitlements(value)

    def test_command_writes_nothing_for_a_rejected_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'profile.plist', Path(directory) / 'entitlements.plist'
            source.write_bytes(plistlib.dumps(profile(ProvisionsAllDevices=False)))
            result = subprocess.run([sys.executable, str(ROOT / 'script/icloud_entitlements.py'), str(source), str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(target.exists())
            source.write_bytes(plistlib.dumps(profile()))
            subprocess.run([sys.executable, str(ROOT / 'script/icloud_entitlements.py'), str(source), str(target)], check=True)
            self.assertIn('com.apple.developer.ubiquity-kvstore-identifier', plistlib.loads(target.read_bytes()))

    def test_signing_adds_icloud_only_to_release_apps_with_the_optional_profile(self):
        script = (ROOT / 'script/sign_and_notarize.sh').read_text()
        self.assertIn('if [[ "${SLICCY_RELEASE:-0}" == 1 && -n "${SLICCY_MAC_PROVISIONING_PROFILE_BASE64:-}" ]]; then', script)
        self.assertIn('--entitlements "$app_entitlements" "$signed_app"', script)
        # Diagnostic helpers keep the empty entitlements.
        self.assertIn('--identifier ai.sliccy.proof-helper --entitlements "$artifact_dir/entitlements.plist" "$helper"', script)
        self.assertEqual(script.count('app_entitlements="$artifact_dir/app-entitlements.plist"'), 1)
        workflow = (ROOT / '.github/workflows/signing.yml').read_text()
        self.assertIn('SLICCY_MAC_PROVISIONING_PROFILE_BASE64: ${{ secrets.SLICCY_MAC_PROVISIONING_PROFILE_BASE64 }}', workflow)


if __name__ == '__main__':
    unittest.main()
