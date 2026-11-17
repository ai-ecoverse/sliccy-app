import base64
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'script'))
from prepare_release import make_appcast, SPARKLE
from release_metadata import configuration

class ReleaseTests(unittest.TestCase):
    def test_appcast_binds_archive_and_compatibility(self):
        config = configuration()
        archive = f'Sliccy-{config["version"]}.zip'
        signature = base64.b64encode(bytes(range(64))).decode()
        item = ET.fromstring(make_appcast(config, archive, 12345, signature)).find('channel/item')
        self.assertEqual(item.find('enclosure').attrib, {
            'url': f'https://github.com/ai-ecoverse/sliccy-app/releases/download/v{config["version"]}/{archive}',
            'length': '12345', 'type': 'application/octet-stream', f'{{{SPARKLE}}}edSignature': signature})
        self.assertEqual(item.find(f'{{{SPARKLE}}}version').text, config['build'])
        self.assertEqual(item.find(f'{{{SPARKLE}}}minimumSystemVersion').text, '26.0')
        self.assertEqual(item.find(f'{{{SPARKLE}}}hardwareRequirements').text, 'arm64')
        for signature, size in [('invalid', 10), (base64.b64encode(bytes(64)).decode(), 0)]:
            with self.assertRaises(ValueError):
                make_appcast(config, 'test.zip', size, signature)

    def test_package_and_release_deployment_targets_agree(self):
        minimum = configuration()['minimumSystemVersion']
        self.assertEqual(minimum, '26.0')
        self.assertIn(f'platforms: [.macOS("{minimum}")]', (ROOT / 'Package.swift').read_text())

    def test_only_release_bundle_enables_updater(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'Info.plist'
            for mode in ['development', 'release', 'proof']:
                path.write_bytes(plistlib.dumps({'CFBundleVersion':'17','CFBundleShortVersionString':'0.1.0','LSMinimumSystemVersion':'27.0'}))
                subprocess.run([sys.executable, str(ROOT/'script/release_metadata.py'), str(path), mode], check=True)
                result = plistlib.loads(path.read_bytes())
                self.assertEqual(result['SliccyEnableUpdater'], mode == 'release')
                self.assertEqual(result['CFBundleVersion'], '17' if mode == 'proof' else configuration()['build'])
                self.assertFalse(result['SUAllowsAutomaticUpdates'])
                self.assertFalse(result['SUSendProfileInfo'])
                if mode == 'proof':
                    self.assertEqual(result['LSMinimumSystemVersion'], '27.0')
                    self.assertNotIn('CFBundleURLTypes', result)
                else:
                    self.assertEqual(result['LSMinimumSystemVersion'], '26.0')
                    self.assertEqual(result['CFBundleURLTypes'][0]['CFBundleURLSchemes'], ['http','https'])
                    self.assertTrue(result['SliccyHandlesWebLinks'])

    def test_version_gate_refuses_drafts_and_downgrades(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'releases.json'
            for data, code, output in [([],0,'publish=true'),
                ([{'tag_name':'v' + configuration()['version'],'draft':False}],0,'publish=false'),
                ([{'tag_name':'v' + configuration()['version'],'draft':True}],1,''),
                ([{'tag_name':'v99.0.0','prerelease':False}],1,'')]:
                path.write_text(json.dumps(data))
                result = subprocess.run([sys.executable,str(ROOT/'script/check_release_version.py'),str(path)],capture_output=True,text=True)
                self.assertEqual(result.returncode, code)
                if output: self.assertIn(output,result.stdout.splitlines())

    def test_existing_release_dmg_backfill_is_one_time(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'releases.json'
            name = f'Sliccy-{configuration()["version"]}.dmg'
            for names, code, expected in [([],0,'package_dmg=true'), ([name],0,'package_dmg=false'), (['DMG-SHA256SUMS'],1,None)]:
                path.write_text(json.dumps([{'tag_name':'v'+configuration()['version'], 'assets':[{'name':n} for n in names]}]))
                result = subprocess.run([sys.executable,str(ROOT/'script/check_release_version.py'),str(path)],capture_output=True,text=True)
                self.assertEqual(result.returncode,code)
                if expected: self.assertIn(expected,result.stdout.splitlines())
