from pathlib import Path
import ast
import hashlib
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SWIFT = 'Sources/Sliccy/Screen/ScreenRunnerOwnedProcess.swift'


def values(path):
    result = {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result


class HelperConsistencyTests(unittest.TestCase):
    def test_swift_packaging_signed_manifest_agree(self):
        source = (ROOT / SWIFT).read_text()
        pins = values(ROOT / 'script/surface_pin.py')
        fixture = ROOT / 'Tests/UniversalManifest/helper12-signed-manifest.json'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), 'a9c524c835d3ea96644ede533800a80751cc3e67c016f8a7eb6f2fa19f1a57ca')
        manifest = json.loads(fixture.read_text())
        matches = re.findall(r'static let surfaceSHA256 = "([0-9a-f]{64})"', source)
        self.assertEqual(len(matches), 1, 'helper-pin-single-source')
        self.assertEqual(matches[0], pins['FILES']['Contents/MacOS/ScreenProofSurface'], 'helper-pin-swift-packaging')
        self.assertEqual(pins['FILES'], manifest['files'], 'helper-pin-manifest-files')
        self.assertEqual(pins['CDHASH'], manifest['cdhash'], 'helper-pin-manifest-cdhash')
        self.assertEqual((pins['RUN'], pins['SOURCE'], pins['ZIP_SHA256']), (manifest['run'], manifest['sourceCommit'], manifest['archiveSHA256']))
        self.assertEqual((manifest['build'], manifest['identifier'], manifest['team']), ('12', 'ai.sliccy.proof-helper', 'S8LB56P782'))
        tree = ast.parse((ROOT / 'script/capture_manifest.py').read_text())
        bundle = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'signed_bundle')
        build = next(node.value for node in bundle.body if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'build' for t in node.targets))
        self.assertIsInstance(build, ast.IfExp)
        self.assertEqual(ast.literal_eval(build.orelse), manifest['build'], 'helper-pin-capture-build')
        self.assertIn('expected: surfaceSHA256', source)
        self.assertIn('identifier: "ai.sliccy.proof-helper", team: "S8LB56P782"', source)

    def test_existing_signing_ci_discovers_this_gate(self):
        workflow = (ROOT / '.github/workflows/signing.yml').read_text()
        self.assertIn("python3 -m unittest discover -s Tests/UniversalManifest -p 'test_*.py'", workflow)
        self.assertLess(workflow.index('unittest discover'), workflow.index('- name: Fetch immutable signed surface'))


if __name__ == '__main__':
    unittest.main()
