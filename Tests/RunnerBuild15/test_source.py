from pathlib import Path
import hashlib
import importlib.util
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]

class SourceTests(unittest.TestCase):
    def test_inventory_guards_identity_modules_and_limits_unchanged(self):
        record = json.loads((ROOT/'Tests/RunnerBuild14/accepted-inputs.json').read_text())
        boundary = (ROOT/'Sources/Sliccy/Screen/ScreenRunnerInventoryBoundary.swift').read_text().split('static func validate',1)[1]
        self.assertEqual([re.sub(r'\s+','',x) for x in re.findall(r'guard (.*?) else',boundary,re.S)],record['boundaryGuardPredicates'])
        for name,expected in record['unchangedFiles'].items():
            if name.endswith('/ScreenRunnerOwnedProcess.swift'):
                continue
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),expected,name)
        old = json.loads((ROOT/'docs/runner-build14-contract.json').read_text())
        new = json.loads((ROOT/'docs/runner-build15-contract.json').read_text())
        self.assertEqual(new['bounds'],old['bounds'])
        self.assertEqual(new['helperBuild'],12)
        self.assertEqual(new['build'],15)

    def test_real_surface_route_requires_refusal_sink_before_hash_and_launch(self):
        source = (ROOT/'Sources/Sliccy/Screen/ScreenRunnerOwnedProcess.swift').read_text()
        surface = source.split('static func surface(',1)[1].split('static func chrome(',1)[0]
        self.assertIn('refusal: @escaping @Sendable (ScreenRunnerSurfaceDiagnostics.Notice) -> Void,',surface)
        self.assertNotIn('Void =',surface.split('refusal:',1)[1].split('ended:',1)[0])
        self.assertLess(surface.index('Data(contentsOf: executable)'),surface.index('diagnostics.verifyHash('))
        self.assertLess(surface.index('diagnostics.verifyHash('),surface.index('try ScreenRunnerOwnedProcess('))
        self.assertIn('surfaceDiagnostics: diagnostics',surface)
        app = (ROOT/'Sources/Sliccy/Screen/ScreenRunnerProofApp.swift').read_text()
        self.assertIn('journal.emit("surface-refusal", notice.fields, at: notice.at)',app)
        self.assertIn('surface(home: home, sliceEvidence: sliceRecord, refusal:',app)
        self.assertNotIn('baff7b8b21264018138c9f7e2e7f6b8052bdcaf6e10b8ffa06dde854ac2b20c9',source)

    def test_producer_and_contract_are_closed_and_proof_only(self):
        source = (ROOT/'Sources/Sliccy/Screen/ScreenRunnerSurfaceDiagnostics.swift').read_text()
        self.assertTrue(source.startswith('#if SLICCY_CAPTURE_RUNNER_PROOF\n'))
        self.assertTrue(source.endswith('#endif\n'))
        for excluded in ['ProcessInfo','Security','AppKit','ScreenCaptureKit']:
            self.assertNotIn('import '+excluded,source)
        self.assertIn('lock.unlock()\n        if first',source)
        self.assertIn('catch { reject(predicate, operation); throw error }',source)
        fields=json.loads((ROOT/'docs/runner-build15-contract.json').read_text())['surfaceRefusal']['fields']
        self.assertEqual(fields['predicate'],['host','identifier','team','hash','role','path','operation'])
        self.assertEqual(len(fields['operation']),10)

    def test_hosted_mutations_match_actual_source_once(self):
        spec=importlib.util.spec_from_file_location('build15_hosted',ROOT/'Tests/RunnerBuild15/hosted.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(len(module.harness.PLAN),10)
        tests=(ROOT/'Tests/SliccyTests/ScreenRunnerSurfaceDiagnosticsTests.swift').read_text()
        for name,path,old,new,selected in module.harness.PLAN:
            self.assertEqual((ROOT/path).read_text().count(old),1,name)
            self.assertIn('func '+selected+'(',tests)
            self.assertNotEqual(old,new)
        workflow=(ROOT/'.github/workflows/runner-build15-tests.yml').read_text()
        self.assertIn('proof/capture-build15-v1',workflow)
        self.assertNotIn('SLICCY_RUNNER_ENVIRONMENT',workflow)
        self.assertNotIn('secrets.',workflow)

if __name__ == '__main__':
    unittest.main()
