from pathlib import Path
import hashlib
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parents[2]

class SourceTests(unittest.TestCase):
    def test_product_filter_stop_body_and_identity_limits_remain_exact(self):
        record = json.loads((ROOT/'Tests/RunnerBuild16/accepted-inputs.json').read_text())
        for name, expected in record['unchangedFiles'].items():
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), expected, name)
        indicator = (ROOT/'Sources/Sliccy/Screen/ScreenIndicator.swift').read_text()
        self.assertEqual(indicator.split('    func invoke(',1)[1].split('\n}\n',1)[0], record['stopRelayBody'])
        body = indicator.split('func proofDisplayChange(',1)[1].split('\n    }',1)[0]
        self.assertLess(body.index('invoke(.sourceChanged, origin: .displayChange)'), body.index('observe()'))
        self.assertIn('relay.proofDisplayChange { ScreenRunnerDisplaySampler.notification() }', indicator)
        old=json.loads((ROOT/'docs/runner-build15-contract.json').read_text())
        new=json.loads((ROOT/'docs/runner-build16-contract.json').read_text())
        self.assertEqual(new['bounds'], old['bounds'])
        self.assertEqual((new['build'],new['helperBuild']), (16,12))

    def test_complete_private_witness_genuine_builder_and_disjoint_receipt_route(self):
        boundary=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerInventoryBoundary.swift').read_text()
        self.assertIn('fileprivate init(owner: Identity, pairs: [Pair])',boundary)
        self.assertIn('var windowServerEmptyBundle: WindowServerEmptyBundleWitness? = nil',boundary)
        inventory=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerInventory.swift').read_text()
        self.assertIn('inventoryIdentity: validated.fingerprint.owners.first { $0.pid == pid }',inventory)
        self.assertIn('validated.windowServerEmptyBundle.flatMap { $0.owner.pid == pid ? $0 : nil }',inventory)
        probe=(ROOT/'Sources/Sliccy/Screen/ScreenProofProtectedProbe.swift').read_text()
        structural=probe.split('if structural {',1)[1].split('                continue',1)[0]
        self.assertIn('ScreenFilterBuilder.display(display, selected: [app], exceptingWindows: [], protected: protected)',structural)
        self.assertIn('ScreenFilterBuilder.window(actual, protected: protected)',structural)
        app=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerProofApp.swift').read_text()
        self.assertIn('journal.emit("protected-structural-refused", structural.fields)\n                    return',app)

    def test_display_contract_and_sampler_are_bounded_without_content(self):
        contract=json.loads((ROOT/'docs/runner-build16-contract.json').read_text())['displayDiagnostics']
        self.assertEqual(contract['maximumRows'],(8+16)*(1+8)+2)
        sampler=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerDisplaySampler.swift').read_text()
        self.assertLess(sampler.index('guard let ticket = recorder.begin(.notification)'), sampler.index('Task { @MainActor'))
        self.assertLess(sampler.index('guard recorder.shouldSample(ticket)'),sampler.index('let screens = NSScreen.screens'))
        for token in ['localizedName','serialNumber','CGDisplaySerialNumber','title','URL(','iccProfileData']:
            self.assertNotIn(token,sampler)
        app=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerProofApp.swift').read_text()
        self.assertLess(app.index('ScreenRunnerDisplayDiagnostics.shared.finish()'),app.index('journal.emit("terminal"'))

    def test_hosted_faults_have_unique_real_source_and_selected_tests(self):
        spec=importlib.util.spec_from_file_location('build16_hosted',ROOT/'Tests/RunnerBuild16/hosted.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        tests='\n'.join(p.read_text() for p in (ROOT/'Tests/SliccyTests').glob('*.swift'))
        self.assertEqual(len(module.harness.PLAN),26)
        for name,path,old,new,selected in module.harness.PLAN:
            self.assertEqual((ROOT/path).read_text().count(old),1,name)
            self.assertNotEqual(old,new,name)
            self.assertIn('func '+selected+'(',tests,name)
        workflow=(ROOT/'.github/workflows/runner-build16-tests.yml').read_text()
        self.assertIn('proof/capture-build16-v1',workflow)
        self.assertNotIn('secrets.',workflow)
        self.assertNotIn('SLICCY_RUNNER_ENVIRONMENT',workflow)

if __name__ == '__main__':
    unittest.main()
