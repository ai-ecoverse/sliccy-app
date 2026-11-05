from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]

class SourceTests(unittest.TestCase):
    def test_original_acceptance_predicates_and_identity_modules_unchanged(self):
        record = json.loads((ROOT / 'Tests/RunnerBuild14/accepted-inputs.json').read_text())
        boundary = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerInventoryBoundary.swift').read_text().split('static func validate', 1)[1]
        predicates = [re.sub(r'\s+', '', x) for x in re.findall(r'guard (.*?) else', boundary, re.S)]
        self.assertEqual(predicates, record['boundaryGuardPredicates'])
        for path, expected in record['unchangedFiles'].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), expected, path)

    def test_actual_inventory_entries_supply_attempts_and_keep_retry(self):
        source = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerProofApp.swift').read_text()
        for site in ['initial', 'refresh', 'monitor']:
            self.assertIn('readInventory(.' + site, source)
        self.assertIn('inventoryDiagnostics.begin(.authorizationBaseline)', source)
        self.assertEqual(source.count('try await ScreenRunnerInventory.read('), 1)
        self.assertIn('diagnostics: attempt, identityRecord:', source)
        self.assertIn('inventoryDiagnostics.begin(site)', source)
        self.assertIn('inventoryDeadline = ContinuousClock.now.advanced(by: .seconds(5))', source)
        self.assertIn('Task.sleep(for: .milliseconds(50))', source)
        self.assertIn('output.emit("inventory-refusal", notice.fields, at: notice.at)', source)
        inventory = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerInventory.swift').read_text()
        self.assertIn('ScreenRunnerInventoryBoundary.sckRecord(', inventory)
        self.assertIn('diagnostics.observe(.ownerIdentifier', inventory)
        self.assertIn('context: context, diagnostics: diagnostics', inventory)

    def test_clock_is_early_causal_and_baseline_capture_limits_unchanged(self):
        source = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerProofApp.swift').read_text()
        read = source.index('ScreenProofSession.readJoin()')
        marker = source.index('marker(ScreenRunnerClockAnchor.marker, timeout: .seconds(5))')
        emit = source.index('journal.emit("clock-anchor", ScreenRunnerClockAnchor.fields, at: anchor)')
        home = source.index('let home = try prepareHome()')
        self.assertLess(read, marker); self.assertLess(marker, emit); self.assertLess(emit, home)
        self.assertIn('guard index == expected.count else { throw ScreenFailure.stalled }\n            return ContinuousClock.now', source)
        self.assertIn('marker("runner-baseline", timeout: .seconds(5))', source)
        self.assertIn('ScreenRunnerSetupAllowance.watchdogSeconds', source)
        self.assertIn('ScreenRunnerSetupAllowance.finalSeconds', source)
        self.assertIn('ScreenRunnerSetupAllowance.cleanupRemaining(elapsed:', source)

    def test_contract_enums_fields_and_withdrawn_limit(self):
        contract = json.loads((ROOT / 'docs/runner-build14-contract.json').read_text())
        self.assertEqual(contract['bounds'], {'appWatchdogSeconds':120,'appFinalCheckSeconds':150,'captureSeconds':10,'inventoryRetrySeconds':5,'runnerBaselineMarkerSeconds':5,'driverBaselineTotalSeconds':2,'driverChromeStaticJobSeconds':30,'driverCaseExecutionSeconds':120,'driverCaseHardSeconds':150,'driverEscalationSeconds':3,'suiteSeconds':960,'goTestSeconds':980,'goCommandSeconds':990,'wrapperWorkSeconds':1500,'sealSeconds':1560,'jobMinutes':30,'journalBytes':1048576,'journalRowBytes':4096})
        self.assertEqual(contract['clock']['fields'], {'marker':'runner-clock-anchor'})
        self.assertEqual(set(contract['inventoryRefusal']['site']), {'initial','refresh','monitor','authorization-baseline'})
        self.assertIn('owner-attribution', contract['inventoryRefusal']['issue'])
        self.assertEqual(contract['helperBuild'], 11)
        self.assertEqual(contract['build'], 14)

    def test_all_overlays_match_exact_source_once(self):
        spec = importlib.util.spec_from_file_location('build14_hosted', ROOT / 'Tests/RunnerBuild14/hosted.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(len(module.harness.PLAN), 17)
        for name, path, old, new, selected in module.harness.PLAN:
            source = (ROOT / path).read_text()
            self.assertEqual(source.count(old), 1, name)
            self.assertNotEqual(old, new)
            tests = (ROOT / 'Tests/SliccyTests/ScreenRunnerInventoryDiagnosticsTests.swift').read_text()
            self.assertIn('func ' + selected + '(', tests)
        self.assertNotIn('SLICCY_RUNNER_ENVIRONMENT', (ROOT / '.github/workflows/runner-build14-tests.yml').read_text())

    def test_positive_nominal_margin_and_fail_closed_worst_case(self):
        spec = importlib.util.spec_from_file_location("build14_volume", ROOT / "Tests/RunnerBuild14/volume.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        model = module.model()
        self.assertEqual(model, json.loads((ROOT / "docs/runner-build14-volume.json").read_text()))
        self.assertEqual(model["nominalMarginBytes"], 76800)
        self.assertLess(model["withAggregationWorstMarginBytes"], 0)

    def test_new_swift_source_is_proof_gated(self):
        for name in ['ScreenRunnerInventoryDiagnostics.swift', 'ScreenRunnerSetupAllowance.swift']:
            source = (ROOT / 'Sources/Sliccy/Screen' / name).read_text()
            self.assertTrue(source.startswith('#if SLICCY_CAPTURE_RUNNER_PROOF\n'))
            self.assertTrue(source.endswith('#endif\n'))
            self.assertNotIn('ProcessInfo', source)
        ast.parse((ROOT / 'Tests/RunnerBuild14/hosted.py').read_text())

if __name__ == '__main__':
    unittest.main()
