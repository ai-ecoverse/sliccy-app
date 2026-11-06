from pathlib import Path
import hashlib
import importlib.util
import json
import unittest

from product_projection import product_projection
import plan_dry_run

ROOT = Path(__file__).resolve().parents[2]


class SourceTests(unittest.TestCase):
    def test_product_path_projection_matches_signed_build16(self):
        record = json.loads((ROOT / 'Tests/RunnerBuild17/accepted-inputs.json').read_text())
        for name, expected in record['unchangedFiles'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected, name)
        indicator = (ROOT / 'Sources/Sliccy/Screen/ScreenIndicator.swift').read_text()
        self.assertEqual(indicator.split('    func invoke(', 1)[1].split('\n}\n', 1)[0], record['stopRelayBody'])
        accepted = json.loads((ROOT / 'Tests/RunnerBuild17/accepted-product-projection.json').read_text())
        for name, expected in accepted['files'].items():
            text = (ROOT / name).read_text() if (ROOT / name).exists() else ''
            actual = product_projection(text)
            self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), expected['productSHA256'], name)
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), expected['sourceSHA256'], name)
        for name in accepted['proofOnlyMustProjectEmpty']:
            text = (ROOT / name).read_text()
            self.assertTrue(text.startswith('#if SLICCY_CAPTURE_RUNNER_PROOF\n'), name)
            self.assertEqual(product_projection(text).strip(), '', name)
        # Every current Sources/*.swift either matches an accepted product projection or is listed proof-only empty.
        current = {p.relative_to(ROOT).as_posix() for p in (ROOT / 'Sources').rglob('*.swift')}
        allowed = set(accepted['files']) | set(accepted['proofOnlyMustProjectEmpty'])
        self.assertEqual(current - allowed, set())

    def test_launch_arm_hook_keeps_product_observer_byte_identical(self):
        indicator = (ROOT / 'Sources/Sliccy/Screen/ScreenIndicator.swift').read_text()
        self.assertIn(
            '#else\n            observers.append(center.addObserver(forName: name, object: nil, queue: nil) '
            '{ [relay] _ in relay.invoke(.sourceChanged, origin: origin) })\n#endif',
            indicator,
        )
        proof = indicator.split('#if SLICCY_CAPTURE_RUNNER_PROOF\n            if origin == .workspaceLaunch', 1)[1].split('#else', 1)[0]
        self.assertIn('try coordinator.arm(relay)', proof)
        self.assertIn('continue', proof)
        self.assertIn('relay.proofWorkspaceChange(notification, origin: origin)', proof)

    def test_instance_equality_forwards_foundation_isEqual(self):
        source = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerLaunchInstance.swift').read_text()
        body = source.split('static func matches', 1)[1].split('\n    }', 1)[0]
        self.assertIn('current.isEqual(original)', body)
        self.assertNotIn('===', body)

    def test_failure_enums_name_bsd_and_instance_boundaries(self):
        barrier = (ROOT / 'Sources/Sliccy/Screen/ScreenRunnerLaunchBarrier.swift').read_text()
        for value in ['launch-bsd-before', 'launch-bsd-after', 'launch-instance', 'launch-pending', 'launch-revision']:
            self.assertIn(value, barrier)

    def test_build16_module_has_no_plan_attribute_like_7e8ad813(self):
        # Exact named first cause of run 42208815999: build16_hosted.PLAN AttributeError.
        with self.assertRaises(AttributeError):
            plan_dry_run.broken_build17_module_plan_access(ROOT)

    def test_hosted_plan_dry_run_assembles_without_subprocess(self):
        report = plan_dry_run.run(ROOT, require_driver=plan_dry_run.DRIVER_HARNESS.is_dir())
        self.assertTrue(report['brokenModulePlanRejected'])
        self.assertGreaterEqual(report['build17PlanCount'], 37)  # 26 build16 + 11 launch
        self.assertIn('launch-instance-equality', report['build17PlanNames'])
        hosted = importlib.util.spec_from_file_location('check_build17_hosted', ROOT / 'Tests/RunnerBuild17/hosted.py')
        module = importlib.util.module_from_spec(hosted)
        hosted.loader.exec_module(module)
        self.assertIs(module.harness, module.build16.harness)
        self.assertTrue(hasattr(module.harness, 'PLAN'))
        self.assertFalse(hasattr(module, 'PLAN'))
        if report.get('driverSkipped'):
            self.assertEqual(report['driverSkipped'], 'harness-absent')
        else:
            self.assertGreaterEqual(report['driverMutantCount'], 146)
