from pathlib import Path
import hashlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'script'))
import surface_pin


class SurfacePinTests(unittest.TestCase):
    def test_real_validator_refuses_changed_bytes_before_native_tools(self):
        with tempfile.TemporaryDirectory() as root, patch.object(surface_pin.subprocess, 'run') as run:
            app = Path(root) / 'ScreenProofSurface.app'
            for relative in surface_pin.FILES:
                file = app / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'modified')
            with self.assertRaisesRegex(ValueError, 'immutable bytes'):
                surface_pin.verify(app)
            run.assert_not_called()

    def test_actual_validation_invokes_strict_role_and_exact_app_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            app = Path(root) / 'ScreenProofSurface.app'
            hashes = {}
            for relative in surface_pin.FILES:
                file = app / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(relative.encode())
                hashes[relative] = hashlib.sha256(relative.encode()).hexdigest()
            def invoke(args, **kwargs):
                if '--entitlements' in args:
                    return subprocess.CompletedProcess(args, 0, plistlib.dumps({}), b'')
                if '-d' in args:
                    return subprocess.CompletedProcess(args, 0, b'', ('CDHash=' + surface_pin.CDHASH + '\n').encode())
                return subprocess.CompletedProcess(args, 3 if '=identifier "ai.sliccy.mac"' in args else 0, b'', b'')
            with patch.object(surface_pin, 'FILES', hashes), patch.object(surface_pin.subprocess, 'run', side_effect=invoke) as run:
                surface_pin.verify(app)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertEqual(calls[0], ['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + surface_pin.REQUIREMENT, str(app)])
            self.assertEqual(calls[-1], ['/usr/bin/codesign', '--verify', '--strict', '-R', '=identifier "ai.sliccy.mac"', str(app)])
            self.assertFalse(any('--sign' in args for args in calls))

    def test_kernel_entry_and_c_support_are_absent_from_production_build_inputs(self):
        root = Path(__file__).resolve().parents[2]
        main = (root / 'Sources/Sliccy/App/SliccyMain.swift').read_text()
        proof = main.split('#if SLICCY_CAPTURE_RUNNER_PROOF\n', 1)[1].split('#elseif', 1)[0]
        self.assertIn('--runner-kernel', proof)
        self.assertNotIn('--runner-kernel', main.replace(proof, ''))
        code = (root / 'Sources/ScreenSystem/ScreenSystem.c').read_text()
        guarded = code.split('#if defined(SLICCY_CAPTURE_RUNNER_PROOF)\n', 1)[1].split('#endif', 1)[0]
        for name in ('sliccy_runner_identity', 'sliccy_runner_path', 'sliccy_runner_hash', 'sliccy_runner_no_acl', 'sliccy_runner_spawn_kernel', 'sliccy_runner_wait_kernel'):
            self.assertIn(name, guarded)
            self.assertNotIn(name, code.replace(guarded, ''))
        script = (root / 'script/build_and_run.sh').read_text()
        self.assertEqual(script.count('-Xcc -DSLICCY_CAPTURE_RUNNER_PROOF'), 1)
        self.assertIn('--scratch-path "$ROOT_DIR/.build/capture-runner-proof"', script)


if __name__ == '__main__':
    unittest.main()
