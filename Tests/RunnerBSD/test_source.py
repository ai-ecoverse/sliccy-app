from pathlib import Path
import ast
import unittest

ROOT=Path(__file__).resolve().parents[2]

class SourceTests(unittest.TestCase):
    def test_identity_path_has_no_root_launch(self):
        sources=list((ROOT/'Sources').rglob('*.swift'))+list((ROOT/'Sources').rglob('*.c'))
        for path in sources:
            text=path.read_text()
            self.assertNotIn('--runner-kernel',text)
            self.assertNotIn('/usr/bin/sudo',text)
            self.assertNotIn('ScreenRunnerKernelChild',text)
        self.assertFalse((ROOT/'Sources/Sliccy/Screen/ScreenRunnerKernelChild.swift').exists())
        guarded=(ROOT/'Sources/ScreenSystem/include/ScreenSystem.h').read_text().split('#if defined(SLICCY_CAPTURE_RUNNER_PROOF)',1)[1]
        self.assertIn('#include "ScreenRunnerBSD.h"',guarded)

    def test_actual_fixed_queries_and_c_boundary_are_wired(self):
        code=(ROOT/'Sources/ScreenSystem/ScreenSystem.c').read_text()
        self.assertIn('int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}',code)
        self.assertIn('sysctl(mib, 4, &info, &length, NULL, 0)',code)
        self.assertIn('value->self_pid = getpid(); value->parent_pid = getppid()',code)
        self.assertIn('return observation ? sliccy_bsd_select(*observation, pid, value, used_sysctl)',code)
        swift=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerBSD.swift').read_text()
        self.assertIn('sliccy_runner_bsd_select(&observation, pid, &value, &used)',swift)
        self.assertIn('sliccy_runner_bsd_windowserver(&a, &b)',swift)
        owner=(ROOT/'Sources/Sliccy/Screen/ScreenRunnerSystemOwner.swift').read_text()
        verify=owner.split('static func verify(',1)[1]
        self.assertLess(verify.index('phase: "before"'),verify.index('try code('))
        self.assertLess(verify.index('try code('),verify.index('phase: "after"'))
        self.assertIn('ScreenRunnerBSD.bind(before, after, windowServer: isWindowServer)',verify)

    def test_native_tests_cannot_run_locally(self):
        text=(ROOT/'Tests/RunnerBSD/hosted.py').read_text()
        ast.parse(text)
        self.assertIn("raise RuntimeError('hosted-only')",text)
        self.assertLess(text.index("raise RuntimeError('hosted-only')"),text.index('subprocess.run('))
        fixture=(ROOT/'Tests/RunnerBSD/fixture.c').read_text()
        for token in ['sysctl(', 'proc_pidinfo(', 'getpid(', 'SecCode', 'sudo']:
            self.assertNotIn(token,fixture)

if __name__=='__main__':unittest.main()
