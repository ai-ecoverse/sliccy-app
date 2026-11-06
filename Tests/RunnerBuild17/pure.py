from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/RunnerBuild17'))
import test_source  # noqa: E402


def denied(*args, **kwargs):
    raise AssertionError('unmocked subprocess prohibited')


def run(suite):
    output = io.StringIO()
    with patch.object(subprocess, 'run', denied), patch.object(subprocess, 'Popen', denied), \
         patch.object(subprocess, 'check_output', denied):
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    return result, output.getvalue()


def suite():
    result = unittest.TestSuite()
    result.addTests(unittest.TestLoader().discover(str(ROOT / 'Tests/UniversalManifest'), pattern='test_*.py'))
    result.addTest(unittest.defaultTestLoader.loadTestsFromModule(test_source))
    return result


def main():
    before = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for base in ['Sources', 'Tests', 'script', 'docs', '.github']
        for p in (ROOT / base).rglob('*')
        if p.is_file() and '__pycache__' not in p.parts
    }
    baseline, baseline_log = run(suite())
    target = ROOT / 'Sources/Sliccy/Screen/ScreenRunnerLaunchInstance.swift'
    original = target.read_bytes()
    assert original.count(b'current.isEqual(original)') == 1
    try:
        target.write_bytes(original.replace(b'current.isEqual(original)', b'false'))
        mutant, mutant_log = run(unittest.TestSuite([
            test_source.SourceTests('test_instance_equality_forwards_foundation_isEqual')
        ]))
    finally:
        target.write_bytes(original)
    restored, restored_log = run(suite())
    after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in before}
    valid = len(mutant.failures) == 1 and not mutant.errors and 'current.isEqual(original)' in mutant_log
    report = {
        'baselineTests': baseline.testsRun,
        'baselinePass': baseline.wasSuccessful(),
        'mutantFailures': len(mutant.failures),
        'mutantErrors': len(mutant.errors),
        'namedRuntimeRed': valid,
        'restoredTests': restored.testsRun,
        'restoredPass': restored.wasSuccessful(),
        'sourceRestored': before == after,
        'baselineLog': baseline_log,
        'mutantLog': mutant_log,
        'restoredLog': restored_log,
        'inputHashes': before,
        'afterHashes': after,
        'scope': 'pure source/mock/filesystem; all unmocked subprocesses blocked',
        'deviation': json.loads((ROOT / 'Tests/RunnerBuild17/accepted-inputs.json').read_text())['deviation'],
    }
    (ROOT / 'build17-pure-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(baseline_log + mutant_log + restored_log)
    return baseline.wasSuccessful() and valid and restored.wasSuccessful() and before == after


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
