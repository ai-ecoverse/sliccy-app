from pathlib import Path
import hashlib
import importlib.util
import io
import json
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

def denied(*args, **kwargs):
    raise AssertionError('unmocked subprocess prohibited')

def run(suite):
    output = io.StringIO()
    with patch.object(subprocess, 'run', denied), patch.object(subprocess, 'Popen', denied):
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    return result, output.getvalue()

def suite():
    result = unittest.TestSuite()
    result.addTests(unittest.TestLoader().discover(str(ROOT / 'Tests/UniversalManifest'), pattern='test_*.py'))
    result.addTests(unittest.TestLoader().discover(str(ROOT / 'Tests/RunnerBuild16'), pattern='test_source.py'))
    return result

def main():
    before = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for base in ['Sources','Tests','script','docs','.github'] for p in (ROOT/base).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    baseline, baseline_log = run(suite())
    target = ROOT/'Sources/Sliccy/Screen/ScreenRunnerOwnedProcess.swift'
    original = target.read_bytes()
    current = '85ef7c16e6542d94b26051ba1e04e6df12da7317923726943e4ff292c75a1e89'
    retired = 'baff7b8b21264018138c9f7e2e7f6b8052bdcaf6e10b8ffa06dde854ac2b20c9'
    assert original.decode().count(current) == 1
    spec = importlib.util.spec_from_file_location('consistency', ROOT/'Tests/UniversalManifest/test_helper_consistency.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    try:
        target.write_text(original.decode().replace(current, retired))
        mutant, mutant_log = run(unittest.TestSuite([module.HelperConsistencyTests('test_swift_packaging_signed_manifest_agree')]))
    finally:
        target.write_bytes(original)
    restored, restored_log = run(suite())
    after = {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in before}
    valid = len(mutant.failures) == 1 and not mutant.errors and 'helper-pin-swift-packaging' in mutant_log
    report = {'baselineTests':baseline.testsRun,'baselinePass':baseline.wasSuccessful(),'mutantFailures':len(mutant.failures),'mutantErrors':len(mutant.errors),'namedRuntimeRed':valid,'restoredTests':restored.testsRun,'restoredPass':restored.wasSuccessful(),'sourceRestored':before==after,'baselineLog':baseline_log,'mutantLog':mutant_log,'restoredLog':restored_log,'inputHashes':before,'afterHashes':after,'scope':'pure source/mock/filesystem; all unmocked subprocesses blocked'}
    (ROOT/'build16-pure-results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(baseline_log+mutant_log+restored_log)
    return baseline.wasSuccessful() and valid and restored.wasSuccessful() and before==after

if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
