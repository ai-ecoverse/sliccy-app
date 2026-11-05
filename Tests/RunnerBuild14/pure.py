from pathlib import Path
import hashlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

def denied(*args, **kwargs):
    raise AssertionError('unmocked subprocess prohibited in pure build14 suite')

def main():
    before = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for base in ['Sources','Tests','script','docs','.github'] for p in (ROOT / base).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    suite = unittest.TestSuite()
    for directory, pattern in [('Tests/RunnerBuild14','test_source.py'),('Tests/UniversalManifest','test_capture_manifest.py'),('Tests/UniversalManifest','test_surface_pin.py'),('Tests/UniversalManifest','test_fetch_surface.py')]:
        suite.addTests(unittest.TestLoader().discover(str(ROOT / directory), pattern=pattern))
    output = io.StringIO()
    with patch.object(subprocess, 'run', denied), patch.object(subprocess, 'Popen', denied), patch.object(subprocess, 'check_output', denied), patch.object(subprocess, 'check_call', denied), patch.object(subprocess, 'call', denied):
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    after = {path:hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in before}
    report = {'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'sourceUnchanged':before==after,'output':output.getvalue(),'scope':'pure source, mocked packaging, filesystem; unmocked subprocesses blocked'}
    (ROOT / 'build14-pure-results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(output.getvalue())
    return result.wasSuccessful() and before == after

if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
