import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import urllib.request

root = Path('Tests/DriverSchema6')
results = Path('driver-schema6-results').resolve()
results.mkdir()
records = []
start = time.monotonic()
assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted' and os.environ['RUNNER_OS'] == 'macOS' and os.environ['RUNNER_ARCH'] == 'ARM64'
assert os.environ['GITHUB_REF'] == 'refs/heads/proof/independent-driver-schema6-v1' and os.environ['GITHUB_EVENT_NAME'] == 'push'
private = Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP'], prefix='driver-schema6-'))
env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(private / 'home'), 'TMPDIR': str(private / 'tmp'), 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_REF': 'refs/heads/proof/independent-driver-schema6-v1', 'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1', 'GOFLAGS': '-mod=readonly', 'GOPATH': str(private / 'gopath'), 'GOCACHE': str(private / 'gocache')}
for name in ['home', 'tmp']:
    (private / name).mkdir()
sha = lambda data: hashlib.sha256(data).hexdigest()
manifest = json.loads((root / 'inputs.json').read_text())
for name, digest in manifest['inputs'].items():
    assert sha((root / name).read_bytes()) == digest
assert sha((root / 'ReceiptFixture.swift').read_bytes()) == manifest['fixtureSHA256']
assert sha((root / 'test_harness.py').read_bytes()) == manifest['collectorTestSHA256']
assert sha((root / 'ClockFixture.swift').read_bytes()) == manifest['clockFixtureSHA256']
for name,digest in manifest['refusalFixtureSources'].items(): assert sha((root / name).read_bytes()) == digest
for name, digest in manifest['actualEncoderSources'].items():
    assert sha(Path(name).read_bytes()) == digest


def command(label, args, maximum=240):
    row = {'label': label, 'args': args, 'beginMs': (time.monotonic()-start)*1000}
    records.append(row)
    try:
        remaining = min(maximum, 600-(time.monotonic()-start))
        assert remaining > 0
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=remaining)
        row['returncode'] = result.returncode
        assert len(result.stdout) <= 8*1024*1024 and len(result.stderr) <= 8*1024*1024
        for suffix, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
            (results / (label+'.'+suffix)).write_bytes(data)
            row[suffix+'SHA256'] = sha(data)
        return result
    finally:
        row['endMs'] = (time.monotonic()-start)*1000


def expand(path, destination, limit, members_limit):
    with tarfile.open(path) as tar:
        seen = set()
        total = 0
        for member in tar.getmembers():
            parts = Path(member.name).parts
            assert not Path(member.name).is_absolute() and '..' not in parts and member.name not in seen
            seen.add(member.name)
            total += member.size
            assert total <= limit and len(seen) <= members_limit and (member.isfile() or member.isdir())
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(tar.extractfile(member).read())
                target.chmod(member.mode & 0o777)


try:
    assert command('collector-selftest', ['/usr/bin/python3', '-B', str(root / 'test_harness.py')], 10).returncode == 0
    with urllib.request.urlopen('https://go.dev/dl/go1.26.5.darwin-arm64.tar.gz', timeout=60) as response:
        data = response.read(64738543)
    assert len(data) == 64738542 and sha(data) == 'efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a'
    archive = private / 'go.tar.gz'
    archive.write_bytes(data)
    expand(archive, private, 320*1024*1024, 24000)
    env['GOROOT'] = str(private / 'go')
    env['PATH'] = str(private / 'go/bin')+':'+env['PATH']
    go = str(private / 'go/bin/go')
    assert command('go-version', [go, 'version'], 10).stdout.strip() == b'go version go1.26.5 darwin/arm64'
    expand(root / 'inputs/slicc-v1.59.0.tar.gz', private / 'source', 64*1024*1024, 10000)
    source = private / 'source/ai-ecoverse-slicc-cli-cea8ec1'
    target = source / 'test/nativeproof'
    target.mkdir(parents=True)
    expand(root / 'inputs/driver-source.tar.gz', target, 4*1024*1024, 128)
    assert {p.name: sha(p.read_bytes()) for p in target.iterdir()} == manifest['files']
    fixture = str(private / 'receipt-fixture')
    compiled = command('foundation-compile', ['/usr/bin/xcrun', 'swiftc', '-D', 'SLICCY_CAPTURE_RUNNER_PROOF', 'Sources/Sliccy/Screen/ScreenRunnerReceiptLedger.swift', 'Sources/Sliccy/Screen/ScreenRunnerJournal.swift', str(root / 'ReceiptFixture.swift'), '-o', fixture], 120)
    assert compiled.returncode == 0
    encoded = command('foundation-encode', [fixture], 10)
    assert encoded.returncode == 0 and 0 < len(encoded.stdout) <= 32768 and encoded.stderr == b''
    fixture_path = results.resolve() / 'foundation-encode.stdout'
    env['SLICCY_RECEIPT_FIXTURE'] = str(fixture_path)
    clock_fixture = str(private / 'clock-fixture')
    clock_compile = command('clock-foundation-compile', ['/usr/bin/xcrun', 'swiftc', '-D', 'SLICCY_CAPTURE_RUNNER_PROOF', 'Sources/Sliccy/Screen/ScreenRunnerJournal.swift', str(root / 'ClockFixture.swift'), '-o', clock_fixture], 120)
    assert clock_compile.returncode == 0
    clock_encoded = command('clock-foundation-encode', [clock_fixture], 10)
    assert clock_encoded.returncode == 0 and 0 < len(clock_encoded.stdout) <= 4096 and clock_encoded.stderr == b''
    env['SLICCY_CLOCK_FIXTURE'] = str(results.resolve() / 'clock-foundation-encode.stdout')
    refusal_fixture = str(private / 'refusal-fixture')
    refusal_compile = command('refusal-foundation-compile', ['/usr/bin/xcrun', 'swiftc', '-D', 'SLICCY_CAPTURE_RUNNER_PROOF', 'Sources/Sliccy/Screen/ScreenRunnerJournal.swift', str(root / 'RefusalDiagnostics.swift'), str(root / 'RefusalFixture.swift'), '-o', refusal_fixture], 120)
    assert refusal_compile.returncode == 0
    refusal_encoded = command('refusal-foundation-encode', [refusal_fixture], 10)
    assert refusal_encoded.returncode == 0 and 0 < len(refusal_encoded.stdout) <= 32768 and refusal_encoded.stderr == b''
    env['SLICCY_REFUSAL_FIXTURE'] = str(results.resolve() / 'refusal-foundation-encode.stdout')
    os.chdir(source)
    selected = '^(TestRunner.*|TestCaptureTimingRejectsLossAndDistinguishesEventFromEmission)$'
    binary = str(private / 'driver-components')
    compile_result = command('go-baseline-compile', [go, 'test', '-c', '-o', binary, './test/nativeproof'], 300)
    assert compile_result.returncode == 0
    baseline = command('go-baseline-runtime', [binary, '-test.count=1', '-test.timeout=30s', '-test.v', '-test.run', selected], 45)
    assert baseline.returncode == 0 and b'--- SKIP:' not in baseline.stdout
    mutation_results = []
    for mutation in json.loads((Path(os.environ['GITHUB_WORKSPACE']) / 'Tests/DriverSchema6/mutants.json').read_text()):
        path = target / mutation['file']
        original = path.read_bytes()
        needle = mutation['old'].encode()
        assert original.count(needle) == 1
        try:
            path.write_bytes(original.replace(needle, mutation['new'].encode(), 1))
            compile_mutant = command(mutation['name']+'-compile', [go, 'test', '-c', '-o', binary, './test/nativeproof'], 120)
            runtime_mutant = None
            if compile_mutant.returncode == 0:
                runtime_mutant = command(mutation['name']+'-runtime', [binary, '-test.count=1', '-test.timeout=30s', '-test.v', '-test.run', '^'+mutation['test']+'$'], 45)
            valid = compile_mutant.returncode == 0 and runtime_mutant is not None and runtime_mutant.returncode == 1 and mutation['assertion'].encode() in runtime_mutant.stdout and not any(token in runtime_mutant.stdout + runtime_mutant.stderr for token in [b'panic:', b'fatal error:', b'runtime error:']) and b'--- SKIP:' not in runtime_mutant.stdout
            mutation_results.append({'name': mutation['name'], 'compile': compile_mutant.returncode, 'runtime': None if runtime_mutant is None else runtime_mutant.returncode, 'assertion': mutation['assertion'], 'validRed': valid})
        finally:
            path.write_bytes(original)
        restored_compile = command(mutation['name']+'-restored-compile', [go, 'test', '-c', '-o', binary, './test/nativeproof'], 120)
        assert restored_compile.returncode == 0
        restored = command(mutation['name']+'-restored-runtime', [binary, '-test.count=1', '-test.timeout=30s', '-test.v', '-test.run', selected], 45)
        assert restored.returncode == 0 and b'--- SKIP:' not in restored.stdout
        assert {p.name: sha(p.read_bytes()) for p in target.iterdir()} == manifest['files']
    (results / 'mutation-results.json').write_text(json.dumps(mutation_results, indent=2))
    (results / 'after-source-map.json').write_text(json.dumps(manifest['files'], indent=2))
    formatted = results / 'formatted'
    formatted.mkdir()
    for name in manifest['files']:
        result = command('format-'+name, [str(private / 'go/bin/gofmt'), str(target / name)], 10)
        assert result.returncode == 0 and result.stderr == b'' and len(result.stdout) <= 1048576
        (formatted / name).write_bytes(result.stdout)
    (results / 'formatted-source-map.json').write_text(json.dumps({p.name: sha(p.read_bytes()) for p in formatted.iterdir()}, indent=2))
    originals = {name: (target / name).read_bytes() for name in manifest['files']}
    formatted_hashes = {p.name: sha(p.read_bytes()) for p in formatted.iterdir()}
    try:
        for name in manifest['files']:
            (target / name).write_bytes((formatted / name).read_bytes())
        assert {p.name: sha(p.read_bytes()) for p in target.iterdir()} == formatted_hashes
        final_compile = command('formatted-final-compile', [go, 'test', '-c', '-o', binary, './test/nativeproof'], 120)
        assert final_compile.returncode == 0
        final_runtime = command('formatted-final-runtime', [binary, '-test.count=1', '-test.timeout=30s', '-test.v', '-test.run', selected], 45)
        assert final_runtime.returncode == 0 and b'--- SKIP:' not in final_runtime.stdout
        (results / 'formatted-tested-source-map.json').write_text(json.dumps(formatted_hashes, indent=2))
    finally:
        for name, raw in originals.items():
            (target / name).write_bytes(raw)
        assert {p.name: sha(p.read_bytes()) for p in target.iterdir()} == manifest['files']
        (results / 'final-restored-source-map.json').write_text(json.dumps(manifest['files'], indent=2))
    assert all(item['validRed'] for item in mutation_results)
finally:
    output = Path(os.environ['GITHUB_WORKSPACE']) / 'driver-schema6-results'
    (output / 'commands.json').write_text(json.dumps(records, indent=2))
    (output / 'input-manifest.json').write_text(json.dumps(manifest, indent=2))
