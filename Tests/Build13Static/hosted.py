import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

SOURCE = '91c1b3ef7aae7a4f2581a2ca6631a740d5556755'
OUTER = '5ff67a7821a8c7920e55b99467b10e64482fbd39ee3f775bbfa6ae1ac9891baf'
INNER = 'bf4a64eb024bc2bff812944bd5cd3c3a2991246fe206b38ccfa7d2a168aaaf6a'
MANIFEST = '815e3778b711bb0bff94d5bb5dbcc741acd1f4f6f202c0d5e5a76ce22e572842'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
sha = lambda value: hashlib.sha256(value).hexdigest()
started = time.monotonic()
deadline = started + 300
private = Path(tempfile.mkdtemp(prefix='build13-static-', dir=os.environ['RUNNER_TEMP']))
private.chmod(0o700)
evidence = private / 'evidence'
evidence.mkdir(mode=0o700)
clean = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(private / 'home'), 'TMPDIR': str(private / 'tmp'), 'LANG': 'en_US.UTF-8'}
for name in ['home', 'tmp']:
    (private / name).mkdir(mode=0o700)
token = os.environ.pop('GH_TOKEN', None)
records = []


def command(stage, args, expected=(0,), maximum=30, env=None, limit=1048576):
    index = len(records)
    stdout = evidence / (str(index) + '.stdout')
    stderr = evidence / (str(index) + '.stderr')
    row = {'stage': stage, 'argv': args, 'expected': list(expected), 'beganMs': (time.monotonic()-started)*1000}
    records.append(row)
    try:
        remaining = min(maximum, deadline-time.monotonic())
        if remaining <= 0:
            raise TimeoutError('absolute work deadline')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=remaining, env=env or clean)
        row['returncode'] = result.returncode
        if result.returncode not in expected:
            raise ValueError('fixed command refusal: ' + stage)
        if stdout.stat().st_size > limit or stderr.stat().st_size > 1048576:
            raise ValueError('static output bound')
        return stdout.read_bytes(), stderr.read_bytes()
    finally:
        row['endedMs'] = (time.monotonic()-started)*1000
        row['stdoutSHA256'] = sha(stdout.read_bytes()) if stdout.exists() else None
        row['stderrSHA256'] = sha(stderr.read_bytes()) if stderr.exists() else None


def extract(archive, destination, limit):
    total = 0
    with zipfile.ZipFile(archive) as z:
        seen = set()
        for item in z.infolist():
            name = Path(item.filename)
            if name.is_absolute() or '..' in name.parts or item.filename in seen:
                raise ValueError('archive member name')
            seen.add(item.filename)
            mode = item.external_attr >> 16
            if mode and stat.S_IFMT(mode) not in [0, stat.S_IFREG, stat.S_IFDIR]:
                raise ValueError('archive member type')
            total += item.file_size
            if total > limit or len(seen) > 128:
                raise ValueError('archive bound')
            target = destination / name
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(z.read(item))
                target.chmod((mode & 0o777) or 0o600)


outcome = 'FAIL'
try:
    assert os.environ['GITHUB_REPOSITORY'] == 'ai-ecoverse/sliccy-app'
    assert os.environ['GITHUB_EVENT_NAME'] == 'push'
    assert os.environ['GITHUB_REF'] == 'refs/heads/proof/independent-build13-static-v1'
    assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
    assert os.environ['RUNNER_OS'] == 'macOS' and os.environ['RUNNER_ARCH'] == 'ARM64'
    version, _ = command('os', ['/usr/bin/sw_vers', '-productVersion'])
    architecture, _ = command('architecture', ['/usr/bin/uname', '-m'])
    assert version.decode().strip().split('.')[0] == '27' and architecture.strip() == b'arm64'
    gh = shutil.which('gh')
    assert gh and Path(gh).resolve().is_file() and token
    gh = str(Path(gh).resolve())
    archive, _ = command('download-immutable-artifact', [gh, 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/13368474555/zip'], maximum=45, env=dict(clean, GH_TOKEN=token), limit=32*1024*1024)
    token = None
    assert sha(archive) == OUTER
    (evidence / (str(len(records)-1) + '.stdout')).unlink()
    original = private / 'artifact.zip'
    original.write_bytes(archive)
    artifact = private / 'artifact'
    artifact.mkdir(mode=0o700)
    extract(original, artifact, 32*1024*1024)
    assert {p.name for p in artifact.iterdir()} == {'Sliccy-0.1.0.zip', 'SHA256SUMS', 'signing.txt', 'capture-manifest.json'}
    assert sha((artifact / 'Sliccy-0.1.0.zip').read_bytes()) == INNER
    assert sha((artifact / 'capture-manifest.json').read_bytes()) == MANIFEST
    appdir = private / 'expanded'
    appdir.mkdir(mode=0o700)
    extract(artifact / 'Sliccy-0.1.0.zip', appdir, 64*1024*1024)
    app = appdir / 'Sliccy.app'
    before = {str(p.relative_to(app)): sha(p.read_bytes()) for p in app.rglob('*') if p.is_file()}
    command('regenerate-strict-role-manifest', ['/usr/bin/python3', '-B', 'script/capture_manifest.py', str(app), str(evidence / 'regenerated-manifest.json')], maximum=120, env=dict(clean, GITHUB_SHA=SOURCE))
    expected = json.loads((artifact / 'capture-manifest.json').read_bytes())
    actual = json.loads((evidence / 'regenerated-manifest.json').read_bytes())
    assert actual == expected and actual['build'] == '13'
    assert actual['helpers']['ScreenProofSurface.app']['immutableArtifact']['run'] == '41752885433'
    command('stapled-notarization-ticket', ['/usr/bin/xcrun', 'stapler', 'validate', str(app)])
    _, assessment = command('gatekeeper', ['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)])
    assert b'accepted' in assessment and b'Notarized Developer ID' in assessment
    after = {str(p.relative_to(app)): sha(p.read_bytes()) for p in app.rglob('*') if p.is_file()}
    assert before == after
    (evidence / 'artifact-binding.json').write_text(json.dumps({'source': SOURCE, 'artifact': 13368474555, 'outerSHA256': OUTER, 'innerSHA256': INNER, 'manifestSHA256': MANIFEST, 'before': before, 'after': after}, indent=2))
    outcome = 'PASS'
except BaseException as error:
    (evidence / 'failure.json').write_text(json.dumps({'type': type(error).__name__, 'message': str(error)}))
finally:
    token = None
    (evidence / 'commands.json').write_text(json.dumps(records, indent=2))
    (evidence / 'outcome.json').write_text(json.dumps({'result': outcome, 'proofOutcome': None, 'sourceHead': os.environ.get('GITHUB_SHA'), 'targetSource': SOURCE, 'subjectExecuted': False, 'TCC': False, 'capture': False}))
    for source in ['Tests/Build13Static/hosted.py', '.github/workflows/build13-static.yml']:
        (evidence / Path(source).name).write_bytes(Path(source).read_bytes())

try:
    with urllib.request.urlopen('https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz', timeout=30) as response:
        age_archive = response.read(24*1024*1024+1)
    assert len(age_archive) == 18106798 and sha(age_archive) == AGE_SHA
    with tarfile.open(fileobj=io.BytesIO(age_archive), mode='r:gz') as tar:
        entries = tar.getmembers()
        members = {m.name: m for m in entries}
        assert len(members) == len(entries)
        member = members['age/age']
        assert member.isfile() and not member.issym() and member.size < 16*1024*1024
        age = private / 'age'
        age.write_bytes(tar.extractfile(member).read())
        age.chmod(0o700)
    envelope = private / 'evidence.tar'
    with tarfile.open(envelope, 'w') as tar:
        for path in sorted(evidence.iterdir()):
            assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576
            tar.add(path, arcname=path.name, recursive=False)
    assert envelope.stat().st_size <= 16*1024*1024
    ciphertext = Path(os.environ['RUNNER_TEMP']) / 'build13-static-evidence.age'
    with ciphertext.open('xb') as output:
        result = subprocess.run([str(age), '-r', RECIPIENT, str(envelope)], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.PIPE, env=clean, timeout=30)
    assert result.returncode == 0 and ciphertext.stat().st_size > 0
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write('sealed=true\n')
    print('STATIC_EVIDENCE_SEALED')
except BaseException:
    print('STATIC_SEAL_FAILED')
    outcome = 'FAIL'
finally:
    shutil.rmtree(private)
raise SystemExit(0 if outcome == 'PASS' else 1)
