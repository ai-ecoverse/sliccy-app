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

SOURCE = '4c873bab986e62f404255cc85e08d9dab52ead93'
OUTER = '66d29c01db53f347dd74ad57cabcc0941aa02376054785cdbff11a1e89e1c907'
INNER = '5e5e19d94c64b629b0f21a19c1015ab60ab0e5fa49a25595132c42d9bc57082f'
MANIFEST = 'a9c524c835d3ea96644ede533800a80751cc3e67c016f8a7eb6f2fa19f1a57ca'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
sha = lambda value: hashlib.sha256(value).hexdigest()
started = time.monotonic()
deadline = started + 300
private = Path(tempfile.mkdtemp(prefix='helper12-static-', dir=os.environ['RUNNER_TEMP']))
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
            if name.is_absolute() or '..' in name.parts or '\\' in item.filename or item.filename.casefold() in seen or name.as_posix().rstrip('/') != item.filename.rstrip('/'):
                raise ValueError('archive member name')
            seen.add(item.filename.casefold())
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
    assert os.environ['GITHUB_REF'] == 'refs/heads/proof/independent-helper12-static-v1'
    assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
    assert os.environ['RUNNER_OS'] == 'macOS' and os.environ['RUNNER_ARCH'] == 'ARM64'
    version, _ = command('os', ['/usr/bin/sw_vers', '-productVersion'])
    architecture, _ = command('architecture', ['/usr/bin/uname', '-m'])
    assert version.decode().strip().split('.')[0] == '27' and architecture.strip() == b'arm64'
    gh = shutil.which('gh')
    assert gh and Path(gh).resolve().is_file() and token
    gh = str(Path(gh).resolve())
    archive, _ = command('download-immutable-artifact', [gh, 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/13392888076/zip'], maximum=45, env=dict(clean, GH_TOKEN=token), limit=32*1024*1024)
    token = None
    assert sha(archive) == OUTER
    (evidence / (str(len(records)-1) + '.stdout')).unlink()
    original = private / 'artifact.zip'
    original.write_bytes(archive)
    artifact = private / 'artifact'
    artifact.mkdir(mode=0o700)
    extract(original, artifact, 32*1024*1024)
    assert {p.name for p in artifact.iterdir()} == {'ScreenProofSurface-0.1.0.zip', 'SHA256SUMS', 'signing.txt', 'entitlements.plist', 'notarization.json', 'helper-manifest.json'}
    assert sha((artifact / 'ScreenProofSurface-0.1.0.zip').read_bytes()) == INNER
    assert sha((artifact / 'helper-manifest.json').read_bytes()) == MANIFEST
    appdir = private / 'expanded'
    appdir.mkdir(mode=0o700)
    extract(artifact / 'ScreenProofSurface-0.1.0.zip', appdir, 64*1024*1024)
    app = appdir / 'ScreenProofSurface.app'
    before = {str(p.relative_to(app)): sha(p.read_bytes()) for p in app.rglob('*') if p.is_file()}
    expected = json.loads((artifact / 'helper-manifest.json').read_bytes())
    assert expected['sourceCommit'] == SOURCE and expected['run'] == '41978928697' and expected['attempt'] == 1
    assert expected['build'] == '12' and expected['version'] == '0.1.0' and expected['identifier'] == 'ai.sliccy.proof-helper' and expected['team'] == 'S8LB56P782'
    assert {str(p.relative_to(app)) for p in app.rglob('*') if p.is_dir()} == {'Contents','Contents/MacOS','Contents/_CodeSignature'}
    assert before == expected['files'] and set(before) == {'Contents/Info.plist', 'Contents/CodeResources', 'Contents/MacOS/ScreenProofSurface', 'Contents/_CodeSignature/CodeResources'}
    assert (artifact / 'SHA256SUMS').read_text().split() == [INNER, 'ScreenProofSurface-0.1.0.zip']
    assert json.loads((artifact / 'notarization.json').read_bytes())['status'] == 'Accepted'
    assert plistlib.loads((artifact / 'entitlements.plist').read_bytes()) == {}
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    assert (info['CFBundleIdentifier'], info['CFBundleVersion'], info['CFBundleShortVersionString'], info['CFBundleExecutable']) == ('ai.sliccy.proof-helper', '12', '0.1.0', 'ScreenProofSurface')
    requirement = 'anchor apple generic and identifier "ai.sliccy.proof-helper" and certificate leaf[subject.OU] = "S8LB56P782" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
    command('strict-developer-id-helper-role', ['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '='+requirement, str(app)])
    command('wrong-app-role-refuses', ['/usr/bin/codesign', '--verify', '--strict', '-R', '=identifier "ai.sliccy.mac"', str(app)], expected=(3,))
    _, signing = command('actual-signing-and-designated-requirement', ['/usr/bin/codesign', '-d', '--verbose=4', '-r-', str(app)])
    import re
    assert re.findall(rb'^Identifier=(.+)$', signing, re.M) == [b'ai.sliccy.proof-helper']
    assert re.findall(rb'^TeamIdentifier=(.+)$', signing, re.M) == [b'S8LB56P782']
    assert re.findall(rb'^CDHash=([0-9a-f]{40})$', signing, re.M) == [b'37517f1a6e6a0085f9188f3723ab6209fd131dfd']
    assert expected['cdhash'] == '37517f1a6e6a0085f9188f3723ab6209fd131dfd'
    assert re.search(rb'^CodeDirectory .*flags=.*\bruntime\b', signing, re.M)
    entitlements, _ = command('actual-empty-entitlements', ['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    assert plistlib.loads(entitlements) == {}
    architectures, _ = command('actual-native-arm64', ['/usr/bin/lipo', '-archs', str(app / 'Contents/MacOS/ScreenProofSurface')])
    assert architectures.strip() == b'arm64'
    ticket = (app / 'Contents/CodeResources').lstat()
    assert stat.S_ISREG(ticket.st_mode) and ticket.st_nlink == 1 and stat.S_IMODE(ticket.st_mode) == 0o600
    for name, digest in expected['sources'].items():
        assert sha(Path(name).read_bytes()) == digest
    command('stapled-notarization-ticket', ['/usr/bin/xcrun', 'stapler', 'validate', str(app)])
    _, assessment = command('gatekeeper', ['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)])
    assert b'accepted' in assessment and b'Notarized Developer ID' in assessment
    after = {str(p.relative_to(app)): sha(p.read_bytes()) for p in app.rglob('*') if p.is_file()}
    assert before == after
    (evidence / 'artifact-binding.json').write_text(json.dumps({'source': SOURCE, 'artifact': 13392888076, 'outerSHA256': OUTER, 'innerSHA256': INNER, 'manifestSHA256': MANIFEST, 'before': before, 'after': after}, indent=2))
    outcome = 'PASS'
except BaseException as error:
    (evidence / 'failure.json').write_text(json.dumps({'type': type(error).__name__, 'message': str(error)}))
finally:
    token = None
    (evidence / 'commands.json').write_text(json.dumps(records, indent=2))
    (evidence / 'outcome.json').write_text(json.dumps({'result': outcome, 'proofOutcome': None, 'sourceHead': os.environ.get('GITHUB_SHA'), 'targetSource': SOURCE, 'subjectExecuted': False, 'TCC': False, 'capture': False}))
    for source in ['Tests/Helper12Static/hosted.py', '.github/workflows/helper12-static.yml']:
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
    ciphertext = Path(os.environ['RUNNER_TEMP']) / 'helper12-static-evidence.age'
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
