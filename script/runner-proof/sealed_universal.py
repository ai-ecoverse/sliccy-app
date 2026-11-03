
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import mac_rosetta_preflight as rosetta
import universal_manifest

RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
APP_RUN = '41582910616'
APP_SOURCE = 'd93cc688e8aed3f1f35cde87735083d5f6b7191d'
APP_ZIP_SHA = '7a1eeab46dcec575a0088ab8ebf78fc0e7ce1de79cea198fa3c283ecbbbb69a6'
APP_MANIFEST_SHA = '4eee10dc478cf870d2f1422378baa10d0d6df10475a81e65c4be351c2e161003'
INPUTS = {
    'universal-driver.tar.gz': '075b6406be321e95c2c613841ee76dfab3db3635e89c05480106e35b6440e4fe',
    'universal-driver-files.json': 'aa35ee8d0b780d36c1ee7fe5d00189d32154b248a3ae9877a50ff6c3f03ec4e4',
    'slicc-v1.59.0.tar.gz': '8f2cfe6b8ae8c091d156f772f5f070527bc7708959b58ec9d8694f3fbad744a9',
}
PREFIX = 'ai-ecoverse-slicc-cli-cea8ec1'
PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_parts(name):
    value = PurePosixPath(name)
    if value.is_absolute() or '..' in value.parts or not value.parts:
        raise ValueError('archive path')
    return value.parts


def extract_sources(inputs, destination):
    for name, expected in INPUTS.items():
        if sha(inputs / name) != expected:
            raise ValueError('source archive digest')
    destination.mkdir(mode=0o700)
    with tarfile.open(inputs / 'slicc-v1.59.0.tar.gz') as archive:
        seen, total = set(), 0
        for entry in archive.getmembers():
            parts = safe_parts(entry.name)
            if parts[0] != PREFIX or entry.name in seen or not (entry.isfile() or entry.isdir()):
                raise ValueError('release archive member')
            seen.add(entry.name)
            total += entry.size
            if len(seen) > 5000 or entry.size > 32 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise ValueError('release archive bound')
            target = destination.joinpath(*parts[1:])
            if entry.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
    metadata = json.loads((inputs / 'universal-driver-files.json').read_text())
    if (metadata['schema'], metadata['sourceTag'], metadata['CGO_ENABLED'], metadata['entryTests']) != (1, 'v1.59.0', '0', ['TestSignedUniversalNative', 'TestSignedUniversalTranslated']):
        raise ValueError('driver contract')
    expected = metadata['files']
    if len(expected) != 21 or any(len(safe_parts(name)) != 1 or not name.endswith('.go') for name in expected):
        raise ValueError('driver file set')
    package = destination / 'test/nativeproof'
    package.mkdir(mode=0o700)
    with tarfile.open(inputs / 'universal-driver.tar.gz') as archive:
        seen = set()
        for entry in archive.getmembers():
            if entry.name not in expected or entry.name in seen or not entry.isfile() or entry.size > 1024 * 1024:
                raise ValueError('driver archive member')
            seen.add(entry.name)
            with archive.extractfile(entry) as source:
                data = source.read()
            if hashlib.sha256(data).hexdigest() != expected[entry.name]:
                raise ValueError('driver source digest')
            (package / entry.name).write_bytes(data)
    if seen != set(expected) or {p.name for p in package.iterdir()} != set(expected):
        raise ValueError('incomplete driver set')
    return metadata


def check_app_zip(archive):
    if sha(archive) != APP_ZIP_SHA:
        raise ValueError('app archive digest')
    with zipfile.ZipFile(archive) as bundle:
        total, seen = 0, set()
        for entry in bundle.infolist():
            parts = safe_parts(entry.filename)
            mode = entry.external_attr >> 16
            if parts[0] != 'Sliccy.app' or stat.S_ISLNK(mode) or entry.filename in seen:
                raise ValueError('app archive member')
            seen.add(entry.filename); total += entry.file_size
            if total > 128 * 1024 * 1024 or len(seen) > 1000:
                raise ValueError('app archive bound')


def validate_source_manifest(workspace):
    document = workspace / 'script/runner-proof/universal-reviewed-sources.json'
    record = json.loads(document.read_text())
    if set(record) != {'schema', 'branch', 'artifactRun', 'artifactSource', 'files'} or record['schema'] != 1:
        raise ValueError('source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['artifactRun'] != APP_RUN or record['artifactSource'] != APP_SOURCE:
        raise ValueError('source manifest binding')
    required = {'.github/workflows/runner-proof.yml', 'script/runner-proof/sealed_universal.py',
                'script/runner-proof/mac_rosetta_preflight.py', 'script/runner-proof/universal_manifest.py'}
    required.update('script/runner-proof/inputs/' + name for name in INPUTS)
    if set(record['files']) != required:
        raise ValueError('source manifest set')
    for name, digest in record['files'].items():
        path = workspace / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or sha(path) != digest:
            raise ValueError('source manifest digest')
    return record


class Interrupted(Exception):
    pass


def interrupted(signum, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise Interrupted()


def run_owned(args, log, env, deadline, maximum=60, cwd=None, check=True):
    remaining = min(maximum, deadline - time.monotonic())
    if remaining <= 0:
        raise subprocess.TimeoutExpired(args, 0)
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             env=env, cwd=cwd, start_new_session=True)
    try:
        code = child.wait(timeout=remaining)
    finally:


        if child.returncode is None:
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=3)
    if check and code != 0:
        raise subprocess.CalledProcessError(code, args)
    return code


def unpack_age(archive, executable):
    if sha(archive) != AGE_SHA:
        raise ValueError('age checksum')
    with tarfile.open(archive) as bundle:
        entries = [e for e in bundle.getmembers() if e.name == 'age/age']
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 50_000_000:
            raise ValueError('age archive')
        with bundle.extractfile(entries[0]) as source, executable.open('xb') as output:
            shutil.copyfileobj(source, output)
    executable.chmod(0o700)


def suite(root, evidence, log, env, deadline, workspace):
    inputs = workspace / 'script/runner-proof/inputs'
    sources = root / 'source'
    metadata = extract_sources(inputs, sources)
    (evidence / 'driver-source-files.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for name in INPUTS:
        shutil.copy2(inputs / name, evidence / name)
    artifacts = root / 'artifact'; artifacts.mkdir(mode=0o700)

    gh_env = dict(env, GH_TOKEN=os.environ['GH_TOKEN'])
    gh = shutil.which('gh', path=PATH)
    go = shutil.which('go', path=PATH)
    if not gh or not go:
        raise ValueError('required runner tooling unavailable')
    run_owned([gh, 'run', 'download', APP_RUN, '--repo', 'ai-ecoverse/sliccy-app', '--name',
               'Sliccy-Universal-Proof-0.1.0-universal-' + APP_SOURCE, '--dir', str(artifacts)], log, gh_env, deadline)
    check_app_zip(artifacts / 'Sliccy-0.1.0.zip')
    if sha(artifacts / 'universal-manifest.json') != APP_MANIFEST_SHA:
        raise ValueError('signed manifest checksum')
    run_owned(['/usr/bin/ditto', '-x', '-k', str(artifacts / 'Sliccy-0.1.0.zip'), str(artifacts)], log, env, deadline)
    app = artifacts / 'Sliccy.app'

    def bounded_static_check(args):
        remaining = min(10, deadline - time.monotonic())
        if remaining <= 0: raise subprocess.TimeoutExpired(args, 0)
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=remaining, check=True, env=env)
        return result.stdout, result.stderr
    universal_manifest.checked = bounded_static_check
    old_sha = os.environ['GITHUB_SHA']
    try:
        os.environ['GITHUB_SHA'] = APP_SOURCE
        actual = universal_manifest.manifest(app)
    finally:
        os.environ['GITHUB_SHA'] = old_sha
    recorded = json.loads((artifacts / 'universal-manifest.json').read_text())
    if actual != recorded:
        raise ValueError('signed manifest differs from artifact')
    run_owned(['/usr/bin/xcrun', 'stapler', 'validate', str(app)], log, env, deadline)
    run_owned(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], log, env, deadline)
    shutil.copy2(artifacts / 'universal-manifest.json', evidence / 'universal-manifest.json')
    (evidence / 'artifact-binding.json').write_text(json.dumps({'run': APP_RUN, 'source': APP_SOURCE,
        'zipSHA256': APP_ZIP_SHA, 'manifestSHA256': APP_MANIFEST_SHA, 'staticVerification': True}) + '\n')
    outcomes = {}
    for label, test in [('native', 'TestSignedUniversalNative'), ('translated', 'TestSignedUniversalTranslated')]:
        case = evidence / label; case.mkdir(mode=0o700)
        if label == 'translated':
            try: preflight = rosetta.inspect()
            except Exception:
                preflight = {'schema': 1, 'macAppRosettaEstablished': False, 'outcome': 'FAILED_TO_DEMONSTRATE', 'reason': 'preflight-unavailable', 'installerAttempted': False, 'translatedLaunchAttempted': False}
            (case / 'mac-rosetta-preflight.json').write_text(json.dumps(preflight, indent=2) + '\n')
            if not preflight['macAppRosettaEstablished']:
                outcomes[label] = 'FAILED_TO_DEMONSTRATE'
                (case / 'result.json').write_text(json.dumps({'result': 'FAILED_TO_DEMONSTRATE', 'reason': 'Mac-app Rosetta not established; translated invocation skipped'}) + '\n')
                continue
        run_env = dict(env, CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly',
                       GOCACHE=str(root / 'go-cache'), GOMODCACHE=str(root / 'go-mod'),
                       SLICCY_SIGNED_PROOF_APP=str(app / 'Contents/MacOS/Sliccy'),
                       SLICCY_UNIVERSAL_MANIFEST=str(artifacts / 'universal-manifest.json'),
                       SLICCY_PROOF_EVIDENCE=str(case))
        with (case / 'go-test.log').open('xb') as case_log:
            try:
                code = run_owned([go, 'test', '-count=1', '-timeout', '55s', '-run', '^' + test + '$', './test/nativeproof'],
                                 case_log, run_env, deadline, maximum=105, cwd=sources, check=False)
                outcomes[label] = 'DRIVER_EXIT_0' if code == 0 else 'DRIVER_FAILED'
            except subprocess.TimeoutExpired:
                outcomes[label] = 'DRIVER_TIMEOUT'

        (case / 'invocation.json').write_text(json.dumps({'entryTest': test, 'result': outcomes[label], 'CGO_ENABLED': '0'}) + '\n')

    try:
        os.environ['GITHUB_SHA'] = APP_SOURCE
        if universal_manifest.manifest(app) != recorded:
            raise ValueError('artifact changed during trials')
    finally:
        os.environ['GITHUB_SHA'] = old_sha
    (evidence / 'suite-outcomes.json').write_text(json.dumps(outcomes, indent=2) + '\n')
    return 0 if all(value == 'DRIVER_EXIT_0' for value in outcomes.values()) else 1


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    root = None; sealed = False; status = 1
    began = time.monotonic()
    try:
        rosetta.require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
        os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
        workspace = Path.cwd().resolve()
        source_manifest = validate_source_manifest(workspace)
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-universal-private-', dir=runner_temp))
        evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
        for name in ['home', 'tmp']: (root / name).mkdir(mode=0o700)
        env = {'PATH': PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/', 'LANG': 'C',
               'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
        destination = runner_temp / 'sliccy-universal-evidence.age'
        if destination.exists() or destination.is_symlink(): raise ValueError('existing output')
        (evidence / 'reviewed-sources.json').write_text(json.dumps(source_manifest, indent=2) + '\n')
        with (evidence / 'runner.log').open('xb') as log:
            age = root / 'age'
            try:
                archive = root / 'age.tar.gz'
                run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                           '--tlsv1.2', '--max-time', '30', 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz',
                           '--output', str(archive)], log, env, began + 255, maximum=35)
                unpack_age(archive, age)

                os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
                status = suite(root, evidence, log, env, began + 255, workspace)
            except Exception as error:
                log.write((type(error).__name__ + '\n').encode()); status = 1
            finally:
                (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                    'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'artifactRun': APP_RUN,
                    'suite': 'universal-only', 'capture': False, 'installerAttempted': False}) + '\n')
                log.flush()
            if age.is_file():
                bootstrap = runner_temp / 'sliccy-universal-bootstrap.log'
                if bootstrap.exists():
                    if bootstrap.is_symlink() or not bootstrap.is_file() or bootstrap.stat().st_size > 1024 * 1024:
                        raise ValueError('bootstrap log bound')
                    shutil.copy2(bootstrap, evidence / 'bootstrap.log')
                payload = root / 'evidence.tar'
                total_bytes = 0
                with tarfile.open(payload, 'w') as bundle:
                    for path in sorted(evidence.rglob('*')):
                        if path.is_symlink(): raise ValueError('evidence symlink')
                        if path.is_dir(): continue
                        if not path.is_file(): raise ValueError('evidence type')
                        total_bytes += path.stat().st_size
                        if total_bytes > 128 * 1024 * 1024: raise ValueError('evidence bound')
                        bundle.add(path, arcname=str(path.relative_to(evidence)), recursive=False)
                temporary = root / 'sealed.age'
                run_owned([str(age), '--encrypt', '--recipient', RECIPIENT, '--output', str(temporary), str(payload)],
                          log, env, began + 300, maximum=40)
                if temporary.stat().st_size <= 0: raise ValueError('empty envelope')
                temporary.replace(destination); sealed = True
        if sealed:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output: output.write('sealed=true\n')
    except Exception:
        status = 1
    finally:
        if root is not None: shutil.rmtree(root, ignore_errors=True)
    print('Universal diagnostic evidence sealed.' if sealed else 'Universal diagnostic evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
