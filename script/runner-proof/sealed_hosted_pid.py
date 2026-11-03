
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
import mac_rosetta_preflight as placement
import universal_manifest
import snapshot_manifest
import hosted_pid_manifest
import setup_support as setup

RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
APP_RUN = '41592474876'
APP_SOURCE = 'e416ccda54027e64e428238852bafa71746be335'
APP_ZIP_SHA = '3661511513f54e8ae4c14361d6b8dfe33019abcb6e4299fc3756285dd37ec8a4'
APP_MANIFEST_SHA = '888706fb69ac7d2900486bc52d855659c43fdcbc566056ba1e788981c16f1824'
INPUTS = {
    'hosted-pid-driver.tar.gz': '424ed033ec26fa46dbcdf520e251e8a9d86551367cf7d01f1a96025c6d04e306',
    'hosted-pid-driver-files.json': '70b9e16ad69d5a7c26386c19b0bafe5f5fc9612eb0707fb9c39d94296cb770a2',
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
    metadata = json.loads((inputs / 'hosted-pid-driver-files.json').read_text())
    if (metadata['schema'], metadata['sourceTag'], metadata['CGO_ENABLED'], metadata['entryTests']) != (1, 'v1.59.0', '0', ['TestSignedHostedPIDReuse']):
        raise ValueError('driver contract')
    if set(metadata) != {'schema', 'sourceTag', 'CGO_ENABLED', 'entryTests', 'case', 'fixtureSource', 'appBuild', 'driverTimeoutSeconds', 'goTestTimeoutSeconds', 'placementAssertions', 'files'}:
        raise ValueError('driver manifest fields')
    if (metadata['case'], metadata['fixtureSource'], metadata['appBuild'], metadata['driverTimeoutSeconds'], metadata['goTestTimeoutSeconds']) != ('pid-reuse-hosted', APP_SOURCE, '9', 650, 670):
        raise ValueError('driver placement contract')
    if metadata['placementAssertions'] != ['GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'SLICCY_RUNNER_ENVIRONMENT']:
        raise ValueError('driver placement fields')
    expected = metadata['files']
    if len(expected) != 29 or any(len(safe_parts(name)) != 1 or not name.endswith('.go') for name in expected):
        raise ValueError('driver file set')
    package = destination / 'test/nativeproof'
    package.mkdir(mode=0o700)
    with tarfile.open(inputs / 'hosted-pid-driver.tar.gz') as archive:
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
    document = workspace / 'script/runner-proof/hosted-pid-reviewed-sources.json'
    record = json.loads(document.read_text())
    if set(record) != {'schema', 'branch', 'artifactRun', 'artifactSource', 'files'} or record['schema'] != 1:
        raise ValueError('source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['artifactRun'] != APP_RUN or record['artifactSource'] != APP_SOURCE:
        raise ValueError('source manifest binding')
    required = {'.github/workflows/runner-proof.yml', 'script/runner-proof/sealed_hosted_pid.py',
                'script/runner-proof/mac_rosetta_preflight.py', 'script/runner-proof/universal_manifest.py',
                'script/runner-proof/setup_support.py', 'script/runner-proof/hosted_pid_manifest.py',
                'script/runner-proof/snapshot_manifest.py'}
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


def suite(root, evidence, log, env, deadline, workspace, trace):
    inputs = workspace / 'script/runner-proof/inputs'
    sources = root / 'source'
    with trace.step('source-extract'):
        metadata = extract_sources(inputs, sources)
    (evidence / 'driver-source-files.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for name in INPUTS:
        shutil.copy2(inputs / name, evidence / name)
    artifacts = root / 'artifact'; artifacts.mkdir(mode=0o700)

    with trace.step('gh-discovery'):
        gh = setup.discover_gh(os.environ.get('PATH', ''), workspace, root, env, deadline)
    with trace.step('go-download'):
        go_archive = root / 'go.tar.gz'
        run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                   '--tlsv1.2', '--max-time', '30', 'https://go.dev/dl/go1.26.5.darwin-arm64.tar.gz',
                   '--output', str(go_archive)], log, env, deadline, maximum=35)
    with trace.step('go-check'):
        go = setup.unpack_go(go_archive, root, sha, safe_parts)
        setup.check_go(go, env, deadline)
    with trace.step('artifact-download'):
        gh_env = dict(env, GH_TOKEN=os.environ['GH_TOKEN'])
        run_owned([gh, 'run', 'download', APP_RUN, '--repo', 'ai-ecoverse/sliccy-app', '--name',
                   'Sliccy-Hosted-PID-Proof-0.1.0-arm64-' + APP_SOURCE, '--dir', str(artifacts)], log, gh_env, deadline)
    with trace.step('artifact-check'):
        check_app_zip(artifacts / 'Sliccy-0.1.0.zip')
        if sha(artifacts / 'hosted-pid-manifest.json') != APP_MANIFEST_SHA:
            raise setup.SetupFailure('checksum')
    with trace.step('artifact-extract'):
        run_owned(['/usr/bin/ditto', '-x', '-k', str(artifacts / 'Sliccy-0.1.0.zip'), str(artifacts)], log, env, deadline)
    app = artifacts / 'Sliccy.app'

    def bounded_static_check(args):
        remaining = min(10, deadline - time.monotonic())
        if remaining <= 0: raise subprocess.TimeoutExpired(args, 0)
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=remaining, check=True, env=env)
        return result.stdout, result.stderr
    universal_manifest.checked = bounded_static_check
    snapshot_manifest.checked = bounded_static_check
    hosted_pid_manifest.checked = bounded_static_check
    old_sha = os.environ['GITHUB_SHA']
    with trace.step('artifact-signature'):
        try:
            os.environ['GITHUB_SHA'] = APP_SOURCE
            actual = hosted_pid_manifest.manifest(app)
        finally:
            os.environ['GITHUB_SHA'] = old_sha
        recorded = json.loads((artifacts / 'hosted-pid-manifest.json').read_text())
        if actual != recorded:
            raise ValueError('signed manifest differs from artifact')
    with trace.step('artifact-staple'):
        run_owned(['/usr/bin/xcrun', 'stapler', 'validate', str(app)], log, env, deadline)
    with trace.step('artifact-gatekeeper'):
        run_owned(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], log, env, deadline)
    shutil.copy2(artifacts / 'hosted-pid-manifest.json', evidence / 'hosted-pid-manifest.json')
    (evidence / 'artifact-binding.json').write_text(json.dumps({'run': APP_RUN, 'source': APP_SOURCE,
        'zipSHA256': APP_ZIP_SHA, 'manifestSHA256': APP_MANIFEST_SHA, 'staticVerification': True}) + '\n')
    case = evidence / 'pid-reuse-hosted'; case.mkdir(mode=0o700)
    assertions = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                  'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
                  'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted'}
    placement.require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
    run_env = dict(env, **assertions, PATH=str(go.parent) + ':' + PATH, GOROOT=str(go.parent.parent),
                   CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly',
                   GOCACHE=str(root / 'go-cache'), GOMODCACHE=str(root / 'go-mod'),
                   SLICCY_SIGNED_PROOF_APP=str(app / 'Contents/MacOS/Sliccy'),
                   SLICCY_HOSTED_PID_MANIFEST=str(artifacts / 'hosted-pid-manifest.json'),
                   SLICCY_PROOF_EVIDENCE=str(case))
    with (case / 'go-test.log').open('xb') as case_log:
        try:
            with trace.step('native-driver'):
                code = run_owned([str(go), 'test', '-count=1', '-timeout', '670s', '-run', '^TestSignedHostedPIDReuse$', './test/nativeproof'],
                                 case_log, run_env, deadline, maximum=680, cwd=sources, check=False)
                if code != 0:
                    raise setup.SetupFailure('command-failed')
            outcome = 'DRIVER_EXIT_0'
        except setup.SetupFailure:
            outcome = 'DRIVER_FAILED'
        except subprocess.TimeoutExpired:
            outcome = 'DRIVER_TIMEOUT'
    outcomes = {'pid-reuse-hosted': outcome}
    (case / 'invocation.json').write_text(json.dumps({'entryTest': 'TestSignedHostedPIDReuse', 'result': outcome,
        'CGO_ENABLED': '0', 'driverTimeoutSeconds': 650, 'goTestTimeoutSeconds': 670}) + '\n')

    with trace.step('artifact-recheck'):
        try:
            os.environ['GITHUB_SHA'] = APP_SOURCE
            if hosted_pid_manifest.manifest(app) != recorded:
                raise ValueError('artifact changed during trials')
        finally:
            os.environ['GITHUB_SHA'] = old_sha
    with trace.step('suite-finished'):
        (evidence / 'suite-outcomes.json').write_text(json.dumps(outcomes, indent=2) + '\n')
    return 0 if all(value == 'DRIVER_EXIT_0' for value in outcomes.values()) else 1


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    root = None; sealed = False; status = 1
    began = time.monotonic()
    try:
        placement.require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
        os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
        workspace = Path.cwd().resolve()
        source_manifest = validate_source_manifest(workspace)
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-hosted-pid-private-', dir=runner_temp))
        evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
        for name in ['home', 'tmp']: (root / name).mkdir(mode=0o700)
        env = {'PATH': PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/', 'LANG': 'C',
               'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
        destination = runner_temp / 'sliccy-hosted-pid-evidence.age'
        if destination.exists() or destination.is_symlink(): raise ValueError('existing output')
        (evidence / 'reviewed-sources.json').write_text(json.dumps(source_manifest, indent=2) + '\n')
        trace = setup.SetupTrace(evidence / 'setup-stages.ndjson', began)
        with (evidence / 'runner.log').open('xb') as log:
            age = root / 'age'
            try:
                archive = root / 'age.tar.gz'
                with trace.step('age-download'):
                    run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                               '--tlsv1.2', '--max-time', '30', 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz',
                               '--output', str(archive)], log, env, began + 700, maximum=35)
                with trace.step('age-check'):
                    unpack_age(archive, age)

                os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
                status = suite(root, evidence, log, env, began + 700, workspace, trace)
            except Exception as error:
                log.write((type(error).__name__ + '\n').encode()); status = 1
            finally:
                (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                    'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'artifactRun': APP_RUN,
                    'suite': 'pid-reuse-hosted', 'capture': False, 'installerAttempted': False}) + '\n')
                log.flush()
            if age.is_file():
                bootstrap = runner_temp / 'sliccy-hosted-pid-bootstrap.log'
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
                          log, env, began + 720, maximum=40)
                if temporary.stat().st_size <= 0: raise ValueError('empty envelope')
                temporary.replace(destination); sealed = True
        if sealed:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output: output.write('sealed=true\n')
    except Exception:
        status = 1
    finally:
        if root is not None: shutil.rmtree(root, ignore_errors=True)
    print('Hosted PID diagnostic evidence sealed.' if sealed else 'Hosted PID diagnostic evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
