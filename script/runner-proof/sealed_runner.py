
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
from types import SimpleNamespace
import mac_rosetta_preflight as placement
import universal_manifest
import snapshot_manifest
import capture_manifest
import capture_setup_support as setup
import capture_tcc
import capture_evidence

RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
APP_RUN = '41619548340'
APP_SOURCE = '357b7f7cc7ef8ae2fd4570efd468c95f58deba41'
APP_ZIP_SHA = 'bda51456eca9214cfb7941549897505b87b54643aa59fbd7033271c3aa659de0'
APP_MANIFEST_SHA = '40d769fdcdb9b8ccc4dc000e92c118445518c3d8e835f36f97c91d0034be398f'
INPUTS = {
    'capture-driver-handoff.json': 'd7f196fdbed604582438e76f2520868f4c078cfb22bd224d42cf02d1ef074ee3',
    'capture-driver.tar.gz': '61bef34d8cb852268e36e4e84bb8485956c4c331dfb1111ef4c0272065b3f9c9',
    'capture-driver-files.json': '931130ccceaa8e334b09fba9320b87eb2f938c616977f4ed638fa4c1359a9fb8',
    'slicc-v1.59.0.tar.gz': '8f2cfe6b8ae8c091d156f772f5f070527bc7708959b58ec9d8694f3fbad744a9',
}
PREFIX = 'ai-ecoverse-slicc-cli-cea8ec1'
PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_parts(name):
    value = PurePosixPath(name)
    if value.is_absolute() or '..' in value.parts or not value.parts or str(value) != name.rstrip('/'):
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
    metadata = json.loads((inputs / 'capture-driver-files.json').read_text())
    contract = {k: v for k, v in metadata.items() if k != 'files'}
    if contract != {
        'schema': 1, 'sourceTag': 'v1.59.0', 'sourceArchiveSHA256': INPUTS['slicc-v1.59.0.tar.gz'],
        'sourceArchiveRoot': PREFIX, 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local',
        'entryTests': ['TestSignedRunnerCapture'],
        'entryCommand': ['go', 'test', '-mod=readonly', './test/nativeproof', '-run', '^TestSignedRunnerCapture$', '-count=1', '-timeout=470s'],
        'fixtureSource': APP_SOURCE, 'signedRun': 41619548340, 'artifactID': 13223456379,
        'appBuild': '11', 'driverTimeoutSeconds': 450, 'goTestTimeoutSeconds': 470,
        'caseTotalSeconds': 45, 'caseExecutionSeconds': 40, 'caseCaptureSeconds': 10}:
        raise ValueError('driver contract')
    expected = metadata['files']
    if len(expected) != 46 or any(len(safe_parts(name)) != 1 or not name.endswith('.go') for name in expected):
        raise ValueError('driver file set')
    package = destination / 'test/nativeproof'
    package.mkdir(mode=0o700)
    with tarfile.open(inputs / 'capture-driver.tar.gz') as archive:
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
            if parts[0] != 'Sliccy.app' or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.filename in seen:
                raise ValueError('app archive member')
            seen.add(entry.filename); total += entry.file_size
            if total > 128 * 1024 * 1024 or len(seen) > 1000:
                raise ValueError('app archive bound')


def validate_source_manifest(workspace):
    document = workspace / 'script/runner-proof/capture-reviewed-sources.json'
    record = json.loads(document.read_text())
    if set(record) != {'schema', 'branch', 'artifactRun', 'artifactSource', 'files'} or record['schema'] != 1:
        raise ValueError('source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['artifactRun'] != APP_RUN or record['artifactSource'] != APP_SOURCE:
        raise ValueError('source manifest binding')
    required = {'.github/workflows/runner-proof.yml', 'script/runner-proof/sealed_runner.py',
                'script/runner-proof/mac_rosetta_preflight.py', 'script/runner-proof/universal_manifest.py',
                'script/runner-proof/capture_setup_support.py', 'script/runner-proof/capture_tcc.py',
                'script/runner-proof/capture_evidence.py', 'script/runner-proof/capture_manifest.py',
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
    crash_baseline = capture_evidence.crash_baseline()
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
                   'Sliccy-Capture-Proof-0.1.0-arm64-' + APP_SOURCE, '--dir', str(artifacts)], log, gh_env, deadline)
    with trace.step('artifact-check'):
        if {p.name for p in artifacts.iterdir()} != {'Sliccy-0.1.0.zip', 'SHA256SUMS', 'signing.txt', 'capture-manifest.json'} or any(not p.is_file() or p.is_symlink() for p in artifacts.iterdir()):
            raise ValueError('artifact file set')
        if (artifacts / 'SHA256SUMS').read_text().strip().split() != [APP_ZIP_SHA, 'Sliccy-0.1.0.zip']:
            raise ValueError('artifact checksum manifest')
        check_app_zip(artifacts / 'Sliccy-0.1.0.zip')
        if sha(artifacts / 'capture-manifest.json') != APP_MANIFEST_SHA:
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
    def bounded_refusal(args, **kwargs):
        remaining = min(15, deadline - time.monotonic())
        if remaining <= 0: raise subprocess.TimeoutExpired(args, 0)
        return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=remaining, check=False, env=env)
    capture_manifest.subprocess = SimpleNamespace(run=bounded_refusal, PIPE=subprocess.PIPE)
    universal_manifest.checked = bounded_static_check
    snapshot_manifest.checked = bounded_static_check
    capture_manifest.checked = bounded_static_check
    old_sha = os.environ['GITHUB_SHA']
    with trace.step('artifact-signature'):
        try:
            os.environ['GITHUB_SHA'] = APP_SOURCE
            actual = capture_manifest.manifest(app)
        finally:
            os.environ['GITHUB_SHA'] = old_sha
        recorded = json.loads((artifacts / 'capture-manifest.json').read_text())
        if actual != recorded:
            raise ValueError('signed manifest differs from artifact')
    with trace.step('artifact-staple'):
        run_owned(['/usr/bin/xcrun', 'stapler', 'validate', str(app)], log, env, deadline)
    with trace.step('artifact-gatekeeper'):
        run_owned(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], log, env, deadline)
    shutil.copy2(artifacts / 'capture-manifest.json', evidence / 'capture-manifest.json')
    (evidence / 'artifact-binding.json').write_text(json.dumps({'run': APP_RUN, 'source': APP_SOURCE,
        'zipSHA256': APP_ZIP_SHA, 'manifestSHA256': APP_MANIFEST_SHA, 'staticVerification': True}) + '\n')
    case = evidence / 'capture'; case.mkdir(mode=0o700)
    assertions = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                  'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
                  'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_ENVIRONMENT': 'github-hosted'}
    require_host()
    version = bounded_static_check(['/usr/bin/sw_vers', '-productVersion'])[0].decode().strip()
    if not version.startswith('27.'):
        raise ValueError('actual version')
    run_env = dict(env, **assertions, PATH=str(go.parent) + ':' + PATH, GOROOT=str(go.parent.parent),
                   CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly',
                   GOCACHE=str(root / 'go-cache'), GOMODCACHE=str(root / 'go-mod'),
                   SLICCY_SIGNED_PROOF_APP=str(app / 'Contents/MacOS/Sliccy'),
                   SLICCY_CAPTURE_MANIFEST=str(artifacts / 'capture-manifest.json'),
                   SLICC_RUNNER_PROOF_ROOT=str(case), SLICCY_RUNNER_OS_VERSION=version)
    outcome = 'DRIVER_NOT_STARTED'
    grants = capture_tcc.ScopedGrants(root, evidence, env, deadline)
    try:
        with trace.step('tcc-setup'):
            grants.install(app)
        with (evidence / 'go-test.log').open('xb') as case_log:
            try:
                with trace.step('native-driver'):
                    code = run_owned([str(go), 'test', '-mod=readonly', './test/nativeproof', '-run',
                                      '^TestSignedRunnerCapture$', '-count=1', '-timeout=470s'],
                                     case_log, run_env, deadline, maximum=480, cwd=sources, check=False)
                    if code != 0:
                        raise setup.SetupFailure('command-failed')
                outcome = 'DRIVER_EXIT_0'
            except setup.SetupFailure:
                outcome = 'DRIVER_FAILED'
            except subprocess.TimeoutExpired:
                outcome = 'DRIVER_TIMEOUT'
    finally:
        try:
            with trace.step('tcc-cleanup'):
                grants.remove()
        finally:
            with trace.step('crash-collection'):
                capture_evidence.collect_crashes(crash_baseline, evidence)
    outcomes = {'capture': outcome}
    (evidence / 'invocation.json').write_text(json.dumps({'entryTest': 'TestSignedRunnerCapture', 'result': outcome,
        'CGO_ENABLED': '0', 'driverTimeoutSeconds': 450, 'goTestTimeoutSeconds': 470,
        'observerGrantAdded': False, 'caseSeconds': 45, 'captureSeconds': 10}) + '\n')

    with trace.step('artifact-recheck'):
        try:
            os.environ['GITHUB_SHA'] = APP_SOURCE
            if capture_manifest.manifest(app) != recorded:
                raise ValueError('artifact changed during trials')
        finally:
            os.environ['GITHUB_SHA'] = old_sha
    with trace.step('suite-finished'):
        (evidence / 'suite-outcomes.json').write_text(json.dumps(outcomes, indent=2) + '\n')
    return 0 if all(value == 'DRIVER_EXIT_0' for value in outcomes.values()) else 1


def require_host():
    placement.require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
    if os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('runner environment')


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    root = None; sealed = False; status = 1
    began = time.monotonic()
    try:
        require_host()
        os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
        workspace = Path.cwd().resolve()
        source_manifest = validate_source_manifest(workspace)
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-capture-private-', dir=runner_temp))
        evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
        for name in ['home', 'tmp']: (root / name).mkdir(mode=0o700)
        env = {'PATH': PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/', 'LANG': 'C',
               'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
        destination = runner_temp / 'sliccy-screen-evidence.age'
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
                               '--output', str(archive)], log, env, began + 900, maximum=35)
                with trace.step('age-check'):
                    unpack_age(archive, age)

                os.environ['SLICC_NO_TELEMETRY'] = '1'; os.environ['SLICC_NO_UPDATE_CHECK'] = '1'
                status = suite(root, evidence, log, env, began + 900, workspace, trace)
            except Exception as error:
                log.write((type(error).__name__ + '\n').encode()); status = 1
            finally:
                (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                    'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'artifactRun': APP_RUN,
                    'suite': 'capture', 'capture': True, 'installerAttempted': False}) + '\n')
                log.flush()
            if age.is_file():
                bootstrap = runner_temp / 'sliccy-screen-bootstrap.log'
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
                        if not path.is_file() or path.stat().st_nlink != 1: raise ValueError('evidence type')
                        total_bytes += path.stat().st_size
                        if total_bytes > 128 * 1024 * 1024: raise ValueError('evidence bound')
                        bundle.add(path, arcname=str(path.relative_to(evidence)), recursive=False)
                temporary = root / 'sealed.age'
                run_owned([str(age), '--encrypt', '--recipient', RECIPIENT, '--output', str(temporary), str(payload)],
                          log, env, began + 960, maximum=40)
                if temporary.stat().st_size <= 0: raise ValueError('empty envelope')
                temporary.replace(destination); sealed = True
        if sealed:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output: output.write('sealed=true\n')
    except Exception:
        status = 1
    finally:
        if root is not None: shutil.rmtree(root, ignore_errors=True)
    print('Capture diagnostic evidence sealed.' if sealed else 'Capture diagnostic evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
