
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
import capture_diagnostics as diagnostics

RECIPIENT = 'age1n5hhvvjf65g96xjksnk2j7aqld83ae2mt3vfdymuxqsh0ex5qqxsarh2nk'
AGE_SHA = 'e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5'
APP_RUN = '41981735530'
APP_ARTIFACT = 13393659909
APP_OUTER_SHA = '60027d9058f32754ff65f1001a7d300f79e44a1e704b9e6f033eeaeef4e39bf2'
APP_SOURCE = '0d98f937d1ba576665ffba64c66ec6a51c65e285'
APP_ZIP_SHA = 'a4fe65982e1ce1858b1e08dc21fa25ee523bcf08a203bf6d5e26a242495f0529'
APP_MANIFEST_SHA = '20286e1d09a4a080992ddbfc1a7bd84512e8332703d2e244c41d8756e2b80a5e'
INPUTS = {
    'capture-build14-contract.json': '0aebf7134d2ec4e02e45a9a82e6d8acb4657f9d0890805d255b5af57592af669',
    'capture-app-schema6.txt': '2d47a525425c3e5cbb23acec0f413b111b3f03f5219c81c9befe3f41837f4ffc',
    'capture-schema6-emitter-addendum.json': '5bac184af0533eae474726a09ec74a3aab2698817cc98277ae3931a6b255fde1',
    'capture-driver-handoff.json': 'f3c187671c658f82483ce1517d3ec685b4ce0ccdc84278b28a829735ef2a62e1',
    'capture-driver.tar.gz': 'd40f05f8207ee4898237535d1749ca1c3b2abee220d2ebf815bfe7f8a915dddc',
    'capture-driver-files.json': '6b9c02f6116132ca8aa57e4f1f18ee3f1b68838193e65930b954adda3f4d0e7a',
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
        'entryCommand': ['go', 'test', '-mod=readonly', './test/nativeproof', '-run', '^TestSignedRunnerCapture$', '-count=1', '-timeout=980s'],
        'fixtureSource': APP_SOURCE, 'signedRun': int(APP_RUN), 'artifactID': APP_ARTIFACT,
        'appBuild': '14', 'driverTimeoutSeconds': 960, 'goTestTimeoutSeconds': 980,
        'caseTotalSeconds': 150, 'caseExecutionSeconds': 120, 'caseCaptureSeconds': 10,
        'helperBuild': '12', 'goCommandTimeoutSeconds': 990,
        'chromeStaticIdentitySeconds': 30, 'baselineIdentityAndWindowsTotalSeconds': 2}:
        raise ValueError('driver contract')
    expected = metadata['files']
    if len(expected) != 86 or any(len(safe_parts(name)) != 1 or not name.endswith('.go') for name in expected):
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
                'script/runner-proof/snapshot_manifest.py', 'script/runner-proof/surface_pin.py',
                'script/runner-proof/capture_diagnostics.py'}
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


def run_owned(args, log, env, deadline, maximum=60, cwd=None, check=True, stderr_log=None):
    remaining = min(maximum, deadline - time.monotonic())
    if remaining <= 0:
        raise subprocess.TimeoutExpired(args, 0)
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=stderr_log if stderr_log is not None else log,
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


def prepare_artifact(root, evidence, log, env, deadline, workspace, trace):
    artifacts = root / 'artifact'; artifacts.mkdir(mode=0o700)

    with trace.step('gh-discovery'):
        gh = setup.discover_gh(os.environ.get('PATH', ''), workspace, root, env, deadline)
    gh_env = dict(env, GH_TOKEN=os.environ['GH_TOKEN'])
    with trace.step('artifact-metadata'):
        metadata_path = evidence / 'artifact-api.json'
        with metadata_path.open('xb') as output:
            run_owned([gh, 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/' + str(APP_ARTIFACT)],
                      output, gh_env, deadline, stderr_log=log)
        metadata = json.loads(metadata_path.read_text())
        if (metadata['id'], metadata['name'], metadata['expired'], metadata['digest'],
            metadata['workflow_run']['id'], metadata['workflow_run']['head_sha']) != (
                APP_ARTIFACT, 'Sliccy-Capture-Proof-0.1.0-arm64-' + APP_SOURCE, False,
                'sha256:' + APP_OUTER_SHA, int(APP_RUN), APP_SOURCE):
            raise ValueError('artifact API binding')
    with trace.step('artifact-download'):
        outer = root / 'artifact.zip'
        with outer.open('xb') as output:
            run_owned([gh, 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/' + str(APP_ARTIFACT) + '/zip'],
                      output, gh_env, deadline, stderr_log=log)
        if sha(outer) != APP_OUTER_SHA:
            raise ValueError('outer artifact digest')
        with zipfile.ZipFile(outer) as archive:
            members = archive.infolist()
            expected = {'Sliccy-0.1.0.zip', 'SHA256SUMS', 'signing.txt', 'capture-manifest.json'}
            if len(members) != 4 or {e.filename for e in members} != expected:
                raise ValueError('outer artifact members')
            for entry in members:
                if entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG) or entry.file_size > 128 * 1024 * 1024:
                    raise ValueError('outer artifact type or bound')
                with (artifacts / entry.filename).open('xb') as output:
                    output.write(archive.read(entry))
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
                              timeout=remaining, check=kwargs.get('check', False), env=env)
    capture_manifest.subprocess = SimpleNamespace(run=bounded_refusal, PIPE=subprocess.PIPE)
    capture_manifest.surface_pin.subprocess = SimpleNamespace(run=bounded_refusal)
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
        'artifactID': APP_ARTIFACT, 'outerSHA256': APP_OUTER_SHA, 'zipSHA256': APP_ZIP_SHA, 'manifestSHA256': APP_MANIFEST_SHA, 'staticVerification': True}) + '\n')
    return app, artifacts, recorded, bounded_static_check


def suite(root, evidence, log, env, deadline, workspace, trace):
    inputs = workspace / 'script/runner-proof/inputs'
    sources = root / 'source'
    with trace.step('crash-baseline'):
        crash_baseline = capture_evidence.crash_baseline()
    with trace.step('source-extract'):
        metadata = extract_sources(inputs, sources)
    (evidence / 'driver-source-files.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for name in INPUTS:
        shutil.copy2(inputs / name, evidence / name)
    with trace.step('go-download'):
        go_archive = root / 'go.tar.gz'
        run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                   '--tlsv1.2', '--max-time', '30', 'https://go.dev/dl/go1.26.5.darwin-arm64.tar.gz',
                   '--output', str(go_archive)], log, env, deadline, maximum=35)
    with trace.step('go-check'):
        go = setup.unpack_go(go_archive, root, sha, safe_parts)
        setup.check_go(go, env, deadline)
    app, artifacts, recorded, bounded_static_check = prepare_artifact(root, evidence, log, env, deadline, workspace, trace)
    old_sha = os.environ['GITHUB_SHA']
    case = evidence / 'capture'; case.mkdir(mode=0o700)
    assertions = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                  'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
                  'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_ENVIRONMENT': 'github-hosted'}
    with trace.step('actual-version'):
        require_host()
        version = bounded_static_check(['/usr/bin/sw_vers', '-productVersion'])[0].decode().strip()
        if not version.startswith('27.'):
            raise ValueError('actual version')
    run_env = dict(env, **assertions, PATH=str(go.parent) + ':' + PATH, GOROOT=str(go.parent.parent),
                   CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOARCH='arm64',
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
                                      '^TestSignedRunnerCapture$', '-count=1', '-timeout=980s'],
                                     case_log, run_env, deadline, maximum=990, cwd=sources, check=False)
                    if code != 0:
                        raise setup.SetupFailure('command-failed')
                outcome = 'DRIVER_EXIT_0'
            except setup.SetupFailure:
                outcome = 'DRIVER_FAILED'
            except subprocess.TimeoutExpired:
                outcome = 'DRIVER_TIMEOUT'
    finally:
        try:
            trace.cleanup(grants.remove)
        finally:
            with trace.step('crash-collection'):
                capture_evidence.collect_crashes(crash_baseline, evidence)
    outcomes = {'capture': outcome}
    (evidence / 'invocation.json').write_text(json.dumps({'entryTest': 'TestSignedRunnerCapture', 'result': outcome,
        'CGO_ENABLED': '0', 'driverTimeoutSeconds': 960, 'goTestTimeoutSeconds': 980,
        'observerGrantAdded': False, 'identityRootOperations': False,
        'authorizationPurposeProven': False, 'nonzeroExitPreservesAllCases': True,
        'goCommandSeconds': 990, 'caseSeconds': 150, 'captureSeconds': 10}) + '\n')

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


def package_evidence(evidence, payload, bootstrap):
    if bootstrap.exists():
        if bootstrap.is_symlink() or not bootstrap.is_file() or bootstrap.stat().st_size > 1024 * 1024:
            raise ValueError('bootstrap log bound')
        shutil.copy2(bootstrap, evidence / 'bootstrap.log')
    total_bytes = 0
    with tarfile.open(payload, 'w') as bundle:
        for path in sorted(evidence.rglob('*')):
            if path.is_symlink(): raise ValueError('evidence symlink')
            if path.is_dir(): continue
            if not path.is_file() or path.stat().st_nlink != 1: raise ValueError('evidence type')
            total_bytes += path.stat().st_size
            if total_bytes > 128 * 1024 * 1024: raise ValueError('evidence bound')
            bundle.add(path, arcname=str(path.relative_to(evidence)), recursive=False)


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    root = None; sealed = False; status = 1
    began = time.monotonic()
    try:
        workspace = Path.cwd().resolve()
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-capture-private-', dir=runner_temp))
        evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
        journal = diagnostics.Journal(evidence / 'step-diagnostics.ndjson', root, workspace, began,
            [os.environ.get('GH_TOKEN'), os.environ.get('GITHUB_TOKEN')])
        journal.call('host-preflight', require_host)
        source_manifest = journal.call('source-preflight', validate_source_manifest, workspace)
        with journal.step('evidence-setup'):
            for name in ['home', 'tmp']: (root / name).mkdir(mode=0o700)
            env = {'PATH': PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/', 'LANG': 'C',
                   'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
            destination = runner_temp / 'sliccy-screen-evidence.age'
            if destination.exists() or destination.is_symlink(): raise ValueError('existing output')
        with journal.step('source-copy'):
            (evidence / 'reviewed-sources.json').write_text(json.dumps(source_manifest, indent=2) + '\n')
            for name in source_manifest['files']:
                copy = evidence / 'reviewed-source' / name
                copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(workspace / name, copy)
        trace = diagnostics.Trace(setup.SetupTrace(evidence / 'setup-stages.ndjson', began), journal)
        with journal.bind(sys.modules[__name__]), (evidence / 'runner.log').open('xb') as log:
            age = root / 'age'
            try:
                archive = root / 'age.tar.gz'
                with trace.step('age-download'):
                    run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                               '--tlsv1.2', '--max-time', '30', 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz',
                               '--output', str(archive)], log, env, began + 1500, maximum=35)
                with trace.step('age-check'):
                    unpack_age(archive, age)
                status = suite(root, evidence, log, env, began + 1500, workspace, trace)
            except Exception as error:
                (evidence / 'pipeline-error.json').write_text(json.dumps({'exceptionClass': type(error).__name__,
                    'message': journal.text(error), 'lastDiagnostic': journal.last_failure}) + '\n')
                status = 1
            finally:
                with journal.step('evidence-envelope'):
                    if journal.loss:
                        status = 1
                    (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                        'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                        'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'workflowAttempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
                        'artifactRun': APP_RUN, 'artifactSource': APP_SOURCE, 'artifactID': APP_ARTIFACT,
                        'suite': 'capture', 'capture': True, 'installerAttempted': False,
                        'identityRootOperations': False, 'rootScope': 'reviewed-signed-app-only-TCC',
                        'workDeadlineSeconds': 1500, 'sealDeadlineSeconds': 1560, 'diagnosticLoss': journal.loss,
                        'authorizationPurposeProven': False, 'ciStatusIsProofVerdict': False}) + '\n')
                log.flush()
            if age.is_file():
                payload = root / 'evidence.tar'
                journal.call('evidence-package', package_evidence, evidence, payload, runner_temp / 'sliccy-screen-bootstrap.log')
                temporary = root / 'sealed.age'
                journal.call('evidence-seal', run_owned, [str(age), '--encrypt', '--recipient', RECIPIENT,
                    '--output', str(temporary), str(payload)], log, env, began + 1560, maximum=40)
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
