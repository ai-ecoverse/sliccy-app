from pathlib import Path
import json
import os
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import capture_tcc_dry_run as diagnostic
import sealed_runner as shared

SOURCES = frozenset([
    '.github/workflows/runner-proof.yml',
    'script/runner-proof/sealed_tcc_dry_run.py', 'script/runner-proof/capture_tcc_dry_run.py',
    'script/runner-proof/sealed_runner.py', 'script/runner-proof/capture_tcc.py',
    'script/runner-proof/capture_setup_support.py', 'script/runner-proof/capture_manifest.py',
    'script/runner-proof/capture_evidence.py', 'script/runner-proof/universal_manifest.py',
    'script/runner-proof/snapshot_manifest.py', 'script/runner-proof/mac_rosetta_preflight.py',
])


def validate_sources(workspace):
    record = json.loads((workspace / 'script/runner-proof/tcc-dry-run-reviewed-sources.json').read_text())
    if set(record) != {'schema', 'branch', 'artifactRun', 'artifactSource', 'mode', 'files'} or record['schema'] != 1:
        raise ValueError('dry-run source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['artifactRun'] != shared.APP_RUN or record['artifactSource'] != shared.APP_SOURCE or record['mode'] != 'setup-read-only':
        raise ValueError('dry-run source binding')
    if set(record['files']) != SOURCES:
        raise ValueError('dry-run source set')
    for name, digest in record['files'].items():
        path = workspace / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or shared.sha(path) != digest:
            raise ValueError('dry-run source hash')
    return record


def suite(root, evidence, log, env, deadline, workspace, trace):
    app, artifacts, recorded, _ = shared.prepare_artifact(root, evidence, log, env, deadline, workspace, trace)
    shared.require_host()
    instance = diagnostic.ReadOnlyValidation(root, evidence, env, deadline)
    with trace.step('tcc-setup'):
        validated = instance.run(app)
    with trace.step('artifact-recheck'):
        old_sha = os.environ['GITHUB_SHA']
        try:
            os.environ['GITHUB_SHA'] = shared.APP_SOURCE
            if shared.capture_manifest.manifest(app) != recorded:
                raise ValueError('artifact changed during read-only setup')
        finally:
            os.environ['GITHUB_SHA'] = old_sha
    result = {'schema': 1, 'mode': 'setup-read-only', 'validated': validated,
              'tccDatabaseWriteAttempted': False, 'grantsInstalled': False,
              'driverInvoked': False, 'captureInvoked': False, 'artifactUnchanged': True}
    (evidence / 'dry-run-outcome.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if validated else 1


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, shared.interrupted)
    signal.signal(signal.SIGINT, shared.interrupted)
    root = None
    sealed, status = False, 1
    began = time.monotonic()
    try:
        shared.require_host()
        workspace = Path.cwd().resolve()
        source_map = validate_sources(workspace)
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-tcc-readonly-private-', dir=runner_temp))
        evidence = root / 'evidence'
        evidence.mkdir(mode=0o700)
        for name in ['home', 'tmp']:
            (root / name).mkdir(mode=0o700)
        env = {'PATH': shared.PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/',
               'LANG': 'C', 'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
        destination = runner_temp / 'sliccy-tcc-setup-evidence.age'
        if destination.exists() or destination.is_symlink():
            raise ValueError('existing dry-run output')
        (evidence / 'reviewed-sources.json').write_text(json.dumps(source_map, indent=2) + '\n')
        for name in sorted(SOURCES):
            copy = evidence / 'reviewed-source' / name
            copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(workspace / name, copy)
        trace = shared.setup.SetupTrace(evidence / 'setup-stages.ndjson', began)
        with (evidence / 'runner.log').open('xb') as log:
            age = root / 'age'
            try:
                archive = root / 'age.tar.gz'
                with trace.step('age-download'):
                    shared.run_owned(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--location',
                                      '--proto', '=https', '--tlsv1.2', '--max-time', '30',
                                      'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz',
                                      '--output', str(archive)], log, env, began + 240, maximum=35)
                with trace.step('age-check'):
                    shared.unpack_age(archive, age)
                status = suite(root, evidence, log, env, began + 240, workspace, trace)
            except Exception as error:
                (evidence / 'pipeline-error.json').write_text(json.dumps(diagnostic.exception_record(error)) + '\n')
                status = 1
            finally:
                (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                    'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'artifactRun': shared.APP_RUN,
                    'artifactSource': shared.APP_SOURCE, 'suite': 'tcc-setup-read-only',
                    'capture': False, 'driver': False, 'installerAttempted': False,
                    'workDeadlineSeconds': 240, 'sealDeadlineSeconds': 300}) + '\n')
                log.flush()
            if age.is_file():
                bootstrap = runner_temp / 'sliccy-tcc-setup-bootstrap.log'
                if bootstrap.exists():
                    if bootstrap.is_symlink() or not bootstrap.is_file() or bootstrap.stat().st_size > 1024 * 1024:
                        raise ValueError('bootstrap log bound')
                    shutil.copyfile(bootstrap, evidence / 'bootstrap.log')
                payload = root / 'evidence.tar'
                total, count = 0, 0
                with tarfile.open(payload, 'w') as bundle:
                    for path in sorted(evidence.rglob('*')):
                        if path.is_symlink():
                            raise ValueError('evidence symlink')
                        if path.is_dir():
                            continue
                        if not path.is_file() or path.stat().st_nlink != 1:
                            raise ValueError('evidence type')
                        total += path.stat().st_size
                        count += 1
                        if total > 8 * 1024 * 1024 or count > 64:
                            raise ValueError('evidence bound')
                        bundle.add(path, arcname=str(path.relative_to(evidence)), recursive=False)
                temporary = root / 'sealed.age'
                shared.run_owned([str(age), '--encrypt', '--recipient', shared.RECIPIENT,
                                  '--output', str(temporary), str(payload)], log, env, began + 300, maximum=40)
                if temporary.stat().st_size <= 0:
                    raise ValueError('empty sealed evidence')
                temporary.replace(destination)
                sealed = True
        if sealed:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('sealed=true\n')
    except Exception:
        status = 1
    finally:
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)
    print('Setup diagnostic evidence sealed.' if sealed else 'Setup diagnostic evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
