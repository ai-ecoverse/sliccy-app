from pathlib import Path
import json
import os
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import sealed_runner as shared
import prerequisite_diagnostics as diagnostics
import prerequisite_probe as probe

SOURCES = frozenset(['.github/workflows/runner-proof.yml', 'script/runner-proof/sealed_prerequisite.py', 'script/runner-proof/prerequisite_probe.py', 'script/runner-proof/prerequisite_diagnostics.py', 'script/runner-proof/prerequisite_visibility.m', 'script/runner-proof/prerequisite_bsd_boundary.h', 'script/runner-proof/capture_stage.py', 'script/runner-proof/capture_stage_root.py', 'script/runner-proof/sealed_runner.py', 'script/runner-proof/mac_rosetta_preflight.py', 'script/runner-proof/universal_manifest.py', 'script/runner-proof/snapshot_manifest.py', 'script/runner-proof/capture_manifest.py', 'script/runner-proof/capture_setup_support.py', 'script/runner-proof/capture_tcc.py', 'script/runner-proof/capture_evidence.py'])


def validate_sources(workspace):
    record = json.loads((workspace / 'script/runner-proof/prerequisite-reviewed-sources.json').read_text())
    if set(record) != {'schema', 'branch', 'callerSource', 'mode', 'files'} or record['schema'] != 1:
        raise ValueError('prerequisite source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['callerSource'] != '2d34d9ad55a86001594798f3ce7df9f22bac2281' or record['mode'] != 'staging-prerequisite-only':
        raise ValueError('prerequisite source binding')
    if set(record['files']) != SOURCES:
        raise ValueError('prerequisite source set')
    for name, digest in record['files'].items():
        path = workspace / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or shared.sha(path) != digest:
            raise ValueError('prerequisite source hash')
    return record


def suite(root, evidence, log, env, deadline, workspace, journal):
    facts = evidence / 'interpreter-facts.ndjson'
    count = 0
    def record(name, value):
        nonlocal count
        count += 1
        if count > 256:
            raise ValueError('interpreter facts bound')
        data = json.dumps({'schema': 1, 'seq': count, 'step': name, 'facts': value}, sort_keys=True)
        if len(data.encode()) > 65536:
            raise ValueError('interpreter fact bound')
        with facts.open('a') as stream:
            stream.write(data + '\n')
    def checked(args):
        remaining = min(20, deadline - time.monotonic())
        if remaining <= 0:
            raise ValueError('prerequisite work deadline')
        result = journal.run(args, capture_output=True, check=True, timeout=remaining, env=env)
        return result.stdout, result.stderr
    outcome = {'schema': 1, 'interpreter': False, 'rootVisibility': False, 'captureProven': False,
               'appDesignatedRequirementProtocolProven': False}
    try:
        with journal.step('interpreter-validation'):
            outcome['interpreter'] = probe.interpreter_component(checked, record)
    except Exception as error:
        outcome['interpreterFailure'] = {'class': type(error).__name__, 'reason': str(error)}
    try:
        with journal.step('system-tools'):
            for path in ('/usr/bin/sudo', '/bin/sleep'):
                probe.path_facts(path, record)
                probe.signature(path, checked, record)
        binary = root / 'prerequisite-visibility'
        with journal.step('observer-build'):
            checked(['/usr/bin/xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                '-framework', 'Security', str(workspace / 'script/runner-proof/prerequisite_visibility.m'), '-o', str(binary)])
        (evidence / 'probe-build.json').write_text(json.dumps({'sourceSHA256': shared.sha(workspace / 'script/runner-proof/prerequisite_visibility.m'),
            'boundarySHA256': shared.sha(workspace / 'script/runner-proof/prerequisite_bsd_boundary.h'),
            'binarySHA256': shared.sha(binary), 'compiledOnHostedRunner': True}) + '\n')
        with journal.step('root-visibility'):
            assertion_env = dict(env, **probe.boundary.ASSERTIONS, RUNNER_ENVIRONMENT='github-hosted')
            remaining = min(10, deadline - time.monotonic())
            if remaining < 10:
                raise ValueError('visibility admission deadline')
            with (evidence / 'visibility.ndjson').open('xb') as raw, (evidence / 'visibility-stderr.log').open('xb') as err:
                result = journal.read_only_native([str(binary)], stdout=raw, stderr=err, timeout=10, env=assertion_env)
            outcome.update(probe.visibility_records(result.stdout, result.returncode))
    except Exception as error:
        outcome['visibilityFailure'] = {'class': type(error).__name__, 'reason': str(error)}
    with journal.step('outcome'):
        (evidence / 'prerequisite-outcome.json').write_text(json.dumps(outcome, indent=2) + '\n')
    return 0 if outcome['interpreter'] and outcome['rootVisibility'] else 1


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, shared.interrupted)
    signal.signal(signal.SIGINT, shared.interrupted)
    root = None
    sealed, status = False, 1
    began = time.monotonic()
    try:
        workspace = Path.cwd().resolve()
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix='sliccy-prerequisite-private-', dir=runner_temp))
        evidence = root / 'evidence'
        evidence.mkdir(mode=0o700)
        journal = diagnostics.Journal(evidence / 'step-diagnostics.ndjson', root, workspace, began,
            [os.environ.get('GH_TOKEN'), os.environ.get('GITHUB_TOKEN')])
        journal.call('host-preflight', shared.require_host)
        source_map = journal.call('source-preflight', validate_sources, workspace)
        with journal.step('evidence-setup'):
            for name in ['home', 'tmp']:
                (root / name).mkdir(mode=0o700)
            env = {'PATH': shared.PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/',
                   'LANG': 'C', 'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
            destination = runner_temp / 'sliccy-prerequisite-evidence.age'
            if destination.exists() or destination.is_symlink():
                raise ValueError('existing dry-run output')
        with journal.step('source-copy'):
            (evidence / 'reviewed-sources.json').write_text(json.dumps(source_map, indent=2) + '\n')
            for name in sorted(SOURCES):
                copy = evidence / 'reviewed-source' / name
                copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(workspace / name, copy)
        trace = journal
        with journal.bind(shared), (evidence / 'runner.log').open('xb') as log:
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
                status = suite(root, evidence, log, env, began + 240, workspace, journal)
            except Exception as error:
                (evidence / 'pipeline-error.json').write_text(json.dumps(dict(exceptionClass=type(error).__name__, message=str(error), lastDiagnostic=journal.last_failure)) + '\n')
                status = 1
            finally:
                (evidence / 'envelope.json').write_text(json.dumps({'schema': 1, 'exitCode': status,
                    'workflowSource': os.environ.get('GITHUB_SHA'), 'workflowRef': os.environ.get('GITHUB_REF'),
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'reviewedCallerSource': '2d34d9ad55a86001594798f3ce7df9f22bac2281', 'suite': 'staging-prerequisite-only',
                    'capture': False, 'screenDriver': False, 'identityObserver': False, 'rootVisibilityProbe': True, 'rootWrites': False, 'installerAttempted': False,
                    'workDeadlineSeconds': 240, 'sealDeadlineSeconds': 300}) + '\n')
                log.flush()
            if age.is_file():
                with journal.step('evidence-package'):
                    bootstrap = runner_temp / 'sliccy-prerequisite-bootstrap.log'
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
                            if total > 64 * 1024 * 1024 or count > 256:
                                raise ValueError('evidence bound')
                            bundle.add(path, arcname=str(path.relative_to(evidence)), recursive=False)
                temporary = root / 'sealed.age'
                journal.call('evidence-seal', shared.run_owned, [str(age), '--encrypt', '--recipient', shared.RECIPIENT,
                                  '--output', str(temporary), str(payload)], log, env, began + 300, maximum=40)
                if temporary.stat().st_size <= 0:
                    raise ValueError('empty sealed evidence')
                temporary.replace(destination)
                sealed = True
        if sealed:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('sealed=true\n')
    except Exception as error:
        if root is not None and 'journal' in locals():
            try:
                journal.finish({'kind': 'wrapper', 'step': 'evidence-envelope', 'tool': {'pythonModule': 'sealed_prerequisite'}, 'arguments': []}, None, error=error)
            except Exception:
                pass
        status = 1
    finally:
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)
    print('Prerequisite evidence sealed.' if sealed else 'Prerequisite evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
