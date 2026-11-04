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
import prerequisite_stage as staging
import prerequisite_artifact as artifact
import prerequisite_kernel as kernel

SOURCES = frozenset(['.github/workflows/runner-proof.yml', 'script/runner-proof/capture_evidence.py', 'script/runner-proof/capture_manifest.py', 'script/runner-proof/capture_setup_support.py', 'script/runner-proof/capture_stage.py', 'script/runner-proof/capture_stage_root.py', 'script/runner-proof/capture_tcc.py', 'script/runner-proof/mac_rosetta_preflight.py', 'script/runner-proof/prerequisite-artifact.json', 'script/runner-proof/prerequisite_artifact.py', 'script/runner-proof/prerequisite_binding.py', 'script/runner-proof/prerequisite_binding_record.h', 'script/runner-proof/prerequisite_bsd_boundary.h', 'script/runner-proof/prerequisite_diagnostics.py', 'script/runner-proof/prerequisite_image.py', 'script/runner-proof/prerequisite_image_native.h', 'script/runner-proof/prerequisite_image_record.h', 'script/runner-proof/prerequisite_kernel.m', 'script/runner-proof/prerequisite_kernel.py', 'script/runner-proof/prerequisite_launch_boundary.h', 'script/runner-proof/prerequisite_slice.py', 'script/runner-proof/prerequisite_slice_binding.h', 'script/runner-proof/prerequisite_slice_native.h', 'script/runner-proof/prerequisite_sysctl.py', 'script/runner-proof/prerequisite_sysctl_native.h', 'script/runner-proof/prerequisite_sysctl_record.h', 'script/runner-proof/prerequisite_platform.m', 'script/runner-proof/prerequisite_probe.py', 'script/runner-proof/prerequisite_stage.py', 'script/runner-proof/sealed_prerequisite.py', 'script/runner-proof/sealed_runner.py', 'script/runner-proof/snapshot_manifest.py', 'script/runner-proof/universal_manifest.py'])


def validate_sources(workspace):
    record = json.loads((workspace / 'script/runner-proof/prerequisite-reviewed-sources.json').read_text())
    if set(record) != {'schema', 'branch', 'callerSource', 'mode', 'files'} or record['schema'] != 1:
        raise ValueError('prerequisite source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['callerSource'] != 'fa4ad8c65d47b075bbe0b96c20f920752108d732' or record['mode'] != 'staging-prerequisite-only':
        raise ValueError('prerequisite source binding')
    if set(record['files']) != SOURCES:
        raise ValueError('prerequisite source set')
    for name, digest in record['files'].items():
        path = workspace / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or shared.sha(path) != digest:
            raise ValueError('prerequisite source hash')
    return record


def suite(root, evidence, log, env, deadline, workspace, journal):
    facts = evidence / 'staging-facts.ndjson'
    count = 0
    def record(name, value):
        nonlocal count
        count += 1
        if count > 256:
            raise ValueError('staging facts bound')
        data = json.dumps({'schema': 2, 'seq': count, 'step': name, 'facts': value}, sort_keys=True)
        if len(data.encode()) > 65536:
            raise ValueError('staging fact bound')
        with facts.open('a') as stream:
            stream.write(data + '\n')
    def checked(args, expected_status=0):
        remaining = min(20, deadline - time.monotonic())
        if remaining <= 0:
            raise ValueError('prerequisite work deadline')
        result = journal.run(args, capture_output=True, check=False, timeout=remaining, env=env)
        if type(result.returncode) is not int or result.returncode != expected_status:
            raise ValueError('static-command-status')
        return result.stdout, result.stderr
    outcome = {'schema': 2, 'platformTools': False, 'staging': False, 'rootVisibility': False,
               'removalConfirmed': False, 'captureProven': False, 'pythonElevated': False,
               'productionParentPathExecuted': False}
    stage = None
    normalized_expected = expected = app = normalized = None
    assertion_env = dict(env, **probe.boundary.ASSERTIONS, RUNNER_ENVIRONMENT='github-hosted')
    try:
        with journal.step('observer-build'):
            for name in ('platform', 'kernel'):
                checked(['/usr/bin/xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                    '-framework', 'Security', str(workspace / ('script/runner-proof/prerequisite_' + name + '.m')),
                    '-o', str(root / ('prerequisite-' + name))])
            (evidence / 'probe-build.json').write_text(json.dumps({name: {'sourceSHA256': shared.sha(workspace / ('script/runner-proof/prerequisite_' + name + '.m')),
                'binarySHA256': shared.sha(root / ('prerequisite-' + name))} for name in ('platform', 'kernel')}) + '\n')
        platform_sequence = 0
        def platform_check():
            nonlocal platform_sequence
            platform_sequence += 1
            if platform_sequence > 8:
                raise ValueError('platform query bound')
            with journal.step('system-tools'):
                remaining = min(3, deadline - time.monotonic())
                if remaining < 3:
                    raise ValueError('platform admission deadline')
                result = journal.run([str(root / 'prerequisite-platform')], capture_output=True, check=False,
                                     timeout=3, env=assertion_env)
                (evidence / ('platform-' + str(platform_sequence) + '.json')).write_bytes(result.stdout)
                row = staging.platform(result.stdout, result.returncode)
                record('platform-validated', row)
                return row
        platform_check()
        outcome['platformTools'] = True
        expected = artifact.expectation(workspace)
        with journal.step('gh-discovery'):
            gh = shared.setup.discover_gh(os.environ.get('PATH', ''), workspace, root, env, deadline)
        archive = root / 'artifact.zip'
        with journal.step('artifact-download'):
            remaining = min(35, deadline - time.monotonic())
            if remaining <= 0:
                raise ValueError('artifact download deadline')
            with archive.open('xb') as output:
                journal.run([gh, 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/' + expected['artifact'] + '/zip'],
                    stdout=output, check=True, timeout=remaining, env=dict(env, GH_TOKEN=os.environ['GH_TOKEN']), output_limit=128 * 1024 * 1024)
        with journal.step('artifact-check'):
            outer = artifact.extract(archive, root / 'artifact', expected, outer=True)
            if shared.sha(outer / 'capture-manifest.json') != expected['manifestSHA256'] or json.loads((outer / 'capture-manifest.json').read_text()) != expected['manifest']:
                raise ValueError('artifact manifest binding')
            if (outer / 'SHA256SUMS').read_text().split() != [expected['innerSHA256'], 'Sliccy-0.1.0.zip']:
                raise ValueError('artifact checksum record')
            extracted = artifact.extract(outer / 'Sliccy-0.1.0.zip', root / 'extracted', expected)
            app = extracted / 'Sliccy.app'
            staging.validate_tree(app, expected, owner=False, deadline=deadline)
            shutil.copyfile(outer / 'capture-manifest.json', evidence / 'capture-manifest.json')
            (evidence / 'artifact-binding.json').write_text(json.dumps({k: expected[k] for k in ('run', 'source', 'artifact', 'outerSHA256', 'innerSHA256', 'manifestSHA256')}) + '\n')
        with journal.step('artifact-signature'):
            artifact.signature(app, expected, checked)
        with journal.step('artifact-staple'):
            checked(['/usr/bin/xcrun', 'stapler', 'validate', str(app)])
        with journal.step('artifact-gatekeeper'):
            checked(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)])
        with journal.step('source-normalize'):
            (root / 'normalized').mkdir(mode=0o700)
            normalized = root / 'normalized/Sliccy.app'
            normalized_expected = artifact.normalized(app, normalized, expected, checked)
            (evidence / 'normalized-manifest.json').write_text(json.dumps(normalized_expected, indent=2) + '\n')
        with journal.step('windowserver-discovery'):
            found, _ = checked(['/usr/bin/pgrep', '-x', 'WindowServer'])
            import re
            if re.fullmatch(rb'[1-9][0-9]*\n', found) is None or int(found) > 2147483647:
                raise ValueError('windowserver-candidate-unavailable')
            target = int(found)
            record('windowserver-candidate', {'pid': target, 'nameIsIdentity': False})
        def verify(copy, end):
            with journal.step('staged-signature'):
                if time.monotonic() >= end:
                    raise ValueError('staged verification deadline')
                def bounded(args, expected_status=0):
                    remaining = min(10, end - time.monotonic())
                    if remaining <= 0:
                        raise ValueError('staged verification deadline')
                    result = journal.run(args, capture_output=True, check=False, timeout=remaining, env=env)
                    if result.returncode != expected_status:
                        raise ValueError('staged static command failed')
                    return result.stdout, result.stderr
                artifact.signature(copy, expected, bounded)
                journal.check_async()
        with journal.step('staging'):
            journal.begin_async()
            stage = staging.Stage(os.environ['GITHUB_RUN_ID'], normalized, normalized_expected, None, verify, None, record)
            stage.platform_check = staging.PlatformCheck(root / 'prerequisite-platform', shared.sha(root / 'prerequisite-platform'), assertion_env, stage.delivery.submit)
            command = staging.FixedCommand(stage.delivery.submit)
            stage.invoke = command
            stage.create(deadline - 15)
            outcome['staging'] = True
        with journal.step('root-visibility'):
            stage.platform_check(deadline - 10)
            if deadline - time.monotonic() < 15:
                raise ValueError('visibility admission deadline')
            stage.settled = False
            try:
                with (evidence / 'visibility.ndjson').open('xb') as raw, (evidence / 'visibility-stderr.log').open('xb') as err:
                    result = journal.read_only_native([str(root / 'prerequisite-kernel'), os.environ['GITHUB_RUN_ID'], str(target)],
                        stdout=raw, stderr=err, timeout=10, env=assertion_env)
            except BaseException as error:
                if getattr(error, 'native_started', None) is False:
                    stage.settled = True
                raise
            rows = kernel.parse(result.stdout)
            stage.settled = kernel.cleanup_confirmed(rows)
            outcome.update(kernel.outcome(rows, result.returncode, os.environ['GITHUB_RUN_ID'], target))
    except BaseException as error:
        outcome['failure'] = {'class': type(error).__name__, 'reason': str(error)}
        if hasattr(error, 'facts'):
            outcome['failure']['facts'] = error.facts
    finally:
        if stage is not None:
            try:
                if stage.removal_state not in ('confirmed-by-inode', 'confirmed-absent-with-retained-identity'):
                    stage.remove(deadline)
                outcome['removalConfirmed'] = True
                outcome['removalState'] = stage.removal_state
                outcome['diagnostics'] = stage.finish()
            except BaseException as error:
                outcome['cleanupFailure'] = {'class': type(error).__name__, 'reason': str(error), 'removalState': stage.removal_state,
                                             'identity': stage.identity, 'settled': stage.settled}
                stage.delivery.close()
        diagnostic_status = journal.end_async()
        outcome['stepDiagnostics'] = diagnostic_status
        if diagnostic_status.get('complete') is not True:
            outcome['diagnosticFailure'] = {'reason': 'diagnostic-delivery-incomplete'}
        if app is not None:
            try:
                with journal.step('artifact-after'):
                    staging.validate_tree(app, expected, owner=False, deadline=deadline)
                    if normalized is not None and normalized_expected is not None:
                        staging.validate_tree(normalized, normalized_expected, owner=False, deadline=deadline)
                    outcome['artifactUnchanged'] = True
            except BaseException as error:
                outcome['artifactFailure'] = {'class': type(error).__name__, 'reason': str(error)}
    with journal.step('outcome'):
        (evidence / 'prerequisite-outcome.json').write_text(json.dumps(outcome, indent=2) + '\n')
    required = ('platformTools', 'staging', 'rootVisibility', 'removalConfirmed', 'artifactUnchanged')
    return 0 if all(outcome.get(key) is True for key in required) and not any(key.endswith('Failure') or key == 'failure' for key in outcome) else 1


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
                    'workflowRun': os.environ.get('GITHUB_RUN_ID'), 'reviewedCallerSource': 'fa4ad8c65d47b075bbe0b96c20f920752108d732', 'suite': 'staging-prerequisite-only',
                    'capture': False, 'screenDriver': False, 'ownerInventory': False, 'nativeKernelObserver': True, 'rootVisibilityProbe': True, 'rootWrites': True, 'rootWriteScope': 'one-run-staging-directory', 'pythonElevated': False, 'installerAttempted': False,
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
