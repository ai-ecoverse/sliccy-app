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
import owner_identity_setup as identity
import plistlib
import re
import stat
import zipfile
import sealed_runner as shared

SOURCES = frozenset([
    '.github/workflows/runner-proof.yml',
    'script/runner-proof/sealed_owner_identity.py', 'script/runner-proof/capture_tcc_dry_run.py',
    'script/runner-proof/owner_identity_probe.m', 'script/runner-proof/owner_identity_setup.py', 'script/runner-proof/owner-probe-pages.json',
    'script/runner-proof/sealed_runner.py', 'script/runner-proof/capture_tcc.py',
    'script/runner-proof/capture_setup_support.py', 'script/runner-proof/capture_manifest.py',
    'script/runner-proof/capture_evidence.py', 'script/runner-proof/universal_manifest.py',
    'script/runner-proof/snapshot_manifest.py', 'script/runner-proof/mac_rosetta_preflight.py',
])


def validate_sources(workspace):
    record = json.loads((workspace / 'script/runner-proof/owner-identity-reviewed-sources.json').read_text())
    if set(record) != {'schema', 'branch', 'artifactRun', 'artifactSource', 'mode', 'files'} or record['schema'] != 1:
        raise ValueError('dry-run source manifest shape')
    if record['branch'] != 'proof/runner-capture-v1' or record['artifactRun'] != shared.APP_RUN or record['artifactSource'] != shared.APP_SOURCE or record['mode'] != 'owner-identification-only':
        raise ValueError('dry-run source binding')
    if set(record['files']) != SOURCES:
        raise ValueError('dry-run source set')
    for name, digest in record['files'].items():
        path = workspace / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or shared.sha(path) != digest:
            raise ValueError('dry-run source hash')
    return record


PREVIEW_RUN = '41484829593'
PREVIEW_SOURCE = 'e1756b3133ed9e7803edf5db53e1c6240852b78b'
PREVIEW_ZIP = '33cbafe06371147f1db882cecb85bc3118d02d08138fe95abafca3d6c5a5734e'
PREVIEW_EXECUTABLE = 'c4165aabbb1c1c88efb55c46295e2eb376442e8aaedda485e954dd7ca955b8a2'
PREVIEW_CDHASH = '1459600acd4a39c88a355fa3c5a4d49bd3a182e9'


def check_preview_zip(path):
    if shared.sha(path) != PREVIEW_ZIP:
        raise ValueError('preview checksum')
    with zipfile.ZipFile(path) as archive:
        seen, total = set(), 0
        for row in archive.infolist():
            parts = shared.safe_parts(row.filename)
            if parts[0] != 'Sliccy.app' or stat.S_IFMT(row.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR) or row.filename in seen:
                raise ValueError('preview archive member')
            seen.add(row.filename)
            total += row.file_size
            if total > 128 * 1024 * 1024 or len(seen) > 1000:
                raise ValueError('preview archive bound')


def bundle_bytes(app):
    result = {}
    for path in sorted(app.rglob('*')):
        if path.is_symlink():
            raise ValueError('bundle symlink')
        if path.is_file():
            result[str(path.relative_to(app))] = shared.sha(path)
    if not result or len(result) > 1000:
        raise ValueError('bundle byte set')
    return result


def fixed_role(path, identifier, checked, apple=False):
    rule = 'anchor apple and identifier "' + identifier + '"' if apple else 'anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier "' + identifier + '"'
    checked(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + rule, str(path)])
    out, error = checked(['/usr/bin/codesign', '-d', '--arch', 'arm64', '--verbose=4', str(path)])
    matches = re.findall(r'^CDHash=([0-9a-f]{40})$', (out + error).decode(), re.M)
    if len(matches) != 1:
        raise ValueError('system tool native hash')
    return matches[0]


def preview(root, evidence, log, env, deadline, workspace, checked):
    directory = root / 'preview-artifact'
    directory.mkdir(mode=0o700)
    gh = shared.setup.discover_gh(os.environ.get('PATH', ''), workspace, root, env, deadline)
    shared.run_owned([gh, 'run', 'download', PREVIEW_RUN, '--repo', 'ai-ecoverse/sliccy-app', '--name',
        'Sliccy-0.1.0-arm64-' + PREVIEW_SOURCE, '--dir', str(directory)], log, dict(env, GH_TOKEN=os.environ['GH_TOKEN']), deadline)
    if {p.name for p in directory.iterdir()} != {'Sliccy-0.1.0.zip', 'SHA256SUMS', 'signing.txt'} or any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError('preview artifact files')
    if (directory / 'SHA256SUMS').read_text().strip().split() != [PREVIEW_ZIP, 'Sliccy-0.1.0.zip']:
        raise ValueError('preview checksums')
    check_preview_zip(directory / 'Sliccy-0.1.0.zip')
    shared.run_owned(['/usr/bin/ditto', '-x', '-k', str(directory / 'Sliccy-0.1.0.zip'), str(directory)], log, env, deadline)
    app = directory / 'Sliccy.app'
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion']) != ('ai.sliccy.mac', '0.1.0', '1'):
        raise ValueError('preview identity')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + shared.universal_manifest.REQUIREMENT, str(app)])
    signature, text = shared.snapshot_manifest.signature(app / 'Contents/MacOS/Sliccy', 'ai.sliccy.mac', 'arm64')
    if signature['sha256'] != PREVIEW_EXECUTABLE or signature['CDHash'] != PREVIEW_CDHASH or 'flags=0x10000(runtime)' not in text:
        raise ValueError('preview signed bytes')
    entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    if plistlib.loads(entitlements) != {}:
        raise ValueError('preview entitlements')
    shared.run_owned(['/usr/bin/xcrun', 'stapler', 'validate', str(app)], log, env, deadline)
    shared.run_owned(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)], log, env, deadline)
    (evidence / 'preview-binding.json').write_text(json.dumps({'run': PREVIEW_RUN, 'source': PREVIEW_SOURCE,
        'artifactID': 13161731819, 'zipSHA256': PREVIEW_ZIP, 'executable': signature, 'mode': '--preview',
        'captureFixtureEquivalent': False}) + '\n')
    return app


def suite(root, evidence, log, env, deadline, workspace, trace):
    app, artifacts, recorded, checked = shared.prepare_artifact(root, evidence, log, env, deadline, workspace, trace)
    preview_app = preview(root, evidence, log, env, deadline, workspace, checked)
    before = {'capture': bundle_bytes(app), 'preview': bundle_bytes(preview_app)}
    (evidence / 'before-bundle-bytes.json').write_text(json.dumps(before, indent=2) + '\n')
    chrome = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    chrome_hash = fixed_role(chrome, 'com.google.Chrome', checked)
    osascript_hash = fixed_role(Path('/usr/bin/osascript'), 'com.apple.osascript', checked, apple=True)
    binary = root / 'owner-identity-probe'
    shared.run_owned(['/usr/bin/xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
        '-framework', 'Foundation', '-framework', 'CoreGraphics', '-framework', 'Security',
        str(workspace / 'script/runner-proof/owner_identity_probe.m'), '-o', str(binary)], log, env, deadline, maximum=30)
    (evidence / 'probe-build.json').write_text(json.dumps({'sourceSHA256': shared.sha(workspace / 'script/runner-proof/owner_identity_probe.m'),
        'executableSHA256': shared.sha(binary), 'compiledOnHostedRunner': True, 'signedRole': None, 'permissionGranted': False}) + '\n')
    pages = json.loads((workspace / 'script/runner-proof/owner-probe-pages.json').read_text())
    pages['osascriptCDHash'] = osascript_hash
    helper = app / 'Contents/Helpers/ScreenProofSurface.app'
    with trace.step('native-driver'):
        complete = identity.run(root, evidence, binary, preview_app, helper, PREVIEW_CDHASH,
            recorded['helpers']['ScreenProofSurface.app']['executable']['CDHash'], chrome_hash, pages, env, log, deadline)
    after = {'capture': bundle_bytes(app), 'preview': bundle_bytes(preview_app)}
    (evidence / 'after-bundle-bytes.json').write_text(json.dumps(after, indent=2) + '\n')
    if before != after:
        raise ValueError('artifact bytes changed')
    (evidence / 'identity-outcome.json').write_text(json.dumps({'schema': 1, 'mode': 'owner-identification-only',
        'setupAndOwnedCleanupCompleted': complete, 'allowlistEstablished': False, 'captureInvoked': False,
        'nativeScreenLink': False, 'tccDatabaseWrites': False, 'grantsInstalled': False, 'artifactUnchanged': True,
        'captureOnlySystemOwnersUnobserved': True}) + '\n')
    return 0 if complete else 1


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
        root = Path(tempfile.mkdtemp(prefix='sliccy-owner-identity-private-', dir=runner_temp))
        evidence = root / 'evidence'
        evidence.mkdir(mode=0o700)
        for name in ['home', 'tmp']:
            (root / name).mkdir(mode=0o700)
        env = {'PATH': shared.PATH, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp') + '/',
               'LANG': 'C', 'SLICC_NO_TELEMETRY': '1', 'SLICC_NO_UPDATE_CHECK': '1'}
        destination = runner_temp / 'sliccy-owner-identity-evidence.age'
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
                    'artifactSource': shared.APP_SOURCE, 'suite': 'owner-identification-only',
                    'capture': False, 'screenDriver': False, 'identityObserver': True, 'installerAttempted': False,
                    'workDeadlineSeconds': 240, 'sealDeadlineSeconds': 300}) + '\n')
                log.flush()
            if age.is_file():
                bootstrap = runner_temp / 'sliccy-owner-identity-bootstrap.log'
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
    print('Owner identity evidence sealed.' if sealed else 'Owner identity evidence unavailable.')
    return status


if __name__ == '__main__':
    sys.exit(main())
