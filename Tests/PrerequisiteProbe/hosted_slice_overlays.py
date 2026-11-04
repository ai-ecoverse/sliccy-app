from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'script/runner-proof/prerequisite_slice_binding.h'
FIXTURE = ROOT / 'Tests/PrerequisiteProbe/slice_fixture.m'
CHANGES = (
    ('unique-match', 'BOOL accepted=[reason isEqual:@"unique-match"];', 'BOOL accepted=NO && [reason isEqual:@"unique-match"];'),
    ('zero-match', '&& matches!=1)', '&& matches>1)'),
    ('multiple-match', '&& matches!=1)', '&& matches==0)'),
    ('wrong-hash-type', '[candidateType isEqual:type] && [item[@"hash"] isEqual:hash]', '([candidateType isEqual:type] || ![candidateType isEqual:type]) && [item[@"hash"] isEqual:hash]'),
    ('identity-full-prefix', '![[value subdataWithRange:NSMakeRange(0,20)] isEqual:hash]', 'NO && ![[value subdataWithRange:NSMakeRange(0,20)] isEqual:hash]'),
    ('changed-file', 'a->st_ino==b->st_ino', '(a->st_ino==b->st_ino || a->st_ino!=b->st_ino)'),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def main():
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/proof/slice-binding-tests-v1',
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64'}
    if any(os.environ.get(key) != value for key, value in expected.items()) or sys.platform != 'darwin' or platform.machine() != 'arm64':
        raise RuntimeError('hosted-synthetic-test-placement')
    output = ROOT / 'slice-test-results'
    output.mkdir(mode=0o700)
    scratch = output / 'scratch'
    scratch.mkdir(mode=0o700)
    source = HEADER.read_bytes()
    fixture = FIXTURE.read_bytes()
    deadline = time.monotonic() + 420
    evidence = {'scope': 'synthetic Foundation policy constructors only; no observer, Security, proc, root, GUI or capture execution',
                'localAttribution': {'status': 'incomplete', 'correlation': 'CrowdStrike Falcon notifications coincided with three local failed mutant attempts',
                                     'killAndRemovalActorProven': False, 'localSignalKillCountsAsRuntimeRed': False},
                'sourceSHA': os.environ['GITHUB_SHA'], 'runID': os.environ['GITHUB_RUN_ID'],
                'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'placement': expected,
                'headerSHA256': sha(source), 'fixtureSHA256': sha(fixture), 'commands': [], 'overlays': []}
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(scratch), 'PYTHONDONTWRITEBYTECODE': '1'}

    def save():
        (output / 'summary.json').write_text(json.dumps(evidence, indent=2) + '\n')

    def command(label, args, maximum):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('synthetic-test-deadline')
        began = time.monotonic()
        try:
            result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, timeout=min(maximum, remaining))
            status, stdout, stderr = result.returncode, result.stdout, result.stderr
            timed_out = False
        except subprocess.TimeoutExpired as error:
            status, stdout, stderr, timed_out = None, error.stdout or b'', error.stderr or b'', True
        (output / (label + '.stdout')).write_bytes(stdout[:1024*1024])
        (output / (label + '.stderr')).write_bytes(stderr[:1024*1024])
        evidence['commands'].append({'step': label, 'argv': args, 'exit': status, 'timeout': timed_out,
                                     'elapsedSeconds': time.monotonic()-began, 'outputTruncated': len(stdout)>1024*1024 or len(stderr)>1024*1024,
                                     'stdoutSHA256': sha(stdout), 'stderrSHA256': sha(stderr)})
        save()
        return status, stdout, stderr

    def build_and_run(label, header):
        directory = scratch / label
        directory.mkdir()
        (directory / HEADER.name).write_bytes(header)
        executable = directory / 'fixture'
        args = ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                '-I', str(directory), str(FIXTURE), '-o', str(executable)]
        status, _, _ = command(label + '-compile', args, 30)
        if status != 0:
            return {'compileExit': status, 'runtimeExit': None, 'sameNamedAssertion': False}
        status, stdout, stderr = command(label + '-runtime', [str(executable)], 5)
        return {'compileExit': 0, 'runtimeExit': status, 'sameNamedAssertion': stderr == ('slice runtime assertion: ' + label + '\n').encode(),
                'stdoutEmpty': not stdout, 'headerSHA256': sha(header)}

    save()
    try:
        baseline = build_and_run('baseline', source)
        evidence['baseline'] = baseline
        for name, old, new in CHANGES:
            text = source.decode()
            if text.count(old) != 1:
                raise RuntimeError('synthetic-overlay-source-count:' + name)
            result = build_and_run(name, text.replace(old, new).encode())
            result['name'] = name
            result['runtimeRed'] = result['compileExit'] == 0 and result['runtimeExit'] == 1 and result['sameNamedAssertion'] and result.get('stdoutEmpty', False)
            evidence['overlays'].append(result)
            save()
        restored = build_and_run('restored', source)
        evidence['restored'] = restored
        status, _, _ = command('component-suite', [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'Tests/PrerequisiteProbe', '-p', 'test_slice_binding.py', '-v'], 90)
        evidence['componentSuiteExit'] = status
        evidence['sourceUnchanged'] = HEADER.read_bytes() == source and FIXTURE.read_bytes() == fixture
        evidence['passed'] = baseline['runtimeExit'] == 0 and restored['runtimeExit'] == 0 and status == 0 and evidence['sourceUnchanged'] and all(row['runtimeRed'] for row in evidence['overlays'])
        save()
        return 0 if evidence['passed'] else 1
    finally:
        for path in scratch.rglob('*'):
            if path.is_file():
                path.unlink()
        for path in sorted(scratch.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
        scratch.rmdir()
        save()


if __name__ == '__main__':
    sys.exit(main())
