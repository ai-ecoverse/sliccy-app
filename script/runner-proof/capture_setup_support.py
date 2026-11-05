from contextlib import contextmanager
from pathlib import Path
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time

GO_VERSION = 'go1.26.5'
GO_SHA = 'efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a'
GO_SIZE = 64738542
STAGES = frozenset(['actual-version', 'artifact-metadata', 'crash-baseline', 'age-download', 'age-check', 'source-extract', 'gh-discovery', 'go-download',
                    'go-check', 'artifact-download', 'artifact-check', 'artifact-extract',
                    'artifact-signature', 'artifact-staple', 'artifact-gatekeeper',
                    'native-driver', 'translation-preflight', 'translated-driver',
                    'artifact-recheck', 'suite-finished', 'tcc-setup', 'tcc-cleanup', 'crash-collection'])
REASONS = frozenset(['none', 'timeout', 'command-failed', 'missing-tool', 'tool-path',
                     'tool-version', 'checksum', 'archive-layout', 'invalid-data',
                     'io', 'interrupted', 'unexpected'])


class SetupFailure(Exception):
    def __init__(self, reason):
        if reason not in REASONS or reason == 'none':
            raise ValueError('setup reason')
        self.reason = reason
        super().__init__()


class SetupTrace:
    def __init__(self, path, began):
        self.path, self.began, self.count = path, began, 0
        with path.open('xb'):
            pass

    def record(self, stage, phase, reason='none'):
        if stage not in STAGES or phase not in {'entered', 'completed', 'failed'} or reason not in REASONS or self.count >= 64:
            raise ValueError('setup record')
        self.count += 1
        row = {'schema': 1, 'seq': self.count, 'stage': stage, 'phase': phase,
               'reason': reason, 'elapsedMs': (time.monotonic() - self.began) * 1000}
        data = json.dumps(row, sort_keys=True) + '\n'
        if len(data.encode()) > 512:
            raise ValueError('setup record bound')
        with self.path.open('a') as output:
            output.write(data)

    @contextmanager
    def step(self, stage):
        self.record(stage, 'entered')
        try:
            yield
        except BaseException as error:
            if isinstance(error, SetupFailure): reason = error.reason
            elif isinstance(error, subprocess.TimeoutExpired): reason = 'timeout'
            elif isinstance(error, subprocess.CalledProcessError): reason = 'command-failed'
            elif isinstance(error, (ValueError, KeyError, TypeError)): reason = 'invalid-data'
            elif isinstance(error, OSError): reason = 'io'
            elif type(error).__name__ == 'Interrupted': reason = 'interrupted'
            else: reason = 'unexpected'
            self.record(stage, 'failed', reason)
            raise
        else:
            self.record(stage, 'completed')


def discover_gh(runner_path, workspace, private_root, env, deadline):
    found = shutil.which('gh', path=runner_path)
    if not found:
        raise SetupFailure('missing-tool')
    raw = Path(found)
    if not raw.is_absolute():
        raise SetupFailure('tool-path')
    executable = raw.resolve(strict=True)
    info = executable.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK) or executable.is_relative_to(workspace.resolve()) or executable.is_relative_to(private_root.resolve()):
        raise SetupFailure('tool-path')
    remaining = min(5, deadline - time.monotonic())
    if remaining <= 0:
        raise SetupFailure('timeout')
    version = subprocess.run([str(executable), '--version'], stdin=subprocess.DEVNULL,
                             capture_output=True, env=env, timeout=remaining, check=True)
    if len(version.stdout) > 4096 or not version.stdout.startswith(b'gh version '):
        raise SetupFailure('tool-version')
    return str(executable)


def unpack_go(archive, root, digest, parts):
    if archive.stat().st_size != GO_SIZE or digest(archive) != GO_SHA:
        raise SetupFailure('checksum')
    destination = root / 'toolchain'
    destination.mkdir(mode=0o700)
    total, seen = 0, set()
    with tarfile.open(archive) as bundle:
        for entry in bundle.getmembers():
            name = parts(entry.name)
            if name[0] != 'go' or entry.name in seen or not (entry.isfile() or entry.isdir()):
                raise SetupFailure('archive-layout')
            seen.add(entry.name); total += entry.size
            if len(seen) > 30000 or not 0 <= entry.size <= 128 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise SetupFailure('archive-layout')
            target = destination.joinpath(*name)
            if entry.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with bundle.extractfile(entry) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o700 if entry.mode & 0o111 else 0o600)
    if (destination / 'go/VERSION').read_text().splitlines()[0] != GO_VERSION:
        raise SetupFailure('tool-version')
    executable = destination / 'go/bin/go'
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SetupFailure('archive-layout')
    return executable


def check_go(go, env, deadline):
    remaining = min(5, deadline - time.monotonic())
    if remaining <= 0:
        raise SetupFailure('timeout')
    result = subprocess.run([str(go), 'version'], stdin=subprocess.DEVNULL, capture_output=True,
                            env=dict(env, GOTOOLCHAIN='local', GOROOT=str(go.parent.parent)),
                            timeout=remaining, check=True)
    if result.stdout.strip() != b'go version go1.26.5 darwin/arm64':
        raise SetupFailure('tool-version')
