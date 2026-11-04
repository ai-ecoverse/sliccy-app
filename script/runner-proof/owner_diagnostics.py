from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import subprocess
import tempfile
import time
import signal

LIMIT = 4096
STEPS = frozenset('host-preflight source-preflight evidence-setup source-copy age-download age-check artifact-prepare gh-discovery artifact-download artifact-check artifact-extract artifact-signature artifact-staple artifact-gatekeeper preview-prepare preview-discovery preview-download preview-check preview-extract preview-identity preview-signature preview-staple preview-gatekeeper bundle-before chrome-signature authorization-signature observer-build page-manifest identity-setup setup-host setup-directories page-server initial app-preview surface host-a-1 host-a-2 host-b-1 host-b-2 app-helper chrome-launched authorization-requester authorization-requested final-setup setup-presence pre-authorization-presence after-owned-cleanup bundle-after outcome evidence-envelope evidence-package evidence-seal privileged-before privileged-owner-recheck privileged-after'.split())
SYSTEM = frozenset(['/usr/bin/curl', '/usr/bin/ditto', '/usr/bin/codesign', '/usr/bin/xcrun', '/usr/sbin/spctl', '/usr/bin/lipo', '/usr/bin/osascript', '/usr/bin/sudo'])


class Journal:
    def __init__(self, path, root, workspace, began, secrets=()):
        self.path, self.root, self.workspace, self.began = path, Path(root), Path(workspace), began
        self.secrets = tuple(value for value in secrets if value)
        self.stack, self.count, self.last_failure = [], 0, None
        self.path.touch(exist_ok=False)

    def text(self, value, limit=LIMIT):
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        value = str(value)
        for secret in self.secrets:
            value = value.replace(secret, '<redacted>')
        return value.encode()[-limit:].decode('utf-8', errors='ignore')

    def tokens(self, args):
        result = []
        for index, arg in enumerate(args):
            value = str(arg).replace(str(self.root), '<private-root>').replace(str(self.workspace), '<reviewed-source>')
            if index == 2 and len(args) == 3 and Path(str(args[0])).name == 'owner-identity-probe' and args[1] == '--owner':
                value = '<owned-pid>'
            if value.startswith('--app=http://127.0.0.1:'):
                value = '--app=<loopback-origin>/' + value.split('/', 3)[3]
            result.append(self.text(value))
        return result

    def tool(self, path):
        path = str(path)
        if path in SYSTEM:
            return {'systemTool': path}
        value = {'path': path, 'sha256': None}
        try:
            value['sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError as error:
            value['identityError'] = type(error).__name__
        return value

    def write(self, row):
        if self.count >= 768:
            raise ValueError('diagnostic record bound')
        self.count += 1
        row = dict(schema=1, seq=self.count, elapsedMs=(time.monotonic() - self.began) * 1000, **row)
        with self.path.open('a') as output:
            output.write(json.dumps(row, sort_keys=True) + '\n')
        if row.get('status') == 'failed':
            self.last_failure = row
        return row

    @contextmanager
    def step(self, name):
        base = name.removeprefix('spawn-').removeprefix('cleanup-')
        if base not in STEPS:
            raise ValueError('unknown diagnostic step')
        self.stack.append(name)
        common = {'kind': 'validation', 'step': name, 'tool': {'pythonModule': 'reviewed-owner-probe'}, 'arguments': [],
                  'exitStatus': None, 'stdoutTail': '', 'stderrTail': ''}
        self.write(dict(common, status='entered'))
        try:
            yield
        except BaseException as error:
            cause = getattr(error, 'owner_diagnostic', None)
            self.write(dict(common, status='failed', exceptionClass=type(error).__name__, message=self.text(error), cause=cause))
            raise
        else:
            self.write(dict(common, status='completed'))
        finally:
            self.stack.pop()

    def call(self, name, function, *args, **kwargs):
        with self.step(name):
            return function(*args, **kwargs)

    def command_record(self, args):
        if not self.stack:
            raise ValueError('tool outside diagnostic step')
        name = Path(str(args[0])).name
        operation = 'invoke'
        if name == 'codesign':
            operation = 'verify' if '--verify' in args else 'entitlements' if '--entitlements' in args else 'display'
        elif name == 'xcrun':
            operation = str(args[1])
        elif name == 'gh':
            operation = 'version' if '--version' in args else 'download'
        elif name == 'lipo':
            operation = 'archs'
        elif name == 'owner-identity-probe':
            operation = 'chrome-static' if '--chrome-static' in args else 'owner' if '--owner' in args else 'windows'
        elif name == 'sudo':
            operation = 'privileged-kernel'
        return {'kind': 'command', 'step': self.stack[-1], 'operation': operation,
                'tool': self.tool(args[0]), 'arguments': self.tokens(args)}

    def finish(self, common, code, out=b'', err=b'', error=None):
        return self.write(dict(common, status='failed' if error is not None or code not in (None, 0) else 'completed',
            exitStatus=code, stdoutTail=self.text(out), stderrTail=self.text(err),
            exceptionClass=type(error).__name__ if error else None, message=self.text(error) if error else None))

    def run(self, args, **kwargs):
        common = self.command_record(args)
        self.write(dict(common, status='entered', exitStatus=None, stdoutTail='', stderrTail=''))
        stdout, stderr = kwargs.pop('stdout', None), kwargs.pop('stderr', None)
        capture = kwargs.pop('capture_output', False)
        check = kwargs.pop('check', False)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result, delivered = None, False
            try:
                result = subprocess.run(args, stdout=out, stderr=err, check=False, **kwargs)
                out.seek(0); err.seek(0)
                data, errors = out.read(4 * 1024 * 1024 + 1), err.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024 or len(errors) > 4 * 1024 * 1024:
                    raise ValueError('command output bound')
                if stdout is not None and stdout != subprocess.PIPE:
                    stdout.write(data)
                if stderr is not None and stderr != subprocess.PIPE:
                    stderr.write(errors)
                delivered = True
                result.stdout = data if capture or stdout == subprocess.PIPE else None
                result.stderr = errors if capture or stderr == subprocess.PIPE else None
                if check and result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, args, output=data, stderr=errors)
            except BaseException as error:
                if not delivered:
                    out.seek(0); err.seek(0)
                    data, errors = out.read(4 * 1024 * 1024 + 1), err.read(4 * 1024 * 1024 + 1)
                    if len(data) <= 4 * 1024 * 1024 and len(errors) <= 4 * 1024 * 1024:
                        if stdout is not None and stdout != subprocess.PIPE:
                            stdout.write(data)
                        if stderr is not None and stderr != subprocess.PIPE:
                            stderr.write(errors)
                error.owner_diagnostic = self.finish(common, result.returncode if result is not None else getattr(error, 'returncode', None), self.tail(out), self.tail(err), error)
                raise
            self.finish(common, result.returncode, self.tail(out), self.tail(err))
            return result

    def tail(self, stream):
        bound = LIMIT + max((len(value.encode()) for value in self.secrets), default=0)
        stream.flush(); stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - bound))
        return stream.read(bound)

    def owned(self, args, log, env, deadline, maximum=60, cwd=None, check=True):
        common = self.command_record(args)
        self.write(dict(common, status='entered', exitStatus=None, stdoutTail='', stderrTail=''))
        child, code = None, None
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                remaining = min(maximum, deadline - time.monotonic())
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, 0)
                child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
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
            except BaseException as error:
                error.owner_diagnostic = self.finish(common, child.returncode if child else None, self.tail(out), self.tail(err), error)
                raise
            self.finish(common, code, self.tail(out), self.tail(err))
            return code

    @contextmanager
    def bind(self, shared):
        old_process, old_setup_process, old_owned = shared.subprocess, shared.setup.subprocess, shared.run_owned
        facade = SimpleNamespace(**{name: getattr(subprocess, name) for name in ['PIPE', 'DEVNULL', 'TimeoutExpired', 'CalledProcessError', 'Popen']}, run=self.run)
        shared.subprocess, shared.setup.subprocess, shared.run_owned = facade, facade, self.owned
        try:
            yield
        finally:
            shared.subprocess, shared.setup.subprocess, shared.run_owned = old_process, old_setup_process, old_owned


class Trace:
    def __init__(self, original, journal):
        self.original, self.journal = original, journal

    @contextmanager
    def step(self, name):
        with self.journal.step('identity-setup' if name == 'native-driver' else name), self.original.step(name):
            yield
