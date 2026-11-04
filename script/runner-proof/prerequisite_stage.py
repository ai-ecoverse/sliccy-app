from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
import capture_stage as prior
import capture_stage_root as boundary

TOOLS = ('/usr/bin/sudo', '/bin/mkdir', '/bin/cp', '/bin/rm')
PATHS = ('/', '/usr', '/usr/bin', '/usr/bin/sudo', '/bin', '/bin/mkdir', '/bin/cp', '/bin/rm')
FLAGS = 0x00000001 | 0x00004000 | 0x40000000
SEALED = 0x02000000


def require(value, reason):
    if not value:
        raise ValueError(reason)


def platform(data, code):
    require(type(data) is bytes and len(data) <= 16384 and data.endswith(b'\n'), 'platform-output')
    row = json.loads(data, object_pairs_hook=boundary.unique_object)
    require(type(row) is dict and set(row) == {'schema', 'accepted', 'statfs', 'capabilities', 'root', 'paths'}
            and type(row['schema']) is int and row['schema'] == 1 and row['accepted'] is True and code == 0, 'platform-result')
    volume, cap = row['statfs'], row['capabilities']
    require(type(volume) is dict and set(volume) == {'status', 'errno', 'flags', 'mountPoint', 'mountedFrom', 'filesystem'}
            and all(type(volume[k]) is int for k in ('status', 'errno', 'flags')) and volume['status'] == 0
            and volume['flags'] & FLAGS == FLAGS and volume['mountPoint'] == '/' and volume['filesystem'] == 'apfs'
            and type(volume['mountedFrom']) is str and volume['mountedFrom'], 'platform-volume')
    require(type(cap) is dict and set(cap) == {'status', 'errno', 'length', 'expectedLength', 'validFormat', 'format'}
            and all(type(v) is int for v in cap.values()) and cap['status'] == 0
            and cap['length'] == cap['expectedLength'] == 36
            and cap['validFormat'] & SEALED and cap['format'] & SEALED, 'platform-seal')
    require(type(row['paths']) is list and len(row['paths']) == len(PATHS), 'platform-path-count')
    for name, value in zip(PATHS, row['paths']):
        require(type(value) is dict and set(value) == {'path', 'device', 'inode', 'uid', 'gid', 'mode'}
                and value['path'] == name and all(type(value[k]) is int for k in ('device', 'inode', 'uid', 'gid', 'mode'))
                and value['uid'] == 0 and value['device'] == row['root']['device'] and value['inode'] > 0,
                'platform-path-identity')
        require((stat.S_ISREG(value['mode']) and value['mode'] & 0o111) if name in TOOLS else stat.S_ISDIR(value['mode']),
                'platform-path-type')
    require(row['root'] == row['paths'][0], 'platform-root-binding')
    return row


def root_directory(path, acl=boundary.no_acl):
    fd = boundary.open_absolute(str(path), True, True)
    try:
        value = os.fstat(fd)
        require(stat.S_IMODE(value.st_mode) == 0o755, 'staging-directory-mode')
        acl(fd)
        return [value.st_dev, value.st_ino]
    finally:
        os.close(fd)


def creation_identity(path):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == 0 and value.st_ino > 0,
            'staging-created-identity')
    return [value.st_dev, value.st_ino]


def validate_tree(app, expected, owner=True, acl=boundary.no_acl, clock=time.monotonic, deadline=float('inf')):
    seen_files, seen_dirs = set(), set()
    count = 0
    for directory, folders, names in os.walk(app, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / x for x in names]:
            require(clock() < deadline, 'staging-validation-deadline')
            value = path.lstat()
            relative = path.relative_to(app).as_posix()
            require(not stat.S_ISLNK(value.st_mode) and not value.st_mode & 0o7022, 'staging-entry-mode')
            is_dir = stat.S_ISDIR(value.st_mode)
            require(is_dir or stat.S_ISREG(value.st_mode) and value.st_nlink == 1, 'staging-entry-type')
            if owner:
                require(value.st_uid == value.st_gid == 0, 'staging-entry-owner')
            fd = os.open(path, boundary.DIR_FLAGS if is_dir else boundary.FILE_FLAGS)
            try:
                opened = os.fstat(fd)
                require((opened.st_dev, opened.st_ino) == (value.st_dev, value.st_ino), 'staging-entry-race')
                if owner:
                    acl(fd)
                if is_dir:
                    if relative != '.':
                        seen_dirs.add(relative)
                    require(stat.S_IMODE(value.st_mode) == 0o755, 'staging-directory-mode')
                else:
                    require(relative in expected['files'], 'staging-extra-file')
                    record = expected['files'][relative]
                    require(value.st_size == record['size'] and stat.S_IMODE(value.st_mode) == record['mode'], 'staging-file-metadata')
                    digest = hashlib.sha256()
                    with os.fdopen(os.dup(fd), 'rb') as source:
                        while chunk := source.read(1024 * 1024):
                            require(clock() < deadline, 'staging-validation-deadline')
                            digest.update(chunk)
                    require(digest.hexdigest() == record['sha256'], 'staging-file-hash')
                    seen_files.add(relative)
            finally:
                os.close(fd)
            count += 1
            require(count <= 4096, 'staging-tree-bound')
        for name in folders:
            require(not (Path(directory) / name).is_symlink(), 'staging-link-directory')
    require(seen_files == set(expected['files']) and seen_dirs == set(expected['directories']), 'staging-tree-set')
    return {'files': len(seen_files), 'directories': len(seen_dirs)}


class FixedCommand:
    def __init__(self, record, clock=time.monotonic, spawn=subprocess.Popen):
        self.record, self.clock, self.spawn = record, clock, spawn
        self.retained = []

    def __call__(self, step, args, deadline):
        require(args[:3] == ['/usr/bin/sudo', '-n', '--'] and args[3] in TOOLS[1:], 'staging-command-tool')
        common = {'step': step, 'tool': {'systemTool': args[0]}, 'arguments': args[1:]}
        self.record('command-entered', dict(common, exitStatus=None, stdoutTail='', stderrTail=''))
        child = None
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                remaining = deadline - self.clock()
                require(remaining > 0, 'staging-command-deadline')
                child = self.spawn(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env={}, close_fds=True, umask=0o022)
                code = child.wait(timeout=remaining)
                result = SimpleNamespace(returncode=code, settled=True, pid=child.pid)
            except BaseException as error:
                settled = child is None or child.poll() is not None
                if not settled:
                    self.retained.append(child)
                error.settled = settled
                error.started = child is not None
                result = None
                raise
            finally:
                tails = []
                for stream in (out, err):
                    stream.flush(); stream.seek(0, 2)
                    stream.seek(max(0, stream.tell() - 4096))
                    tails.append(stream.read().decode('utf-8', 'replace'))
                self.record('command-completed', dict(common, exitStatus=child.returncode if child else None,
                    started=child is not None, settled=child is None or child.returncode is not None,
                    stdoutTail=tails[0], stderrTail=tails[1]))
            return result


class PlatformCheck:
    def __init__(self, binary, expected_hash, env, record, clock=time.monotonic, spawn=subprocess.Popen):
        self.binary, self.expected_hash, self.env, self.record = Path(binary), expected_hash, env, record
        self.clock, self.spawn = clock, spawn
        self.count = 0

    def __call__(self, deadline):
        self.count += 1
        require(self.count <= 8, 'platform-query-bound')
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.expected_hash, 'platform-observer-changed')
        remaining = min(3, deadline - self.clock())
        require(remaining > 0, 'platform-recheck-deadline')
        common = {'step': 'system-tools', 'tool': {'path': str(self.binary), 'sha256': self.expected_hash}, 'arguments': []}
        self.record('platform-entered', dict(common, exitStatus=None, stdoutTail='', stderrTail=''))
        child = None
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                child = self.spawn([str(self.binary)], stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=self.env, close_fds=True)
                code = child.wait(timeout=remaining)
                out.seek(0); err.seek(0)
                raw, errors = out.read(16385), err.read(4097)
                self.record('platform-completed', dict(common, exitStatus=code, raw=raw.decode('utf-8', 'replace'),
                    stdoutTail=raw[-4096:].decode('utf-8', 'replace'), stderrTail=errors[-4096:].decode('utf-8', 'replace')))
                return platform(raw, code)
            except BaseException as error:
                out.seek(0, 2); out.seek(max(0, out.tell() - 4096))
                err.seek(0, 2); err.seek(max(0, err.tell() - 4096))
                self.record('platform-failed', dict(common, exitStatus=child.returncode if child else None,
                    exceptionClass=type(error).__name__, reason=str(error),
                    settled=child is None or child.returncode is not None,
                    stdoutTail=out.read().decode('utf-8', 'replace'), stderrTail=err.read().decode('utf-8', 'replace')))
                raise


class Stage:
    def __init__(self, run, source, expected, invoke, verify, platform_check, record,
                 root=Path('/Library'), inspect=root_directory, tree=validate_tree, clock=time.monotonic, identify=creation_identity):
        self.path = root / boundary.canonical_run(run)
        self.source, self.expected, self.invoke, self.verify = Path(source), expected, invoke, verify
        self.platform_check, self.inspect, self.tree, self.clock = platform_check, inspect, tree, clock
        self.delivery = prior.DiagnosticDelivery(record)
        self.identify = identify
        self.identity = None
        self.started = False
        self.settled = True
        self.validated = False
        self.removal_state = 'unconfirmed'
        self.ends = None

    def command(self, step, tail, deadline):
        self.platform_check(deadline)
        self.settled = False
        try:
            result = self.invoke(step, ['/usr/bin/sudo', '-n', '--'] + tail, deadline)
            self.settled = result.settled is True
            require(self.settled, 'staging-writer-unsettled')
            require(type(result.returncode) is int and result.returncode == 0, step + '-failed')
        except BaseException as error:
            self.settled = self.settled or getattr(error, 'settled', False) is True
            raise

    def retain_created(self):
        self.identity = self.identify(self.path)
        require(self.inspect(self.path) == self.identity, 'staging-created-changed')
        self.delivery.submit('staging-created', {'path': str(self.path), 'identity': list(self.identity)})

    def create(self, deadline):
        require(not self.started and self.identity is None, 'staging-single-use')
        self.ends = min(deadline, self.clock() + 60)
        work_end = self.ends - 5
        try:
            require(self.clock() < work_end, 'staging-admission-deadline')
            self.inspect(self.path.parent)
            require(not self.path.exists() and not self.path.is_symlink(), 'staging-existing-directory')
            self.tree(self.source, self.expected, owner=False, deadline=work_end)
            self.started = True
            self.command('staging-mkdir', ['/bin/mkdir', '-m', '0755', str(self.path)], work_end)
            self.retain_created()
            require(self.identity is not None, 'cleanup-creation-identity-unavailable')
            self.command('staging-copy', ['/bin/cp', '-R', str(self.source), str(self.path) + '/'], work_end)
            require(self.inspect(self.path) == self.identity, 'staging-directory-replaced')
            require({p.name for p in self.path.iterdir()} == {'Sliccy.app'}, 'staging-top-level-set')
            app = self.path / 'Sliccy.app'
            facts = self.tree(app, self.expected, owner=True, deadline=work_end)
            self.verify(app, work_end)
            require(self.inspect(self.path) == self.identity, 'staging-directory-replaced')
            self.delivery.submit('staging-validated', dict(facts, identity=self.identity, executable=str(app / 'Contents/MacOS/Sliccy')))
            require(self.delivery.finish_success()['complete'], 'staging-diagnostic-incomplete')
            self.validated = True
            return app
        except BaseException as original:
            self.validated = False
            cleanup = None
            try:
                if self.started:
                    self.remove(self.ends)
            except BaseException as error:
                cleanup = str(error)
            raise boundary.CheckFailure('staging-failed', {'cause': str(original), 'cleanup': cleanup,
                'identity': self.identity, 'removalState': self.removal_state,
                'removalConfirmed': self.removal_state in ('confirmed-by-inode', 'confirmed-absent-with-retained-identity'),
                'diagnostics': self.delivery.snapshot()}) from original

    def remove(self, deadline):
        self.validated = False
        self.removal_state = 'unconfirmed'
        require(self.identity is not None, 'cleanup-creation-identity-unavailable')
        require(self.settled, 'cleanup-writer-unsettled')
        require(self.clock() < deadline, 'cleanup-reserve-exhausted')
        self.inspect(self.path.parent)
        if not self.path.exists() and not self.path.is_symlink():
            self.removal_state = 'confirmed-absent-with-retained-identity'
        else:
            require(self.inspect(self.path) == self.identity, 'cleanup-directory-replaced')
            self.command('staging-removal', ['/bin/rm', '-rf', str(self.path)], deadline)
            require(not self.path.exists() and not self.path.is_symlink(), 'cleanup-path-remains')
            self.removal_state = 'confirmed-by-inode'
        self.delivery.submit('staging-removed', {'identity': self.identity, 'removalState': self.removal_state})
        return self.removal_state

    def finish(self):
        self.delivery.finish_success()
        result = self.delivery.close()
        require(result['complete'], 'staging-diagnostic-incomplete')
        require(self.removal_state in ('confirmed-by-inode', 'confirmed-absent-with-retained-identity'), 'staging-removal-unconfirmed')
        return result
