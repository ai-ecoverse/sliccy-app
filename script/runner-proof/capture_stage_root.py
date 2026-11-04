import ctypes
import errno
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

ASSERTIONS = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
              'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
              'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted'}
REQUIREMENT = ('anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
               'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
               'and certificate leaf[subject.OU] = "S8LB56P782" and identifier "ai.sliccy.mac"')
MAX_FILES = 4096
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
STEPS = frozenset(['staging-placement', 'staging-os-version', 'staging-input', 'staging-ancestors',
                   'staging', 'staging-create', 'staging-copy', 'staged-role', 'staged-designated-requirement',
                   'staged-code-directory', 'staging-validated', 'staging-removal'])


class CheckFailure(ValueError):
    def __init__(self, reason, facts):
        super().__init__(reason)
        self.reason = reason
        self.facts = facts or {}


def require(value, reason, facts=None):
    if not value:
        raise CheckFailure(reason, facts)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def canonical_run(value):
    require(type(value) is str and re.fullmatch('[1-9][0-9]{0,19}', value) is not None
            and int(value) < 2 ** 64, 'run-id')
    return 'SliccyProof-' + value


def components(value):
    require(type(value) is str and 0 < len(value.encode()) <= 1024 and '\x00' not in value, 'relative-path')
    parts = value.split('/')
    require(len(parts) <= 16 and all(part not in ('', '.', '..') and len(part.encode()) <= 255 for part in parts), 'relative-path')
    return parts


def no_acl(fd):
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.acl_get_fd_np.restype = ctypes.c_void_p
    lib.acl_valid.argtypes = [ctypes.c_void_p]
    lib.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    lib.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = lib.acl_get_fd_np(fd, 0x100)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT, 'acl-unavailable')
        return
    try:
        require(lib.acl_valid(acl) == 0, 'acl-invalid')
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = lib.acl_get_entry(acl, 0, ctypes.byref(entry))
        require(result == -1 and ctypes.get_errno() == errno.EINVAL, 'acl-present')
    finally:
        lib.acl_free(acl)


def immutable(fd, directory, acl=no_acl):
    value = os.fstat(fd)
    require((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
            and value.st_uid == 0 and value.st_gid == 0 and not value.st_mode & 0o7022,
            'root-ownership-mode', dict(uid=value.st_uid, gid=value.st_gid, mode=value.st_mode, directory=directory))
    if not directory:
        require(value.st_nlink == 1, 'root-file-links', dict(links=value.st_nlink))
    acl(fd)
    return value


def open_absolute(path, directory, immutable_ancestors=False):
    require(type(path) is str and path.startswith('/') and not path.startswith('//'), 'absolute-path')
    parts = components(path[1:])
    fd = os.open('/', DIR_FLAGS)
    try:
        if immutable_ancestors:
            immutable(fd, True)
        for index, part in enumerate(parts):
            is_dir = index != len(parts) - 1 or directory
            other = os.open(part, DIR_FLAGS if is_dir else FILE_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = other
            if immutable_ancestors:
                immutable(fd, is_dir)
        return fd
    except BaseException:
        os.close(fd)
        raise


def manifest(value):
    require(type(value) is dict and set(value) == {'files', 'directories', 'cdhash', 'requirement', 'source'}, 'manifest-keys')
    require(type(value['files']) is dict and 0 < len(value['files']) <= MAX_FILES, 'manifest-files')
    require(type(value['directories']) is list and len(value['directories']) <= MAX_FILES, 'manifest-directories')
    require(type(value['cdhash']) is str and re.fullmatch('[0-9a-f]{40}', value['cdhash']) is not None, 'manifest-cdhash')
    require(type(value['requirement']) is str and 0 < len(value['requirement']) <= 4096
            and '\x00' not in value['requirement'] and '\n' not in value['requirement'], 'manifest-requirement')
    require(type(value['source']) is str and value['source'].endswith('/Sliccy.app'), 'manifest-source')
    total = 0
    for path, row in value['files'].items():
        components(path)
        require(type(row) is dict and set(row) == {'size', 'sha256', 'executable'}, 'manifest-file-row')
        require(type(row['size']) is int and 0 <= row['size'] <= MAX_FILE
                and type(row['executable']) is bool and type(row['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None, 'manifest-file-values')
        total += row['size']
    directories = set(value['directories'])
    require(len(directories) == len(value['directories']) and not directories.intersection(value['files'])
            and total <= MAX_BYTES, 'manifest-tree')
    for path in directories:
        components(path)
    for path in directories.union(value['files']):
        parts = components(path)
        require(all('/'.join(parts[:index]) in directories for index in range(1, len(parts))), 'manifest-parent')
    require('Contents/MacOS/Sliccy' in value['files'] and value['files']['Contents/MacOS/Sliccy']['executable'], 'manifest-executable')
    return value


class Journal:
    def __init__(self, write=None):
        self.seq = 0
        self.began = time.monotonic()
        self.write = write or (lambda data: os.write(1, data))

    def emit(self, step, phase, **fields):
        require(step in STEPS and phase in {'entered', 'completed', 'failed'}, 'journal-stage')
        self.seq += 1
        require(self.seq <= 40, 'journal-bound')
        row = dict(schema=1, seq=self.seq, step=step, phase=phase,
                   elapsedMs=(time.monotonic() - self.began) * 1000, **fields)
        data = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(len(data) <= 65536 and self.write(data) == len(data), 'journal-write')


def command(journal, step, arguments, deadline):
    journal.emit(step, 'entered', tool=arguments[0], arguments=arguments[1:])
    remaining = min(15, deadline - time.monotonic())
    require(remaining > 0, 'command-deadline')
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={}, timeout=remaining, check=False)
    except subprocess.TimeoutExpired as error:
        journal.emit(step, 'failed', exitStatus=None, reason='timeout',
                     stdoutTail=(error.stdout or b'')[-4096:].decode('utf-8', 'replace'),
                     stderrTail=(error.stderr or b'')[-4096:].decode('utf-8', 'replace'))
        raise
    journal.emit(step, 'completed' if result.returncode == 0 else 'failed', exitStatus=result.returncode,
                 stdoutTail=result.stdout[-4096:].decode('utf-8', 'replace'),
                 stderrTail=result.stderr[-4096:].decode('utf-8', 'replace'))
    require(result.returncode == 0, step + '-command-failed')
    require(len(result.stdout) <= 16384 and len(result.stderr) <= 16384, step + '-output-bound')
    return result.stdout, result.stderr


def copy_tree(source, destination, expected, deadline, prefix='', state=None):
    state = state if state is not None else {'files': {}, 'directories': [], 'bytes': 0, 'entries': 0}
    require(time.monotonic() < deadline, 'copy-deadline')
    for name in sorted(os.listdir(source)):
        require('/' not in name and name not in ('', '.', '..'), 'copy-name')
        path = prefix + name
        components(path)
        state['entries'] += 1
        require(state['entries'] <= MAX_FILES, 'copy-entry-bound')
        value = os.stat(name, dir_fd=source, follow_symlinks=False)
        require(not value.st_mode & 0o7000, 'copy-special-mode')
        if stat.S_ISDIR(value.st_mode):
            require(path in expected['directories'], 'copy-unexpected-directory')
            original = os.open(name, DIR_FLAGS, dir_fd=source)
            created = None
            try:
                require((os.fstat(original).st_dev, os.fstat(original).st_ino) == (value.st_dev, value.st_ino), 'copy-directory-replaced')
                os.mkdir(name, 0o755, dir_fd=destination)
                created = os.open(name, DIR_FLAGS, dir_fd=destination)
                os.fchmod(created, 0o755)
                immutable(created, True)
                state['directories'].append(path)
                copy_tree(original, created, expected, deadline, path + '/', state)
            finally:
                os.close(original)
                if created is not None:
                    os.close(created)
        else:
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and path in expected['files'], 'copy-file-type')
            row = expected['files'][path]
            require(value.st_size == row['size'] and bool(value.st_mode & 0o111) == row['executable'], 'copy-file-layout',
                    dict(path=path, size=value.st_size, expectedSize=row['size'], mode=value.st_mode, expectedExecutable=row['executable']))
            original = os.open(name, FILE_FLAGS, dir_fd=source)
            created = None
            try:
                before = os.fstat(original)
                require((before.st_dev, before.st_ino, before.st_mode, before.st_size) ==
                        (value.st_dev, value.st_ino, value.st_mode, value.st_size), 'copy-file-replaced')
                created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=destination)
                sha = hashlib.sha256()
                size = 0
                while True:
                    require(time.monotonic() < deadline, 'copy-deadline')
                    data = os.read(original, 1024 * 1024)
                    if not data:
                        break
                    size += len(data)
                    state['bytes'] += len(data)
                    require(size <= row['size'] and state['bytes'] <= MAX_BYTES, 'copy-byte-bound')
                    sha.update(data)
                    view = memoryview(data)
                    while view:
                        count = os.write(created, view)
                        require(count > 0, 'copy-write')
                        view = view[count:]
                after = os.fstat(original)
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'copy-source-mutated')
                require(size == row['size'] and sha.hexdigest() == row['sha256'], 'copy-checksum',
                        dict(path=path, size=size, expectedSize=row['size'], sha256=sha.hexdigest(), expectedSHA256=row['sha256']))
                os.fchmod(created, 0o444)
                immutable(created, False)
                state['files'][path] = dict(row)
            finally:
                os.close(original)
                if created is not None:
                    os.close(created)
    return state


def enumerate_owned(fd, prefix='', result=None):
    result = result if result is not None else []
    immutable(fd, True)
    for name in sorted(os.listdir(fd)):
        path = prefix + name
        components(path)
        require(len(result) < MAX_FILES + 4, 'cleanup-entry-bound')
        value = os.stat(name, dir_fd=fd, follow_symlinks=False)
        directory = stat.S_ISDIR(value.st_mode)
        require(directory or stat.S_ISREG(value.st_mode), 'cleanup-file-type')
        child = os.open(name, DIR_FLAGS if directory else FILE_FLAGS, dir_fd=fd)
        try:
            checked = immutable(child, directory)
            require((checked.st_dev, checked.st_ino) == (value.st_dev, value.st_ino), 'cleanup-replaced')
            result.append((path, directory, value.st_dev, value.st_ino))
            if directory:
                enumerate_owned(child, path + '/', result)
        finally:
            os.close(child)
    return result


def enable_executables(fd, expected):
    for path, row in expected['files'].items():
        if not row['executable']:
            continue
        parts = components(path)
        parent = os.dup(fd)
        child = None
        try:
            for part in parts[:-1]:
                other = os.open(part, DIR_FLAGS, dir_fd=parent)
                os.close(parent)
                parent = other
                immutable(parent, True)
            child = os.open(parts[-1], FILE_FLAGS, dir_fd=parent)
            immutable(child, False)
            require(stat.S_IMODE(os.fstat(child).st_mode) == 0o444, 'staged-pre-execution-mode')
            os.fchmod(child, 0o555)
            immutable(child, False)
        finally:
            if child is not None:
                os.close(child)
            os.close(parent)


def remove_owned(library, name, identity, journal):
    journal.emit('staging-removal', 'entered', directory=name)
    fd = os.open(name, DIR_FLAGS, dir_fd=library)
    try:
        value = immutable(fd, True)
        require([value.st_dev, value.st_ino] == identity, 'cleanup-root-replaced')
        entries = enumerate_owned(fd)
        for path, directory, device, inode in reversed(entries):
            parts = components(path)
            parent = os.dup(fd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, DIR_FLAGS, dir_fd=parent)
                    os.close(parent)
                    parent = child
                    immutable(parent, True)
                current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (device, inode), 'cleanup-entry-replaced')
                (os.rmdir if directory else os.unlink)(parts[-1], dir_fd=parent)
            finally:
                os.close(parent)
        current = os.stat(name, dir_fd=library, follow_symlinks=False)
        require([current.st_dev, current.st_ino] == identity, 'cleanup-root-replaced')
        os.rmdir(name, dir_fd=library)
        require(name not in os.listdir(library), 'cleanup-root-present')
    finally:
        os.close(fd)
    journal.emit('staging-removal', 'completed', directory=name, removed=True)


def stage(library, name, expected, journal, deadline):
    journal.emit('staging-create', 'entered', directory=name)
    os.mkdir(name, 0o755, dir_fd=library)
    fd = os.open(name, DIR_FLAGS, dir_fd=library)
    identity = None
    try:
        os.fchmod(fd, 0o755)
        value = os.fstat(fd)
        identity = [value.st_dev, value.st_ino]
        journal.emit('staging-create', 'completed', directory=name, identity=identity, uid=value.st_uid, gid=value.st_gid, mode=0o755)
        immutable(fd, True)
        source = open_absolute(expected['source'], True)
        target = None
        try:
            os.mkdir('Sliccy.app', 0o755, dir_fd=fd)
            target = os.open('Sliccy.app', DIR_FLAGS, dir_fd=fd)
            os.fchmod(target, 0o755)
            immutable(target, True)
            journal.emit('staging-copy', 'entered')
            copied = copy_tree(source, target, expected, deadline)
            require(copied['files'] == expected['files'] and set(copied['directories']) == set(expected['directories']), 'copy-tree-mismatch')
            journal.emit('staging-copy', 'completed', files=len(copied['files']), directories=len(copied['directories']), bytes=copied['bytes'])
        finally:
            os.close(source)
            if target is not None:
                os.close(target)
        app = '/Library/' + name + '/Sliccy.app'
        command(journal, 'staged-role', ['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + REQUIREMENT, app], deadline)
        command(journal, 'staged-designated-requirement', ['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + expected['requirement'], app], deadline)
        out, err = command(journal, 'staged-code-directory', ['/usr/bin/codesign', '-d', '-r-', '--verbose=4', app], deadline)
        metadata = (out + err).decode('utf-8', 'strict')
        require(re.findall(r'^CDHash=([0-9a-f]{40})$', metadata, re.M) == [expected['cdhash']], 'staged-cdhash')
        require(re.findall(r'^designated => (.+)$', metadata, re.M) == [expected['requirement']], 'staged-requirement')
        bundle = os.open('Sliccy.app', DIR_FLAGS, dir_fd=fd)
        try:
            enable_executables(bundle, expected)
        finally:
            os.close(bundle)
        enumerate_owned(fd)
        journal.emit('staging-validated', 'completed', executable=app + '/Contents/MacOS/Sliccy', cdhash=expected['cdhash'], identity=identity)
        return identity
    except BaseException:
        if identity is not None:
            remove_owned(library, name, identity, journal)
        raise
    finally:
        os.close(fd)


def main():
    journal = Journal()
    current = 'staging-placement'
    try:
        signal.alarm(60)
        os.umask(0o077)
        require(os.geteuid() == 0 and len(sys.argv) == 3 and sys.argv[1] in {'stage', 'remove'}, 'staging-arguments')
        name = canonical_run(sys.argv[2])
        require(all(os.environ.get(key) == value for key, value in ASSERTIONS.items()), 'staging-host-assertions')
        require(sys.platform == 'darwin' and os.uname().machine == 'arm64', 'staging-platform')
        deadline = time.monotonic() + 55
        out, _ = command(journal, 'staging-os-version', ['/usr/bin/sw_vers', '-productVersion'], deadline)
        require(re.fullmatch(rb'27\.[0-9]+(?:\.[0-9]+)?\n', out) is not None, 'staging-os-version')
        current = 'staging-input'
        raw = sys.stdin.buffer.read(512 * 1024 + 1)
        require(0 < len(raw) <= 512 * 1024, 'staging-input-bound')
        value = json.loads(raw, object_pairs_hook=unique_object)
        current = 'staging-ancestors'
        library = open_absolute('/Library', True, True)
        try:
            if sys.argv[1] == 'stage':
                current = 'staging'
                stage(library, name, manifest(value), journal, deadline)
            else:
                current = 'staging-removal'
                require(type(value) is dict and set(value) == {'identity'} and type(value['identity']) is list
                        and len(value['identity']) == 2 and all(type(x) is int and x > 0 for x in value['identity']), 'cleanup-identity')
                remove_owned(library, name, value['identity'], journal)
        finally:
            os.close(library)
        return 0
    except BaseException as error:
        journal.emit(current, 'failed', exception=type(error).__name__, reason=str(error)[:512], facts=getattr(error, 'facts', {}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
