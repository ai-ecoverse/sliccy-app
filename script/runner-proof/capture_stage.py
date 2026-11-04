from pathlib import Path
import hashlib
import json
import math
import os
import stat

import capture_stage_root as root


DISCOVERY = ('import json,sys,sysconfig;print(json.dumps({"executable":sys.executable,'
             '"stdlib":sysconfig.get_path("stdlib"),"prefix":sys.base_prefix},sort_keys=True))')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def hash_file(path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def interpreter(discovered, verify, record):
    require(type(discovered) is dict and set(discovered) == {'executable', 'stdlib', 'prefix'}, 'interpreter-shape')
    require(all(type(value) is str and len(value.encode()) <= 4096 for value in discovered.values()), 'interpreter-record-bound')
    record('staging-interpreter-discovery', discovered)
    paths = {}
    for key in ('executable', 'stdlib', 'prefix'):
        value = discovered[key]
        require(type(value) is str and value.startswith('/'), 'interpreter-path')
        paths[key] = Path(value).resolve(strict=True)
        require(str(paths[key]).startswith('/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/'), 'interpreter-fixed-framework')
    require(paths['executable'].is_relative_to(paths['prefix']) and paths['stdlib'].is_relative_to(paths['prefix'])
            and paths['executable'] != Path('/usr/bin/python3'), 'interpreter-layout')
    for key, path in paths.items():
        fd = root.open_absolute(str(path), key != 'executable', True)
        os.close(fd)
    count = 0
    for directory, folders, files in os.walk(paths['prefix'], followlinks=False):
        for name in folders + files:
            item = Path(directory) / name
            count += 1
            require(count <= 30000, 'interpreter-tree-bound')
            value = item.lstat()
            if stat.S_ISLNK(value.st_mode):
                require(value.st_uid == 0 and value.st_gid == 0, 'interpreter-link-owner')
                item = item.resolve(strict=True)
                require(item.is_relative_to(paths['prefix']), 'interpreter-link-target')
                value = item.lstat()
            require(stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode), 'interpreter-tree-type')
            fd = root.open_absolute(str(item), stat.S_ISDIR(value.st_mode), True)
            os.close(fd)
    verify('staging-interpreter-identity', ['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=anchor apple', str(paths['executable'])])
    digest = hash_file(paths['executable'])
    record('staging-interpreter', dict(path=str(paths['executable']), sha256=digest,
                                      stdlib=str(paths['stdlib']), prefix=str(paths['prefix']), entries=count))
    return paths['executable'], digest


def bundle_manifest(app, cdhash, requirement):
    app = app.resolve(strict=True)
    require(app.name == 'Sliccy.app', 'staging-source-name')
    files, directories = {}, []
    for directory, folders, names in os.walk(app, followlinks=False):
        for name in folders + names:
            path = Path(directory) / name
            value = path.lstat()
            relative = path.relative_to(app).as_posix()
            root.components(relative)
            require(not stat.S_ISLNK(value.st_mode) and not value.st_mode & 0o7000, 'staging-source-type')
            if stat.S_ISDIR(value.st_mode):
                directories.append(relative)
            else:
                require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, 'staging-source-type')
                files[relative] = dict(size=value.st_size, sha256=hash_file(path), executable=bool(value.st_mode & 0o111))
    return root.manifest(dict(files=files, directories=sorted(directories), cdhash=cdhash,
                              requirement=requirement, source=str(app)))


def arguments(python, program, action, run):
    root.canonical_run(run)
    require(action in ('stage', 'remove'), 'staging-action')
    return ['/usr/bin/sudo', '-n', '--preserve-env=' + ','.join(sorted(root.ASSERTIONS)), '--',
            str(python), '-I', '-S', '-B', '-c', program, action, run]


def validate_record(row, index):
    require(type(row) is dict and type(row.get('schema')) is int and row['schema'] == 1
            and type(row.get('seq')) is int and row['seq'] == index
            and type(row.get('step')) is str and row['step'] in root.STEPS
            and type(row.get('phase')) is str and row['phase'] in {'entered', 'completed', 'failed'}
            and type(row.get('elapsedMs')) in (int, float) and math.isfinite(row['elapsedMs']) and row['elapsedMs'] >= 0,
            'staging-record-schema')
    allowed = {'schema', 'seq', 'step', 'phase', 'elapsedMs', 'tool', 'arguments', 'exitStatus', 'reason',
               'stdoutTail', 'stderrTail', 'exception', 'facts', 'directory', 'identity', 'uid', 'gid', 'mode',
               'files', 'directories', 'bytes', 'executable', 'cdhash', 'removed', 'alreadyAbsent'}
    require(set(row) <= allowed, 'staging-record-fields')


class RecordStream:
    def __init__(self, accept):
        self.accept = accept
        self.raw = bytearray()
        self.pending = bytearray()
        self.rows = []
        self.failure = None

    def feed(self, chunk):
        require(self.failure is None, 'staging-stream-retired')
        try:
            require(type(chunk) is bytes and len(self.raw) + len(chunk) <= 1024 * 1024, 'staging-record-bound')
            self.raw.extend(chunk)
            self.pending.extend(chunk)
            while b'\n' in self.pending:
                line, _, rest = self.pending.partition(b'\n')
                self.pending = bytearray(rest)
                require(len(line) <= 65536 and len(self.rows) < 40, 'staging-record-count')
                row = json.loads(line, object_pairs_hook=root.unique_object)
                validate_record(row, len(self.rows) + 1)
                self.rows.append(row)
                self.accept(row)
            require(len(self.pending) <= 65536, 'staging-record-line-bound')
        except BaseException as error:
            self.failure = error
            raise

    def finish(self):
        require(self.failure is None and self.rows and not self.pending, 'staging-record-incomplete')
        return self.rows


def records(data):
    stream = RecordStream(lambda row: None)
    stream.feed(data)
    return stream.finish()


class Stage:
    def __init__(self, run, python, python_hash, source_hash, invoke, record):
        self.name = root.canonical_run(run)
        self.run, self.python, self.python_hash = run, python, python_hash
        self.invoke, self.record = invoke, record
        program = Path(__file__).with_name('capture_stage_root.py').read_bytes()
        require(hashlib.sha256(program).hexdigest() == source_hash, 'staging-program-source')
        self.program = program.decode('utf-8', 'strict')
        self.identity = None
        self.validated = False
        self.started = False
        self.settled = False
        self.delivery_failure = None

    def retain(self, row):
        if row['step'] == 'staging-create' and row['phase'] == 'completed':
            require(row.get('directory') == self.name and type(row.get('identity')) is list
                    and len(row['identity']) == 2 and all(type(x) is int and x > 0 for x in row['identity']), 'staging-root-identity')
            require(self.identity is None or self.identity == row['identity'], 'staging-root-identity-changed')
            self.identity = list(row['identity'])

    def call(self, action, payload):
        checked = root.open_absolute(str(self.python), False, True)
        os.close(checked)
        require(hash_file(self.python) == self.python_hash, 'staging-interpreter-changed')
        args = arguments(self.python, self.program, action, self.run)
        self.delivery_failure = None
        def deliver(name, value):
            try:
                self.record(name, value)
            except BaseException as error:
                self.delivery_failure = self.delivery_failure or error
        def accept(row):
            self.retain(row)
            deliver('root-staging-' + action + '-row', row)
        stream = RecordStream(accept)
        self.started = True
        self.settled = False
        result = None
        try:
            result = self.invoke('root-staging-' + action, args, json.dumps(payload, sort_keys=True).encode(),
                                 dict(root.ASSERTIONS), 60, on_stdout=stream.feed)
            self.settled = getattr(result, 'settled', None) is True
            require(self.settled, 'staging-writer-unsettled')
            require(type(result.stdout) is bytes and bytes(stream.raw) == result.stdout, 'staging-stream-delivery-mismatch')
            rows = stream.finish()
            deliver('root-staging-' + action, dict(exitStatus=result.returncode, rows=rows))
            require(type(result.returncode) is int and result.returncode == 0
                    and not any(row['phase'] == 'failed' for row in rows), 'root-staging-' + action + '-failed')
            if action == 'stage':
                require(self.delivery_failure is None, 'staging-diagnostic-loss')
            return rows
        except BaseException as error:
            self.settled = self.settled or getattr(error, 'settled', None) is True
            available = getattr(result, 'stdout', None) if result is not None else getattr(error, 'stdout', None)
            if type(available) is bytes:
                recovery = RecordStream(self.retain)
                try:
                    recovery.feed(available)
                except BaseException:
                    pass
            raise

    def create(self, expected):
        require(self.identity is None and not self.validated, 'staging-already-created')
        self.started = False
        try:
            rows = self.call('stage', expected)
            validated = [row for row in rows if row['step'] == 'staging-validated' and row['phase'] == 'completed']
            executable = '/Library/' + self.name + '/Sliccy.app/Contents/MacOS/Sliccy'
            require(len(validated) == 1 and self.identity is not None and validated[0].get('identity') == self.identity
                    and validated[0].get('executable') == executable and validated[0].get('cdhash') == expected['cdhash'], 'staging-validation-record')
            self.validated = True
            return Path(executable)
        except BaseException as original:
            self.validated = False
            if self.started:
                try:
                    require(self.identity is not None, 'cleanup-creation-identity-unavailable')
                    require(self.settled, 'cleanup-writer-unsettled')
                    self.remove()
                except BaseException as cleanup:
                    confirmed = self.identity is None
                    raise root.CheckFailure('staging-cleanup-diagnostic-loss' if confirmed else 'staging-cleanup-unconfirmed',
                        dict(original=type(original).__name__, cleanup=type(cleanup).__name__,
                             cleanupReason=str(cleanup)[:512], identity=self.identity, removalConfirmed=confirmed)) from original
            raise

    def remove(self):
        require(self.identity is not None, 'staging-removal-missing-identity')
        require(self.settled, 'cleanup-writer-unsettled')
        expected = list(self.identity)
        rows = self.call('remove', {'identity': expected})
        complete = [row for row in rows if row['step'] == 'staging-removal' and row['phase'] == 'completed']
        require(len(complete) == 1 and complete[0].get('directory') == self.name
                and complete[0].get('identity') == expected and complete[0].get('removed') is True
                and type(complete[0].get('alreadyAbsent')) is bool, 'staging-removal-unconfirmed')
        self.identity = None
        self.validated = False
        require(self.delivery_failure is None, 'staging-cleanup-diagnostic-loss')
