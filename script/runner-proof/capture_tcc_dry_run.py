import hashlib
import json
import platform
import stat
import struct
import subprocess
import time
import capture_tcc as tcc
from universal_manifest import REQUIREMENT

READS = frozenset([
    'PRAGMA table_info(access);',
    'PRAGMA user_version;',
    'PRAGMA schema_version;',
    "SELECT name,type FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 65;",
    'SELECT service FROM access WHERE ' + tcc.predicates() + ';',
])


def exception_record(error, command_detail=False):
    if isinstance(error, subprocess.CalledProcessError):
        message = 'fixed read-only command exited ' + str(error.returncode)
    elif isinstance(error, subprocess.TimeoutExpired):
        message = 'fixed read-only command exceeded deadline'
    elif isinstance(error, (ValueError, KeyError, TypeError, OSError)):
        message = str(error)[:2048]
    else:
        message = 'unexpected diagnostic exception'
    record = {'class': type(error).__name__, 'message': message}
    if command_detail and isinstance(error, subprocess.CalledProcessError):
        record['message'] = str(error)[:2048]
        stderr = error.stderr or b''
        record['stderr'] = stderr[:4096].decode('utf-8', errors='replace') if isinstance(stderr, bytes) else str(stderr)[:4096]
    return record


class ReadOnlyValidation(tcc.ScopedGrants):
    def __init__(self, root, evidence, env, deadline):
        super().__init__(root, evidence, env, deadline)
        self.stage = 'placement'
        self.app = None
        self.paths = {tcc.SYSTEM}
        self.facts = {'macOSVersion': platform.mac_ver()[0], 'system': platform.system(),
                      'architecture': platform.machine(), 'requirementText': REQUIREMENT,
                      'compiledRequirement': None, 'databaseCandidates': None, 'activeCandidates': None,
                      'databases': {}}
        self.journal = []
        self.completed = False
        self.began = time.monotonic()

    def save(self, phase, error=None):
        self.journal.append({'stage': self.stage, 'phase': phase,
                             'elapsedMs': (time.monotonic() - self.began) * 1000,
                             'exception': exception_record(error, command_detail=True) if error else None})
        if len(self.journal) > 96:
            raise ValueError('dry-run event bound')
        record = {'schema': 1, 'mode': 'setup-read-only', 'validated': self.completed,
                  'databaseWriteAttempted': False, 'driverInvoked': False, 'captureInvoked': False,
                  'facts': self.facts, 'events': self.journal}
        data = json.dumps(record, indent=2) + '\n'
        if len(data.encode()) > 256 * 1024:
            raise ValueError('dry-run evidence bound')
        (self.evidence / 'tcc-dry-run.json').write_text(data)

    def enter(self, stage):
        self.stage = stage
        self.save('entered')

    def read_query(self, db, sql):
        if db not in self.paths or sql not in READS:
            raise ValueError('dry-run SQL refused')
        raw = super().command(['/usr/bin/sudo', '-n', '/usr/bin/sqlite3', '-readonly', '-json',
                               '-cmd', '.timeout 1000', db, sql])
        rows = json.loads(raw or b'[]')
        if not isinstance(rows, list) or len(rows) > 64 or any(not isinstance(row, dict) for row in rows):
            raise ValueError('dry-run row bound')
        return rows

    def database_facts(self, db):
        self.enter('database-metadata')
        values = self.facts['databases'].setdefault(db, {})
        raw = super().command(['/usr/bin/sudo', '-n', '/usr/bin/stat', '-f', '%p %u %g %z %i', db]).decode().strip()
        fields = raw.split()
        if len(fields) != 5:
            raise ValueError('database stat shape')
        mode = int(fields[0], 8)
        values['stat'] = {'modeOctal': fields[0], 'uid': int(fields[1]), 'gid': int(fields[2]),
                          'size': int(fields[3]), 'inode': int(fields[4]),
                          'regular': stat.S_ISREG(mode), 'symlink': stat.S_ISLNK(mode)}
        self.save('observed')
        for label, sql in [('tables', "SELECT name,type FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 65;"),
                           ('userVersion', 'PRAGMA user_version;'), ('schemaVersion', 'PRAGMA schema_version;')]:
            self.enter('database-' + label)
            values[label] = self.read_query(db, sql)
            self.save('observed')

    def query(self, db, sql, cleanup=False):
        if cleanup or db not in self.paths:
            raise ValueError('dry-run query target')
        if sql == 'PRAGMA table_info(access);':
            self.database_facts(db)
            self.enter('access-schema-read')
            rows = self.read_query(db, sql)
            self.facts['databases'][db]['accessColumns'] = rows
            self.enter('access-schema-validation')
            return rows
        if sql == 'SELECT service FROM access WHERE ' + tcc.predicates() + ';':
            self.enter('existing-permission-read')
            rows = self.read_query(db, sql)
            self.facts['databases'][db]['existingAppServices'] = rows
            self.enter('existing-permission-validation')
            return rows
        raise ValueError('dry-run write refused')

    def command(self, args, cleanup=False):
        if cleanup:
            raise ValueError('dry-run cleanup command refused')
        req = self.root / 'app.csreq'
        fixed = {
            'app-role': ['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + REQUIREMENT, str(self.app)],
            'requirement-compile': ['/usr/bin/csreq', '-r', '=' + REQUIREMENT, '-b', str(req)],
            'database-discovery': ['/usr/bin/sudo', '-n', '/usr/bin/find', tcc.USER_BASE, '-mindepth', '6', '-maxdepth', '6',
                                   '-type', 'f', '-path', '*/Data/Library/Application Support/com.apple.TCC/TCC.db', '-print'],
            'database-active-owner': ['/usr/bin/sudo', '-n', '/usr/sbin/lsof', '-c', 'tccd', '-Fn'],
        }
        stage = next((name for name, value in fixed.items() if args == value), None)
        for db in sorted(self.paths):
            if args == ['/usr/bin/sudo', '-n', '/bin/test', '-f', db]:
                stage = 'database-regular-file'
                self.facts['currentDatabase'] = db
            if args == ['/usr/bin/sudo', '-n', '/bin/test', '!', '-L', db]:
                stage = 'database-no-symlink'
                self.facts['currentDatabase'] = db
        if stage is None:
            raise ValueError('dry-run command refused')
        self.enter(stage)
        result = super().command(args)
        if stage == 'requirement-compile':
            self.enter('requirement-shape')
            data = req.read_bytes()
            if len(data) > 4096:
                raise ValueError('requirement size')
            self.facts['compiledRequirement'] = {'length': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'headerBE32': list(struct.unpack_from('>III', data)) if len(data) >= 12 else None}
            self.enter('requirement-validation')
        elif stage == 'database-discovery':
            candidates = result.decode().splitlines()
            if len(candidates) > 16 or any(len(path) > 4096 for path in candidates):
                raise ValueError('database discovery bound')
            self.facts['databaseCandidates'] = candidates
            for path in candidates:
                tcc.user_database([path], [])
                self.paths.add(path)
            self.enter('database-selection')
        elif stage == 'database-active-owner':
            names = [line[1:] for line in result.decode().splitlines() if line.startswith('n')]
            self.facts['activeCandidates'] = sorted(set(names) & self.paths)
            self.enter('database-selection')
        else:
            self.save('completed')
            if stage == 'app-role':
                self.enter('requirement-destination')
        return result

    def record(self, stage, **values):
        if stage != 'validated' or self.touched:
            raise ValueError('dry-run validation boundary')
        self.completed = True
        self.enter('validated')
        self.save('completed')

    def install(self, app):
        raise ValueError('dry-run installation forbidden')

    def remove(self):
        raise ValueError('dry-run removal forbidden')

    def run(self, app):
        self.app = app
        self.enter('placement')
        try:
            super().validate(app)
            if not self.completed or self.touched:
                raise ValueError('dry-run incomplete validation')
        except Exception as error:
            self.completed = False
            self.save('failed', error)
            return False
        return True
