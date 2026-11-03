from pathlib import Path
import json
import os
import platform
import re
import struct
import subprocess
import time
import mac_rosetta_preflight as placement
from universal_manifest import REQUIREMENT

SERVICES = ('kTCCServiceScreenCapture', 'kTCCServiceListenEvent', 'kTCCServicePostEvent')
COLUMNS = ('service', 'client', 'client_type', 'auth_value', 'auth_reason', 'auth_version', 'csreq',
           'policy_id', 'indirect_object_identifier_type', 'indirect_object_identifier',
           'indirect_object_code_identity', 'flags', 'last_modified', 'pid', 'pid_version',
           'boot_uuid', 'last_reminded')
EXTRA_COLUMNS = ('one_time_reprompt_eligible', 'reminder_count')
SYSTEM = '/Library/Application Support/com.apple.TCC/TCC.db'
USER_BASE = '/private/var/containers/Data/ProtectedSystem'


def user_database(candidates, active):
    paths = set(candidates)
    if not paths or len(paths) > 16:
        raise ValueError('TCC database candidates')
    for path in paths:
        p = Path(path)
        if not p.is_absolute() or '..' in p.parts or not path.startswith(USER_BASE + '/') or not path.endswith('/Data/Library/Application Support/com.apple.TCC/TCC.db'):
            raise ValueError('TCC database path')
    if len(paths) == 1:
        return next(iter(paths))
    selected = paths & set(active)
    if len(selected) != 1:
        raise ValueError('TCC database ambiguous')
    return next(iter(selected))


def schema_supported(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get('name'), str) for row in rows):
        raise ValueError('TCC schema row metadata')
    names = tuple(row['name'] for row in rows)
    if names not in (COLUMNS, COLUMNS + EXTRA_COLUMNS):
        unexpected = [name for name in names if name not in COLUMNS + EXTRA_COLUMNS]
        missing = [name for name in COLUMNS if name not in names]
        raise ValueError('TCC schema layout: unexpected=' + repr(unexpected) + '; missing=' + repr(missing) + '; observed order=' + repr(names))
    for index, row in enumerate(rows):
        name = row['name']
        if type(row.get('cid')) is not int or row['cid'] != index:
            raise ValueError('TCC column position: ' + name)
        expected = 'TEXT' if name in ('service', 'client', 'indirect_object_identifier', 'boot_uuid') else 'BLOB' if name in ('csreq', 'indirect_object_code_identity') else 'INTEGER'
        if not isinstance(row.get('type'), str) or row['type'].upper() != expected:
            raise ValueError('TCC column type: ' + name)
        if name in EXTRA_COLUMNS:
            if row.get('notnull') == 1 and row.get('dflt_value') is None:
                raise ValueError('TCC omitted NOT NULL column without default: ' + name)
            constraint = (row.get('notnull'), row.get('dflt_value'), row.get('pk'))
            observed = (0, None, 0) if name == EXTRA_COLUMNS[0] else (1, '0', 0)
            if constraint != observed or type(row.get('notnull')) is not int or type(row.get('pk')) is not int:
                raise ValueError('TCC column constraints: ' + name)


def compiled_requirement(data):
    if not 12 <= len(data) <= 4096:
        raise ValueError('requirement size')
    magic, size, kind = struct.unpack_from('>III', data)
    if magic != 0xfade0c00 or size != len(data) or kind != 1:
        raise ValueError('requirement format')
    return data.hex()


def predicates():
    services = ','.join("'" + s + "'" for s in SERVICES)
    return "client='ai.sliccy.mac' AND client_type=0 AND service IN (" + services + ')'


def insert_sql(requirement_hex, epoch):
    if not re.fullmatch('[0-9a-f]{24,8192}', requirement_hex) or type(epoch) is not int or epoch <= 0:
        raise ValueError('TCC fixed values')
    statements = ['BEGIN IMMEDIATE;']
    for service in SERVICES:
        statements.append('INSERT INTO access (' + ','.join(COLUMNS) + ") VALUES ('" + service +
                          "','ai.sliccy.mac',0,2,4,1,X'" + requirement_hex +
                          "',NULL,0,'UNUSED',NULL,0," + str(epoch) + ",NULL,NULL,'UNUSED'," + str(epoch) + ');')
    statements.append('COMMIT;')
    return '\n'.join(statements)


class ScopedGrants:
    def __init__(self, root, evidence, env, deadline):
        self.root, self.evidence, self.env, self.deadline = root, evidence, dict(env), deadline
        self.touched, self.hex = [], None
        self.events = []

    def record(self, stage, **values):
        self.events.append(dict(stage=stage, **values))
        if len(self.events) > 24:
            raise ValueError('TCC event bound')
        (self.evidence / 'tcc-setup.json').write_text(json.dumps({'schema': 1, 'scope': 'signed-app-only',
            'observerGrantAdded': False, 'permissionInferred': False, 'events': self.events}, indent=2) + '\n')

    def command(self, args, cleanup=False):
        remaining = min(10, self.deadline + (15 if cleanup else 0) - time.monotonic())
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, 0)
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=self.env,
                                timeout=remaining, check=True)
        if len(result.stdout) + len(result.stderr) > 1024 * 1024:
            raise ValueError('TCC output bound')
        return result.stdout

    def query(self, db, sql, cleanup=False):
        raw = self.command(['/usr/bin/sudo', '-n', '/usr/bin/sqlite3', '-json', '-cmd', '.timeout 1000', db, sql], cleanup)
        return json.loads(raw or b'[]')

    def validate(self, app):
        placement.require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
        if os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
            raise ValueError('TCC hosted guard')
        self.command(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + REQUIREMENT, str(app)])
        req = self.root / 'app.csreq'
        if req.exists() or req.is_symlink():
            raise ValueError('requirement destination')
        self.command(['/usr/bin/csreq', '-r', '=' + REQUIREMENT, '-b', str(req)])
        self.hex = compiled_requirement(req.read_bytes())
        found = self.command(['/usr/bin/sudo', '-n', '/usr/bin/find', USER_BASE, '-mindepth', '6', '-maxdepth', '6',
                              '-type', 'f', '-path', '*/Data/Library/Application Support/com.apple.TCC/TCC.db', '-print']).decode().splitlines()
        active = []
        if len(set(found)) > 1:
            raw = self.command(['/usr/bin/sudo', '-n', '/usr/sbin/lsof', '-c', 'tccd', '-Fn']).decode().splitlines()
            active = [line[1:] for line in raw if line.startswith('n')]
        databases = [SYSTEM, user_database(found, active)]
        for db in databases:
            self.command(['/usr/bin/sudo', '-n', '/bin/test', '-f', db])
            self.command(['/usr/bin/sudo', '-n', '/bin/test', '!', '-L', db])
            schema_supported(self.query(db, 'PRAGMA table_info(access);'))
            if self.query(db, 'SELECT service FROM access WHERE ' + predicates() + ';'):
                raise ValueError('preexisting app permission')
        self.record('validated', databases=databases, services=list(SERVICES))
        return databases

    def install(self, app):
        databases = self.validate(app)
        for db in databases:
            self.touched.append(db)
            self.query(db, insert_sql(self.hex, int(time.time())))
            rows = self.query(db, 'SELECT service,client,client_type,auth_value,auth_reason,auth_version,hex(csreq) AS csreq FROM access WHERE ' + predicates() + ';')
            expected = [{'service': service, 'client': 'ai.sliccy.mac', 'client_type': 0, 'auth_value': 2,
                         'auth_reason': 4, 'auth_version': 1, 'csreq': self.hex.upper()} for service in SERVICES]
            if sorted(rows, key=lambda row: row['service']) != sorted(expected, key=lambda row: row['service']):
                raise ValueError('TCC readback')
            self.record('installed', database=db, rowCount=3)

    def remove(self):
        errors = []
        for db in reversed(self.touched):
            try:
                self.query(db, "DELETE FROM access WHERE " + predicates() + " AND csreq=X'" + self.hex + "';", cleanup=True)
                if self.query(db, 'SELECT service FROM access WHERE ' + predicates() + ';', cleanup=True):
                    raise ValueError('TCC cleanup mismatch')
                self.record('removed', database=db)
            except Exception as error:
                errors.append(type(error).__name__)
        self.record('cleanup', complete=not errors, failures=errors)
        if errors:
            raise ValueError('TCC cleanup failed')
