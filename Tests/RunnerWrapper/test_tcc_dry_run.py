from pathlib import Path
import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'script/runner-proof'))
import capture_tcc as tcc
import capture_tcc_dry_run as diagnostic
import sealed_tcc_dry_run as wrapper
import sealed_runner as shared

USER = tcc.USER_BASE + '/a/b/c/Data/Library/Application Support/com.apple.TCC/TCC.db'
TEXT = {'service', 'client', 'indirect_object_identifier', 'boot_uuid'}
BLOB = {'csreq', 'indirect_object_code_identity'}
COLUMNS = [{'cid': i, 'name': n, 'type': 'TEXT' if n in TEXT else 'BLOB' if n in BLOB else 'INTEGER',
            'notnull': 0, 'dflt_value': None, 'pk': 0} for i, n in enumerate(tcc.COLUMNS)]
HOST = {'RUNNER_ENVIRONMENT': 'github-hosted'}


class DryRunTests(unittest.TestCase):
    def exercise(self, columns=None, requirement=None, preexisting=False, command_error=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obj = diagnostic.ReadOnlyValidation(root, root, {'PATH': '/usr/bin:/bin'}, time.monotonic() + 30)
            calls = []
            def command(args, cleanup=False):
                calls.append(args)
                self.assertFalse(cleanup)
                if command_error and command_error[0] in args:
                    raise command_error[1]
                if '/usr/bin/csreq' in args:
                    (root / 'app.csreq').write_bytes(requirement if requirement is not None else struct.pack('>IIII', 0xfade0c00, 16, 1, 1))
                if '/usr/bin/find' in args:
                    return (USER + '\n').encode()
                if '/usr/bin/stat' in args:
                    return b'100600 0 0 4096 123\n'
                if '/usr/bin/sqlite3' in args:
                    self.assertIn('-readonly', args)
                    sql = args[-1]
                    self.assertIn(sql, diagnostic.READS)
                    if sql == 'PRAGMA table_info(access);': return json.dumps(COLUMNS if columns is None else columns).encode()
                    if sql == 'PRAGMA user_version;': return b'[{"user_version":29}]'
                    if sql == 'PRAGMA schema_version;': return b'[{"schema_version":3}]'
                    if sql.startswith('SELECT name,type'): return b'[{"name":"access","type":"table"}]'
                    return b'[{"service":"kTCCServiceScreenCapture"}]' if preexisting else b'[]'
                return b''
            with patch.dict(os.environ, HOST), patch.object(tcc.placement, 'require_host'), patch.object(tcc.ScopedGrants, 'command', side_effect=command):
                result = obj.run(root / 'Sliccy.app')
            self.assertEqual(obj.touched, [])
            return result, json.loads((root / 'tcc-dry-run.json').read_text()), calls

    def test_exact_validation_pass_has_readonly_facts_no_writes(self):
        result, record, calls = self.exercise()
        self.assertTrue(result)
        self.assertTrue(record['validated'])
        self.assertFalse(record['databaseWriteAttempted'])
        self.assertFalse(record['driverInvoked'])
        self.assertEqual(set(record['facts']['databases']), {tcc.SYSTEM, USER})
        for facts in record['facts']['databases'].values():
            self.assertEqual(facts['accessColumns'], COLUMNS)
            self.assertEqual(facts['schemaVersion'], [{'schema_version': 3}])
            self.assertEqual(facts['userVersion'], [{'user_version': 29}])
            self.assertTrue(facts['stat']['regular'])
        self.assertEqual(record['facts']['compiledRequirement']['headerBE32'], [0xfade0c00, 16, 1])
        self.assertTrue(all('INSERT' not in ' '.join(call) and 'DELETE' not in ' '.join(call) for call in calls))

    def test_exact_schema_failure_retains_actual_columns_and_message(self):
        result, record, _ = self.exercise(columns=COLUMNS[:-1])
        self.assertFalse(result)
        self.assertEqual(record['events'][-1]['stage'], 'access-schema-validation')
        self.assertEqual(record['events'][-1]['exception'], {'class': 'ValueError', 'message': 'TCC schema'})
        self.assertEqual(record['facts']['databases'][tcc.SYSTEM]['accessColumns'], COLUMNS[:-1])

    def test_column_type_and_preexisting_checks_unchanged(self):
        columns = [dict(row) for row in COLUMNS]
        columns[0]['type'] = 'INTEGER'
        result, record, _ = self.exercise(columns=columns)
        self.assertFalse(result)
        self.assertEqual(record['events'][-1]['exception']['message'], 'TCC column type')
        result, record, _ = self.exercise(preexisting=True)
        self.assertFalse(result)
        self.assertEqual(record['events'][-1]['stage'], 'existing-permission-validation')
        self.assertEqual(record['events'][-1]['exception']['message'], 'preexisting app permission')

    def test_requirement_failure_reports_shape_without_fixing_header(self):
        result, record, calls = self.exercise(requirement=struct.pack('>IIII', 0xfade0c00, 16, 3, 1))
        self.assertFalse(result)
        self.assertEqual(record['events'][-1]['stage'], 'requirement-validation')
        self.assertEqual(record['events'][-1]['exception']['message'], 'requirement format')
        self.assertEqual(record['facts']['compiledRequirement']['headerBE32'][2], 3)
        self.assertFalse(any('/usr/bin/sqlite3' in args for args in calls))

    def test_read_failure_has_stage_command_status_and_bounded_stderr(self):
        error = subprocess.CalledProcessError(1, ['fixed-stat'], stderr=b'read permission denied')
        result, record, _ = self.exercise(command_error=('/usr/bin/stat', error))
        self.assertFalse(result)
        row = record['events'][-1]
        self.assertEqual(row['stage'], 'database-metadata')
        self.assertEqual(row['exception']['class'], 'CalledProcessError')
        self.assertEqual(row['exception']['stderr'], 'read permission denied')

    def test_write_launch_cleanup_and_unknown_sql_are_refused_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = diagnostic.ReadOnlyValidation(Path(tmp), Path(tmp), {}, time.monotonic() + 10)
            with patch.object(tcc.ScopedGrants, 'command') as command:
                for call in [lambda: obj.install(Path(tmp)), lambda: obj.remove(),
                             lambda: obj.query(tcc.SYSTEM, 'DELETE FROM access;'),
                             lambda: obj.read_query(tcc.SYSTEM, 'PRAGMA user_version=1;'),
                             lambda: obj.read_query('/tmp/unknown', 'PRAGMA user_version;'),
                             lambda: obj.command(['/usr/bin/open', 'Sliccy.app']),
                             lambda: obj.command(['/usr/bin/tccutil', 'reset', 'All'])]:
                    with self.assertRaises(ValueError): call()
                command.assert_not_called()

    def test_local_guard_precedes_all_commands(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            obj = diagnostic.ReadOnlyValidation(Path(tmp), Path(tmp), {}, time.monotonic() + 10)
            with patch.object(tcc.ScopedGrants, 'command') as command:
                self.assertFalse(obj.run(Path(tmp) / 'app'))
                command.assert_not_called()
            self.assertEqual(obj.journal[-1]['stage'], 'placement')

    def test_real_readonly_sqlite_refuses_mutation_and_preserves_database_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'owned-test.db'
            with contextlib.closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE access(service TEXT)'); db.commit()
            before = path.read_bytes()
            with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
                self.assertEqual(db.execute('PRAGMA table_info(access)').fetchone()[1], 'service')
                with self.assertRaises(sqlite3.OperationalError): db.execute("INSERT INTO access VALUES ('blocked')")
            self.assertEqual(before, path.read_bytes())

    def test_extracted_validator_is_exact_original_prewrite_body(self):
        frozen = Path('/Users/trieloff/.bb/thread-storage/thr_desfnajij8/runner-plan/capture-wrapper-v3/script/runner-proof/capture_tcc.py')
        if not frozen.exists(): self.skipTest('prior immutable source freeze unavailable')
        def method(source, name):
            cls = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'ScopedGrants')
            return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
        old = method(frozen.read_text(), 'install').body
        current = method((BASE / 'script/runner-proof/capture_tcc.py').read_text(), 'validate').body
        original = old[:next(i for i, node in enumerate(old) if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and getattr(node.value.func, 'attr', None) == 'record') + 1]
        self.assertEqual([ast.dump(n) for n in original], [ast.dump(n) for n in current[:-1]])


class EnvelopeTests(unittest.TestCase):
    def test_source_manifest_and_tamper_refusal(self):
        record = wrapper.validate_sources(BASE)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in record['files']:
                out = root / name; out.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(BASE / name, out)
            shutil.copyfile(BASE / 'script/runner-proof/tcc-dry-run-reviewed-sources.json', root / 'script/runner-proof/tcc-dry-run-reviewed-sources.json')
            (root / 'script/runner-proof/capture_tcc.py').write_text('changed')
            with self.assertRaises(ValueError): wrapper.validate_sources(root)

    def test_setup_suite_cannot_enter_driver_or_grants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); app = root / 'app'; recorded = {'fixed': 'manifest'}
            trace = shared.setup.SetupTrace(root / 'trace', time.monotonic())
            for valid in (False, True):
                with patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}), patch.object(shared, 'prepare_artifact', return_value=(app, root, recorded, None)), patch.object(shared, 'require_host'), patch.object(shared.capture_manifest, 'manifest', return_value=recorded), patch.object(diagnostic.ReadOnlyValidation, 'run', return_value=valid), patch.object(tcc.ScopedGrants, 'install') as install, patch.object(shared, 'suite') as capture, patch.object(shared, 'run_owned') as run:
                    self.assertEqual(wrapper.suite(root, root, None, {}, time.monotonic() + 10, BASE, trace), 0 if valid else 1)
                    install.assert_not_called(); capture.assert_not_called(); run.assert_not_called()

    def test_local_entry_refuses_without_commands(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(shared, 'run_owned') as run, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(wrapper.main(), 1); run.assert_not_called()
        self.assertEqual(out.getvalue(), 'Setup diagnostic evidence unavailable.\n')

    def test_failure_is_sealed_and_encrypt_failure_uploads_nothing(self):
        for encrypts in (False, True):
            with self.subTest(encrypts=encrypts), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); output = root / 'output'; calls = []
                def run(args, log, env, deadline, **kwargs):
                    calls.append((args, env, deadline))
                    self.assertNotIn('GH_TOKEN', env)
                    if '--encrypt' in args:
                        if not encrypts: raise RuntimeError('private failure')
                        Path(args[args.index('--output') + 1]).write_bytes(b'ciphertext-fixture')
                    return 0
                def unpack(_, path): path.write_bytes(b'never-executed')
                with patch.dict(os.environ, {'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output), 'GH_TOKEN': 'TOKEN-SENTINEL'}), patch.object(shared, 'require_host'), patch.object(wrapper, 'validate_sources', return_value={}), patch.object(shared, 'run_owned', side_effect=run), patch.object(shared, 'unpack_age', side_effect=unpack), patch.object(wrapper, 'suite', return_value=1), patch.object(wrapper, 'SOURCES', frozenset()), contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(wrapper.main(), 1)
                self.assertEqual((root / 'sliccy-tcc-setup-evidence.age').exists(), encrypts)
                self.assertEqual(output.exists(), encrypts)
                self.assertEqual(calls[-1][2] - calls[0][2], 60)
                self.assertNotIn('private failure', out.getvalue()); self.assertNotIn('TOKEN-SENTINEL', out.getvalue())
                self.assertFalse(list(root.glob('sliccy-tcc-readonly-private-*')))

    def test_workflow_only_enables_setup_without_driver_or_grant(self):
        text = (BASE / '.github/workflows/runner-proof.yml').read_text()
        for job in ['diagnostic', 'universal', 'hosted-pid']:
            self.assertIn('  ' + job + ':\n    if: false', text)
        block = text.split('  setup-read-only:')[1].split('  diagnostic:')[0]
        self.assertIn('sealed_tcc_dry_run.py', block)
        self.assertIn('timeout-minutes: 7', block)
        self.assertIn('name: tcc-setup-diagnostic-sealed', block)
        self.assertNotIn('secrets.', text); self.assertNotIn('id-token:', text)
        self.assertNotIn('go test', block); self.assertNotIn('tccutil', block)


if __name__ == '__main__': unittest.main(verbosity=2)
