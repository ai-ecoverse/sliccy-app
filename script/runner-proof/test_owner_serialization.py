from pathlib import Path
import copy
import json
import subprocess
import tempfile
import unittest
import time
from unittest.mock import patch
import owner_diagnostics as diagnostics
import sealed_owner_identity as wrapper
import owner_identity_setup as setup


class NativeSerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='sliccy-serialization-unit-')
        executable = Path(cls.directory.name) / 'serialization-fixture'
        source = Path(__file__).with_suffix('.m').resolve()
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'}
        subprocess.run(['/usr/bin/xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
            '-framework', 'Foundation', '-framework', 'Security', '-framework', 'CoreGraphics',
            str(source), '-o', str(executable)], env=env, capture_output=True, timeout=30, check=True)
        result = subprocess.run([str(executable)], env=env, capture_output=True, timeout=5, check=True)
        if len(result.stdout) > 65536 or result.stderr:
            raise ValueError('serialization fixture output')
        payload = json.loads(result.stdout)
        cls.kernels = payload['kernelRecords']
        cls.records = {row['name']: row['record'] for row in payload['staticRecords']}
        if set(cls.records) != {'clean', 'detritus', 'wrong-identity', 'broken-seal', 'missing-metadata', 'missing-code', 'wrong-team', 'wrong-digest-length'}:
            raise ValueError('serialization fixture cases')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_real_native_record_builders_and_encoder_feed_strict_wrapper(self):
        for name, record in self.records.items():
            with self.subTest(name=name):
                policy = wrapper.chrome_record_shape(record)
                self.assertIs(type(record['accepted']), bool)
                for key in ['schema', 'createStatus', 'requirementStatus', 'signingInformationStatus']:
                    self.assertIs(type(record[key]), int)
                for key in ['identifier', 'team', 'cdHash']:
                    self.assertTrue(record[key] is None or type(record[key]) is str)
                if policy:
                    for key in ['identityFlags', 'strictFlags', 'identityStatus', 'strictStatus']:
                        self.assertIs(type(policy[key]), int)
                    for key in ['accepted', 'detritusTolerated']:
                        self.assertIs(type(policy[key]), bool)
                    self.assertIs(type(policy['requirement']), str)
                    self.assertTrue(policy['strictErrorDomain'] is None or type(policy['strictErrorDomain']) is str)
                    self.assertTrue(policy['strictErrorCode'] is None or type(policy['strictErrorCode']) is int)
                if name in {'clean', 'detritus'}:
                    self.assertEqual(wrapper.parse_chrome_identity(record, 0), 'aa' * 20)
                else:
                    with self.assertRaises(ValueError): wrapper.parse_chrome_identity(record, 0)
        for parent, key in [(None, 'accepted'), ('policy', 'accepted'), ('policy', 'detritusTolerated')]:
            values = {(r[parent] if parent else r)[key] for r in self.records.values() if parent is None or r[parent]}
            self.assertEqual(values, {False, True})

    def test_every_typed_field_rejects_wrong_type_and_numeric_booleans(self):
        baseline = self.records['detritus']
        for parent, values in [(None, baseline), ('policy', baseline['policy'])]:
            for key, value in values.items():
                with self.subTest(parent=parent, key=key):
                    bad = copy.deepcopy(baseline)
                    target = bad[parent] if parent else bad
                    target[key] = int(value) if type(value) is bool else False if type(value) is int else 7
                    with self.assertRaises(ValueError): wrapper.chrome_record_shape(bad)
            bad = copy.deepcopy(baseline)
            (bad[parent] if parent else bad)['unknown'] = 0
            with self.assertRaises(ValueError): wrapper.chrome_record_shape(bad)
        for parent, key in [(None, 'accepted'), ('policy', 'accepted'), ('policy', 'detritusTolerated')]:
            for integer in [0, 1]:
                bad = copy.deepcopy(baseline); (bad[parent] if parent else bad)[key] = integer
                with self.assertRaises(ValueError): wrapper.chrome_record_shape(bad)
        for key in ['strictErrorCode', 'strictErrorDomain']:
            bad = copy.deepcopy(baseline); bad['policy'][key] = None
            wrapper.chrome_record_shape(bad)

    def test_actual_kernel_encoder_nullable_flags_and_all_typed_fields(self):
        self.assertEqual(len(self.kernels), 4)
        for sample in self.kernels:
            self.assertEqual(setup.kernel_record_shape(sample), sample)
            setup.observation_kernel_shapes({'before': sample, 'after': sample}, 42)
            setup.observation_kernel_shapes({'owners': [{'before': sample, 'after': sample}]}, None)
        self.assertIs(self.kernels[0]['platformBinary'], False)
        self.assertIs(self.kernels[1]['platformBinary'], True)
        self.assertIsNone(self.kernels[2]['platformBinary'])
        self.assertIs(self.kernels[0]['processInfoAvailable'], True)
        self.assertIs(self.kernels[2]['processInfoAvailable'], False)
        self.assertIs(self.kernels[3]['processInfoAvailable'], False)
        for key in ['parent', 'uid', 'startSeconds', 'startMicroseconds', 'path', 'codeStatus', 'platformBinary', 'cdHash']:
            self.assertIsNone(self.kernels[2][key])
        for key, value in self.kernels[1].items():
            with self.subTest(key=key):
                bad = copy.deepcopy(self.kernels[1])
                bad[key] = int(value) if type(value) is bool else False if type(value) is int else 7
                with self.assertRaises(ValueError): setup.kernel_record_shape(bad)
        for key in ['processInfoAvailable', 'platformBinary']:
            for integer in [0, 1]:
                bad = copy.deepcopy(self.kernels[1]); bad[key] = integer
                for pid, record in [(42, {'before': bad, 'after': self.kernels[0]}),
                                    (None, {'owners': [{'before': self.kernels[0], 'after': bad}]})]:
                    with self.assertRaises(ValueError): setup.observation_kernel_shapes(record, pid)
        for key in self.kernels[1]:
            bad = self.kernels[1].copy(); del bad[key]
            with self.assertRaises(ValueError): setup.kernel_record_shape(bad)
        bad = self.kernels[1].copy(); bad['unknown'] = 0
        with self.assertRaises(ValueError): setup.kernel_record_shape(bad)

    def test_actual_observer_boundary_refuses_numeric_flag_before_return(self):
        for pid in [42, None]:
            for flag in [True, False, None, 0, 1]:
                with self.subTest(pid=pid, flag=repr(flag)), tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    binary = root / 'synthetic-observer'; binary.write_bytes(b'not executable')
                    journal = diagnostics.Journal(root / 'steps', root, root, time.monotonic())
                    observer = setup.Observer(binary, root, {}, time.monotonic() + 15, journal)
                    sample = self.kernels[1].copy(); sample['platformBinary'] = flag
                    owner = {'before': self.kernels[0], 'after': sample}
                    value = owner if pid is not None else {'available': True, 'allWindowRowsClassifiable': True, 'owners': [owner]}
                    def output(args, **kwargs):
                        kwargs['stdout'].write(json.dumps(value).encode())
                        return subprocess.CompletedProcess(args, 0)
                    with patch.object(diagnostics.subprocess, 'run', side_effect=output):
                        if type(flag) is int:
                            with self.assertRaisesRegex(ValueError, 'kernel-record-type-platformBinary'):
                                observer.read('initial', pid)
                        else:
                            self.assertEqual(observer.read('initial', pid), value)
                    self.assertEqual(json.loads((root / 'observation-001.json').read_text()), value)


if __name__ == '__main__':
    unittest.main()
