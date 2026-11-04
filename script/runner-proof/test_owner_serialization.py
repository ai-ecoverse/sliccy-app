from pathlib import Path
import copy
import json
import subprocess
import tempfile
import unittest
import sealed_owner_identity as wrapper


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
        cls.records = {row['name']: row['record'] for row in json.loads(result.stdout)}
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


if __name__ == '__main__':
    unittest.main()
