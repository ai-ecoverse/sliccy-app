from pathlib import Path
from unittest import TestCase, main
import copy
import hashlib
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'script/runner-proof'
sys.path.insert(0, str(SCRIPTS))
import prerequisite_binding as binding
import prerequisite_kernel as kernel


class BindingDiagnosticsTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        executable = Path(cls.temp.name) / 'binding-fixture'
        subprocess.run(['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-framework', 'Foundation',
                        '-I', str(SCRIPTS), str(Path(__file__).with_name('binding_fixture.m')), '-o', str(executable)],
                       check=True, capture_output=True, timeout=30)
        result = subprocess.run([str(executable)], check=True, capture_output=True, timeout=5)
        cls.result = json.loads(result.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_every_actual_comparison_fault_has_same_fixed_name(self):
        names = ['kernel-status-zero', 'live-cdhash-type', 'live-cdhash-length', 'live-static-cdhash',
                 'live-kernel-cdhash', 'live-expected-cdhash', 'live-identifier', 'static-identifier', 'live-input-path']
        self.assertEqual(len(self.result['cases']), 10)
        for case in self.result['cases']:
            self.assertEqual([r['comparison'] for r in case['rows']], names)
            for row in case['rows']:
                binding.comparison(row)
            if case['fault'] == -1:
                self.assertTrue(all(row['matched'] is True for row in case['rows']))
            else:
                row = case['rows'][case['fault']]
                self.assertEqual(row['comparison'], names[case['fault']])
                self.assertIs(row['matched'], False)
                self.assertIs(row['affectsVerdict'], True)

    def test_optional_expected_pin_retains_original_semantics(self):
        for row in self.result['optional']: binding.comparison(row)
        row = self.result['optional'][5]
        self.assertIs(row['matched'], True)
        self.assertIs(row['affectsVerdict'], False)
        self.assertEqual(row['right'], {'type':'null', 'value':None})

    def test_every_filesystem_comparison_and_unavailable_record(self):
        rows = self.result['filesystem']
        self.assertEqual(len(rows), 12)
        for index, row in enumerate(rows):
            binding.comparison(row)
            self.assertIs(row['affectsVerdict'], False)
            self.assertIs(row['matched'], (True, False, False, None)[index % 4])
            self.assertEqual(row['status'], 'unavailable' if index % 4 == 3 else 'compared')

    def test_real_encoder_platform_anchor_true_false_null(self):
        for phase, key in [('binding-kernel-flags', 'platform'), ('binding-live-apple-anchor', 'anchor')]:
            field = 'platformBinary' if key == 'platform' else 'appleAnchored'
            for row, expected in zip(self.result[key], (True, False, None)):
                binding.supplemental(phase, row)
                self.assertIs(row[field], expected)
                self.assertIs(row['affectsVerdict'], False)
                for invalid in (0, 1, 'true'):
                    changed = copy.deepcopy(row); changed[field] = invalid
                    with self.subTest(phase=phase, expected=expected, invalid=invalid), self.assertRaises(ValueError):
                        binding.supplemental(phase, changed)

    def test_typed_values_bounds_and_numeric_booleans(self):
        for value in self.result['values']: binding.typed(value)
        for key in ('matched', 'affectsVerdict'):
            for value in (0, 1, None, 'true'):
                row = copy.deepcopy(self.result['cases'][0]['rows'][0]); row[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): binding.comparison(row)
        for row in self.result['cases'][0]['rows']:
            for key in ('comparison','status'):
                bad=copy.deepcopy(row);bad[key]='unknown'
                with self.assertRaises(ValueError):binding.comparison(bad)

    def test_actual_stream_parser_accepts_diagnostics_not_numeric_flags(self):
        rows=[]
        for facts in self.result['cases'][0]['rows']:
            rows.append({'schema':2,'seq':len(rows)+1,'phase':'binding-comparison','state':'completed','elapsedMs':len(rows),'facts':facts})
        rows.append({'schema':2,'seq':len(rows)+1,'phase':'result','state':'completed','elapsedMs':len(rows),'facts':{'observed':False,'reaped':False,'rootGone':False}})
        encoded=b''.join((json.dumps(r)+'\n').encode() for r in rows)
        self.assertEqual(kernel.parse(encoded),rows)
        rows[0]['facts']=dict(rows[0]['facts'],matched=0)
        with self.assertRaises(ValueError):kernel.parse(b''.join((json.dumps(r)+'\n').encode() for r in rows))

    def test_original_native_decision_expression_unchanged(self):
        text=(SCRIPTS/'prerequisite_kernel.m').read_text()
        expected='''        require(kernelStatus == 0 && [ah isKindOfClass:NSData.class] && ah.length == 20 && [ah isEqual:bh] &&
            [ah isEqual:kernelHash] && (!expected || [ah isEqual:expected]) && [ai isEqual:identifier] && [bi isEqual:identifier] &&
            [image.path isEqual:path], @"code-binding");'''
        self.assertEqual(text.count(expected),1)
        self.assertIn('SecStaticCodeCheckValidity(file, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement)',text)
        self.assertIn('SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement)',text)
        self.assertIn('sliccy_binding_rows(kernelStatus, ah, bh, kernelHash, expected, ai, bi, identifier, image, path)',text)


if __name__ == '__main__':
    main()
