from pathlib import Path
from unittest import TestCase
import json
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
SCRIPTS=ROOT/'script/runner-proof'
sys.path.insert(0,str(SCRIPTS))
import prerequisite_slice as policy
import prerequisite_kernel as kernel


class SliceBindingTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();exe=Path(cls.temp.name)/'fixture'
        r=subprocess.run(['/usr/bin/clang','-fobjc-arc','-Wall','-Wextra','-Werror','-framework','Foundation','-I',str(SCRIPTS),str(Path(__file__).with_name('slice_fixture.m')),'-o',str(exe)],capture_output=True,timeout=30)
        if r.returncode:raise AssertionError(r.stderr.decode())
        cls.value=json.loads(subprocess.check_output([str(exe)],timeout=5))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_unique_match_explicit_index(self):
        row=self.value['results'][0];policy.record('slice-selection',row)
        self.assertEqual(row,dict(accepted=True,reason='unique-match',matchCount=1,selectedIndex=1))

    def test_no_match_refuses(self):
        row=self.value['results'][1];policy.record('slice-selection',row)
        self.assertEqual(row,dict(accepted=False,reason='zero-match',matchCount=0,selectedIndex=None))

    def test_two_matches_refuse(self):
        row=self.value['results'][2];policy.record('slice-selection',row)
        self.assertEqual(row,dict(accepted=False,reason='multiple-match',matchCount=2,selectedIndex=None))

    def test_wrong_hash_type_refuses(self):
        row=self.value['results'][3];policy.record('slice-selection',row)
        self.assertEqual(row,dict(accepted=False,reason='zero-match',matchCount=0,selectedIndex=None))

    def test_malformed_inputs_and_stable_file_boundary(self):
        for row in self.value['invalid']:policy.record('slice-selection',row);self.assertIs(row['accepted'],False)
        self.assertEqual(self.value['fileMutations'],8)

    def test_actual_encoder_stream_and_boolean_refusal(self):
        for value in self.value['results']+self.value['invalid']:
            rows=[dict(schema=2,seq=1,phase='slice-selection',state='completed',elapsedMs=0,facts=value),
                  dict(schema=2,seq=2,phase='result',state='completed',elapsedMs=1,facts=dict(observed=False,reaped=False,rootGone=False))]
            self.assertEqual(kernel.parse(b''.join((json.dumps(x)+'\n').encode() for x in rows)),rows)
            with self.assertRaises(ValueError):policy.record('slice-selection',dict(value,accepted=int(value['accepted'])))

    def test_common_native_helper_and_selected_flags25(self):
        source=(SCRIPTS/'prerequisite_kernel.m').read_text();native=(SCRIPTS/'prerequisite_slice_native.h').read_text()
        self.assertEqual(source.count('BOOL sliceBound=bindUniqueSlice(pid,guest,requirement,a,path,identifier,kernelHash);'),1)
        self.assertIn('ah.length == 20 && sliceBound &&',source);self.assertNotIn('ah.length == 20 && [ah isEqual:bh]',source)
        self.assertIn('(!expected || [ah isEqual:expected])',source)
        self.assertIn('SecStaticCodeCheckValidity(references[index],kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode,requirement)',native)
        self.assertIn('require([selection[@"accepted"] isEqual:@YES],@"slice-unique-match")',native)
        self.assertIn('require(finalSame,@"slice-path-changed")',native)
        self.assertIn('require(kernelSame,@"slice-kernel-changed")',native)
        self.assertNotIn('kSecCodeAttributeUniversalFileOffset',native)
