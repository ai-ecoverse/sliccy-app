from pathlib import Path
from unittest import TestCase
import copy
import json
import os
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'script/runner-proof'))
import prerequisite_sysctl as diagnostic
from test_sysctl_diagnostics import rows,parse


class NativeSysctlFixtureTests(TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
            raise RuntimeError('native-fixtures-hosted-only')
        cls.directory=tempfile.TemporaryDirectory();exe=Path(cls.directory.name)/'sysctl-fixture'
        subprocess.run(['/usr/bin/clang','-fobjc-arc','-Wall','-Wextra','-Werror','-framework','Foundation','-I',str(ROOT/'script/runner-proof'),str(Path(__file__).with_name('sysctl_fixture.m')),'-o',str(exe)],check=True,capture_output=True,timeout=30)
        cls.data=json.loads(subprocess.check_output([str(exe)],timeout=5))

    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()

    def test_actual_record_encoder_to_strict_parser(self):
        before=self.data['before'];proc=self.data['proc'];summary=self.data['summary']
        diagnostic.result(before);diagnostic.result(proc,True)
        parse(rows(before,proc,before,summary))
        for record in self.data['unavailable']:diagnostic.result(record);self.assertIs(record['available'],False)
        for field in diagnostic.FIELDS:
            self.assertEqual(before['value'][field],proc['value'][field])
        for key in ('available','affectsVerdict'):
            bad=copy.deepcopy(before);bad[key]=int(bad[key])
            with self.assertRaises(ValueError):diagnostic.result(bad)

    def test_actual_field_faults_and_diagnostic_semantics(self):
        before=self.data['before'];proc=self.data['proc']
        for mutation in self.data['mutations']:
            field=mutation['field'];self.assertIs(mutation['summary']['beforeVsProc'][field],False)
            if field=='pid':continue
            changed=copy.deepcopy(proc);changed['value'][field]='124' if field=='startSeconds' else changed['value'][field]+1
            parse(rows(before,changed,before,mutation['summary']))
        parse(rows(before,proc,before,self.data['root']))
        denied=copy.deepcopy(proc);denied.update(count=0,errno=1,available=False,value=None)
        parse(rows(before,denied,before,self.data['denied']))
