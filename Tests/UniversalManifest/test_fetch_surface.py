from pathlib import Path
import hashlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'script'))
import fetch_surface as subject

class FetchSurfaceTests(unittest.TestCase):
    def archive(self, entries):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            for name,body,mode in entries:
                info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=mode<<16
                archive.writestr(info,body)
        return output.getvalue()

    def exercise(self, change=None):
        files={name:('fabricated '+name).encode() for name in subject.surface_pin.FILES}
        entries=[('ScreenProofSurface.app/'+name,body,stat.S_IFREG|0o600) for name,body in files.items()]
        if change=='missing-ticket':entries=[entry for entry in entries if not entry[0].endswith('/Contents/CodeResources')]
        if change=='unexpected':entries.append(('ScreenProofSurface.app/Contents/unexpected',b'x',stat.S_IFREG|0o600))
        if change=='symlink':entries[0]=(entries[0][0],entries[0][1],stat.S_IFLNK|0o777)
        if change=='changed-file':entries[0]=(entries[0][0],b'changed',entries[0][2])
        inner=self.archive(entries)
        outer=self.archive([('Sliccy-0.1.0.zip' if change=='old-layout' else 'ScreenProofSurface-0.1.0.zip',inner,stat.S_IFREG|0o600)])
        with tempfile.TemporaryDirectory() as value:
            root=Path(value).resolve()
            calls=[]
            def invoke(args,**kwargs):
                calls.append(args)
                self.assertEqual(args,['gh','api','repos/ai-ecoverse/sliccy-app/actions/artifacts/13392888076/zip'])
                kwargs['stdout'].write(outer)
                return subprocess.CompletedProcess(args,0)
            env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'ai-ecoverse/sliccy-app','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main'}
            with patch.dict(os.environ,env,clear=True),patch.object(subject,'__file__',str(root/'script/fetch_surface.py')),patch.object(subject.subprocess,'run',side_effect=invoke),patch.object(subject.surface_pin,'FILES',{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}),patch.object(subject.surface_pin,'ARCHIVE_SHA256','0'*64 if change=='outer-hash' else hashlib.sha256(outer).hexdigest()),patch.object(subject.surface_pin,'ZIP_SHA256','0'*64 if change=='inner-hash' else hashlib.sha256(inner).hexdigest()),patch.object(subject.surface_pin,'verify') as verify:
                if change:
                    with self.assertRaises(ValueError):subject.main()
                    verify.assert_not_called()
                else:
                    subject.main()
                    target=root/'.build/pinned-surface/ScreenProofSurface.app'
                    verify.assert_called_once_with(target)
                    self.assertEqual({str(p.relative_to(target)):p.read_bytes() for p in target.rglob('*') if p.is_file()},files)
                    for path in target.rglob('*'):
                        if path.is_file():
                            self.assertEqual(path.stat().st_nlink,1)
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700 if path.name=='ScreenProofSurface' else 0o600)
            self.assertEqual(len(calls),1)

    def test_standalone_four_file_fetch_enters_existing_verifier(self):
        self.exercise()

    def test_stale_layout_hash_or_member_refuses(self):
        for change in ['old-layout','outer-hash','inner-hash','missing-ticket','unexpected','symlink','changed-file']:
            with self.subTest(change=change):self.exercise(change)

    def test_pin_has_only_helper12_no_compatibility_alias(self):
        self.assertEqual((subject.surface_pin.RUN,subject.surface_pin.SOURCE,subject.surface_pin.ARTIFACT),('41978928697','4c873bab986e62f404255cc85e08d9dab52ead93','13392888076'))
        self.assertEqual(subject.surface_pin.CDHASH,'37517f1a6e6a0085f9188f3723ab6209fd131dfd')
        self.assertEqual(len(subject.surface_pin.FILES),4)
        self.assertEqual(subject.surface_pin.FILES['Contents/CodeResources'],'26ac87e435876410294563f19a3a0872668910af8c6640c7a03b8c61fb3f5188')

if __name__=='__main__':unittest.main()
