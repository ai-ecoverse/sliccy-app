from contextlib import redirect_stderr
from pathlib import Path
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
import test_source
from test_source import module, ROOT
from types import SimpleNamespace

class ListingTests(unittest.TestCase):
    def fixture(self, root):
        app = test_source.Helper12Tests().fixture(root)
        listing = json.loads((ROOT/'Tests/Helper12Packaging/helper11-listing.json').read_text())
        self.assertEqual(listing['artifact'],13286983486)
        self.assertEqual(listing['innerSHA256'],'964c490824e573139c2f615f4674eea448717a9fe7b94f39feff5ec65b6565ba')
        self.assertEqual({row['relativePath'] for row in listing['rows']},{str(p.relative_to(app)) for p in app.rglob('*')})
        for row in listing['rows']:
            path = app/row['relativePath']
            mode = int(row['archiveMode'],8)
            self.assertIsNone(row['archiveNlink'])
            self.assertEqual(stat.S_ISDIR(mode),path.is_dir())
            path.chmod(stat.S_IMODE(mode))
            if path.is_file():
                self.assertEqual(row['retainedExtractionNlink'],1)
                self.assertEqual(path.stat().st_nlink,1)
        return app

    def check_failure(self, root, predicate, path):
        stream = io.StringIO()
        with redirect_stderr(stream):
            with self.assertRaisesRegex(ValueError,'helper12-'+predicate+':') as caught:
                module.manifest(root,'b'*40,'1','1')
        fields = json.loads(str(caught.exception).split(':',1)[1])
        self.assertEqual(fields,module.path_fields(path))
        lines = stream.getvalue().splitlines()
        self.assertTrue(lines,'ASSERTION:manifest-failure-listing')
        rows = [json.loads(line.removeprefix('helper12-bundle-entry ')) for line in lines]
        self.assertTrue(any(row['path']=='.' for row in rows))
        for row in rows:
            self.assertTrue({'path','type','nlink','mode','size'}<=row.keys())
            self.assertNotIn('\x1b',row['path'])
            self.assertLessEqual(len(row['path']),512)
        return rows

    def test_real_listing_four_files_and_stapler_order(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); self.fixture(root)
            try:
                result=module.manifest(root,'b'*40,'1','1')
            except ValueError as error:
                self.fail('ASSERTION:real-listing-four-files '+str(error))
            self.assertEqual(len(result['files']),4,'ASSERTION:real-listing-four-files')
            self.assertIn('Contents/CodeResources',result['files'])
            self.assertIn('Contents/_CodeSignature/CodeResources',result['files'])
        script=(ROOT/'script/sign_helper12.sh').read_text()
        self.assertLess(script.index('stapler validate "$signed_app"'),script.index('python3 -B script/helper12_manifest.py'))
        self.assertIn('set -euo pipefail',script)
        workflow=(ROOT/'.github/workflows/helper12-signing.yml').read_text()
        upload=workflow.split('      - name: Upload verified helper12 only',1)[1]
        self.assertNotIn('if:',upload)
        self.assertLess(workflow.index('run: ./script/ci_sign_helper12.sh'),workflow.index('      - name: Upload verified helper12 only'))

    def test_non_regular(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            path=app/'Contents/CodeResources'; path.unlink(); path.symlink_to('Info.plist')
            self.check_failure(root,'non-regular','Contents/CodeResources')

    def test_nlink(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            original=Path.lstat
            def link_count(path, *args, **kwargs):
                value=original(path,*args,**kwargs)
                if path==app/'Contents/CodeResources':
                    return SimpleNamespace(st_mode=value.st_mode,st_size=value.st_size,st_nlink=2)
                return value
            with patch.object(Path,'lstat',link_count):
                self.check_failure(root,'nlink','Contents/CodeResources')

    def test_unexpected_path(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            (app/'Contents/unexpected').write_bytes(b'fixture')
            self.check_failure(root,'unexpected-path','Contents/unexpected')

    def test_ticket_mode(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            (app/'Contents/CodeResources').chmod(0o644)
            self.check_failure(root,'ticket-mode','Contents/CodeResources')

    def test_missing_ticket(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            (app/'Contents/CodeResources').unlink()
            self.check_failure(root,'missing-ticket','Contents/CodeResources')

    def test_extra_directory(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            (app/'Contents/extra').mkdir()
            self.check_failure(root,'file-set','Contents/extra')

    def test_full_listing_on_metadata_failure_no_link_traversal(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value); app=self.fixture(root)
            outside=root/'outside'; outside.mkdir(); (outside/'not-listed').write_bytes(b'fixture')
            (app/'Contents/bad\n\x1b').symlink_to(outside,target_is_directory=True)
            rows=self.check_failure(root,'non-regular','Contents/bad\n\x1b')
            self.assertEqual(len(rows),9,'ASSERTION:complete-listing')
            self.assertFalse(any('not-listed' in row['path'] for row in rows))
            (app/'Contents/bad\n\x1b').unlink()
            (root/'notarization.json').write_text('{"status":"Rejected"}')
            stream=io.StringIO()
            with redirect_stderr(stream),self.assertRaisesRegex(ValueError,'helper12-notarization'):
                module.manifest(root,'b'*40,'1','1')
            self.assertEqual(len(stream.getvalue().splitlines()),8)

    def test_bounded_sanitized_paths(self):
        path='x'*600+'\n\x1b'
        fields=module.path_fields(path)
        self.assertEqual(len(fields['path']),512)
        self.assertTrue(fields['pathTruncated'])
        self.assertEqual(fields['pathSHA256'],hashlib.sha256(os.fsencode(path)).hexdigest())

if __name__=='__main__': unittest.main()
