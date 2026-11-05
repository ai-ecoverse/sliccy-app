from contextlib import redirect_stderr
from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
import test_source
import test_manifest_listing

SOURCE = test_source.ROOT/'script/helper12_manifest.py'
MUTATIONS = [
    ('non-regular','if not stat.S_ISREG(value.st_mode):','if False:','test_non_regular'),
    ('nlink','if value.st_nlink != 1:','if False:','test_nlink'),
    ('unexpected-path','if relative not in expected:','if False:','test_unexpected_path'),
    ('ticket-mode',"if relative == 'Contents/CodeResources' and stat.S_IMODE(value.st_mode) != 0o600:",'if False:','test_ticket_mode'),
    ('missing-ticket',"if 'Contents/CodeResources' not in files:",'if False:','test_missing_ticket'),
    ('file-set',"if set(files) != expected or directories != {'Contents','Contents/MacOS','Contents/_CodeSignature'}:",'if False:','test_extra_directory'),
    ('ticket-path-rollback',"'Contents/_CodeSignature/CodeResources','Contents/CodeResources'","'Contents/_CodeSignature/CodeResources'",'test_real_listing_four_files_and_stapler_order'),
    ('failure-listing',"for row in bundle_listing(directory / 'ScreenProofSurface.app'):",'for row in []:','test_non_regular'),
    ('path-bound',"'path':encoded[:512]","'path':encoded",'test_bounded_sanitized_paths'),
]

def run(suite):
    stream=io.StringIO()
    with redirect_stderr(stream):
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    return result,stream.getvalue()

def main(destination):
    destination.mkdir(mode=0o700)
    original=SOURCE.read_bytes()
    original_module=test_source.module
    records=[]
    def full():
        return unittest.defaultTestLoader.discover(str(Path(__file__).parent))
    with patch.object(subprocess,'Popen',side_effect=AssertionError('unmocked-subprocess')),patch('os.system',side_effect=AssertionError('unmocked-system')):
        baseline,log=run(full());(destination/'baseline.log').write_text(log)
        assert baseline.wasSuccessful()
        for name,old,new,target in MUTATIONS:
            source=original.decode();assert source.count(old)==1,(name,'match-count')
            mutated=types.ModuleType('helper12_manifest_mutant');mutated.__file__=str(SOURCE)
            exec(compile(source.replace(old,new),str(SOURCE),'exec'),mutated.__dict__)
            test_source.module=mutated;test_manifest_listing.module=mutated
            result,log=run(unittest.TestSuite([test_manifest_listing.ListingTests(target)]))
            (destination/(name+'-mutant.log')).write_text(log)
            assert len(result.failures)==1 and not result.errors,(name,'not-runtime-assertion',log)
            assert target in log and 'AssertionError' in log
            test_source.module=original_module;test_manifest_listing.module=original_module
            restored,log=run(full());(destination/(name+'-restored.log')).write_text(log)
            assert restored.wasSuccessful()
            assert SOURCE.read_bytes()==original
            records.append({'name':name,'test':target,'compile':0,'runtimeFailures':len(result.failures),'runtimeErrors':len(result.errors),'restoredTests':restored.testsRun,'restoredPass':True})
    report={'sourceSHA256':hashlib.sha256(original).hexdigest(),'baselineTests':baseline.testsRun,'mutations':records,'diskUnchanged':SOURCE.read_bytes()==original,'subprocessesBlocked':True}
    (destination/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__': main(Path(sys.argv[1]))
