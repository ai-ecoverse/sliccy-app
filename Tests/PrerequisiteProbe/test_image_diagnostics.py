from pathlib import Path
from unittest import TestCase
import copy
import json
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
SCRIPTS=ROOT/'script/runner-proof'
sys.path.insert(0,str(SCRIPTS))
import prerequisite_image as image
import prerequisite_kernel as kernel


class ImageDiagnosticsTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();exe=Path(cls.temp.name)/'fixture'
        r=subprocess.run(['/usr/bin/clang','-fobjc-arc','-Wall','-Wextra','-Werror','-framework','Foundation','-I',str(SCRIPTS),
                          str(Path(__file__).with_name('image_fixture.m')),'-o',str(exe)],capture_output=True,timeout=30)
        if r.returncode:raise AssertionError(r.stderr.decode())
        cls.value=json.loads(subprocess.check_output([str(exe)],timeout=5))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def stream(self,phase,record):
        rows=[]
        if phase in image.PAIRED:rows.append(dict(schema=2,seq=1,phase=phase,state='entered',elapsedMs=0,facts={}))
        rows.append(dict(schema=2,seq=len(rows)+1,phase=phase,state='completed',elapsedMs=1,facts=record))
        rows.append(dict(schema=2,seq=len(rows)+1,phase='result',state='completed',elapsedMs=2,facts=dict(observed=False,reaped=False,rootGone=False)))
        self.assertEqual(kernel.parse(b''.join((json.dumps(x)+'\n').encode() for x in rows)),rows)

    def test_every_thin_fat32_fat64_and_endian_slice(self):
        self.assertEqual([len(x) for x in self.value['layouts']],[1,2,2,2,2])
        self.assertEqual(self.value['invalidLayouts'],6)
        for rows in self.value['layouts']:
            for row in rows:image.slice_row(row)
            self.assertEqual(rows[0]['cpuType'],0x0100000c)
        for rows in self.value['layouts'][1:]:self.assertEqual([x['offset'] for x in rows],[128,256])

    def test_live_full_set_hash_type(self):
        row=self.value['hashes'][0];image.hashes(row)
        self.assertEqual(row['uniqueHashTypes'],[1]);self.assertEqual(row['selectedHashType'],1)

    def test_static_full_set_hash_type(self):
        row=self.value['hashes'][1];image.hashes(row)
        self.assertEqual(row['uniqueHashTypes'],[2]);self.assertEqual(row['selectedHashType'],2)
        self.assertEqual([x['length'] for x in row['hashes']],[20,32])
        bad=copy.deepcopy(row);bad['hashes'][1]['length']=20
        with self.assertRaises(ValueError):image.hashes(bad)

    def test_kernel_full_set_matches_and_ambiguity(self):
        self.assertEqual(self.value['hashes'][1]['kernelHashTypes'],[1])
        self.assertEqual(self.value['hashes'][4]['kernelHashTypes'],[1,3])
        for row in self.value['hashes']:image.hashes(row)
        for row in self.value['hashes'][2:4]:self.assertEqual(row['status'],'unavailable')

    def test_hash_origin_each_slice_and_no_authority(self):
        for origin in ('guest-derived-static','pathname-default','pathname-slice'):
            row=dict(origin=origin,slice=self.value['layouts'][0][0] if origin=='pathname-slice' else None,
                     value=self.value['hashes'][0],codeOffset=dict(type='null',value=None),affectsVerdict=False)
            self.stream('image-hash-set',row)
            row['affectsVerdict']=True
            with self.assertRaises(ValueError):image.record('image-hash-set',row)

    def test_running_architecture_exact_size_and_unavailable(self):
        for row in self.value['architectures']:self.stream('image-architecture',row)
        self.assertEqual(self.value['architectures'][0]['cpuSubtype'],2)
        bad=dict(self.value['architectures'][1],cpuType=0)
        with self.assertRaises(ValueError):image.record('image-architecture',bad)

    def test_kernel_offset_success_and_failure(self):
        for status,offset in ((0,16384),(-1,None)):
            self.stream('image-kernel-offset',dict(status=status,errno=0 if status==0 else 1,offset=offset,affectsVerdict=False))
        with self.assertRaises(ValueError):image.record('image-kernel-offset',dict(status=-1,errno=1,offset=0,affectsVerdict=False))

    def test_live_pidpath_match_mismatch_unavailable(self):
        for count,path,match in ((40,'/System/WindowServer',True),(40,'/alternate/WindowServer',False),(0,None,None)):
            self.stream('image-live-path',dict(count=count,errno=0,path=path,matchesInput=match,affectsVerdict=False))
        with self.assertRaises(ValueError):image.record('image-live-path',dict(count=0,errno=1,path='/fake',matchesInput=True,affectsVerdict=False))

    def test_stable_file_slice_read_and_failed_read(self):
        for available in (True,False):
            self.stream('image-file-read',dict(affectsVerdict=False,stableFileSample=available,status='observed' if available else 'unavailable',
                                               slices=self.value['layouts'][0] if available else [],openStatus=0,openErrno=0,beforeStatStatus=0,afterStatStatus=0,
                                               readCount=32 if available else -1,readErrno=0 if available else 1,device=1,inode=2))

    def test_slice_create_validity_info_statuses(self):
        for phase in ('image-slice-create','image-slice-info'):
            for status,available in ((0,True),(-67050,False)):self.stream(phase,dict(status=status,available=available))
        for status in (0,-67050):self.stream('image-slice-validity',dict(status=status,affectsVerdict=False))

    def test_vnode_device_inode_differences_and_unavailable(self):
        for row in self.value['vnodes']:image.relation(row)
        self.assertEqual([x['same'] for x in self.value['vnodes']],[True,False,False,None,None])
        for row in self.value['vnodes']:
            bad=dict(row,same=1)
            with self.assertRaises(ValueError):image.relation(bad)

    def test_mapped_region_is_never_text_proof(self):
        for available in (True,False):
            row=dict(affectsVerdict=False,executableTextIdentityProven=False,count=248 if available else 0,expectedSize=248,errno=0 if available else 1,
                     status='observed' if available else 'unavailable',address=4096 if available else None,size=4096 if available else None,
                     fileOffset=0 if available else None,protection=5 if available else None,path='/System/WindowServer' if available else None,
                     sameExecutablePath=True if available else None,vnodeComparison=self.value['vnodes'][0 if available else 3])
            self.stream('image-region',row)
            with self.assertRaises(ValueError):image.record('image-region',dict(row,executableTextIdentityProven=True))
        self.stream('image-region-summary',dict(observed=0,end='unavailable',executableTextIdentityProven=False,affectsVerdict=False))
        self.stream('image-region-static-stat',dict(status=0,errno=0,device=1,inode=2))

    def test_mount_firmlink_boolean_unavailable_and_no_cryptex_inference(self):
        for status,flag in ((0,True),(0,False),(-1,None)):
            row=dict(affectsVerdict=False,cryptexMountProven=None,lstatStatus=status,statfsStatus=status,firmlinkMarker=flag,symlink=flag,
                     path='/System',lstatErrno=0,statfsErrno=0,device=1 if status==0 else None,inode=2 if status==0 else None,
                     fileFlags=0 if status==0 else None,linkCount=-1,linkErrno=0,linkTarget=None,mountFlags=0 if status==0 else None,
                     mountPoint='/' if status==0 else None,mountSource='snapshot' if status==0 else None,filesystem='apfs' if status==0 else None)
            self.stream('image-mount-component',row)
            with self.assertRaises(ValueError):image.record('image-mount-component',dict(row,firmlinkMarker=1))
        for total in (8,17):
            self.stream('image-mount-summary',dict(path='/System/WindowServer',components=total,observed=min(total,16),complete=total<=16,
                                                 firmlinkTraversalProven=None,cryptexTraversalProven=None,affectsVerdict=False))

    def test_native_scope_and_exact_original_guard(self):
        source=(SCRIPTS/'prerequisite_kernel.m').read_text();native=(SCRIPTS/'prerequisite_image_native.h').read_text()
        self.assertIn('if (!expected) imageDiagnostics(pid, requirement, a, b, path, kernelHash);',source)
        self.assertLess(source.index('imageDiagnostics(pid,'),source.index('require(kernelStatus == 0'))
        self.assertIn('SecStaticCodeCreateWithPathAndAttributes',native)
        self.assertNotIn('kSecCodeAttributeUniversalFileOffset',native)
        self.assertNotIn('posix_spawn',native);self.assertNotIn('sudo',native)
        self.assertNotIn('require(',native)
        self.assertIn('proc_pidinfo(pid,22,address,&region,sizeof(region))',native)
        self.assertIn('kSecCodeAttributeArchitecture:slice[@"cpuType"]',native)
