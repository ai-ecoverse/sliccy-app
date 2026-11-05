from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import stat

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    'Tests/NativeCaptureSurface/surface-app.swift':'f9ba2d6a1f1e8d31f1b4e90ff78afbf609ee7ad788660a2ea1ca51d051e882d8',
    'Tests/NativeCaptureSurface/surface-presence.swift':'00da5e062f53f31ff81c899b6f957b9c8a5480574bb5b1534d58e845423a49e5',
    'Tests/NativeCaptureSurface/presence-tests.swift':'1dc096704240c1b87611aba6b9321d90619444a1fc9359b111f9cd15e5921bf9',
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def manifest(directory, source, run, attempt):
    app = directory / 'ScreenProofSurface.app'
    expected = {'Contents/Info.plist','Contents/MacOS/ScreenProofSurface','Contents/_CodeSignature/CodeResources'}
    files = {}
    directories = set()
    for path in app.rglob('*'):
        value = path.lstat()
        relative = path.relative_to(app).as_posix()
        if stat.S_ISDIR(value.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or relative not in expected:
            raise ValueError('helper12-file-type-or-name')
        files[relative] = digest(path)
    if set(files) != expected or directories != {'Contents','Contents/MacOS','Contents/_CodeSignature'}:
        raise ValueError('helper12-file-set')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if (info.get('CFBundleIdentifier'),info.get('CFBundleVersion'),info.get('CFBundleShortVersionString'),info.get('CFBundleExecutable')) != ('ai.sliccy.proof-helper','12','0.1.0','ScreenProofSurface'):
        raise ValueError('helper12-plist')
    if plistlib.loads((directory / 'entitlements.plist').read_bytes()) != {}:
        raise ValueError('helper12-entitlements')
    signing = (directory / 'signing.txt').read_text()
    hashes = re.findall(r'^CDHash=([0-9a-f]{40})$',signing,re.M)
    if len(hashes) != 1 or re.findall(r'^Identifier=(.+)$',signing,re.M) != ['ai.sliccy.proof-helper'] or re.findall(r'^TeamIdentifier=(.+)$',signing,re.M) != ['S8LB56P782'] or not re.search(r'^CodeDirectory .*flags=.*\bruntime\b',signing,re.M):
        raise ValueError('helper12-signing-metadata')
    if json.loads((directory / 'notarization.json').read_text()).get('status') != 'Accepted':
        raise ValueError('helper12-notarization')
    if not re.fullmatch('[0-9a-f]{40}',source) or not run.isdecimal() or attempt != '1':
        raise ValueError('helper12-run-source')
    return {'schema':1,'sourceCommit':source,'run':run,'attempt':1,'identifier':'ai.sliccy.proof-helper','version':'0.1.0','build':'12',
        'team':'S8LB56P782','architectures':['arm64'],'runtime':True,'entitlements':{},'appRoleRefused':True,
        'appRoleRefusalExit':3,'cdhash':hashes[0],'files':files,'archive':'ScreenProofSurface-0.1.0.zip',
        'archiveSHA256':digest(directory / 'ScreenProofSurface-0.1.0.zip'),'sources':SOURCES,
        'scope':'Static distribution/role binding only; helper not launched, no presence/capture claim.'}

def main():
    required={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'ai-ecoverse/sliccy-app','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/proof/helper12-signing-v1','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'macOS','RUNNER_ARCH':'ARM64'}
    if not all(os.environ.get(k)==v for k,v in required.items()):
        raise ValueError('helper12-hosted-guard')
    for name, expected in SOURCES.items():
        if digest(ROOT / name) != expected:
            raise ValueError('helper12-source-binding')
    directory = ROOT / 'artifacts/helper12'
    value = manifest(directory,os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'])
    (directory / 'helper-manifest.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

if __name__ == '__main__':
    main()
