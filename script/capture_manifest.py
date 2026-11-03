from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from snapshot_manifest import signature, RESOURCES
from universal_manifest import REQUIREMENT, checked

CASES = ['selected-window', 'display-exclusion', 'authorization-exclusion', 'reciprocal-revoke', 'active-stop', 'hotkey-stop']


def signed_bundle(app, role, name):
    plist = (app / 'Contents/Info.plist').read_bytes()
    info = plistlib.loads(plist)
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion'], info['CFBundleExecutable']) != (role, '0.1.0', '11', name):
        raise ValueError('wrong fixture identity')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + REQUIREMENT.replace('ai.sliccy.mac', role), str(app)])
    executable, text = signature(app / 'Contents/MacOS' / name, role, 'arm64')
    if 'flags=0x10000(runtime)' not in text:
        raise ValueError('hardened runtime required')
    entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    if plistlib.loads(entitlements) != {}:
        raise ValueError('empty entitlements required')
    return {'identifier': role, 'team': 'S8LB56P782', 'executable': executable,
            'emptyEntitlements': True, 'infoPlistSHA256': hashlib.sha256(plist).hexdigest()}


def manifest(app):
    if any(p.is_symlink() for p in app.rglob('*')):
        raise ValueError('unexpected symbolic link')
    if {p.name for p in (app / 'Contents/Helpers').iterdir()} != {'ScreenProofSurface.app'} or {p.name for p in (app / 'Contents/Resources').iterdir()} != {'slicc'}:
        raise ValueError('unexpected fixture resources')
    value = signed_bundle(app, 'ai.sliccy.mac', 'Sliccy')
    helper = app / 'Contents/Helpers/ScreenProofSurface.app'
    if {p.name for p in (helper / 'Contents').iterdir()} != {'MacOS', 'Info.plist', '_CodeSignature'} or {p.name for p in (helper / 'Contents/MacOS').iterdir()} != {'ScreenProofSurface'}:
        raise ValueError('unexpected helper contents')
    surface = signed_bundle(helper, 'ai.sliccy.proof-helper', 'ScreenProofSurface')
    refusal = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + REQUIREMENT, str(helper)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if refusal.returncode != 3:
        raise ValueError('helper app-role refusal absent')
    surface['appRoleRefused'] = True
    resource, _ = signature(app / 'Contents/Resources/slicc', 'ai.sliccy.slicc', 'arm64')
    if resource['sha256'] != RESOURCES['slicc'][1] or resource['CDHash'] != RESOURCES['slicc'][2]:
        raise ValueError('changed release resource')
    source = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('source commit required')
    return dict(value, schema=1, sourceCommit=source, version='0.1.0', build='11',
                resources={'slicc': resource}, helpers={'ScreenProofSurface.app': surface}, cases=CASES,
                hostedOnly=True, productionEnabled=False, nativeTrialsPerformed=False)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: capture_manifest.py APP NEW_MANIFEST')
    result = manifest(Path(sys.argv[1]))
    with Path(sys.argv[2]).open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
