from pathlib import Path
import surface_pin
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
    build = '14' if role == 'ai.sliccy.mac' else '12'
    plist = (app / 'Contents/Info.plist').read_bytes()
    info = plistlib.loads(plist)
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion'], info['CFBundleExecutable']) != (role, '0.1.0', build, name):
        raise ValueError('wrong fixture identity')
    checked(['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + REQUIREMENT.replace('ai.sliccy.mac', role), str(app)])
    executable, text = signature(app / 'Contents/MacOS' / name, role, 'arm64')
    if 'flags=0x10000(runtime)' not in text:
        raise ValueError('hardened runtime required')
    entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    if plistlib.loads(entitlements) != {}:
        raise ValueError('empty entitlements required')
    output, error = checked(['/usr/bin/codesign', '-d', '-r-', str(app)])
    designated = re.findall(r'^designated => (.+)$', (output + error).decode('utf-8', 'strict'), re.M)
    if len(designated) != 1 or len(designated[0]) > 4096:
        raise ValueError('designated requirement unavailable')
    return {'identifier': role, 'team': 'S8LB56P782', 'executable': executable,
            'emptyEntitlements': True, 'infoPlistSHA256': hashlib.sha256(plist).hexdigest(),
            'designatedRequirement': designated[0]}


def manifest(app):
    if any(p.is_symlink() for p in app.rglob('*')):
        raise ValueError('unexpected symbolic link')
    if {p.name for p in (app / 'Contents/Helpers').iterdir()} != {'ScreenProofSurface.app'} or {p.name for p in (app / 'Contents/Resources').iterdir()} != {'slicc'}:
        raise ValueError('unexpected fixture resources')
    value = signed_bundle(app, 'ai.sliccy.mac', 'Sliccy')
    helper = app / 'Contents/Helpers/ScreenProofSurface.app'
    if {p.name for p in (helper / 'Contents').iterdir()} != {'MacOS', 'Info.plist', '_CodeSignature', 'CodeResources'} or {p.name for p in (helper / 'Contents/MacOS').iterdir()} != {'ScreenProofSurface'}:
        raise ValueError('unexpected helper contents')
    surface_pin.verify(helper)
    surface = signed_bundle(helper, 'ai.sliccy.proof-helper', 'ScreenProofSurface')
    refusal = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + REQUIREMENT, str(helper)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if refusal.returncode != 3:
        raise ValueError('helper app-role refusal absent')
    surface['appRoleRefused'] = True
    surface['immutableArtifact'] = {'run': surface_pin.RUN, 'source': surface_pin.SOURCE, 'artifact': surface_pin.ARTIFACT, 'files': surface_pin.FILES}
    resource, _ = signature(app / 'Contents/Resources/slicc', 'ai.sliccy.slicc', 'arm64')
    if resource['sha256'] != RESOURCES['slicc'][1] or resource['CDHash'] != RESOURCES['slicc'][2]:
        raise ValueError('changed release resource')
    source = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('source commit required')
    return dict(value, schema=1, sourceCommit=source, version='0.1.0', build='14',
                resources={'slicc': resource}, helpers={'ScreenProofSurface.app': surface}, cases=CASES,
                hostedOnly=True, productionEnabled=False, nativeTrialsPerformed=False)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: capture_manifest.py APP NEW_MANIFEST')
    result = manifest(Path(sys.argv[1]))
    with Path(sys.argv[2]).open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
