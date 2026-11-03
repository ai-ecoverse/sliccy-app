from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import sys
from snapshot_manifest import signature, RESOURCES
from universal_manifest import REQUIREMENT, checked


def manifest(app):
    plist = (app / 'Contents/Info.plist').read_bytes()
    info = plistlib.loads(plist)
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion']) != ('ai.sliccy.mac', '0.1.0', '9'):
        raise ValueError('wrong fixture identity')
    if (app / 'Contents/Helpers').exists() or {p.name for p in (app / 'Contents/Resources').iterdir()} != {'slicc'}:
        raise ValueError('unexpected fixture resources')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + REQUIREMENT, str(app)])
    executable, text = signature(app / 'Contents/MacOS/Sliccy', 'ai.sliccy.mac', 'arm64')
    if 'flags=0x10000(runtime)' not in text:
        raise ValueError('hardened runtime required')
    entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    if plistlib.loads(entitlements) != {}:
        raise ValueError('empty app entitlements required')
    resource, _ = signature(app / 'Contents/Resources/slicc', 'ai.sliccy.slicc', 'arm64')
    if resource['sha256'] != RESOURCES['slicc'][1] or resource['CDHash'] != RESOURCES['slicc'][2]:
        raise ValueError('changed release resource')
    source = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('source commit required')
    return {'schema': 1, 'sourceCommit': source, 'version': '0.1.0', 'build': '9',
            'identifier': 'ai.sliccy.mac', 'team': 'S8LB56P782', 'executable': executable,
            'emptyEntitlements': True, 'infoPlistSHA256': hashlib.sha256(plist).hexdigest(),
            'resources': {'slicc': resource}, 'case': 'pid-reuse-hosted', 'capture': False,
            'productionEnabled': False, 'nativeTrialsPerformed': False}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: hosted_pid_manifest.py APP NEW_MANIFEST')
    result = manifest(Path(sys.argv[1]))
    with Path(sys.argv[2]).open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
