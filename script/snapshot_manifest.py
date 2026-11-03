"""Static manifest for the closed disposable-snapshot fixture. Never executes it."""
from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from universal_manifest import REQUIREMENT, checked

RESOURCES = {
    'slicc': ('arm64', '0055c051f48364dbf6d3744c637a06353305a392d06edbedd96bd6764adb5a73', '5da1a3199bd3f895bce2e53023c28ca1c33d249e'),
    'slicc-snapshot-amd64': ('x86_64', '9ff520697095ce930cc25d4a5e208a72eb82a072211fd7b9bbd6da2b9b78278e', 'bf246edfa276fa4242db674e139a872270633673'),
}


def signature(path, identifier, arch):
    checked(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + REQUIREMENT.replace('ai.sliccy.mac', identifier), str(path)])
    out, _ = checked(['/usr/bin/lipo', '-archs', str(path)])
    if out.decode().strip() != arch:
        raise ValueError('wrong architecture')
    out, err = checked(['/usr/bin/codesign', '-d', '--verbose=4', str(path)])
    text = (out + err).decode()
    hashes = re.findall(r'^CDHash=([0-9a-f]{40})$', text, re.M)
    full = re.findall(r'^CandidateCDHashFull sha256=([0-9a-f]{64})$', text, re.M)
    if len(hashes) != 1 or len(full) != 1 or hashes[0] != full[0][:40] or 'TeamIdentifier=S8LB56P782' not in text:
        raise ValueError('ambiguous signature identity')
    return {'architecture': arch, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'CDHash': hashes[0], 'codeDirectorySHA256': full[0]}, text


def manifest(app):
    plist = (app / 'Contents/Info.plist').read_bytes()
    info = plistlib.loads(plist)
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion']) != ('ai.sliccy.mac', '0.1.0', '8'):
        raise ValueError('wrong fixture identity')
    if (app / 'Contents/Helpers').exists():
        raise ValueError('snapshot fixture has no helpers')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '-R', '=' + REQUIREMENT, str(app)])
    executable, text = signature(app / 'Contents/MacOS/Sliccy', 'ai.sliccy.mac', 'arm64')
    if 'flags=0x10000(runtime)' not in text:
        raise ValueError('hardened runtime required')
    entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)])
    if plistlib.loads(entitlements) != {}:
        raise ValueError('empty app entitlements required')
    resources = {}
    for name, (arch, digest, cdhash) in RESOURCES.items():
        result, _ = signature(app / 'Contents/Resources' / name, 'ai.sliccy.slicc', arch)
        if result['sha256'] != digest or result['CDHash'] != cdhash:
            raise ValueError('changed release resource')
        resources[name] = result
    source = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('source commit required')
    return {'schema': 1, 'sourceCommit': source, 'version': '0.1.0', 'build': '8',
            'identifier': 'ai.sliccy.mac', 'team': 'S8LB56P782', 'executable': executable,
            'emptyEntitlements': True, 'infoPlistSHA256': hashlib.sha256(plist).hexdigest(),
            'resources': resources, 'productionEnabled': False, 'nativeTrialsPerformed': False}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: snapshot_manifest.py APP NEW_MANIFEST')
    result = manifest(Path(sys.argv[1]))
    with Path(sys.argv[2]).open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
