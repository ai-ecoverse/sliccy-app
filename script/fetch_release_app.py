#!/usr/bin/env python3
"""Backfill a DMG from published signed bytes; never rebuild a released version."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import subprocess
import sys
import zipfile
from release_metadata import configuration

config = configuration()
version = config['version']
repo = 'ai-ecoverse/sliccy-app'
release = json.loads(subprocess.check_output(['gh','api',f'repos/{repo}/releases/tags/v{version}']))
if release['draft'] or release['prerelease']:
    raise ValueError('Expected published stable release')
name = f'Sliccy-{version}.zip'
assets = [a for a in release['assets'] if a['name'] == name]
if len(assets) != 1:
    raise ValueError('Expected exactly one published app ZIP')
asset = assets[0]
output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=False)
subprocess.run(['gh','release','download',f'v{version}','--repo',repo,'--pattern',name,'--dir',str(output)],check=True)
archive = output/name
if archive.stat().st_size != asset['size'] or asset.get('digest') != 'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest():
    raise ValueError('Published ZIP API digest/size mismatch')
with zipfile.ZipFile(archive) as z:
    for info in z.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or '..' in path.parts or path.parts[0] not in ('Sliccy.app','__MACOSX'):
            raise ValueError('Unexpected published ZIP path')
subprocess.run(['ditto','-x','-k',str(archive),str(output/'unpacked')],check=True)
app = output/'unpacked/Sliccy.app'
plist = plistlib.loads((app/'Contents/Info.plist').read_bytes())
if (plist['CFBundleIdentifier'],plist['CFBundleShortVersionString'],plist['CFBundleVersion']) != ('ai.sliccy.mac',version,config['build']):
    raise ValueError('Published app version/identity mismatch')
(output/'source-asset.json').write_text(json.dumps(asset,indent=2)+'\n')
print(f'Verified original published ZIP: {asset["digest"]}')
