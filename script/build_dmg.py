#!/usr/bin/env python3
"""Package an already signed app without altering its contents."""
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile


def bundle_files(root):
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if path.is_symlink():
                result[relative] = ('link', os.readlink(path))
            elif path.is_file():
                result[relative] = ('file', hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def verify(dmg, app):
    with tempfile.TemporaryDirectory(prefix='sliccy-dmg-mount-') as d:
        mount = Path(d) / 'volume'
        subprocess.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(dmg)], check=True, stdout=subprocess.DEVNULL)
        try:
            if not (mount/'Applications').is_symlink() or os.readlink(mount/'Applications') != '/Applications':
                raise ValueError('DMG Applications shortcut missing')
            if bundle_files(app) != bundle_files(mount/'Sliccy.app'):
                raise ValueError('DMG app differs from signed input')
            subprocess.run(['codesign','--verify','--deep','--strict',str(mount/'Sliccy.app')],check=True)
        finally:
            subprocess.run(['hdiutil','detach',str(mount)],check=True,stdout=subprocess.DEVNULL)
    print('DMG verified: unchanged signed app and Applications shortcut.')


def build(app, dmg):
    if dmg.exists():
        raise ValueError('DMG output already exists')
    plist = plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if plist['CFBundleIdentifier'] != 'ai.sliccy.mac':
        raise ValueError('Unexpected app identifier')
    subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
    with tempfile.TemporaryDirectory(prefix='sliccy-dmg-') as d:
        staging = Path(d)/'contents'
        staging.mkdir()
        subprocess.run(['ditto',str(app),str(staging/'Sliccy.app')],check=True)
        (staging/'Applications').symlink_to('/Applications', target_is_directory=True)
        subprocess.run(['hdiutil','create','-volname','Sliccy','-srcfolder',str(staging),'-format','UDZO','-fs','HFS+',str(dmg)],check=True)
    verify(dmg,app)

if __name__ == '__main__':
    build(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
