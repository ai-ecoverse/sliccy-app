from pathlib import Path
import hashlib
import plistlib
import re
import stat
import subprocess
import sys

RUN = '41752885433'
SOURCE = '34fdccf5158e6e4e82d49b006857c6018433a8f2'
ARTIFACT = '13286983486'
ARCHIVE_SHA256 = 'c065f7f8b10672cdea7124872377c14e78eaf7cdb3e3151ff3014ac35fc88781'
ZIP_SHA256 = '964c490824e573139c2f615f4674eea448717a9fe7b94f39feff5ec65b6565ba'
CDHASH = '3e61ce8a28e4b7659f2e711f7fb752ce4935f256'
FILES = {
    'Contents/Info.plist': '11a51ca14176be56ce266330b5c15f8341301a5a9dab8f891765ac11b112e794',
    'Contents/MacOS/ScreenProofSurface': 'baff7b8b21264018138c9f7e2e7f6b8052bdcaf6e10b8ffa06dde854ac2b20c9',
    'Contents/_CodeSignature/CodeResources': '6686de10a28a2fe11b36cbb86dcbacc827cfc4ea116b4dabf1845e5aee629e9b'
}
REQUIREMENT = ('anchor apple generic and identifier "ai.sliccy.proof-helper" '
               'and certificate leaf[subject.OU] = "S8LB56P782" '
               'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
               'and certificate 1[field.1.2.840.113635.100.6.2.6] exists')


def verify(app):
    found = {}
    directories = set()
    for path in app.rglob('*'):
        value = path.lstat()
        if stat.S_ISDIR(value.st_mode):
            directories.add(path.relative_to(app).as_posix())
            continue
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ValueError('surface file type')
        found[path.relative_to(app).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if found != FILES or directories != {'Contents', 'Contents/MacOS', 'Contents/_CodeSignature'}:
        raise ValueError('surface immutable bytes')
    subprocess.run(['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + REQUIREMENT, str(app)],
                   capture_output=True, check=True, timeout=15)
    display = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', str(app)], capture_output=True, check=True, timeout=15)
    text = (display.stdout + display.stderr).decode()
    if re.findall(r'^CDHash=([0-9a-f]{40})$', text, re.M) != [CDHASH]:
        raise ValueError('surface CodeDirectory')
    entitlements = subprocess.run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(app)], capture_output=True, check=True, timeout=15)
    if plistlib.loads(entitlements.stdout) != {}:
        raise ValueError('surface entitlements')
    refusal = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=identifier "ai.sliccy.mac"', str(app)], capture_output=True, timeout=15)
    if refusal.returncode != 3:
        raise ValueError('surface app-role refusal')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(2)
    verify(Path(sys.argv[1]))
