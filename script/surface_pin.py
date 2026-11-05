from pathlib import Path
import hashlib
import plistlib
import re
import stat
import subprocess
import sys

RUN = '41978928697'
SOURCE = '4c873bab986e62f404255cc85e08d9dab52ead93'
ARTIFACT = '13392888076'
ARCHIVE_SHA256 = '66d29c01db53f347dd74ad57cabcc0941aa02376054785cdbff11a1e89e1c907'
ZIP_SHA256 = '5e5e19d94c64b629b0f21a19c1015ab60ab0e5fa49a25595132c42d9bc57082f'
CDHASH = '37517f1a6e6a0085f9188f3723ab6209fd131dfd'
FILES = {
    'Contents/CodeResources': '26ac87e435876410294563f19a3a0872668910af8c6640c7a03b8c61fb3f5188',
    'Contents/Info.plist': '14f7874c0fe98de803e48c3945067f11e66d7ef2054a94798b70f4a723c4aa29',
    'Contents/MacOS/ScreenProofSurface': '85ef7c16e6542d94b26051ba1e04e6df12da7317923726943e4ff292c75a1e89',
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
