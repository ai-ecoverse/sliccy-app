
from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import sys

CPUS = {0x0100000C: 'arm64', 0x01000007: 'x86_64'}
CLI_SHA256 = '0055c051f48364dbf6d3744c637a06353305a392d06edbedd96bd6764adb5a73'
REQUIREMENT = ('anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
               'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
               'and certificate leaf[subject.OU] = "S8LB56P782" and identifier "ai.sliccy.mac"')


def slices(data):
    if not 48 <= len(data) <= 128 * 1024 * 1024:
        raise ValueError('binary size')
    magic, count = struct.unpack_from('>II', data)
    if magic not in (0xCAFEBABE, 0xCAFEBABF) or count != 2:
        raise ValueError('exactly two universal slices required')
    wide = magic == 0xCAFEBABF
    entry_size = 32 if wide else 20
    table_end = 8 + count * entry_size
    if table_end > len(data):
        raise ValueError('truncated fat table')
    result = []
    for i in range(count):
        values = struct.unpack_from('>IIQQII' if wide else '>IIIII', data, 8 + i * entry_size)
        cpu, subtype, offset, size, alignment = values[:5]
        if wide and values[5] != 0:
            raise ValueError('reserved fat field')
        if cpu not in CPUS or cpu in [r['cpuType'] for r in result]:
            raise ValueError('unexpected or duplicate architecture')
        if alignment > 30 or offset % (1 << alignment) or offset < table_end or size < 32 or offset > len(data) or size > len(data) - offset:
            raise ValueError('invalid slice range')
        if any(offset < r['offset'] + r['size'] and r['offset'] < offset + size for r in result):
            raise ValueError('overlapping slices')
        header = struct.unpack_from('<IIIIIIII', data, offset)
        if header[0] != 0xFEEDFACF or (header[1], header[2]) != (cpu, subtype) or header[3] != 2:
            raise ValueError('slice header mismatch')
        if header[4] > 4096 or header[5] > 1024 * 1024 or header[5] > size - 32:
            raise ValueError('load commands outside slice')
        cursor = offset + 32
        command_end = cursor + header[5]
        signatures = 0
        for _ in range(header[4]):
            if cursor + 8 > command_end:
                raise ValueError('truncated load command')
            command, length = struct.unpack_from('<II', data, cursor)
            if length < 8 or length % 8 or length > command_end - cursor:
                raise ValueError('invalid command size')
            if command == 0x1D:
                if length != 16:
                    raise ValueError('invalid signature command')
                start, length_on_disk = struct.unpack_from('<II', data, cursor + 8)
                if start < 32 + header[5] or length_on_disk < 12 or start > size or length_on_disk > size - start:
                    raise ValueError('signature outside slice')
                signatures += 1
            cursor += length
        if cursor != command_end or signatures != 1:
            raise ValueError('missing/duplicate signature command')
        result.append({'architecture': CPUS[cpu], 'cpuType': cpu, 'cpuSubtype': subtype,
                       'offset': offset, 'size': size, 'alignmentExponent': alignment})
    return sorted(result, key=lambda row: row['architecture'])


def checked(args):
    completed = subprocess.run(args, capture_output=True, check=True)
    return completed.stdout, completed.stderr


def manifest(app):
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    if (info['CFBundleIdentifier'], info['CFBundleShortVersionString'], info['CFBundleVersion']) != ('ai.sliccy.mac', '0.1.0', '7'):
        raise ValueError('unexpected universal fixture identity')
    if (app / 'Contents/Helpers').exists():
        raise ValueError('universal fixture must have no helpers')
    executable = app / 'Contents/MacOS/Sliccy'
    data = executable.read_bytes()
    rows = slices(data)
    cli = app / 'Contents/Resources/slicc'
    if hashlib.sha256(cli.read_bytes()).hexdigest() != CLI_SHA256:
        raise ValueError('CLI must be unchanged released arm64 bytes')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', '-R', '=' + REQUIREMENT, str(app)])
    for row in rows:
        arch = row['architecture']
        checked(['/usr/bin/codesign', '--verify', '--strict', '--architecture', arch, '-R', '=' + REQUIREMENT, str(app)])
        out, err = checked(['/usr/bin/codesign', '-d', '--architecture', arch, '--verbose=4', str(app)])
        signature = (out + err).decode()
        if 'TeamIdentifier=S8LB56P782' not in signature or 'flags=0x10000(runtime)' not in signature:
            raise ValueError('signature policy')
        cdhash = re.findall(r'^CDHash=([0-9a-f]{40})$', signature, re.M)
        full = re.findall(r'^CandidateCDHashFull sha256=([0-9a-f]{64})$', signature, re.M)
        if len(cdhash) != 1 or len(full) != 1 or cdhash[0] != full[0][:40]:
            raise ValueError('ambiguous CodeDirectory identity')
        entitlements, _ = checked(['/usr/bin/codesign', '-d', '--architecture', arch, '--entitlements', ':-', str(app)])
        if plistlib.loads(entitlements) != {}:
            raise ValueError('unexpected entitlement')
        row.update(CDHash=cdhash[0], codeDirectorySHA256=full[0], emptyEntitlements=True)
    if rows[0]['CDHash'] == rows[1]['CDHash']:
        raise ValueError('slice identities must differ')
    source = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('source commit required')
    return {'schema': 1, 'sourceCommit': source, 'identifier': 'ai.sliccy.mac', 'team': 'S8LB56P782',
            'version': '0.1.0', 'build': '7', 'executableSHA256': hashlib.sha256(data).hexdigest(),
            'infoPlistSHA256': hashlib.sha256((app / 'Contents/Info.plist').read_bytes()).hexdigest(),
            'slices': rows, 'bundledCLI': {'version': '1.59.0', 'architecture': 'arm64', 'sha256': CLI_SHA256,
                                        'CDHash': '5da1a3199bd3f895bce2e53023c28ca1c33d249e'},
            'productionEnabled': False, 'nativeTrialsPerformed': False}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: universal_manifest.py APP NEW_MANIFEST')
    result = manifest(Path(sys.argv[1]))
    with Path(sys.argv[2]).open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
