#!/usr/bin/env python3
"""Bound the pinned SwiftPM binary download and seed its checksum-checked cache."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'https://github.com/sparkle-project/Sparkle'


def locked_sparkle(root):
    pins = [p for p in json.loads((root / 'Package.resolved').read_text())['pins'] if p['identity'] == 'sparkle']
    if len(pins) != 1 or pins[0]['location'] != REPOSITORY:
        raise ValueError('sparkle-lock-repository')
    version, revision = (pins[0]['state'][key] for key in ['version', 'revision'])
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('sparkle-lock-version-or-revision')
    if f'.package(url: "{REPOSITORY}", exact: "{version}")' not in (root / 'Package.swift').read_text():
        raise ValueError('sparkle-manifest-lock-mismatch')
    return version, revision


def artifact_pin(manifest, version):
    for field in ['version', 'tag']:
        if re.findall(rf'^let {field} = "([^"]+)"$', manifest, re.M) != [version]:
            raise ValueError('sparkle-upstream-version-mismatch')
    expected_url = REPOSITORY + '/releases/download/\\(tag)/Sparkle-for-Swift-Package-Manager.zip'
    if re.findall(r'^let url = "([^"]+)"$', manifest, re.M) != [expected_url]:
        raise ValueError('sparkle-upstream-url-mismatch')
    checksums = re.findall(r'^let checksum = "([0-9a-f]{64})"$', manifest, re.M)
    if len(checksums) != 1 or not re.search(r'\.binaryTarget\(\s*name: "Sparkle",\s*url: url,\s*checksum: checksum', manifest):
        raise ValueError('sparkle-upstream-checksum')
    return REPOSITORY + f'/releases/download/{version}/Sparkle-for-Swift-Package-Manager.zip', checksums[0]


def download(url, destination, seconds):
    subprocess.run(['/usr/bin/curl', '--fail', '--location', '--silent', '--show-error',
                    '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15',
                    '--max-time', str(seconds), '--output', str(destination), url],
                   check=True, timeout=seconds + 10)


def seed_cache(root, cache, fetch=download):
    version, revision = locked_sparkle(root)
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sliccy-sparkle-', dir=cache) as temporary:
        temporary = Path(temporary)
        manifest = temporary / 'Package.swift'
        fetch(f'https://raw.githubusercontent.com/sparkle-project/Sparkle/{revision}/Package.swift', manifest, 60)
        url, checksum = artifact_pin(manifest.read_text(), version)
        # SwiftPM BinaryArtifactsManager uses this C99-mangled URL cache key.
        destination = cache / re.sub(r'[^a-zA-Z0-9_]', '_', url)
        if destination.is_file() and hashlib.sha256(destination.read_bytes()).hexdigest() == checksum:
            print(f'Verified cached Sparkle {version}', flush=True)
            return destination
        archive = temporary / 'Sparkle.zip'
        print(f'Downloading pinned Sparkle {version} (300-second limit)', flush=True)
        fetch(url, archive, 300)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
            raise ValueError('sparkle-archive-checksum-mismatch')
        archive.replace(destination)
        print(f'Cached verified Sparkle {version}: {checksum}', flush=True)
        return destination


if __name__ == '__main__':
    seed_cache(ROOT, Path.home() / 'Library/Caches/org.swift.swiftpm/artifacts')
