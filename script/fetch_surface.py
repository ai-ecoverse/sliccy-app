from pathlib import Path
import hashlib
import io
import os
import stat
import subprocess
import zipfile

import surface_pin


def main():
    required = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main'}
    if not all(os.environ.get(key) == value for key, value in required.items()):
        raise ValueError('guarded main CI only')
    root = Path(__file__).resolve().parent.parent
    download = root / '.build/pinned-surface-download'
    download.mkdir(parents=True, exist_ok=False)
    archive = download / 'artifact.zip'
    with archive.open('xb') as output:
        subprocess.run(['gh', 'api', 'repos/ai-ecoverse/sliccy-app/actions/artifacts/' + surface_pin.ARTIFACT + '/zip'],
                       stdout=output, stderr=subprocess.PIPE, check=True, timeout=90)
    if archive.stat().st_size > 128 * 1024 * 1024 or hashlib.sha256(archive.read_bytes()).hexdigest() != surface_pin.ARCHIVE_SHA256:
        raise ValueError('surface artifact checksum')
    with zipfile.ZipFile(archive) as outer:
        matches = [entry for entry in outer.infolist() if entry.filename == 'ScreenProofSurface-0.1.0.zip']
        if len(matches) != 1 or matches[0].file_size > 128 * 1024 * 1024:
            raise ValueError('surface artifact layout')
        data = outer.read(matches[0])
    if hashlib.sha256(data).hexdigest() != surface_pin.ZIP_SHA256:
        raise ValueError('surface signed archive checksum')
    target = root / '.build/pinned-surface/ScreenProofSurface.app'
    target.mkdir(parents=True, exist_ok=False)
    prefix = 'ScreenProofSurface.app/'
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        for entry in bundle.infolist():
            if not entry.filename.startswith(prefix) or entry.is_dir():
                continue
            relative = entry.filename[len(prefix):]
            mode = entry.external_attr >> 16
            if relative not in surface_pin.FILES or relative in seen or not stat.S_ISREG(mode) or entry.file_size > 16 * 1024 * 1024:
                raise ValueError('surface archive member')
            body = bundle.read(entry)
            if hashlib.sha256(body).hexdigest() != surface_pin.FILES[relative]:
                raise ValueError('surface member checksum')
            seen.add(relative)
            path = target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as output:
                output.write(body)
            path.chmod(0o700 if relative == 'Contents/MacOS/ScreenProofSurface' else 0o600)
    if seen != set(surface_pin.FILES):
        raise ValueError('surface missing members')
    surface_pin.verify(target)


if __name__ == '__main__':
    main()
