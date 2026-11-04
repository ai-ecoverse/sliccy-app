from pathlib import Path
import hashlib
import json
import os
import plistlib
import shutil
import stat
import zipfile
import prerequisite_stage as stage
import capture_stage_root as boundary


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expectation(workspace):
    value = json.loads((workspace / 'script/runner-proof/prerequisite-artifact.json').read_text(), object_pairs_hook=boundary.unique_object)
    require(value['run'] == '41847302926' and value['artifact'] == '13331283695'
            and value['source'] == 'fa4ad8c65d47b075bbe0b96c20f920752108d732'
            and value['innerSHA256'] == '9198555bc50d455f4d9cdbcd9c79e30d4f38bfbe0c82db178b245a93ba58befe', 'artifact-binding')
    return value


def extract(archive, destination, expected, outer=False):
    require(digest(archive) == expected['outerSHA256' if outer else 'innerSHA256'], 'artifact-archive-hash')
    names = {'Sliccy-0.1.0.zip', 'SHA256SUMS', 'signing.txt', 'capture-manifest.json'} if outer else {
        'Sliccy.app/' + x for x in expected['files']} | {'Sliccy.app/'} | {'Sliccy.app/' + x + '/' for x in expected['directories']}
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as source:
        require(len(source.infolist()) == len(names) and {x.filename for x in source.infolist()} == names, 'artifact-archive-set')
        require(sum(x.file_size for x in source.infolist()) <= 128 * 1024 * 1024, 'artifact-archive-bound')
        for entry in source.infolist():
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFDIR, stat.S_IFREG), 'artifact-member-type')
            path = destination / entry.filename
            if entry.is_dir():
                require(not outer and stat.S_IMODE(mode) == 0o755, 'artifact-directory-mode')
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
                path.chmod(0o755)
            else:
                data = source.read(entry)
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                if not outer:
                    record = expected['files'][entry.filename.removeprefix('Sliccy.app/')]
                    require(len(data) == record['size'] and hashlib.sha256(data).hexdigest() == record['sha256']
                            and stat.S_IMODE(mode) == record['mode'], 'artifact-member-binding')
                with path.open('xb') as output:
                    output.write(data)
                path.chmod(0o600 if outer else stat.S_IMODE(mode))
    return destination


def signature(app, expected, checked):
    manifest = expected['manifest']
    helper = app / 'Contents/Helpers/ScreenProofSurface.app'
    for bundle, info, build in ((app, manifest, '12'), (helper, manifest['helpers']['ScreenProofSurface.app'], '11')):
        plist = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        require(plist['CFBundleIdentifier'] == info['identifier'] and plist['CFBundleVersion'] == build
                and plist['CFBundleShortVersionString'] == '0.1.0', 'artifact-plist')
        checked(['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=' + info['designatedRequirement'], str(bundle)])
        out, err = checked(['/usr/bin/codesign', '-d', '--verbose=4', str(bundle)])
        text = (out + err).decode('utf-8', 'strict')
        require('\nCDHash=' + info['executable']['CDHash'] + '\n' in '\n' + text
                and '\nTeamIdentifier=S8LB56P782\n' in '\n' + text and 'flags=0x10000(runtime)' in text, 'artifact-code-identity')
        entitlements, _ = checked(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(bundle)])
        require(plistlib.loads(entitlements) == {}, 'artifact-entitlements')
        architecture, _ = checked(['/usr/bin/lipo', '-archs', str(bundle / 'Contents/MacOS' / plist['CFBundleExecutable'])])
        require(architecture.strip() == b'arm64', 'artifact-architecture')
    refusal = checked(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + manifest['designatedRequirement'], str(helper)], expected_status=3)
    cli = app / 'Contents/Resources/slicc'
    checked(['/usr/bin/codesign', '--verify', '--all-architectures', '--strict', '-R', '=' + boundary.REQUIREMENT.replace('ai.sliccy.mac', 'ai.sliccy.slicc'), str(cli)])
    require(digest(cli) == manifest['resources']['slicc']['sha256'], 'artifact-cli')
    return refusal


def normalized(source, destination, expected, checked):
    require(not destination.exists() and not destination.is_symlink(), 'normalized-existing')
    stage.validate_tree(source, expected, owner=False)
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    normalized_expected = dict(expected, files={name: dict(row, mode=0o755 if row['mode'] & 0o111 else 0o644)
                                              for name, row in expected['files'].items()})
    for name in sorted(expected['directories'], key=lambda item: (item.count('/'), item)):
        path = destination / name
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    for name, row in normalized_expected['files'].items():
        original = source / name
        require(not original.is_symlink(), 'normalized-source-link')
        with original.open('rb') as src, (destination / name).open('xb') as target:
            shutil.copyfileobj(src, target)
        (destination / name).chmod(row['mode'])
    stage.validate_tree(destination, normalized_expected, owner=False)
    signature(destination, expected, checked)
    stage.validate_tree(source, expected, owner=False)
    return normalized_expected
