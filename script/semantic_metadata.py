#!/usr/bin/env python3
"""Generate ephemeral build metadata from semantic-release and the published feed."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from release_metadata import ROOT, configuration

SPARKLE = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'


def next_configuration(config, version, previous_tag, feed):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Only stable semantic versions can be published')
    previous_build = int(config['build'])
    if previous_tag:
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', previous_tag):
            raise ValueError('Invalid previous release tag')
        if tuple(map(int, version.split('.'))) <= tuple(map(int, previous_tag[1:].split('.'))):
            raise ValueError('Release version must increase')
        items = ET.fromstring(feed).findall('channel/item')
        if len(items) != 1 or items[0].findtext(SPARKLE + 'shortVersionString') != previous_tag[1:]:
            raise ValueError('Previous feed does not match the release tag')
        build = items[0].findtext(SPARKLE + 'version', '')
        if not re.fullmatch(r'[1-9][0-9]*', build):
            raise ValueError('Invalid previous Sparkle build')
        previous_build = max(previous_build, int(build))
    return {**config, 'version': version, 'build': str(previous_build + 1)}


def main():
    request = json.load(sys.stdin)
    previous_tag = request.get('previousTag')
    feed = None
    if previous_tag:
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', previous_tag):
            raise ValueError('Invalid previous release tag')
        with tempfile.TemporaryDirectory(prefix='sliccy-semantic-feed-') as directory:
            subprocess.run(['gh', 'release', 'download', previous_tag, '--repo',
                            'ai-ecoverse/sliccy-app', '--pattern', 'appcast.xml', '--dir', directory], check=True)
            feed = (Path(directory) / 'appcast.xml').read_bytes()
    config = next_configuration(configuration(), request['version'], previous_tag, feed)
    # Never commit generated metadata or add a second release commit.
    (ROOT / 'release/version.json').write_text(json.dumps(config, indent=2) + '\n')
    (ROOT / 'release/notes.md').write_text(request['notes'] + '\n')
    print(f'Sliccy {config["version"]}, Sparkle build {config["build"]}')


if __name__ == '__main__':
    main()
