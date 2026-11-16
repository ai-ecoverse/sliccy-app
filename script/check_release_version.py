#!/usr/bin/env python3
import json
import re
import sys
import subprocess
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
from release_metadata import configuration

config = configuration()
# gh --paginate emits one JSON array per page.
text = open(sys.argv[1]).read().strip()
releases = []
while text:
    page, end = json.JSONDecoder().raw_decode(text)
    releases.extend(page)
    text = text[end:].lstrip()
current = tuple(map(int, config['version'].split('.')))
for release in releases:
    if release['tag_name'] == 'v' + config['version']:
        if release.get('draft'):
            raise SystemExit('Release draft already exists; inspect it before publishing.')
        names = [a['name'] for a in release.get('assets', [])]
        dmg = f'Sliccy-{config["version"]}.dmg'
        present = dmg in names
        if not present and 'DMG-SHA256SUMS' in names:
            raise SystemExit('Partial DMG publication; inspect existing assets.')
        print('package_dmg=' + ('false' if present else 'true'))
        print('publish=false')
        break
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', release['tag_name'])
    if match and not release.get('prerelease') and tuple(map(int, match.groups())) >= current:
        raise SystemExit('Release version must increase.')
else:
    stable = [r for r in releases if re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name']) and not r.get('draft') and not r.get('prerelease')]
    if stable:
        previous = max(stable, key=lambda r: tuple(map(int, r['tag_name'][1:].split('.'))))
        with tempfile.TemporaryDirectory(prefix='sliccy-previous-feed-') as d:
            subprocess.run(['gh', 'release', 'download', previous['tag_name'], '--repo', 'ai-ecoverse/sliccy-app', '--pattern', 'appcast.xml', '--dir', d], check=True)
            root = ET.fromstring((Path(d)/'appcast.xml').read_bytes())
            builds = [int(x.text) for x in root.findall('.//{http://www.andymatuschak.org/xml-namespaces/sparkle}version')]
            if not builds or int(config['build']) <= max(builds):
                raise SystemExit('Release build must increase beyond the published appcast.')
    print('publish=true')
