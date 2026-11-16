import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'script'))
from cache_sparkle import seed_cache, REPOSITORY


class SparkleCacheTests(unittest.TestCase):
    def test_exact_revision_checksum_and_cached_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Package.swift').write_text(f'.package(url: "{REPOSITORY}", exact: "2.10.1")')
            revision = 'a' * 40
            (root / 'Package.resolved').write_text(json.dumps({'pins': [{'identity': 'sparkle', 'location': REPOSITORY,
                'state': {'version': '2.10.1', 'revision': revision}}]}))
            payload = b'fabricated binary artifact'
            manifest = ('let version = "2.10.1"\nlet tag = "2.10.1"\n'
                f'let checksum = "{hashlib.sha256(payload).hexdigest()}"\n'
                f'let url = "{REPOSITORY}/releases/download/\\(tag)/Sparkle-for-Swift-Package-Manager.zip"\n'
                '.binaryTarget(name: "Sparkle", url: url, checksum: checksum)')
            calls = []
            def fetch(url, destination, seconds):
                calls.append((url, seconds))
                destination.write_bytes(manifest.encode() if url.endswith('Package.swift') else payload)
            cache = root / 'cache'
            artifact = seed_cache(root, cache, fetch)
            self.assertEqual(artifact.read_bytes(), payload)
            self.assertEqual(calls[0], (f'https://raw.githubusercontent.com/sparkle-project/Sparkle/{revision}/Package.swift', 60))
            self.assertEqual(calls[1][1], 300)
            self.assertEqual(artifact.name, 'https___github_com_sparkle_project_Sparkle_releases_download_2_10_1_Sparkle_for_Swift_Package_Manager_zip')
            calls.clear()
            seed_cache(root, cache, fetch)
            self.assertEqual(len(calls), 1)
            artifact.unlink()
            def corrupt(url, destination, seconds):
                fetch(url, destination, seconds)
                if not url.endswith('Package.swift'):
                    destination.write_bytes(b'corrupted download')
            with self.assertRaisesRegex(ValueError, 'archive-checksum-mismatch'):
                seed_cache(root, cache, corrupt)
            self.assertFalse(artifact.exists())
            manifest = manifest.replace('let tag = "2.10.1"', 'let tag = "2.10.2"')
            with self.assertRaisesRegex(ValueError, 'upstream-version-mismatch'):
                seed_cache(root, cache, fetch)
