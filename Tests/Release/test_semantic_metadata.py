import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
from release_metadata import configuration
from semantic_metadata import next_configuration


def feed(version='7.1.0', build='70100'):
    return f'''<rss xmlns:s="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
      <s:version>{build}</s:version><s:shortVersionString>{version}</s:shortVersionString>
    </item></channel></rss>'''


class SemanticMetadataTests(unittest.TestCase):
    def test_feed_build_increases_even_when_checkout_baseline_is_stale(self):
        baseline = configuration()
        result = next_configuration(baseline, '7.2.1', 'v7.2.0', feed('7.2.0', '90000'))
        self.assertEqual(result['build'], '90001')
        self.assertEqual(result['version'], '7.2.1')
        for key in ['publicEDKey', 'feedURL', 'minimumSystemVersion']:
            self.assertEqual(result[key], baseline[key])
        self.assertEqual(baseline, configuration())

    def test_major_and_large_minor_versions_do_not_collide_in_build_numbers(self):
        baseline = {**configuration(), 'build': '70100'}
        for version in ['8.0.0', '7.100.0', '7.1.100']:
            result = next_configuration(baseline, version, 'v7.1.0', feed())
            self.assertEqual(result['build'], '70101')

    def test_refuse_stale_missing_mismatched_or_invalid_feed(self):
        baseline = {**configuration(), 'build': '70100'}
        for version, tag, xml in [
            ('7.1.0', 'v7.1.0', feed()), ('7.0.0', 'v7.1.0', feed()),
            ('7.2.0-beta.1', 'v7.1.0', feed()), ('7.2.0', 'v7.1.0', feed('7.0.0')),
            ('7.2.0', 'v7.1.0', feed(build='invalid')), ('7.2.0', 'v7.1.0', '<rss/>'),
            ('7.2.0', '--help', feed()),
        ]:
            with self.assertRaises(ValueError):
                next_configuration(baseline, version, tag, xml)
