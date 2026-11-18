import json
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'script'))
import user_notes
from user_notes import NOTES

SEMANTIC = '''## [7.5.0](https://github.com/ai-ecoverse/sliccy-app/compare/v7.4.1...v7.5.0) (2026-11-18)

### ⚠ BREAKING CHANGES

* **runtime:** custom CLI paths must be selected again ([1234567](https://github.com/ai-ecoverse/sliccy-app/commit/1234567))

### Features

* **joins:** save join URLs in the keychain and sync them through iCloud ([28b642a](https://github.com/ai-ecoverse/sliccy-app/commit/28b642ab9092526f7e2e0c64c3fac4c1352b9618))

### Bug Fixes

* **joins:** restore URLs that reach iCloud after launch ([43ea51d](https://github.com/ai-ecoverse/sliccy-app/commit/43ea51d)), closes [#12](https://github.com/ai-ecoverse/sliccy-app/issues/12)
* keep [Chrome](https://example.com) open ([b5de517](https://github.com/ai-ecoverse/sliccy-app/commit/b5de517))

### Reverts

* "feat: something" ([aaaaaaa](https://github.com/ai-ecoverse/sliccy-app/commit/aaaaaaa))
'''


def feed(history):
    rss = ET.Element('rss')
    item = ET.SubElement(ET.SubElement(rss, 'channel'), 'item')
    item.append(user_notes.history_element(history))
    return ET.tostring(rss)


class UserNotesTests(unittest.TestCase):
    def test_fallback_strips_developer_markup(self):
        self.assertEqual(user_notes.fallback(SEMANTIC), [
            'Important: Custom CLI paths must be selected again',
            'New: Save join URLs in the keychain and sync them through iCloud',
            'Fixed: Restore URLs that reach iCloud after launch',
            'Fixed: Keep Chrome open',
        ])
        self.assertEqual(user_notes.fallback('## [7.5.0](x)\n'), [user_notes.GENERIC])
        many = '### Bug Fixes\n' + ''.join(f'* fix {n}\n' for n in range(12))
        result = user_notes.fallback(many)
        self.assertEqual(len(result), user_notes.MAX_NOTES)
        self.assertEqual(result[-1], 'And 5 more fixes and improvements.')

    def test_model_notes_are_used_when_valid(self):
        calls = []

        def call(model, region, token, system, prompt):
            calls.append((model, region, token))
            self.assertIn('<release-notes>', prompt)
            self.assertIn('restore URLs', prompt)
            self.assertIn('Longer body explaining the fix', prompt)
            self.assertNotIn('chore: bump tools', prompt)
            return 'Sure:\n{"notes": ["You can now sync saved join links through iCloud.", "  Fixed   links\\nthat arrived late. "]}'

        result = user_notes.user_notes(
            SEMANTIC, ['fix(joins): restore URLs\n\nLonger body explaining the fix', 'chore: bump tools'],
            env={'AWS_BEARER_TOKEN_BEDROCK': 'token', 'SLICCY_NOTES_MODEL': 'primary'}, call=call)
        self.assertEqual(result, ['You can now sync saved join links through iCloud.', 'Fixed links that arrived late.'])
        self.assertEqual(calls, [('primary', 'us-west-2', 'token')])

    def test_unusable_model_output_falls_back_without_blocking(self):
        replies = iter(['no json here', '{"notes": ["' + 'x' * 500 + '"]}'])
        models = []

        def call(model, *_):
            models.append(model)
            return next(replies)

        env = {'AWS_BEARER_TOKEN_BEDROCK': 'token', 'SLICCY_NOTES_MODEL': 'a', 'SLICCY_NOTES_FALLBACK_MODEL': 'b'}
        self.assertEqual(user_notes.user_notes(SEMANTIC, [], env=env, call=call), user_notes.fallback(SEMANTIC))
        self.assertEqual(models, ['a', 'b'])

        def outage(*_):
            raise OSError('network down')
        self.assertEqual(user_notes.user_notes(SEMANTIC, [], env=env, call=outage), user_notes.fallback(SEMANTIC))
        self.assertEqual(user_notes.user_notes(SEMANTIC, [], env={}, call=outage), user_notes.fallback(SEMANTIC))
        self.assertEqual(user_notes.parse_reply('{"notes": []}'), [user_notes.GENERIC])
        self.assertEqual(user_notes.parse_reply('Here: {"notes": ["Fixed it."]} Hope that helps {}'), ['Fixed it.'])
        for reply in ['{"notes": "x"}', '{"notes": [1]}', json.dumps({'notes': ['x'] * 9})]:
            with self.assertRaises(ValueError):
                user_notes.parse_reply(reply)

    def test_bedrock_rejects_unsafe_model_or_region(self):
        for model, region in [('a/b', 'us-west-2'), ('model', 'evil.example.com/x')]:
            with self.assertRaises(ValueError):
                user_notes.bedrock(model, region, 'token', 'system', 'prompt')

    def test_history_round_trips_through_the_appcast(self):
        old = [user_notes.entry('7.4.1', '70106', ['Fixed a crash.']),
               user_notes.entry('7.4.0', '70105', ['You can now rename links.'])]
        parsed = user_notes.previous_history(feed(old))
        self.assertEqual(parsed, old)
        current = user_notes.entry('7.5.0', '70107', ['New thing.'])
        self.assertEqual([e['version'] for e in user_notes.next_history(current, parsed)], ['7.5.0', '7.4.1', '7.4.0'])
        # Re-published or newer versions are never repeated.
        stale = old + [user_notes.entry('7.5.0', '70107', ['dup']), user_notes.entry('7.9.0', '70200', ['future'])]
        self.assertEqual([e['version'] for e in user_notes.next_history(current, stale)], ['7.5.0', '7.4.1', '7.4.0'])
        many = [user_notes.entry(f'7.4.{n}', str(70000 + n), ['n']) for n in range(20)]
        self.assertEqual(len(user_notes.next_history(current, many)), user_notes.HISTORY_LIMIT)

    def test_missing_or_malformed_history_is_dropped(self):
        self.assertEqual(user_notes.previous_history(None), [])
        self.assertEqual(user_notes.previous_history(b'<rss><channel><item/></channel></rss>'), [])
        bad = (f'<rss xmlns:n="{NOTES}"><channel><item><n:releases>'
               '<n:release version="7.4.0" build="x"><n:note>a</n:note></n:release>'
               '<n:release version="7.3.0" build="70104"></n:release>'
               '<n:release version="7.2.0" build="70103"><n:note>Kept.</n:note></n:release>'
               '</n:releases></item></channel></rss>')
        self.assertEqual(user_notes.previous_history(bad), [user_notes.entry('7.2.0', '70103', ['Kept.'])])

    def test_html_escapes_notes_and_tags_builds_for_sparkle(self):
        markup = user_notes.render_html([user_notes.entry('7.5.0', '70107', ['<script>alert(1)</script> & more'])])
        self.assertNotIn('<script>', markup)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt; &amp; more', markup)
        self.assertIn('<section data-sparkle-version="70107"><h3>Sliccy 7.5.0</h3>', markup)
        self.assertIn('.sparkle-installed-version~section{display:none}', markup)
