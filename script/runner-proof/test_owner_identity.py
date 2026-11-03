from pathlib import Path
import ast
import copy
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch, Mock
import owner_identity_setup as setup
import sealed_owner_identity as wrapper


class OwnerIdentityTests(unittest.TestCase):
    def record(self):
        sample = {'pid': 12, 'parent': 10, 'uid': 501, 'processInfoAvailable': True,
                  'startSeconds': '100', 'startMicroseconds': 2, 'path': '/fixed', 'cdHash': 'a' * 40}
        return {'pid': 12, 'liveStaticKernelConsistent': True, 'signingIdentifier': 'fixed.role',
                'securityCDHash': 'a' * 40, 'before': sample.copy(), 'after': sample.copy()}

    def test_signal_identity_requires_bracketed_role_incarnation_and_parent(self):
        original = self.record()
        self.assertTrue(setup.same_owned(original, original, 12, 10, 501, 'fixed.role', 'a' * 40))
        for side, key, value in [('before', 'parent', 11), ('after', 'uid', 502), ('before', 'startSeconds', '101'), ('before', 'cdHash', 'b' * 40)]:
            changed = copy.deepcopy(original)
            changed[side][key] = value
            self.assertFalse(setup.same_owned(original, changed, 12, 10, 501, 'fixed.role', 'a' * 40))
        for key, value in [('liveStaticKernelConsistent', False), ('signingIdentifier', 'other'), ('securityCDHash', None)]:
            changed = copy.deepcopy(original)
            changed[key] = value
            self.assertFalse(setup.same_owned(original, changed, 12, 10, 501, 'fixed.role', 'a' * 40))
        self.assertFalse(setup.same_owned(None, original, 12, 10, 501, 'fixed.role', 'a' * 40))

    def test_unknown_identity_never_signals(self):
        owned = setup.Owned.__new__(setup.Owned)
        owned.label, owned.role, owned.digest = 'test', 'fixed.role', 'a' * 40
        owned.child, owned.record, owned.observer = Mock(pid=12), None, Mock()
        owned.observer.read.return_value = self.record()
        with patch.object(owned, 'reap', return_value=False), patch.object(setup.os, 'kill') as kill:
            result = owned.cleanup(setup.time.monotonic() + 1)
        kill.assert_not_called()
        self.assertFalse(result['reaped'])
        self.assertEqual(result['refused'], 'identity-unavailable-or-changed')

    def test_same_live_record_can_receive_term_then_actual_reap(self):
        owned = setup.Owned.__new__(setup.Owned)
        owned.label, owned.role, owned.digest = 'test', 'fixed.role', 'a' * 40
        owned.child, owned.record, owned.observer = Mock(pid=12), self.record(), Mock()
        owned.observer.read.return_value = self.record()
        with patch.object(owned, 'reap', side_effect=[False, True]), patch.object(setup.os, 'getpid', return_value=10), patch.object(setup.os, 'geteuid', return_value=501), patch.object(setup.os, 'kill') as kill:
            result = owned.cleanup(setup.time.monotonic() + 1)
        kill.assert_called_once_with(12, setup.signal.SIGTERM)
        self.assertTrue(result['reaped'])
        self.assertEqual(result['signals'], [int(setup.signal.SIGTERM)])

    def test_reaped_child_never_queried_or_signalled(self):
        owned = setup.Owned.__new__(setup.Owned)
        owned.label, owned.child, owned.record, owned.observer = 'test', Mock(pid=12), None, Mock()
        with patch.object(owned, 'reap', return_value=True), patch.object(setup.os, 'kill') as kill:
            result = owned.cleanup(setup.time.monotonic() + 1)
        owned.observer.read.assert_not_called()
        kill.assert_not_called()
        self.assertTrue(result['reaped'])

    def test_fixed_pages_and_query_refusal_without_capture(self):
        manifest = json.loads(Path(__file__).with_name('owner-probe-pages.json').read_text())
        with setup.Pages(manifest) as pages:
            for page in manifest['pages']:
                with urllib.request.urlopen(pages.url(page['path']), timeout=2) as response:
                    text = response.read().decode()
                    self.assertIn(page['title'], text)
                    self.assertIn('background:rgb(%d,%d,%d)' % tuple(page['sRGB']), text)
                    self.assertIn('min-height:100%', text)
                    self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
            try:
                urllib.request.urlopen(pages.url(manifest['pages'][0]['path']) + '?secret=x', timeout=2)
                self.fail('query was accepted')
            except urllib.error.HTTPError as error:
                self.assertEqual(error.code, 400)
                error.close()
            self.assertEqual(sum(pages.counts.values()), 4)

    def test_no_capture_or_tcc_mutation_api_and_host_only_workflow(self):
        root = Path(__file__).parent
        text = (root / 'owner_identity_probe.m').read_text()
        for forbidden in ['CGWindowListCreateImage', 'CGDisplayCreateImage', 'SCStream', 'CGRequestScreenCaptureAccess', 'CGEventPost', 'sqlite', 'tccutil', 'SecCodeSetStatus']:
            self.assertNotIn(forbidden, text)
        self.assertIn('CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly', text)
        self.assertIn('csops(pid, 0,', text)
        self.assertIn('csops(pid, 5,', text)
        workflow = (root.parent.parent / '.github/workflows/runner-proof.yml').read_text()
        for job in ['diagnostic', 'setup-read-only', 'universal', 'hosted-pid']:
            self.assertIn('  ' + job + ':\n    if: false', workflow)
        self.assertIn('owner-identity-diagnostic-sealed', workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('APPLE_', workflow)
        tree = ast.parse((root / 'sealed_owner_identity.py').read_text())
        calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
        self.assertNotIn('grants.install', calls)
        self.assertNotIn('shared.suite', calls)

    def test_probe_outputs_cannot_claim_allowlist_or_capture(self):
        text = Path(wrapper.__file__).read_text()
        self.assertIn("'allowlistEstablished': False", text)
        self.assertIn("'captureInvoked': False", text)
        self.assertIn("'tccDatabaseWrites': False", text)
        self.assertIn("'captureOnlySystemOwnersUnobserved': True", text)
        self.assertEqual(wrapper.PREVIEW_RUN, '41484829593')
        self.assertEqual(wrapper.shared.APP_RUN, '41619548340')

    def test_source_manifest_refuses_tampered_copy(self):
        workspace = Path(__file__).resolve().parent.parent.parent
        wrapper.validate_sources(workspace)
        with tempfile.TemporaryDirectory() as name:
            target = Path(name)
            for relative in wrapper.SOURCES | {'script/runner-proof/owner-identity-reviewed-sources.json'}:
                source = workspace / relative
                copied = target / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(source.read_bytes())
            changed = target / 'script/runner-proof/owner_identity_probe.m'
            changed.write_text(changed.read_text() + '\n')
            with self.assertRaises(ValueError):
                wrapper.validate_sources(target)


if __name__ == '__main__':
    unittest.main()
