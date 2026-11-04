from pathlib import Path
from unittest.mock import patch
import copy
import json
import subprocess
import tempfile
import unittest
import owner_identity_setup as setup
import owner_diagnostics as diagnostics


def owner_record():
    sample = {'pid': 42, 'processInfoAvailable': False, 'processInfoError': 1, 'parent': None, 'uid': None,
        'startSeconds': None, 'startMicroseconds': None, 'path': '/synthetic/WindowServer', 'pathError': 0,
        'codeStatus': 1, 'codeStatusError': 0, 'platformBinary': True, 'cdHash': 'a' * 40, 'cdHashError': 0}
    row = {'pid': 42, 'before': sample.copy(), 'after': sample.copy(), 'signingIdentifier': 'com.apple.WindowServer',
        'appleAnchored': True, 'securedExecutablePath': sample['path'], 'securityCDHash': sample['cdHash'],
        'stableKernelSamples': False, 'liveStaticKernelConsistent': False}
    for key in ['guestLookupStatus', 'liveValidityStatus', 'liveValidityAfterStatus', 'appleRequirementStatus',
                'appleAnchorStatus', 'staticCopyStatus', 'staticValidityStatus', 'signingInformationStatus']:
        row[key] = 0
    return row


def root_record():
    return {'schema': 1, 'kind': 'privileged-kernel-identity', 'pid': 42, 'processInfoAvailable': True,
        'processInfoError': 0, 'parent': 1, 'uid': 88, 'startSeconds': '123', 'startMicroseconds': 456,
        'path': '/synthetic/WindowServer', 'pathError': 0}


class PrivilegedTests(unittest.TestCase):
    def test_only_recorded_apple_window_server_can_select_privileged_pid(self):
        original = owner_record()
        self.assertTrue(setup.window_server_candidate(original))
        for key, value in [('signingIdentifier', 'com.apple.finder'), ('appleAnchored', False),
                           ('appleAnchored', 1), ('pid', True), ('securedExecutablePath', '/other'),
                           ('securityCDHash', 'b' * 40)]:
            changed = copy.deepcopy(original); changed[key] = value
            self.assertFalse(setup.window_server_candidate(changed))
        for key in [k for k in original if k.endswith('Status')]:
            for value in [-1, False, None]:
                changed = copy.deepcopy(original); changed[key] = value
                self.assertFalse(setup.window_server_candidate(changed))
        for side in ['before', 'after']:
            for key, value in [('pid', 43), ('path', '/other'), ('cdHash', None), ('platformBinary', 1)]:
                changed = copy.deepcopy(original); changed[side][key] = value
                self.assertFalse(setup.window_server_candidate(changed))
        changed = copy.deepcopy(original)
        for side in ['before', 'after']: changed[side]['processInfoError'] = 3
        self.assertFalse(setup.window_server_candidate(changed))

    def test_root_bracket_never_rewrites_native_record_or_adds_signal_authority(self):
        original, before, after = owner_record(), root_record(), root_record()
        saved = copy.deepcopy(original)
        self.assertTrue(setup.privileged_bracket_matches(original, before, original, after))
        self.assertEqual(original, saved)
        self.assertFalse(setup.same_owned(None, original, 42, 1, 88, 'com.apple.WindowServer', 'a' * 40))
        for key, value in [('pid', 43), ('parent', 2), ('uid', 89), ('startSeconds', '124'),
                           ('startMicroseconds', 457), ('path', '/other'), ('processInfoAvailable', False)]:
            changed = after.copy(); changed[key] = value
            if key == 'pid':
                with self.assertRaises(ValueError): setup.privileged_bracket_matches(original, before, original, changed)
            else:
                self.assertFalse(setup.privileged_bracket_matches(original, before, original, changed))
        for key, value in [('signingIdentifier', 'com.apple.finder'), ('securityCDHash', 'b' * 40), ('liveValidityStatus', -1)]:
            current = copy.deepcopy(original); current[key] = value
            self.assertFalse(setup.privileged_bracket_matches(original, before, current, after))
        current = copy.deepcopy(original); current['after']['codeStatus'] = 2
        self.assertFalse(setup.privileged_bracket_matches(original, before, current, after))

    def test_fixed_sudo_argv_and_assertions_only(self):
        args = setup.privileged_arguments(Path('/fixed/owner-identity-probe'), 42, setup.ASSERTIONS)
        self.assertEqual(args, ['/usr/bin/sudo', '-n', '--preserve-env=' + ','.join(setup.ASSERTIONS), '--', '/fixed/owner-identity-probe', '--kernel', '42'])
        for pid in [0, -1, True, '42', 2147483648]:
            with self.assertRaises(ValueError): setup.privileged_arguments(Path('/fixed'), pid, setup.ASSERTIONS)
        for key in setup.ASSERTIONS:
            env = setup.ASSERTIONS.copy(); del env[key]
            with self.assertRaises(ValueError): setup.privileged_arguments(Path('/fixed'), 42, env)

    def test_actual_observer_shared_deadline_and_separate_supplement(self):
        for snapshot in [False, True]:
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory() as name:
                root = Path(name); binary = root / 'owner-identity-probe'; binary.write_bytes(b'fixed')
                clock = [100.0]; calls = []
                original = owner_record()
                value = {'available': True, 'allWindowRowsClassifiable': True, 'owners': [original]} if snapshot else original
                with patch.object(setup.time, 'monotonic', side_effect=lambda: clock[0]):
                    journal = diagnostics.Journal(root / 'steps', root, root, clock[0])
                    observer = setup.Observer(binary, root, dict(setup.ASSERTIONS, GH_TOKEN='not-forwarded'), 300, journal)
                    def execute(args, **kwargs):
                        calls.append((args, kwargs['timeout'], kwargs['env']))
                        row = value if len(calls) == 1 else root_record() if args[0] == '/usr/bin/sudo' else original
                        kwargs['stdout'].write(json.dumps(row).encode())
                        clock[0] += 2
                        return subprocess.CompletedProcess(args, 0)
                    with patch.object(diagnostics.subprocess, 'run', side_effect=execute):
                        self.assertEqual(observer.read('initial', None if snapshot else 42), value)
                self.assertEqual([x[1] for x in calls], [15, 13, 11, 9])
                self.assertEqual([x[0][0] for x in calls], [str(binary), '/usr/bin/sudo', str(binary), '/usr/bin/sudo'])
                for args, _, env in calls:
                    if args[0] == '/usr/bin/sudo':
                        self.assertEqual(env, dict(setup.ASSERTIONS, PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C'))
                supplement = json.loads(next(root.glob('privileged-bracket-*.json')).read_text())
                self.assertTrue(supplement['bindingComplete'])
                self.assertFalse(supplement['cleanupAuthority'])
                self.assertFalse(supplement['allowlistEstablished'])
                self.assertFalse(supplement['original']['stableKernelSamples'])
                self.assertEqual(supplement['original'], original)

    def test_unknown_owner_never_launches_sudo_and_expired_budget_refuses_spawn(self):
        for unknown in [True, False]:
            with self.subTest(unknown=unknown), tempfile.TemporaryDirectory() as name:
                root = Path(name); binary = root / 'owner-identity-probe'; binary.write_bytes(b'fixed')
                clock = [100.0]; calls = []
                original = owner_record()
                if unknown: original['signingIdentifier'] = 'unknown'
                with patch.object(setup.time, 'monotonic', side_effect=lambda: clock[0]):
                    journal = diagnostics.Journal(root / 'steps', root, root, clock[0])
                    observer = setup.Observer(binary, root, setup.ASSERTIONS, 300, journal)
                    def execute(args, **kwargs):
                        calls.append(args); kwargs['stdout'].write(json.dumps(original).encode()); clock[0] += 15
                        return subprocess.CompletedProcess(args, 0)
                    with patch.object(diagnostics.subprocess, 'run', side_effect=execute):
                        if unknown: self.assertEqual(observer.read('initial', 42), original)
                        else:
                            with self.assertRaisesRegex(ValueError, 'observer-deadline'): observer.read('initial', 42)
                self.assertEqual(len(calls), 1)
                self.assertFalse(list(root.glob('privileged-bracket-*.json')))

    def test_timeout_retains_full_bounded_phase_bytes_and_does_not_reraise_with_new_budget(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); binary = root / 'owner-identity-probe'; binary.write_bytes(b'fixed')
            journal = diagnostics.Journal(root / 'steps', root, root, setup.time.monotonic())
            observer = setup.Observer(binary, root, setup.ASSERTIONS, setup.time.monotonic() + 60, journal)
            phases = b'{"fixed":"phase"}\n' * 1024
            def execute(args, **kwargs):
                self.assertLessEqual(kwargs['timeout'], 15)
                kwargs['stdout'].write(b'partial'); kwargs['stderr'].write(phases)
                raise subprocess.TimeoutExpired(args, kwargs['timeout'])
            with patch.object(diagnostics.subprocess, 'run', side_effect=execute) as command:
                with self.assertRaises(subprocess.TimeoutExpired): observer.read('spawn-host-a-1', 42)
            self.assertEqual(command.call_count, 1)
            self.assertEqual((root / 'observer-errors.log').read_bytes(), phases)
            self.assertEqual((root / 'observation-001.json').read_bytes(), b'partial')
            rows = [json.loads(row) for row in (root / 'steps').read_text().splitlines()]
            failure = next(row for row in rows if row['kind'] == 'command' and row['status'] == 'failed')
            self.assertLessEqual(len(failure['stderrTail'].encode()), 4096)
            self.assertEqual(failure['step'], 'spawn-host-a-1')


if __name__ == '__main__':
    unittest.main()
