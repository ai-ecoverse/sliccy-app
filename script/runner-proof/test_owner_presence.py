from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import io
import json
import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
import owner_identity_setup as setup
import owner_diagnostics as diagnostics


def sample(pid, role):
    kernel = {'pid': pid, 'parent': os.getpid(), 'uid': os.geteuid(), 'processInfoAvailable': True,
        'startSeconds': '100', 'startMicroseconds': 2, 'path': '/synthetic', 'cdHash': 'a' * 40}
    return {'pid': pid, 'signingIdentifier': role, 'securityCDHash': 'a' * 40,
        'liveStaticKernelConsistent': True, 'before': kernel.copy(), 'after': kernel.copy()}


def phases(pid=101):
    base = {'schema': 1, 'pid': pid, 'seq': 1, 'elapsedMs': 1, 'windowID': 8, 'visible': True,
        'onActiveSpace': True, 'occlusionVisible': True, 'applicationActive': False, 'attempt': 0,
        'windowFrameCG': {'x': 128, 'y': 128, 'width': 256, 'height': 256}}
    rows = [dict(base, stage='surface-window-created'), dict(base, stage='surface-window-ordered', seq=2, elapsedMs=2),
        dict(base, stage='surface-presence', seq=3, elapsedMs=3, attempt=1, cgAvailable=True,
            ownedOnScreenCount=1, observedWindows=[{'windowID': 8, 'layer': 0, 'bounds': {'X': 128, 'Y': 128, 'Width': 256, 'Height': 256}}], presenceVerified=True),
        dict(base, stage='surface-ready', seq=4, elapsedMs=4, attempt=1, bundleIdentifier='ai.sliccy.proof-helper',
            rect=base['windowFrameCG'].copy(), presenceVerified=True)]
    return rows


def encoded(rows):
    return b''.join(json.dumps(row).encode() + b'\n' for row in rows)


class PresenceTests(unittest.TestCase):
    def fixture(self):
        manifest = json.loads(Path(__file__).with_name('owner-probe-pages.json').read_text())
        labels = ['app-preview', 'surface'] + [page['path'].rsplit('/', 1)[1] for page in manifest['pages']]
        roles = ['ai.sliccy.mac', 'ai.sliccy.proof-helper'] + ['com.google.Chrome'] * 4
        rects = [{'x': 64, 'y': 512, 'width': 320, 'height': 128}, manifest['allowedHelperRectCGPoints']] + [page['rectCGPoints'] for page in manifest['pages']]
        owned, windows, records = [], [], []
        for index, (label, role, rect) in enumerate(zip(labels, roles, rects)):
            pid = 100 + index
            record = sample(pid, role)
            owned.append(SimpleNamespace(label=label, role=role, digest='a' * 40, child=SimpleNamespace(pid=pid), record=copy.deepcopy(record)))
            records.append(record)
            windows.append({'pid': pid, 'windowID': index + 7, 'validShape': True, 'layer': 0,
                'bounds': dict(zip(['X', 'Y', 'Width', 'Height'], [rect[key] for key in ['x', 'y', 'width', 'height']]))})
        return {'windows': windows, 'owners': records}, owned, manifest, {page['path']: 1 for page in manifest['pages']}, setup.parse_surface_ready(encoded(phases()), 101)

    def complete(self, fixture):
        return setup.setup_presence(*fixture, os.getpid(), os.geteuid())['complete']

    def test_full_independent_presence_requires_four_distinct_owners_pages_and_bounds(self):
        self.assertTrue(self.complete(self.fixture()))
        for mode in ['no-get', 'wrong-owner', 'dead-forwarder', 'duplicate-bounds', 'duplicate-id', 'extra-window', 'no-helper', 'ready-only', 'wrong-role', 'new-incarnation', 'wrong-layer', 'shared-profile']:
            with self.subTest(mode=mode):
                f = self.fixture()
                if mode == 'no-get': f[3][f[2]['pages'][0]['path']] = 0
                elif mode == 'wrong-owner': f[0]['windows'][2]['pid'] += 100
                elif mode == 'dead-forwarder': f[0]['owners'][2]['liveStaticKernelConsistent'] = False
                elif mode == 'duplicate-bounds': f[0]['windows'][3]['bounds'] = f[0]['windows'][2]['bounds'].copy()
                elif mode == 'duplicate-id': f[0]['windows'][3]['windowID'] = f[0]['windows'][2]['windowID']
                elif mode == 'extra-window': f[0]['windows'].append(copy.deepcopy(f[0]['windows'][2]))
                elif mode in ['no-helper', 'ready-only']: f[0]['windows'].pop(1)
                elif mode == 'wrong-role': f[0]['owners'][2]['signingIdentifier'] = 'other'
                elif mode == 'new-incarnation': f[0]['owners'][2]['before']['startSeconds'] = '101'
                elif mode == 'wrong-layer': f[0]['windows'][2]['layer'] = 1
                elif mode == 'shared-profile':
                    f[2]['pages'][1]['profile'] = f[2]['pages'][0]['profile']
                    with self.assertRaises(ValueError): self.complete(f)
                    continue
                self.assertFalse(self.complete(f))

    def test_titles_have_no_presence_authority(self):
        f = self.fixture()
        for row in f[0]['windows']: row['name'] = 'conflicting diagnostic title'
        self.assertTrue(self.complete(f))
        f[0]['windows'][2]['bounds']['X'] += 1
        self.assertFalse(self.complete(f))

    def test_real_emitter_shape_requires_prior_matched_presence_and_exact_types(self):
        self.assertIsNotNone(setup.parse_surface_ready(encoded(phases()), 101))
        for field, value in [('windowID', True), ('attempt', 1.0), ('seq', 8), ('visible', 1), ('elapsedMs', float('nan')), ('windowFrameCG', {'x': True, 'y': 128, 'width': 256, 'height': 256})]:
            rows = phases(); rows[-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): setup.parse_surface_ready(encoded(rows), 101)
        for edit in ['missing-presence', 'wrong-observed-window', 'wrong-observed-layer', 'wrong-observed-bounds', 'duplicate-observed', 'late-ready-id', 'late-presence', 'unknown-stage']:
            rows = phases()
            if edit == 'missing-presence': rows.pop(2); rows[-1]['seq'] = 3
            elif edit == 'wrong-observed-window': rows[2]['observedWindows'][0]['windowID'] = 99
            elif edit == 'wrong-observed-layer': rows[2]['observedWindows'][0]['layer'] = 1
            elif edit == 'wrong-observed-bounds': rows[2]['observedWindows'][0]['bounds']['X'] = 1
            elif edit == 'duplicate-observed': rows[2]['observedWindows'] *= 2
            elif edit == 'late-ready-id': rows[3]['windowID'] = 9
            elif edit == 'late-presence': rows[2]['elapsedMs'] = 2000; rows[3]['elapsedMs'] = 2001
            elif edit == 'unknown-stage': rows[3]['stage'] = 'ready'
            with self.subTest(edit=edit), self.assertRaises(ValueError): setup.parse_surface_ready(encoded(rows), 101)
        self.assertIsNone(setup.parse_surface_ready(encoded(phases())[:-1], 101))
        rows = phases(); rows.append(dict(rows[-1], stage='surface-control-ended', seq=5, elapsedMs=5, reason='control-eof'))
        for key in ['rect', 'bundleIdentifier', 'presenceVerified']: rows[-1].pop(key)
        self.assertIsNone(setup.parse_surface_ready(encoded(rows), 101))

    def test_actual_argument_builder_keeps_four_profiles_pages_and_positions_distinct(self):
        manifest = self.fixture()[2]
        with setup.Pages(manifest) as pages:
            args = [setup.chrome_arguments(Path('/synthetic'), page, pages) for page in manifest['pages']]
            for prefix in ['--user-data-dir=', '--app=', '--window-position=']:
                self.assertEqual(len({next(arg for arg in row if arg.startswith(prefix)) for row in args}), 4)
            for row, page in zip(args, manifest['pages']):
                self.assertIn('--app=' + pages.url(page['path']), row)
                self.assertIn('--user-data-dir=/synthetic/chrome-' + page['profile'], row)
                self.assertIn('--window-position=%d,%d' % (page['rectCGPoints']['x'], page['rectCGPoints']['y']), row)
                self.assertFalse(any('remote-debug' in arg for arg in row))
            self.assertEqual(sum(pages.counts.values()), 0)

    def test_actual_run_uses_four_launch_profiles_and_gates_final_presence(self):
        for missing_get in [False, True]:
            with self.subTest(missing_get=missing_get), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                evidence = root / 'evidence'; evidence.mkdir()
                fixture = self.fixture()
                manifest = fixture[2]; manifest['osascriptCDHash'] = 'a' * 40
                observer_phases, launched = [], []
                class Observer:
                    def __init__(self, *args): pass
                    def read(self, phase, pid=None):
                        observer_phases.append(phase)
                        return fixture[0]
                class Pages:
                    def __init__(self, manifest):
                        self.counts = fixture[3].copy()
                        if missing_get: self.counts[manifest['pages'][0]['path']] = 0
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def wait_all(self, deadline): return not missing_get
                    def url(self, path): return 'http://127.0.0.1:12345' + path
                class Owned:
                    def __init__(self, label, args, role, digest, *unused):
                        self.label, self.role, self.digest = label, role, digest
                        self.child = SimpleNamespace(pid=100 + len(launched))
                        self.record = sample(self.child.pid, role)
                        launched.append((label, args))
                    def identify(self): return True
                    def surface_ready(self): return fixture[4]
                    def cleanup(self, deadline): return {'label': self.label, 'pid': self.child.pid, 'reaped': True}
                journal = diagnostics.Journal(evidence / 'steps', root, root, time.monotonic())
                with patch.object(setup, 'Observer', Observer), patch.object(setup, 'Owned', Owned), patch.object(setup, 'Pages', Pages), patch.object(setup.shared, 'require_host'), patch.object(setup.threading.Event, 'wait'):
                    result = setup.run(root, evidence, root / 'observer', root / 'preview.app', root / 'helper.app', 'a' * 40, 'a' * 40, 'a' * 40, manifest, {}, io.BytesIO(), time.monotonic() + 100, journal)
                self.assertEqual(result, not missing_get)
                self.assertEqual([label for label, _ in launched], ['app-preview', 'surface', 'host-a-1', 'host-a-2', 'host-b-1', 'host-b-2', 'authorization-requester'])
                browser_args = [args for label, args in launched if label.startswith('host-')]
                self.assertEqual(len({next(arg for arg in row if arg.startswith('--user-data-dir=')) for row in browser_args}), 4)
                self.assertEqual(observer_phases, ['initial', 'app-helper', 'chrome-launched', 'authorization-requested', 'final-setup', 'after-owned-cleanup'])
                self.assertEqual(json.loads((evidence / 'setup-presence.json').read_text())['complete'], not missing_get)
                self.assertEqual(len(json.loads((evidence / 'owned-cleanup.json').read_text())), 7)

    def test_actual_owned_pipe_holds_synthetic_child_until_cleanup_eof(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fifo = root / 'ready'; os.mkfifo(fifo, 0o600)
            ready_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            journal = diagnostics.Journal(root / 'journal', root, root, time.monotonic())
            observer = SimpleNamespace(journal=journal, evidence=root, read=lambda *args: self.fail('No identity query needed for already reaped synthetic child'))
            script = "import os,sys,select;f=os.open(sys.argv[1],os.O_WRONLY);os.write(f,b'R');os.close(f);r,_,_=select.select([0],[],[],3);sys.exit(0 if r and os.read(0,1)==b'' else 2)"
            child = journal.call('surface', setup.Owned, 'surface', [sys.executable, '-c', script, str(fifo)], 'synthetic-only', 'a' * 40, observer, {}, io.BytesIO())
            try:
                self.assertTrue(select.select([ready_fd], [], [], 2)[0])
                self.assertEqual(os.read(ready_fd, 1), b'R')
                with self.assertRaises(subprocess.TimeoutExpired): child.child.wait(timeout=0.15)
                self.assertIsNotNone(child.child.stdin)
                self.assertFalse(child.child.stdin.closed)
                with patch.object(setup.os, 'kill') as kill:
                    result = child.cleanup(time.monotonic() + 2)
                kill.assert_not_called()
                self.assertTrue(result['controlClosed'])
                self.assertTrue(result['reaped'])
                self.assertEqual(child.child.returncode, 0)
                self.assertTrue(child.child.stdin.closed)
                self.assertTrue((root / 'surface-phases.ndjson').is_file())
            finally:
                os.close(ready_fd)
                if child.child.stdin and not child.child.stdin.closed: child.child.stdin.close()
                child.child.wait(timeout=4)


if __name__ == '__main__':
    unittest.main()
