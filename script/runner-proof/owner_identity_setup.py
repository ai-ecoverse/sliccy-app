from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import errno
import math
import os
import signal
import subprocess
import threading
import tempfile
import time
import sealed_runner as shared

ASSERTIONS = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
    'RUNNER_ENVIRONMENT': 'github-hosted', 'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted'}


def same_owned(record, current, pid, parent, uid, role, digest):
    if record is None or current is None:
        return False
    for row in [record, current]:
        if row.get('pid') != pid or row.get('liveStaticKernelConsistent') is not True or row.get('signingIdentifier') != role or row.get('securityCDHash') != digest:
            return False
        for side in ['before', 'after']:
            value = row.get(side, {})
            if value.get('pid') != pid or value.get('parent') != parent or value.get('uid') != uid or value.get('processInfoAvailable') is not True:
                return False
    return all(record['before'][key] == current['before'][key] for key in ['pid', 'parent', 'uid', 'startSeconds', 'startMicroseconds', 'cdHash', 'path'])


def kernel_record_shape(value):
    integers = {'pid', 'processInfoError', 'pathError', 'codeStatusError', 'cdHashError'}
    nullable_integers = {'parent', 'uid', 'startMicroseconds', 'codeStatus'}
    nullable_strings = {'startSeconds', 'path', 'cdHash'}
    keys = integers | nullable_integers | nullable_strings | {'processInfoAvailable', 'platformBinary'}
    if type(value) is not dict or set(value) != keys:
        raise ValueError('kernel-record-fields')
    for key in integers:
        if type(value[key]) is not int:
            raise ValueError('kernel-record-type-' + key)
    for fields, expected in [(nullable_integers, int), (nullable_strings, str), ({'platformBinary'}, bool)]:
        for key in fields:
            if value[key] is not None and type(value[key]) is not expected:
                raise ValueError('kernel-record-type-' + key)
    if type(value['processInfoAvailable']) is not bool:
        raise ValueError('kernel-record-type-processInfoAvailable')
    return value


def observation_kernel_shapes(value, pid):
    owners = [value] if pid is not None else value.get('owners')
    if type(owners) is not list:
        raise ValueError('kernel-owner-records')
    for owner in owners:
        if type(owner) is not dict:
            raise ValueError('kernel-owner-record')
        for side in ['before', 'after']:
            kernel_record_shape(owner.get(side))


def privileged_kernel_shape(value, pid):
    keys = {'schema', 'kind', 'pid', 'processInfoAvailable', 'processInfoError', 'parent', 'uid',
            'startSeconds', 'startMicroseconds', 'path', 'pathError'}
    if type(value) is not dict or set(value) != keys:
        raise ValueError('privileged-kernel-fields')
    for key in ['schema', 'pid', 'processInfoError', 'pathError']:
        if type(value[key]) is not int:
            raise ValueError('privileged-kernel-type-' + key)
    if value['schema'] != 1 or value['kind'] != 'privileged-kernel-identity' or value['pid'] != pid:
        raise ValueError('privileged-kernel-identity')
    if type(value['processInfoAvailable']) is not bool:
        raise ValueError('privileged-kernel-type-processInfoAvailable')
    for fields, expected in [(['parent', 'uid', 'startMicroseconds'], int), (['startSeconds', 'path'], str)]:
        for key in fields:
            if value[key] is not None and type(value[key]) is not expected:
                raise ValueError('privileged-kernel-type-' + key)
    return value


def window_server_candidate(owner):
    if type(owner) is not dict or owner.get('signingIdentifier') != 'com.apple.WindowServer' or owner.get('appleAnchored') is not True:
        return False
    if type(owner.get('pid')) is not int or not 0 < owner['pid'] <= 2147483647:
        return False
    for key in ['guestLookupStatus', 'liveValidityStatus', 'liveValidityAfterStatus', 'appleRequirementStatus',
                'appleAnchorStatus', 'staticCopyStatus', 'staticValidityStatus', 'signingInformationStatus']:
        if type(owner.get(key)) is not int or owner[key] != 0:
            return False
    image, digest = owner.get('securedExecutablePath'), owner.get('securityCDHash')
    if type(image) is not str or not image.startswith('/') or type(digest) is not str or len(digest) != 40 or any(c not in '0123456789abcdef' for c in digest):
        return False
    denied = False
    for side in ['before', 'after']:
        row = owner.get(side)
        try:
            kernel_record_shape(row)
        except ValueError:
            return False
        if row['pid'] != owner['pid'] or row['path'] != image or row['cdHash'] != digest or type(row['codeStatus']) is not int:
            return False
        if any(row[key] != 0 for key in ['pathError', 'codeStatusError', 'cdHashError']):
            return False
        identity = ['parent', 'uid', 'startSeconds', 'startMicroseconds']
        if row['processInfoAvailable']:
            if row['processInfoError'] != 0 or any(row[key] is None for key in identity):
                return False
            if row['parent'] < 0 or row['uid'] < 0 or not row['startSeconds'].isdigit() or int(row['startSeconds']) <= 0 or not 0 <= row['startMicroseconds'] < 1000000:
                return False
        else:
            if row['processInfoError'] != errno.EPERM or any(row[key] is not None for key in identity):
                return False
            denied = True
    return denied


def privileged_bracket_matches(original, before, observed, after):
    if not window_server_candidate(original) or not window_server_candidate(observed):
        return False
    keys = ['pid', 'parent', 'uid', 'startSeconds', 'startMicroseconds', 'path']
    for row in [before, after]:
        privileged_kernel_shape(row, original['pid'])
        if row['processInfoAvailable'] is not True or row['processInfoError'] != 0 or row['pathError'] != 0:
            return False
        if any(row[key] is None for key in keys):
            return False
        if row['parent'] < 0 or row['uid'] < 0 or not row['startSeconds'].isdigit() or int(row['startSeconds']) <= 0 or not 0 <= row['startMicroseconds'] < 1000000:
            return False
    if any(before[key] != after[key] for key in keys):
        return False
    for owner in [original, observed]:
        for side in ['before', 'after']:
            sample = owner[side]
            if sample['processInfoAvailable'] and any(sample[key] != before[key] for key in keys):
                return False
    for key in ['pid', 'signingIdentifier', 'securedExecutablePath', 'securityCDHash']:
        if original[key] != observed[key]:
            return False
    return before['path'] == observed['securedExecutablePath'] and all(
        original['before'][key] == original['after'][key] == observed['before'][key] == observed['after'][key]
        for key in ['pid', 'path', 'cdHash', 'codeStatus'])


def privileged_arguments(binary, pid, env):
    if type(pid) is not int or not 0 < pid <= 2147483647 or any(env.get(k) != v for k, v in ASSERTIONS.items()):
        raise ValueError('privileged-kernel-placement-or-pid')
    return ['/usr/bin/sudo', '-n', '--preserve-env=' + ','.join(ASSERTIONS), '--', str(binary), '--kernel', str(pid)]


class Observer:
    def __init__(self, binary, evidence, env, deadline, journal):
        self.binary, self.evidence, self.env, self.deadline = binary, evidence, env, deadline
        self.sequence = 0
        self.journal = journal

    def read(self, phase, pid=None):
        return self.journal.call(phase, self.read_observation, phase, pid)

    def read_observation(self, phase, pid=None):
        deadline = min(self.deadline, time.monotonic() + 15)
        value = self.invoke(phase, pid, deadline)
        owners = [value] if pid is not None else value['owners']
        for owner in owners:
            if window_server_candidate(owner):
                target_pid = owner['pid']
                before = self.journal.call('privileged-before', self.invoke, 'privileged-before', target_pid, deadline, True)
                current = self.journal.call('privileged-owner-recheck', self.invoke, 'privileged-owner-recheck', target_pid, deadline)
                after = self.journal.call('privileged-after', self.invoke, 'privileged-after', target_pid, deadline, True)
                supplement = {'schema': 1, 'kind': 'window-server-privileged-bracket', 'pid': target_pid,
                    'original': owner, 'privilegedBefore': before, 'unprivilegedRecheck': current, 'privilegedAfter': after,
                    'bindingComplete': privileged_bracket_matches(owner, before, current, after),
                    'originalRecordUnchanged': True, 'cleanupAuthority': False, 'allowlistEstablished': False}
                target = self.evidence / ('privileged-bracket-%03d.json' % self.sequence)
                with target.open('x') as out:
                    json.dump(supplement, out, indent=2); out.write('\n')
        return value

    def invoke(self, phase, pid, deadline, privileged=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('observer-deadline')
        self.sequence += 1
        target = self.evidence / ('observation-%03d.json' % self.sequence)
        args = privileged_arguments(self.binary, pid, self.env) if privileged else [str(self.binary)] + ([] if pid is None else ['--owner', str(pid)])
        child_env = dict(self.env)
        if privileged:
            child_env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', **ASSERTIONS}
        with target.open('xb') as out, (self.evidence / 'observer-errors.log').open('ab') as error:
            result = self.journal.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=error, env=child_env, timeout=remaining)
        if result.returncode != 0 or target.stat().st_size > (16384 if privileged else 4 * 1024 * 1024):
            raise ValueError('observer-failed')
        value = json.loads(target.read_text())
        with (self.evidence / 'observation-index.ndjson').open('a') as index:
            index.write(json.dumps({'phase': phase, 'pid': pid, 'file': target.name, 'sha256': shared.sha(target), 'monotonicSeconds': time.monotonic()}) + '\n')
        if privileged:
            privileged_kernel_shape(value, pid)
        else:
            if pid is None and (value.get('available') is not True or value.get('allWindowRowsClassifiable') is not True):
                raise ValueError('window-inventory-unavailable')
            observation_kernel_shapes(value, pid)
        return value


def parse_surface_ready(data, pid):
    if len(data) > 96 * 4096:
        raise ValueError('surface-output-bound')
    if not data or not data.endswith(b'\n'):
        return None
    lines = data.splitlines()
    if len(lines) > 96 or any(len(line) >= 4096 for line in lines):
        raise ValueError('surface-record-bound')
    common = {'schema', 'stage', 'pid', 'seq', 'elapsedMs', 'windowID', 'visible', 'onActiveSpace',
              'occlusionVisible', 'applicationActive', 'attempt', 'windowFrameCG'}
    extras = {'surface-window-created': set(), 'surface-window-ordered': set(), 'surface-space-changed': set(),
        'surface-presence': {'cgAvailable', 'ownedOnScreenCount', 'observedWindows', 'presenceVerified'},
        'surface-ready': {'bundleIdentifier', 'rect', 'presenceVerified'},
        'surface-unavailable': {'reason'}, 'surface-control-ended': {'reason'}}
    created = ordered = False
    matched = None
    ready = None
    elapsed = -1
    for sequence, line in enumerate(lines, 1):
        row = json.loads(line)
        if type(row) is not dict or row.get('stage') not in extras or set(row) != common | extras[row['stage']]:
            raise ValueError('surface-record-fields')
        for key in ['schema', 'pid', 'seq', 'windowID', 'attempt']:
            if type(row[key]) is not int:
                raise ValueError('surface-record-type')
        if row['schema'] != 1 or row['pid'] != pid or row['seq'] != sequence or row['windowID'] < 0 or not 0 <= row['attempt'] <= 40:
            raise ValueError('surface-record-identity')
        if type(row['elapsedMs']) not in (int, float) or not math.isfinite(row['elapsedMs']) or row['elapsedMs'] < max(0, elapsed):
            raise ValueError('surface-record-clock')
        elapsed = row['elapsedMs']
        for key in ['visible', 'onActiveSpace', 'occlusionVisible', 'applicationActive']:
            if type(row[key]) is not bool:
                raise ValueError('surface-record-boolean')
        if not rectangle(row['windowFrameCG'], lowercase=True):
            raise ValueError('surface-record-frame')
        stage = row['stage']
        if stage == 'surface-window-created':
            if created or ordered or ready: raise ValueError('surface-created-order')
            created = True
        elif stage == 'surface-window-ordered':
            if not created or ordered or ready: raise ValueError('surface-ordered-order')
            ordered = True
        elif stage == 'surface-space-changed':
            if not created: raise ValueError('surface-space-order')
        elif stage == 'surface-presence':
            if not ordered or ready or type(row['cgAvailable']) is not bool or type(row['presenceVerified']) is not bool:
                raise ValueError('surface-presence-order')
            if type(row['ownedOnScreenCount']) is not int or type(row['observedWindows']) is not list or len(row['observedWindows']) > 8:
                raise ValueError('surface-presence-fields')
            if row['ownedOnScreenCount'] < 0 or len(row['observedWindows']) != min(8, row['ownedOnScreenCount']):
                raise ValueError('surface-observed-count')
            for window in row['observedWindows']:
                if type(window) is not dict or set(window) != {'windowID', 'layer', 'bounds'} or type(window['windowID']) is not int or type(window['layer']) is not int or not rectangle(window['bounds']):
                    raise ValueError('surface-observed-window')
            matched = None
            if row['presenceVerified']:
                if not row['cgAvailable'] or row['ownedOnScreenCount'] != 1 or not 1 <= row['attempt'] <= 40 or row['elapsedMs'] >= 2000:
                    raise ValueError('surface-matched-state')
                actual = row['observedWindows'][0]
                if actual != {'windowID': row['windowID'], 'layer': 0, 'bounds': {'X': 128, 'Y': 128, 'Width': 256, 'Height': 256}} or row['windowID'] <= 0 or any(row[key] is not True for key in ['visible', 'onActiveSpace', 'occlusionVisible']):
                    raise ValueError('surface-matched-window')
                matched = (row['windowID'], row['attempt'])
        elif stage == 'surface-ready':
            if ready or matched != (row['windowID'], row['attempt']) or row['presenceVerified'] is not True or row['bundleIdentifier'] != 'ai.sliccy.proof-helper' or row['windowID'] <= 0:
                raise ValueError('surface-ready-order')
            if any(row[key] is not True for key in ['visible', 'onActiveSpace', 'occlusionVisible']) or not rectangle(row['rect'], lowercase=True) or row['rect'] != {'x': 128, 'y': 128, 'width': 256, 'height': 256}:
                raise ValueError('surface-ready-presence')
            ready = row
        elif stage in ['surface-unavailable', 'surface-control-ended']:
            reasons = ['presence-unproved'] if stage == 'surface-unavailable' else ['control-eof', 'control-stop', 'control-invalid', 'control-deadline']
            if row['reason'] not in reasons: raise ValueError('surface-terminal-reason')
            return None
    return ready


def rectangle(value, lowercase=False):
    keys = ['x', 'y', 'width', 'height'] if lowercase else ['X', 'Y', 'Width', 'Height']
    return type(value) is dict and set(value) == set(keys) and all(
        type(value[key]) in (int, float) and math.isfinite(value[key]) for key in keys)


def exact_window(rows, pid, expected):
    owned = [row for row in rows if type(row) is dict and type(row.get('pid')) is int and row['pid'] == pid]
    if len(owned) != 1:
        return None
    row = owned[0]
    if row.get('validShape') is not True or type(row.get('windowID')) is not int or row['windowID'] <= 0 or type(row.get('layer')) is not int or row['layer'] != 0:
        return None
    if not rectangle(row.get('bounds')):
        return None
    bounds = dict(zip(['X', 'Y', 'Width', 'Height'], [expected[key] for key in ['x', 'y', 'width', 'height']]))
    return row if row['bounds'] == bounds else None


def setup_presence(observation, owned, manifest, counts, surface_ready, parent, uid):
    pages = manifest['pages']
    paths = ['/screen-proof/host-a-1', '/screen-proof/host-a-2', '/screen-proof/host-b-1', '/screen-proof/host-b-2']
    if [page['path'] for page in pages] != paths or [page['profile'] for page in pages] != ['a-1', 'a-2', 'b-1', 'b-2'] or manifest.get('expectedChromeOwnerCount') != 4:
        raise ValueError('fixed-four-window-contract')
    expected_labels = ['app-preview', 'surface'] + [path.rsplit('/', 1)[1] for path in paths]
    selected = [child for child in owned if child.label in expected_labels]
    if len(selected) != 6 or len({child.label for child in selected}) != 6 or len({child.child.pid for child in selected}) != 6:
        return {'schema': 2, 'complete': False, 'reason': 'required-distinct-owners', 'allowlistEstablished': False}
    windows, records = observation['windows'], observation['owners']
    results = []
    used_ids, geometries = set(), set()
    complete = set(counts) == set(paths)
    for child in selected:
        matches = [row for row in records if row.get('pid') == child.child.pid]
        valid = len(matches) == 1 and same_owned(child.record, matches[0], child.child.pid, parent, uid, child.role, child.digest)
        actual = None
        requested = None
        if child.label == 'app-preview':
            present = any(row.get('pid') == child.child.pid and row.get('validShape') is True for row in windows)
        else:
            if child.label == 'surface':
                requested = manifest['allowedHelperRectCGPoints']
            else:
                page = next(page for page in pages if page['path'].endswith('/' + child.label))
                requested = page['rectCGPoints']
            actual = exact_window(windows, child.child.pid, requested)
            present = actual is not None
            if actual:
                geometry = tuple(actual['bounds'][key] for key in ['X', 'Y', 'Width', 'Height'])
                if actual['windowID'] in used_ids or geometry in geometries:
                    present = False
                used_ids.add(actual['windowID']); geometries.add(geometry)
        get_count = None
        if child.label.startswith('host-'):
            get_count = counts.get('/screen-proof/' + child.label)
            present = present and type(get_count) is int and get_count > 0
        if child.label == 'surface':
            present = present and surface_ready is not None and surface_ready['pid'] == child.child.pid and surface_ready['windowID'] == actual['windowID']
        complete = complete and valid and present
        results.append({'label': child.label, 'pid': child.child.pid, 'identityVerified': valid,
            'presenceVerified': present, 'expectedRect': requested, 'windowID': actual['windowID'] if actual else None, 'pageGETs': get_count})
    return {'schema': 2, 'complete': bool(complete), 'requiredChromeOwners': 4, 'owners': results,
        'allFixedPagesRequested': all(type(counts.get(path)) is int and counts[path] > 0 for path in paths),
        'authorizationWindowInferred': False, 'renderInferredFromGET': False, 'allowlistEstablished': False}


class Owned:
    def __init__(self, label, args, role, digest, observer, env, log):
        self.label, self.role, self.digest, self.observer = label, role, digest, observer
        self.journal = observer.journal
        self.output, self.errors = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.command = self.journal.command_record(args)
        self.journal.write(dict(self.command, status='entered', exitStatus=None, stdoutTail='', stderrTail=''))
        try:
            self.child = subprocess.Popen(args, stdin=subprocess.PIPE if label == 'surface' else subprocess.DEVNULL,
                stdout=self.output, stderr=self.errors, env=env, close_fds=True)
        except BaseException as error:
            self.journal.finish(self.command, None, error=error)
            self.output.close(); self.errors.close()
            raise
        self.record, self.reported = None, False

    def identify(self):
        value = self.observer.read('spawn-' + self.label, self.child.pid)
        if same_owned(value, value, self.child.pid, os.getpid(), os.geteuid(), self.role, self.digest):
            self.record = value
        return self.record is not None

    def reap(self, seconds):
        try:
            self.child.wait(timeout=max(0, seconds))
            if self.label == 'surface' and self.child.stdin is not None:
                self.child.stdin.close()
            if hasattr(self, 'journal') and not self.reported:
                self.retain_surface_output()
                self.journal.finish(self.command, self.child.returncode, self.journal.tail(self.output), self.journal.tail(self.errors))
                self.output.close(); self.errors.close()
                self.reported = True
            return True
        except subprocess.TimeoutExpired:
            return False

    def surface_output(self):
        if self.label != 'surface':
            raise ValueError('not-surface-child')
        if self.reported:
            data = (self.observer.evidence / 'surface-phases.ndjson').read_bytes()
            if len(data) > 96 * 4096: raise ValueError('surface-output-bound')
            return data
        size = os.fstat(self.output.fileno()).st_size
        if size > 96 * 4096:
            raise ValueError('surface-output-bound')
        return os.pread(self.output.fileno(), size, 0)

    def retain_surface_output(self):
        if self.label == 'surface':
            target = self.observer.evidence / 'surface-phases.ndjson'
            with target.open('xb') as out:
                out.write(self.surface_output())

    def surface_ready(self):
        return parse_surface_ready(self.surface_output(), self.child.pid)

    def cleanup(self, deadline):
        if hasattr(self, 'journal'):
            try:
                return self.journal.call('cleanup-' + self.label, self.cleanup_owned, deadline)
            finally:
                if not self.reported:
                    self.retain_surface_output()
                    self.journal.finish(self.command, self.child.returncode, self.journal.tail(self.output), self.journal.tail(self.errors), ValueError('owned-child-unreaped'))
                    self.output.close(); self.errors.close()
                    self.reported = True
        return self.cleanup_owned(deadline)

    def cleanup_owned(self, deadline):
        control_closed = False
        if self.label == 'surface' and self.child.stdin is not None and not self.child.stdin.closed:
            self.child.stdin.close()
            control_closed = True
        result = {'label': self.label, 'pid': self.child.pid, 'recorded': self.record is not None, 'signals': [], 'reaped': False, 'controlClosed': control_closed}
        if self.reap(min(2, max(0, deadline - time.monotonic())) if control_closed else 0):
            result['reaped'] = True
            return result
        for sig in [signal.SIGTERM, signal.SIGKILL]:
            if time.monotonic() >= deadline:
                result['refused'] = 'deadline'
                break
            try:
                value = self.observer.read('cleanup-' + self.label, self.child.pid)
            except Exception:
                value = None
            if not same_owned(self.record, value, self.child.pid, os.getpid(), os.geteuid(), self.role, self.digest):
                result['reaped'] = self.reap(min(2, max(0, deadline - time.monotonic())))
                result['refused'] = 'identity-unavailable-or-changed'
                break
            try:
                if hasattr(self, 'journal'):
                    self.journal.call('cleanup-' + self.label, os.kill, self.child.pid, sig)
                else:
                    os.kill(self.child.pid, sig)
                result['signals'].append(int(sig))
            except ProcessLookupError:
                pass
            if self.reap(min(2, max(0, deadline - time.monotonic()))):
                result['reaped'] = True
                break
        return result


class Pages:
    def __init__(self, manifest):
        pages = {p['path']: p for p in manifest['pages']}
        self.counts = {path: 0 for path in pages}
        self.condition = threading.Condition()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(2)

            def do_GET(self):
                expected = '127.0.0.1:' + str(self.server.server_port)
                if self.headers.get('Host') != expected or self.path not in pages or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0' or sum(owner.counts.values()) >= 64:
                    self.send_error(400)
                    return
                page = pages[self.path]
                with owner.condition:
                    owner.counts[self.path] += 1
                    owner.condition.notify_all()
                rgb = ','.join(str(x) for x in page['sRGB'])
                body = ('<!doctype html><html><head><meta charset=utf-8><title>' + page['title'] + '</title><style>html,body{margin:0;min-height:100%;background:rgb(' + rgb + ');color:white;font:16px monospace}h1{margin:16px;font:inherit}</style></head><body><h1>' + page['title'] + '</h1></body></html>').encode()
                self.send_response(200)
                for key, value in {'Content-Type': 'text/html; charset=utf-8', 'Content-Length': str(len(body)), 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff'}.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        if 9222 <= self.server.server_port <= 9229:
            self.server.server_close()
            raise ValueError('forbidden-server-port')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise ValueError('page-server-cleanup')

    def wait_all(self, deadline):
        with self.condition:
            return self.condition.wait_for(lambda: all(value > 0 for value in self.counts.values()),
                timeout=max(0, min(5, deadline - time.monotonic())))

    def url(self, path):
        return 'http://127.0.0.1:' + str(self.server.server_port) + path


def pre_authorization_presence(observation, phase):
    if phase not in ['initial', 'app-helper', 'chrome-launched']:
        raise ValueError('pre-authorization-phase')
    verified, unresolved = [], []
    owners = observation['owners']
    for window in observation['windows']:
        if window.get('validShape') is not True or type(window.get('pid')) is not int or type(window.get('windowID')) is not int:
            raise ValueError('pre-authorization-window-shape')
        matches = [owner for owner in owners if owner.get('pid') == window['pid']]
        if len(matches) != 1 or type(matches[0].get('signingIdentifier')) is not str:
            unresolved.append({'pid': window['pid'], 'windowID': window['windowID']})
            continue
        owner = matches[0]
        if owner['signingIdentifier'] != 'com.apple.SecurityAgent':
            continue
        entry = {'pid': window['pid'], 'windowID': window['windowID']}
        if owner.get('appleAnchored') is True and owner.get('stableKernelSamples') is True and owner.get('liveStaticKernelConsistent') is True:
            verified.append(entry)
        else:
            unresolved.append(entry)
    return {'schema': 1, 'phase': phase, 'verifiedSecurityAgentWindows': verified,
        'unresolvedWindowOwners': unresolved, 'clear': not verified and not unresolved,
        'scope': 'owner-probe-setup-only', 'captureProtectionChanged': False, 'promptPurposeInferred': False}


def chrome_arguments(root, page, pages):
    rect = page['rectCGPoints']
    return ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '--user-data-dir=' + str(root / ('chrome-' + page['profile'])),
        '--no-first-run', '--no-default-browser-check', '--use-mock-keychain', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
        '--window-position=%d,%d' % (rect['x'], rect['y']), '--window-size=288,224', '--app=' + pages.url(page['path'])]


def run(root, evidence, observer_binary, app, helper, app_hash, helper_hash, chrome_hash, manifest, env, log, deadline, journal):
    journal.call('setup-host', shared.require_host)
    env = dict(env, **ASSERTIONS)
    with journal.step('setup-directories'):
        for name in ['surface-home', 'browser-home'] + ['chrome-' + page['profile'] for page in manifest['pages']]:
            (root / name).mkdir(mode=0o700)
    observer = Observer(observer_binary, evidence, env, deadline, journal)
    owned, cleanup, pre_authorization = [], [], []
    body_ok = False
    with journal.call('page-server', Pages, manifest) as pages:
        try:
            def before_authorization(phase):
                value = observer.read(phase)
                pre_authorization.append(pre_authorization_presence(value, phase))
                (evidence / 'pre-authorization-presence.json').write_text(json.dumps(pre_authorization, indent=2) + '\n')
            before_authorization('initial')
            def launch(label, args, role, digest, child_env):
                if deadline - time.monotonic() < 35:
                    raise ValueError('setup-admission-deadline')
                child = journal.call(label, Owned, label, args, role, digest, observer, child_env, log)
                owned.append(child)
                if not child.identify() and not child.reap(0):
                    raise ValueError('spawn-identity-unavailable')
                return child
            launch('app-preview', [str(app / 'Contents/MacOS/Sliccy'), '--preview'], 'ai.sliccy.mac', app_hash, env)
            surface = launch('surface', [str(helper / 'Contents/MacOS/ScreenProofSurface')], 'ai.sliccy.proof-helper', helper_hash, dict(env, HOME=str(root / 'surface-home')))
            threading.Event().wait(2)
            before_authorization('app-helper')
            for page in manifest['pages']:
                args = chrome_arguments(root, page, pages)
                launch(page['path'].rsplit('/', 1)[1], args, 'com.google.Chrome', chrome_hash, dict(env, HOME=str(root / 'browser-home')))
            threading.Event().wait(2)
            before_authorization('chrome-launched')
            with journal.step('pre-authorization-presence'):
                if not all(row['clear'] for row in pre_authorization):
                    raise ValueError('pre-authorization-security-agent-or-unresolved-owner')
            launch('authorization-requester', ['/usr/bin/osascript', '-e', 'do shell script "/usr/bin/true" with administrator privileges'], 'com.apple.osascript', manifest['osascriptCDHash'], dict(env, HOME=str(root / 'browser-home')))
            threading.Event().wait(2)
            observer.read('authorization-requested')
            pages.wait_all(deadline)
            final = observer.read('final-setup')
            with journal.step('setup-presence'):
                readiness = surface.surface_ready()
                (evidence / 'surface-ready-evidence.json').write_text(json.dumps(readiness, indent=2) + '\n')
                presence = setup_presence(final, owned, manifest, pages.counts, readiness, os.getpid(), os.geteuid())
                body_ok = presence['complete']
                if not body_ok:
                    journal.finish({'kind': 'setup', 'step': 'setup-presence', 'tool': {'pythonModule': 'owner_identity_setup'}, 'arguments': []},
                        None, error=ValueError('required-owner-fixed-page-geometry-or-helper-absent'))
            (evidence / 'setup-presence.json').write_text(json.dumps(presence, indent=2) + '\n')

        finally:
            cleanup_deadline = min(deadline, time.monotonic() + 25)
            for child in reversed(owned):
                try:
                    cleanup.append(child.cleanup(cleanup_deadline))
                except Exception as error:
                    cleanup.append({'label': child.label, 'pid': child.child.pid, 'reaped': False, 'errorClass': type(error).__name__})
            (evidence / 'owned-cleanup.json').write_text(json.dumps(cleanup, indent=2) + '\n')
            (evidence / 'page-counts.json').write_text(json.dumps(pages.counts, indent=2) + '\n')
            if time.monotonic() < deadline:
                observer.read('after-owned-cleanup')
    complete = body_ok and all(value.get('reaped') is True for value in cleanup)
    if not complete:
        journal.finish({'kind': 'setup', 'step': 'identity-setup', 'tool': {'pythonModule': 'owner_identity_setup'}, 'arguments': []}, None, error=ValueError('setup-or-owned-cleanup-incomplete'))
    return complete
