from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import errno
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
        denied = denied or (row['processInfoAvailable'] is False and row['processInfoError'] == errno.EPERM)
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


class Owned:
    def __init__(self, label, args, role, digest, observer, env, log):
        self.label, self.role, self.digest, self.observer = label, role, digest, observer
        self.journal = observer.journal
        self.output, self.errors = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.command = self.journal.command_record(args)
        self.journal.write(dict(self.command, status='entered', exitStatus=None, stdoutTail='', stderrTail=''))
        try:
            self.child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.output, stderr=self.errors, env=env, close_fds=True)
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
            if hasattr(self, 'journal') and not self.reported:
                self.journal.finish(self.command, self.child.returncode, self.journal.tail(self.output), self.journal.tail(self.errors))
                self.output.close(); self.errors.close()
                self.reported = True
            return True
        except subprocess.TimeoutExpired:
            return False

    def cleanup(self, deadline):
        if hasattr(self, 'journal'):
            try:
                return self.journal.call('cleanup-' + self.label, self.cleanup_owned, deadline)
            finally:
                if not self.reported:
                    self.journal.finish(self.command, self.child.returncode, self.journal.tail(self.output), self.journal.tail(self.errors), ValueError('owned-child-unreaped'))
                    self.output.close(); self.errors.close()
                    self.reported = True
        return self.cleanup_owned(deadline)

    def cleanup_owned(self, deadline):
        result = {'label': self.label, 'pid': self.child.pid, 'recorded': self.record is not None, 'signals': [], 'reaped': False}
        if self.reap(0):
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
                owner.counts[self.path] += 1
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

    def url(self, path):
        return 'http://127.0.0.1:' + str(self.server.server_port) + path


def run(root, evidence, observer_binary, app, helper, app_hash, helper_hash, chrome_hash, manifest, env, log, deadline, journal):
    journal.call('setup-host', shared.require_host)
    env = dict(env, **ASSERTIONS)
    with journal.step('setup-directories'):
        for name in ['surface-home', 'browser-home', 'chrome-a', 'chrome-b']:
            (root / name).mkdir(mode=0o700)
    observer = Observer(observer_binary, evidence, env, deadline, journal)
    owned, cleanup = [], []
    body_ok = False
    with journal.call('page-server', Pages, manifest) as pages:
        try:
            observer.read('initial')
            def launch(label, args, role, digest, child_env):
                if deadline - time.monotonic() < 35:
                    raise ValueError('setup-admission-deadline')
                child = journal.call(label, Owned, label, args, role, digest, observer, child_env, log)
                owned.append(child)
                if not child.identify() and not child.reap(0):
                    raise ValueError('spawn-identity-unavailable')
                return child
            launch('app-preview', [str(app / 'Contents/MacOS/Sliccy'), '--preview'], 'ai.sliccy.mac', app_hash, env)
            launch('surface', [str(helper / 'Contents/MacOS/ScreenProofSurface')], 'ai.sliccy.proof-helper', helper_hash, dict(env, HOME=str(root / 'surface-home')))
            threading.Event().wait(2)
            observer.read('app-helper')
            for page in manifest['pages']:
                rect = page['rectCGPoints']
                args = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '--user-data-dir=' + str(root / ('chrome-' + page['profile'])),
                    '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
                    '--window-position=%d,%d' % (rect['x'], rect['y']), '--window-size=288,224', '--app=' + pages.url(page['path'])]
                launch(page['path'].rsplit('/', 1)[1], args, 'com.google.Chrome', chrome_hash, dict(env, HOME=str(root / 'browser-home')))
            threading.Event().wait(2)
            observer.read('chrome-launched')
            launch('authorization-requester', ['/usr/bin/osascript', '-e', 'do shell script "/usr/bin/true" with administrator privileges'], 'com.apple.osascript', manifest['osascriptCDHash'], dict(env, HOME=str(root / 'browser-home')))
            threading.Event().wait(2)
            observer.read('authorization-requested')
            final = observer.read('final-setup')
            visible = {row['pid'] for row in final['windows'] if row.get('validShape') is True}
            expected = {child.child.pid for child in owned if child.label in {'app-preview', 'surface', 'host-a-1', 'host-b-1'}}
            with journal.step('setup-presence'):
                body_ok = expected.issubset(visible) and all(count > 0 for count in pages.counts.values())
                if not body_ok:
                    journal.finish({'kind': 'setup', 'step': 'setup-presence', 'tool': {'pythonModule': 'owner_identity_setup'}, 'arguments': []}, None, error=ValueError('required-owner-or-fixed-page-absent'))
            (evidence / 'setup-presence.json').write_text(json.dumps({'requiredDirectOwnersPresent': expected.issubset(visible),
                'allFixedPagesRequested': all(count > 0 for count in pages.counts.values()),
                'authorizationWindowInferred': False, 'renderInferredFromGET': False}) + '\n')
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
