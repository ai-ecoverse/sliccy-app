from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
import subprocess
import threading
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


class Observer:
    def __init__(self, binary, evidence, env, deadline):
        self.binary, self.evidence, self.env, self.deadline = binary, evidence, env, deadline
        self.sequence = 0

    def read(self, phase, pid=None):
        remaining = min(15, self.deadline - time.monotonic())
        if remaining <= 0:
            raise ValueError('observer-deadline')
        self.sequence += 1
        target = self.evidence / ('observation-%03d.json' % self.sequence)
        args = [str(self.binary)] + ([] if pid is None else ['--owner', str(pid)])
        with target.open('xb') as out, (self.evidence / 'observer-errors.log').open('ab') as error:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=error, env=self.env, timeout=remaining)
        if result.returncode != 0 or target.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('observer-failed')
        value = json.loads(target.read_text())
        with (self.evidence / 'observation-index.ndjson').open('a') as index:
            index.write(json.dumps({'phase': phase, 'pid': pid, 'file': target.name, 'sha256': shared.sha(target), 'monotonicSeconds': time.monotonic()}) + '\n')
        if pid is None and (value.get('available') is not True or value.get('allWindowRowsClassifiable') is not True):
            raise ValueError('window-inventory-unavailable')
        return value


class Owned:
    def __init__(self, label, args, role, digest, observer, env, log):
        self.label, self.role, self.digest, self.observer = label, role, digest, observer
        self.child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env, close_fds=True)
        self.record = None

    def identify(self):
        value = self.observer.read('spawn-' + self.label, self.child.pid)
        if same_owned(value, value, self.child.pid, os.getpid(), os.geteuid(), self.role, self.digest):
            self.record = value
        return self.record is not None

    def reap(self, seconds):
        try:
            self.child.wait(timeout=max(0, seconds))
            return True
        except subprocess.TimeoutExpired:
            return False

    def cleanup(self, deadline):
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


def run(root, evidence, observer_binary, app, helper, app_hash, helper_hash, chrome_hash, manifest, env, log, deadline):
    shared.require_host()
    env = dict(env, **ASSERTIONS)
    for name in ['surface-home', 'browser-home', 'chrome-a', 'chrome-b']:
        (root / name).mkdir(mode=0o700)
    observer = Observer(observer_binary, evidence, env, deadline)
    owned, cleanup = [], []
    body_ok = False
    with Pages(manifest) as pages:
        try:
            observer.read('initial')
            def launch(label, args, role, digest, child_env):
                if deadline - time.monotonic() < 35:
                    raise ValueError('setup-admission-deadline')
                child = Owned(label, args, role, digest, observer, child_env, log)
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
            body_ok = expected.issubset(visible) and all(count > 0 for count in pages.counts.values())
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
    return body_ok and all(value.get('reaped') is True for value in cleanup)
