#!/usr/bin/python3 -I
"""Test-only local CLI stand-in. No keys, browser, network client or login. All
state (including the socket and an op-name-only receipt) is in a disposable 0700
profile. Never echo argv, stdin, control data, URLs or fingerprints to stderr.
"""
import json
import os
from pathlib import Path
import socket
import sys
import time

root = Path(__file__).resolve().parent
config = json.loads((root / 'fixture.json').read_bytes())
ops = ['status', 'cdp-lease-list', 'cdp-lease-approve', 'cdp-lease-deny', 'cdp-lease-revoke']
mode = config['mode']

def record(op):
    with (root / 'ops').open('a') as f:
        f.write(op + '\n')

if sys.argv[1:] == ['capabilities', '--json']:
    record('capabilities')
    print(json.dumps({'schema': 1, 'contract': 1, 'version': 'fixture',
                      'control': {'v': 1, 'ops': ['detach'] + ops},
                      'commands': {'prompt': {'json': 'events'}, 'abort': {'json': 'none'},
                                   'follow': {'json': 'events', 'cdpLeaseV1': mode != 'old'}}}))
    sys.exit(0)

endpoint = 'http://127.0.0.1:49999'
label = 'fixture-job'
assert sys.argv[1:] == ['-', 'follow', '--json', '--lease-browser', endpoint, '--name', label]
assert sys.stdin.readline().strip() == 'https://fixture.invalid/join/test-only'
record('exclusive-follow')
identity = {'jkt': config['jkt'], 'browser': config['browser'], 'link': label}
billing = {'kind': 'origin', 'url': 'https://billing.example'}
receipt = {'kind': 'exact', 'url': 'https://receipts.example/r/1042?q=two#detail'}
pending = [dict(identity, request='R1', ttlSeconds=3600, allow=[billing])]
active = []
reads = 0
pid = os.getpid()
with socket.socket(socket.AF_UNIX) as server:
    server.bind(str(root / f'{pid}.sock'))
    server.listen(1)
    server.settimeout(20)
    print('{"event":"linked","schema":1}', flush=True)
    while True:
        conn, _ = server.accept()
        with conn, conn.makefile('rb') as rx:
            conn.settimeout(5)
            req = json.loads(rx.readline(4096))
            op = req['op']
            assert op in ops
            record(op)
            reply = {'v': 1, 'ok': True}
            if op == 'status':
                assert req == {'v': 1, 'op': op}
                reply.update(pid=(pid + 1 if mode == 'wrong-pid' else pid),
                             ops=(ops[:-1] if mode == 'missing' else ops),
                             offers=(['cdp', 'cdp-lease-v1'] if mode == 'mixed' or (mode == 'lost-exclusive' and reads >= 2) else ['cdp-lease-v1']))
            elif op == 'cdp-lease-list':
                assert req == {'v': 1, 'op': op}
                reads += 1
                if mode == 'changed' and reads > 1:
                    pending[0]['ttlSeconds'] = 7200  # buggy broker: same ID, altered terms
                reply.update(pending=pending, active=active)
            elif op == 'cdp-lease-revoke':
                assert req == {'v': 1, 'op': op, 'lease': active[0]['lease']}
                active = []
            else:
                item = pending.pop()
                assert req == {'v': 1, 'op': op, 'request': item['request']}
                if op == 'cdp-lease-approve':
                    if item['request'] == 'R1':
                        active = [dict(identity, lease='L1', allow=[billing], exp=int(time.time()) + 3600)]
                        pending = [dict(identity, request='R2', parent='L1', allow=[receipt])]
                    else:
                        active = [dict(identity, lease='L2', allow=[billing, receipt], exp=active[0]['exp'])]
                if mode == 'lost-ack':
                    continue  # close after mutation; no implicit retry is safe
            conn.sendall(json.dumps(reply).encode() + b'\n')
