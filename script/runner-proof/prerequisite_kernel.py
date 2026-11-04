import base64
import json
import math
import re
import capture_stage_root as boundary
from prerequisite_probe import sample
import prerequisite_binding as binding

APP_HASH = 'stPyiHVvDcejjgvo90frsO5TZ2c='
PAIRED = {'placement', 'bsd', 'pidpath', 'file-static', 'requirement', 'static-validity', 'file-info',
          'guest', 'dynamic-validity', 'guest-static', 'live-info', 'kernel-hash', 'spawn', 'hello', 'facts', 'reap', 'root-exit-bsd', 'binding-requirement-text', 'binding-apple-requirement',
          'binding-static-validity', 'binding-live-apple-anchor', 'binding-kernel-flags', 'binding-path-resolve', 'binding-path-stat'}
SINGLES = {'target-before', 'target-after', 'candidate', 'ack', 'failure', 'result', 'binding-code-info', 'binding-comparison'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def parse(data):
    require(type(data) is bytes and 0 < len(data) <= 4 * 1024 * 1024 and data.endswith(b'\n'), 'kernel-output')
    rows = [json.loads(line, object_pairs_hook=boundary.unique_object) for line in data.splitlines()]
    require(0 < len(rows) <= 512, 'kernel-row-bound')
    pending, clock = [], -1
    for index, row in enumerate(rows, 1):
        require(type(row) is dict and set(row) == {'schema', 'seq', 'phase', 'state', 'elapsedMs', 'facts'}
                and type(row['schema']) is int and row['schema'] == 2 and type(row['seq']) is int and row['seq'] == index,
                'kernel-row-shape')
        require(type(row['elapsedMs']) in (int, float) and math.isfinite(row['elapsedMs']) and row['elapsedMs'] >= clock,
                'kernel-clock')
        clock = row['elapsedMs']
        require(type(row['facts']) is dict, 'kernel-facts')
        if row['phase'] == 'binding-static-validity':
            binding.static_validity(row['state'], row['facts'])
        if row['state'] == 'completed':
            if row['phase'] == 'binding-comparison':
                binding.comparison(row['facts'])
            elif row['phase'] in ('binding-kernel-flags', 'binding-live-apple-anchor'):
                binding.supplemental(row['phase'], row['facts'])
        phase = row['phase']
        require(phase in PAIRED | SINGLES, 'kernel-phase')
        if row['state'] == 'entered':
            require(phase in PAIRED and (not pending or pending == ['reap'] and phase == 'root-exit-bsd'), 'kernel-phase-nesting')
            pending.append(phase)
        else:
            require(row['state'] == 'completed', 'kernel-state')
            if phase in PAIRED:
                require(pending and pending[-1] == phase, 'kernel-phase-match')
                pending.pop()
            elif phase == 'failure':
                pending = []
    require(not pending and rows[-1]['phase'] == 'result', 'kernel-incomplete')
    return rows


def one(rows, phase):
    selected = [x for x in rows if x['phase'] == phase and x['state'] == 'completed']
    require(len(selected) == 1, 'kernel-unique-' + phase)
    return selected[0]['facts']


def cleanup_confirmed(rows):
    spawned = [x['facts'] for x in rows if x['phase'] == 'spawn' and x['state'] == 'completed']
    entered = [x for x in rows if x['phase'] == 'spawn' and x['state'] == 'entered']
    if not entered and not spawned:
        return True
    require(len(entered) == len(spawned) == 1, 'kernel-spawn-incomplete')
    launch = spawned[0]
    require(set(launch) == {'status', 'pid', 'launchWall'} and type(launch['status']) is int and type(launch['pid']) is int,
            'kernel-spawn-shape')
    if launch['status'] != 0:
        require(launch['pid'] == 0, 'kernel-failed-spawn-pid')
        return True
    require(launch['pid'] > 0, 'kernel-spawn-pid')
    reap = one(rows, 'reap')
    require(set(reap) == {'pid', 'reaped', 'rootGone', 'rootPID', 'waitStatus', 'errno'}
            and all(type(reap[k]) is int for k in ('pid', 'rootPID', 'waitStatus', 'errno'))
            and reap['pid'] == launch['pid'] and reap['reaped'] is True and reap['rootGone'] is True
            and reap['rootPID'] > 0 and reap['errno'] == 0, 'kernel-cleanup-unconfirmed')
    hello = json.loads(base64.b64decode(one(rows, 'hello')['rawBase64'], validate=True), object_pairs_hook=boundary.unique_object)
    require(set(hello) == {'schema', 'pid'} and type(hello['schema']) is int and hello['schema'] == 1
            and type(hello['pid']) is int and hello['pid'] == reap['rootPID'], 'kernel-root-cleanup-binding')
    if reap['rootPID'] != launch['pid']:
        require(one(rows, 'root-exit-bsd') == {'pid': reap['rootPID'], 'status': 3}, 'kernel-root-exit-binding')
    return True


def root_candidate(value, launch, executable):
    require(type(value) is dict and set(value) == {'sudoPID', 'launchWall', 'before', 'after', 'chain', 'chainAfter', 'code'}, 'kernel-candidate-shape')
    require(type(value['sudoPID']) is int and value['sudoPID'] == launch['pid'] and value['launchWall'] == launch['launchWall'], 'kernel-candidate-spawn')
    root = sample(value['before'])
    require(value['before'] == value['after'] and root['uid'] == 0 and value['before']['path'] == executable, 'kernel-root-binding')
    start = int(root['seconds']) + root['microseconds'] / 1000000
    require(type(launch['launchWall']) in (int, float) and math.isfinite(launch['launchWall'])
            and launch['launchWall'] <= start <= launch['launchWall'] + 2, 'kernel-start')
    require(value['code'] == {'identifier': 'ai.sliccy.mac', 'path': executable, 'hash': APP_HASH, 'matched': True}
            and value['code']['matched'] is True, 'kernel-app-code')
    chain = value['chain']
    require(type(chain) is list and 1 <= len(chain) <= 5 and chain == value['chainAfter'], 'kernel-chain-bracket')
    seen = {}
    for item in chain:
        identity = sample(item)
        require(identity['pid'] not in seen, 'kernel-chain-duplicate')
        seen[identity['pid']] = item
    require(seen.get(root['pid']) == value['before'], 'kernel-root-chain-binding')
    current = root['pid']
    visited = set()
    while current in seen and current not in visited:
        visited.add(current)
        if current == launch['pid']:
            require(visited == set(seen), 'kernel-extra-chain')
            return root
        current = seen[current]['bsd']['parent']
    raise ValueError('kernel-chain-incomplete')


def target_binding(before, after, facts, pid):
    require(before == after and type(before) is dict and set(before) == {'sample', 'code'}, 'kernel-target-bracket')
    value, code = before['sample'], before['code']
    require(type(code) is dict and set(code) == {'identifier', 'path', 'hash', 'matched'}
            and code['identifier'] == 'com.apple.WindowServer' and code['matched'] is True
            and type(code['path']) is str and code['path'].startswith('/')
            and len(base64.b64decode(code['hash'], validate=True)) == 20, 'kernel-target-code')
    require(type(facts) is dict and set(facts) == {'schema', 'sample', 'path', 'hash'}
            and type(facts['schema']) is int and facts['schema'] == 1
            and facts['path'] == code['path'] and facts['hash'] == code['hash'], 'kernel-child-facts')
    identity = facts['sample']
    require(type(identity) is dict and set(identity) == {'pid', 'parent', 'uid', 'seconds', 'microseconds'}
            and all(type(x) is int for x in identity.values()) and identity['pid'] == pid and identity['parent'] > 0
            and identity['uid'] >= 0 and identity['seconds'] > 0 and 0 <= identity['microseconds'] < 1000000, 'kernel-target-facts')
    require(type(value) is dict and set(value) == {'pid', 'bsdStatus', 'pathStatus', 'bsd', 'path'}
            and all(type(value[k]) is int for k in ('pid', 'bsdStatus', 'pathStatus'))
            and value['pid'] == pid and value['pathStatus'] == 0 and value['path'] == code['path'], 'kernel-target-sample')
    if value['bsdStatus'] == 0:
        observed = sample(value)
        require(observed == dict(identity, seconds=str(identity['seconds'])), 'kernel-target-contradiction')
    else:
        require(value['bsdStatus'] == 1 and value['bsd'] is None, 'kernel-target-unavailable')
    return True


def outcome(rows, status, run, pid):
    require(status == 0 and not any(x['phase'] == 'failure' for x in rows), 'kernel-native-failure')
    executable = '/Library/' + boundary.canonical_run(run) + '/Sliccy.app/Contents/MacOS/Sliccy'
    require(one(rows, 'placement') == {'run': run, 'target': pid, 'executable': executable}, 'kernel-placement-binding')
    require(cleanup_confirmed(rows) and one(rows, 'reap')['waitStatus'] == 0, 'kernel-cleanup')
    launch = one(rows, 'spawn')
    root = root_candidate(one(rows, 'candidate'), launch, executable)
    require(one(rows, 'ack') == {'rootPID': root['pid']} and one(rows, 'reap')['rootPID'] == root['pid'], 'kernel-ack-binding')
    fact_bytes = base64.b64decode(one(rows, 'facts')['rawBase64'], validate=True)
    require(len(fact_bytes) < 4096, 'kernel-fact-bound')
    facts = json.loads(fact_bytes, object_pairs_hook=boundary.unique_object)
    target_binding(one(rows, 'target-before'), one(rows, 'target-after'), facts, pid)
    for phase in ('file-static', 'requirement', 'static-validity', 'file-info', 'guest', 'dynamic-validity', 'guest-static', 'live-info', 'kernel-hash'):
        complete = [x for x in rows if x['phase'] == phase and x['state'] == 'completed']
        require(len(complete) == 3 and all(type(x['facts'].get('status')) is int and x['facts']['status'] == 0 for x in complete), 'kernel-required-check-' + phase)
    requirements = [x['facts'] for x in rows if x['phase'] == 'requirement' and x['state'] == 'entered']
    require(requirements == [{'designated': False, 'rule': 'anchor apple and identifier "com.apple.WindowServer"'},
                             {'designated': True, 'rule': 'staged-build12-designated-requirement'},
                             {'designated': False, 'rule': 'anchor apple and identifier "com.apple.WindowServer"'}]
            and all(type(x['designated']) is bool for x in requirements), 'kernel-check-requirements')
    for phase, flags in [('static-validity', 25), ('dynamic-validity', 16)]:
        require(all(x['facts'] == {'flags': flags} and type(x['facts'].get('flags')) is int for x in rows if x['phase'] == phase and x['state'] == 'entered'), 'kernel-check-flags')
    important = ['target-before', 'spawn', 'hello', 'candidate', 'ack', 'facts', 'target-after', 'reap', 'result']
    positions = [next(i for i, x in enumerate(rows) if x['phase'] == phase and x['state'] == 'completed') for phase in important]
    require(positions == sorted(positions), 'kernel-order')
    result = one(rows, 'result')
    require(result == {'observed': True, 'reaped': True, 'rootGone': True} and all(type(v) is bool for v in result.values()), 'kernel-result')
    return {'schema': 2, 'rootVisibility': True, 'fixedRootChildVerified': True,
            'captureProven': False, 'productionParentPathExecuted': False}
