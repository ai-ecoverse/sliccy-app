from pathlib import Path
import json
import math
import os
import re
import stat
import subprocess
import time
import capture_stage as stage
import capture_stage_root as boundary


def require(value, reason):
    if not value:
        raise ValueError(reason)


def snapshot(path, record, acl=boundary.no_acl):
    path = Path(path)
    row = {'path': str(path), 'available': False}
    try:
        value = path.lstat()
        row.update(uid=value.st_uid, gid=value.st_gid, mode=value.st_mode, device=value.st_dev,
                   inode=value.st_ino, links=value.st_nlink, available=True, symlink=stat.S_ISLNK(value.st_mode))
        if stat.S_ISLNK(value.st_mode):
            row['target'] = os.readlink(path)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if stat.S_ISDIR(value.st_mode) else 0))
            try:
                opened = os.fstat(fd)
                require((opened.st_dev, opened.st_ino) == (value.st_dev, value.st_ino), 'ancestor-open-race')
                acl(fd)
                row['aclAbsent'] = True
            finally:
                os.close(fd)
    except Exception as error:
        row.update(errorClass=type(error).__name__, reason=str(error), aclAbsent=None)
        record('path-fact', row)
        raise
    record('path-fact', row)
    return row


def path_facts(path, record, inspect=snapshot):
    require(type(path) is str and path.startswith('/') and '\x00' not in path and len(path) <= 4096, 'fact-path')
    pending = list(Path(path).parts[1:])
    current = Path('/')
    inspect(current, record)
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            current = current.parent
            continue
        current /= part
        row = inspect(current, record)
        if row['symlink']:
            hops += 1
            require(hops <= 32, 'symlink-hop-bound')
            target = row['target']
            record('symlink-hop', {'path': str(current), 'target': target, 'hop': hops})
            parts = list(Path(target).parts)
            if target.startswith('/'):
                current = Path('/')
                pending = parts[1:] + pending
            else:
                current = current.parent
                pending = parts + pending
    return current


def signature(path, checked, record):
    path = str(path)
    checked(['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', '-R', '=anchor apple', path])
    out, err = checked(['/usr/bin/codesign', '-d', '--verbose=4', path])
    data = (out + err).decode('utf-8', errors='strict')
    identifier = re.findall(r'^Identifier=(.+)$', data, re.M)
    cdhash = re.findall(r'^CDHash=([0-9a-f]{40})$', data, re.M)
    require(len(identifier) == len(cdhash) == 1, 'signature-shape')
    result = dict(path=path, appleAnchored=True, identifier=identifier[0], cdHash=cdhash[0])
    record('signature', result)
    return result


def interpreter_component(checked, record, inspect=path_facts, validate=stage.interpreter):
    launcher = inspect('/usr/bin/python3', record)
    signature(launcher, checked, record)
    out, _ = checked(['/usr/bin/python3', '-I', '-S', '-B', '-c', stage.DISCOVERY])
    discovered = json.loads(out, object_pairs_hook=boundary.unique_object)
    require(type(discovered) is dict and set(discovered) == {'executable', 'stdlib', 'prefix'}, 'discovery-shape')
    record('discovery', discovered)
    resolved = {key: inspect(value, record) for key, value in discovered.items()}
    framework = next((x for x in (resolved['prefix'], *resolved['prefix'].parents) if x.name == 'Python3.framework'), None)
    require(framework is not None, 'framework-unavailable')
    signature(resolved['executable'], checked, record)
    signature(framework, checked, record)
    executable, digest = validate(discovered, lambda name, args: checked(args), record)
    record('interpreter-validated', {'path': str(executable), 'sha256': digest})
    return True


def sample(row):
    require(type(row) is dict and set(row) == {'pid', 'bsdStatus', 'pathStatus', 'bsd', 'path'}, 'sample-shape')
    require(all(type(row[k]) is int for k in ('pid', 'bsdStatus', 'pathStatus')), 'sample-status-type')
    require(row['pid'] > 0 and row['bsdStatus'] == row['pathStatus'] == 0, 'sample-unavailable')
    value = row['bsd']
    require(type(value) is dict and set(value) == {'pid', 'parent', 'uid', 'seconds', 'microseconds'}, 'bsd-shape')
    require(all(type(value[k]) is int for k in ('pid', 'parent', 'uid', 'microseconds')), 'bsd-type')
    require(value['pid'] == row['pid'] and value['parent'] > 0 and value['uid'] >= 0 and 0 <= value['microseconds'] < 1000000,
            'bsd-values')
    require(type(value['seconds']) is str and re.fullmatch('[1-9][0-9]*', value['seconds']) and type(row['path']) is str and row['path'].startswith('/') and len(row['path']) <= 4096, 'bsd-time-path')
    return value


def candidate(row):
    require(type(row) is dict and set(row) == {'sudoPID', 'launchWall', 'before', 'after', 'code', 'chain', 'chainAfter'}, 'candidate-shape')
    require(type(row['sudoPID']) is int and row['sudoPID'] > 0, 'sudo-pid')
    require(type(row['launchWall']) in (int, float) and math.isfinite(row['launchWall']), 'launch-time')
    root = sample(row['before'])
    require(row['before'] == row['after'] and root['uid'] == 0 and row['before']['path'] == '/bin/sleep', 'root-binding')
    start = int(root['seconds']) + root['microseconds'] / 1000000
    require(row['launchWall'] <= start <= row['launchWall'] + 2, 'root-start')
    code = row['code']
    require(type(code) is dict and set(code) == {'matched', 'identifier', 'cdHashBase64'} and code['matched'] is True
            and type(code['identifier']) is str and code['identifier'] and type(code['cdHashBase64']) is str, 'root-code')
    import base64
    require(len(base64.b64decode(code['cdHashBase64'], validate=True)) == 20, 'root-code-hash')
    chain = row['chain']
    require(type(chain) is list and 1 <= len(chain) <= 8 and chain == row['chainAfter'], 'chain-bracket')
    samples = {}
    for item in chain:
        value = sample(item)
        require(value['pid'] not in samples, 'chain-duplicate')
        samples[value['pid']] = value
    require(next((item for item in chain if item['pid'] == root['pid']), None) == row['before'], 'root-chain-binding')
    pid = root['pid']
    for _ in range(5):
        require(pid in samples, 'chain-incomplete')
        if pid == row['sudoPID']:
            return True
        pid = samples[pid]['parent']
    raise ValueError('chain-depth')


def visibility_records(data, code):
    require(type(data) is bytes and len(data) <= 4 * 1024 * 1024 and data.endswith(b'\n'), 'visibility-bytes')
    rows = [json.loads(line, object_pairs_hook=boundary.unique_object) for line in data.splitlines()]
    require(0 < len(rows) <= 1500, 'visibility-count')
    pending = None
    candidates = []
    spawn = None
    spawn_entered = False
    reap_entered = False
    last_clock = -1
    for index, row in enumerate(rows, 1):
        require(type(row) is dict and set(row) == {'schema', 'seq', 'phase', 'state', 'elapsedMs', 'facts'}, 'visibility-shape')
        require(type(row['schema']) is int and row['schema'] == 1 and type(row['seq']) is int and row['seq'] == index, 'visibility-sequence')
        elapsed = row['elapsedMs']
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= last_clock, 'visibility-clock')
        last_clock = elapsed
        phase = row['phase']
        require(phase in {'placement', 'spawn', 'bsd', 'pidpath', 'requirement', 'guest', 'dynamic-validity', 'guest-static', 'live-info',
                          'file-static', 'static-validity', 'file-info', 'candidate', 'children', 'reap', 'failure', 'result'}, 'visibility-phase')
        require(type(row['facts']) is dict, 'visibility-facts')
        if row['state'] == 'entered':
            require(pending is None, 'phase-incomplete')
            pending = phase
            if phase == 'spawn':
                require(not spawn_entered and row['facts'] == {'tool': '/usr/bin/sudo', 'arguments': ['-n', '--', '/bin/sleep', '2']}, 'single-fixed-spawn')
                spawn_entered = True
            if phase == 'reap':
                require(spawn is not None and not reap_entered and set(row['facts']) == {'pid'}
                        and type(row['facts']['pid']) is int and row['facts']['pid'] == spawn['pid'], 'reap-spawn-binding')
                reap_entered = True
        else:
            require(row['state'] == 'completed', 'visibility-state')
            if phase not in {'candidate', 'failure', 'result'}:
                require(pending == phase, 'phase-unmatched')
                pending = None
            if phase == 'spawn':
                facts = row['facts']
                require(spawn_entered and spawn is None and set(facts) == {'status', 'pid', 'launchWall'}
                        and type(facts['status']) is int and facts['status'] == 0
                        and type(facts['pid']) is int and facts['pid'] > 0
                        and type(facts['launchWall']) in (int, float) and math.isfinite(facts['launchWall']), 'successful-spawn')
                spawn = facts
            if phase == 'candidate':
                require(spawn is not None and not reap_entered and row['facts'].get('sudoPID') == spawn['pid']
                        and row['facts'].get('launchWall') == spawn['launchWall'], 'candidate-spawn-binding')
            if phase == 'candidate' and elapsed <= 2000:
                try:
                    candidates.append(candidate(row['facts']))
                except ValueError:
                    pass
    require(pending is None and rows[-1]['phase'] == 'result', 'phase-incomplete')
    require(all(type(rows[-1]['facts'].get(k)) is bool for k in ('candidateObserved', 'reaped')), 'result-boolean-type')
    require(code == 0 and any(candidates) and rows[-1]['facts'] == {'candidateObserved': True, 'reaped': True}, 'visibility-inconclusive')
    reap = [x for x in rows if x['phase'] == 'reap' and x['state'] == 'completed']
    require(spawn is not None and reap_entered and len(reap) == 1 and reap[0]['facts'].get('pid') == spawn['pid'] and all(type(reap[0]['facts'].get(k)) is int for k in ('pid', 'waitStatus', 'errno')) and reap[0]['facts']['reaped'] is True and reap[0]['facts']['waitStatus'] == 0
            and reap[0]['facts']['errno'] == 0, 'owned-reap')
    return {'schema': 1, 'rootVisibility': True, 'appDesignatedRequirementProtocolProven': False, 'captureProven': False}
