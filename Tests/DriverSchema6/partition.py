import json
from pathlib import Path


def select_mutations(mutations, index, count):
    if type(index) is not int or type(count) is not int or count != 6 or index not in (0, 1, 2, 3, 4, 5):
        raise ValueError('fixed-shard-selector')
    names = [row['name'] for row in mutations]
    if len(names) != 135 or len(set(names)) != 135 or any(type(name) is not str or not name for name in names):
        raise ValueError('fixed-mutant-universe')
    ledger = json.loads((Path(__file__).parent / 'shards.json').read_text())
    assignment = ledger['assignment']
    if ledger['shardCount'] != 6 or len(assignment) != 6:
        raise ValueError('fixed-shard-ledger')
    flattened = [name for shard in assignment for name in shard]
    if len(flattened) != 135 or sorted(flattened) != sorted(names) or any(shard != sorted(set(shard)) for shard in assignment):
        raise ValueError('fixed-shard-exhaustiveness')
    if 'v83-nominal-volume-gate-bypassed' not in assignment[0] or 'v83-overflow-loss-blocker-removed' not in assignment[1]:
        raise ValueError('fixed-heavy-shard-assignment')
    selected_ids = assignment[index]
    selected_set = set(selected_ids)
    return [row for row in mutations if row['name'] in selected_set], selected_ids, sorted(names)
