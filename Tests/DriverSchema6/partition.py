def select_mutations(mutations, index, count):
    if type(index) is not int or type(count) is not int or count != 2 or index not in (0, 1):
        raise ValueError('fixed-shard-selector')
    names = [row['name'] for row in mutations]
    if len(names) != 101 or len(set(names)) != 101 or any(type(name) is not str or not name for name in names):
        raise ValueError('fixed-mutant-universe')
    ordered = sorted(names)
    selected_ids = ordered[index::count]
    selected_set = set(selected_ids)
    return [row for row in mutations if row['name'] in selected_set], selected_ids, ordered
