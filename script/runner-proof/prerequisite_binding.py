POLICY = frozenset(('kernel-status-zero', 'live-cdhash-type', 'live-cdhash-length', 'live-static-cdhash',
                    'live-kernel-cdhash', 'live-expected-cdhash', 'live-identifier', 'static-identifier', 'live-input-path'))
FILESYSTEM = frozenset(('filesystem-input-live-inode', 'filesystem-input-static-inode', 'filesystem-live-static-inode'))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def typed(value):
    require(type(value) is dict and value.get('type') in {'data', 'string', 'number', 'null', 'other'}, 'binding-value-type')
    kind = value['type']
    if kind in ('data', 'string'):
        require(set(value) == {'type', 'length', 'value'} and type(value['length']) is int and value['length'] >= 0, 'binding-value-length')
        require(value['value'] is None if value['length'] > 4096 else type(value['value']) is str, 'binding-value-bound')
        if kind == 'data' and value['value'] is not None:
            import base64
            require(len(base64.b64decode(value['value'], validate=True)) == value['length'], 'binding-value-data')
    else:
        require(set(value) == {'type', 'value'}, 'binding-value-shape')
        require(type(value['value']) is int if kind == 'number' else value['value'] is None, 'binding-value-scalar')


def comparison(row):
    require(type(row) is dict and set(row) == {'comparison', 'left', 'right', 'matched', 'affectsVerdict', 'status'}, 'binding-row-shape')
    name = row['comparison']
    require(name in POLICY | FILESYSTEM and type(row['affectsVerdict']) is bool, 'binding-row-name')
    if name in POLICY:
        require(row['status'] == 'compared' and type(row['matched']) is bool, 'binding-row-result')
        require(row['affectsVerdict'] is False if name == 'live-static-cdhash' else row['affectsVerdict'] is True or name == 'live-expected-cdhash', 'binding-policy-label')
        typed(row['left']); typed(row['right'])
    else:
        require(row['affectsVerdict'] is False and row['status'] in ('compared', 'unavailable'), 'binding-filesystem-label')
        require(type(row['matched']) is bool if row['status'] == 'compared' else row['matched'] is None, 'binding-filesystem-result')
        for side in ('left', 'right'):
            value = row[side]
            require(type(value) is dict and 'statStatus' in value and 'device' in value and 'inode' in value, 'binding-filesystem-shape')
            require(type(value['statStatus']) is int or value['statStatus'] is None, 'binding-filesystem-status')
            for key in ('device', 'inode'):
                require(type(value[key]) is int if value['statStatus'] == 0 else value[key] is None, 'binding-filesystem-fact')
    return row


def supplemental(phase, row):
    if phase == 'binding-kernel-flags':
        require(set(row) == {'status', 'errno', 'flags', 'platformBinary', 'affectsVerdict'}
                and type(row['status']) is int and type(row['errno']) is int and row['affectsVerdict'] is False, 'binding-platform-shape')
        require(type(row['flags']) is int and type(row['platformBinary']) is bool if row['status'] == 0
                else row['flags'] is None and row['platformBinary'] is None, 'binding-platform-values')
    elif phase == 'binding-live-apple-anchor':
        require(set(row) == {'queried', 'status', 'appleAnchored', 'affectsVerdict'}
                and type(row['queried']) is bool and row['affectsVerdict'] is False, 'binding-anchor-shape')
        require(type(row['status']) is int and type(row['appleAnchored']) is bool if row['queried']
                else row['status'] is None and row['appleAnchored'] is None, 'binding-anchor-values')


def static_validity(state, row):
    names = {'static-default': 0, 'static-all-architectures': 1, 'static-nested': 8, 'static-strict': 16}
    expected = {'check', 'flags', 'affectsVerdict'} | ({'status', 'matched'} if state == 'completed' else set())
    require(state in ('entered', 'completed') and type(row) is dict and set(row) == expected, 'binding-static-shape')
    require(row['check'] in names and type(row['flags']) is int and row['flags'] == names[row['check']]
            and row['affectsVerdict'] is False, 'binding-static-policy')
    if state == 'completed':
        require(type(row['status']) is int and -(2**31) <= row['status'] < 2**31
                and type(row['matched']) is bool and row['matched'] == (row['status'] == 0), 'binding-static-result')
