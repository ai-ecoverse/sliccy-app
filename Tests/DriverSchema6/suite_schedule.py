import re
from runtime_result import suite_result

NOMINAL = 'TestRunnerV83ActualFullNominalVolumeGate'
OVERFLOW = 'TestRunnerV83MaxFixtureOverflowAndLossBlockers'


def checked_suite_groups(ledger):
    names = ledger['baselineTests']
    if len(names) != 101 or len(set(names)) != 101 or names != sorted(names) or any(not re.fullmatch(r'Test[A-Za-z0-9_]+', n) for n in names):
        raise ValueError('full-suite-universe')
    groups = ledger['suiteInvocations']
    expected = [
        {'id': 'non-heavy', 'tests': [n for n in names if n not in (NOMINAL, OVERFLOW)], 'testSeconds': 30},
        {'id': 'nominal', 'tests': [NOMINAL], 'testSeconds': 60},
        {'id': 'overflow', 'tests': [OVERFLOW], 'testSeconds': 30},
    ]
    if groups != expected:
        raise ValueError('fixed-suite-invocation-partition')
    flattened = [name for group in groups for name in group['tests']]
    if len(flattened) != len(set(flattened)) or sorted(flattened) != names:
        raise ValueError('full-suite-disjoint-exhaustive')
    return groups


def mutation_test_seconds(name):
    return 60 if name.split('/')[0] == NOMINAL else 30


def run_full_suite(phase, binary, command, ledger, report):
    groups = checked_suite_groups(ledger)
    accepted = []
    for group in groups:
        names = group['tests']
        pattern = '^(' + '|'.join(re.escape(name) for name in names) + ')$'
        limit = group['testSeconds']
        result = command(phase + '-' + group['id'] + '-runtime', [binary, '-test.count=1', '-test.timeout=' + str(limit) + 's', '-test.v', '-test.run', pattern], limit + 15)
        valid = suite_result(result, names)
        report({'phase': phase, 'invocation': group['id'], 'tests': names, 'testSeconds': limit, 'returncode': result.returncode, 'exactTestsPassed': valid})
        if not valid:
            raise AssertionError('full-suite-invocation-failed:' + phase + ':' + group['id'])
        accepted.extend(names)
    if len(accepted) != len(set(accepted)) or sorted(accepted) != ledger['baselineTests']:
        raise AssertionError('full-suite-executed-coverage')
