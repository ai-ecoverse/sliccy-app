import json


def model():
    cap = 1048576
    prior_nominal = 541696
    refusal_allowance = 104
    clock_allowance = 1
    added = (refusal_allowance + clock_allowance) * 4096
    nominal = prior_nominal + added
    refreshes = 100 + 1 + 600
    without = 47 * refreshes * 4096 + 8 * refreshes * 512 + 32768 + added
    with_aggregation = 47 * 4096 + 47 * 8 * 384 + 8 * refreshes * 512 + 32768 + added
    return {'scope':'planning only; not an observed fit or timing guarantee','journalCapBytes':cap,
        'priorConservativeNominalBytes':prior_nominal,'newFailedAttemptAllowance':refusal_allowance,
        'newClockAllowance':clock_allowance,'rowCapBytes':4096,'addedBytes':added,
        'nominalTotalBytes':nominal,'nominalMarginBytes':cap-nominal,
        'worstRefreshEnvelope':refreshes,'withoutAggregationBytes':without,
        'withAggregationWorstBytes':with_aggregation,'withAggregationWorstMarginBytes':cap-with_aggregation,
        'limits':['Each attempt retains its first issue; first failed source-monitor iteration terminates the monitor.',
            '104 refusal rows conservatively cover the original5-second/50ms initial retry plus authorization baseline, refresh and monitor.',
            'The150-second whole-case envelope is deliberately pessimistic for refresh volume; it is not a capture allowance. Capture remains10seconds.',
            'Changed receipt keys, extra owners or slow/unsettled workers can exhaust bytes or deadlines; original journal overflow remains fail-closed.',
            'No capacity, row or stream bound is raised. Aggregation and all identity checks remain unchanged.']}

if __name__ == '__main__':
    value=model()
    assert value['nominalMarginBytes']>0 and value['withAggregationWorstMarginBytes']<0
    print(json.dumps(value,indent=2))
