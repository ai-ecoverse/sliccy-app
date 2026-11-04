import json

FULL = 4096
AGGREGATE = 384
BUDGET = 1048576


def main():
    refreshes = 100 + 1 + 180
    fixture_code_streams = 37
    fixture_bsd_streams = 10
    streams = fixture_code_streams + fixture_bsd_streams
    flushes = 8
    legacy_chrome_rows = 4 * 2 * refreshes
    legacy_chrome_bytes = 512
    bounded_nonreceipt_reserve = 32768
    unaggregated = streams * refreshes * FULL + legacy_chrome_rows * legacy_chrome_bytes + bounded_nonreceipt_reserve
    stable_receipts = streams * FULL + streams * flushes * AGGREGATE
    nominal_refreshes = 42
    nominal_legacy = 4 * 2 * nominal_refreshes * legacy_chrome_bytes
    total = stable_receipts + nominal_legacy + bounded_nonreceipt_reserve
    assert total < BUDGET
    print(json.dumps({
        'model': 'conservative stable fixture; not an observed native run or admission guarantee',
        'fullRowCap': FULL, 'aggregateRowAllowance': AGGREGATE, 'caseJournalCap': BUDGET,
        'receiptFieldCap': 3584, 'rowEnvelopeReserve': 512,
        'refreshUpperEnvelope': {'inventoryAttempts': 100, 'pregrant': 1, 'case45sAt250ms': 180},
        'fixtureStreams': {'code': fixture_code_streams, 'bsd': fixture_bsd_streams},
        'flushAllowance': flushes,
        'withoutAggregationBytes': unaggregated,
        'stableAggregatedReceiptBytes': stable_receipts,
        'nominalRefreshes': nominal_refreshes, 'nominalLegacyChromeBytes': nominal_legacy,
        'nonreceiptReserve': bounded_nonreceipt_reserve,
        'worstTotalWithAggregation': stable_receipts + legacy_chrome_rows * legacy_chrome_bytes + bounded_nonreceipt_reserve,
        'worstMarginWithAggregation': BUDGET - stable_receipts - legacy_chrome_rows * legacy_chrome_bytes - bounded_nonreceipt_reserve,
        'nominalStableTotalWithReserve': total,
        'nominalStableMargin': BUDGET - total,
        'limits': [
            'Each full receipt immediately consumes its measured bytes; repeats reference its complete canonical SHA256 key.',
            'A changed value or any failure emits a full receipt immediately and can exhaust the unchanged journal cap.',
            '128-owner source admission maximum is not a promise that diagnostic rows fit: 256 streams and the byte cap fail closed.',
            'The nonreceipt reserve is a planning allowance, not a separate counter. Existing Chrome and frame rows remain subject to the shared cap.',
            'An adversarial stream of changes or failures has no promised margin; exact measured overflow retires authority.',
            'Stable repeated check volume is independent of refresh count; count cap100000 and case deadline still refuse overflow.'
        ]}, indent=2))

if __name__ == '__main__':
    main()
