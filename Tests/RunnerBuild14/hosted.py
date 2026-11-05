from pathlib import Path
import importlib.util
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('slice_hosted', ROOT / 'Tests/RunnerSlice/hosted.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
harness.OUT = ROOT / 'build14-results'
harness.FILTER = 'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests|ChildReceiptTests|OwnerEvidenceTests|JournalTests|InventoryDiagnosticsTests)'
DIAGNOSTICS = 'Sources/Sliccy/Screen/ScreenRunnerInventoryDiagnostics.swift'
ALLOWANCE = 'Sources/Sliccy/Screen/ScreenRunnerSetupAllowance.swift'
harness.PLAN = [
    ('refusal-first-only', DIAGNOSTICS, 'if first {', 'if true {', 'everyRetryKeepsItsOwnIssueWithoutDuplicateFallback'),
    ('refusal-drop', DIAGNOSTICS, 'if first {', 'if first && false {', 'everyRetryKeepsItsOwnIssueWithoutDuplicateFallback'),
    ('refusal-attempt', DIAGNOSTICS, 'ordinal += 1', 'ordinal += 0', 'everyRetryKeepsItsOwnIssueWithoutDuplicateFallback'),
    ('refusal-comparison', DIAGNOSTICS, 'checks.first(where: { !$0.1 })?.0 ?? .operation', '.operation', 'realBoundaryNamesBundleBoundsLayerAndPIDRefusals'),
    ('refusal-pid', DIAGNOSTICS, '?? .operation, pid: pid, windowID: windowID,', '?? .operation, pid: nil, windowID: windowID,', 'realBoundaryNamesBundleBoundsLayerAndPIDRefusals'),
    ('refusal-window', DIAGNOSTICS, 'pid: pid, windowID: windowID,\n                    signingIdentifier:', 'pid: pid, windowID: nil,\n                    signingIdentifier:', 'realBoundaryNamesBundleBoundsLayerAndPIDRefusals'),
    ('refusal-cg', DIAGNOSTICS, 'cg: cg, sck: sck, owner: owner, at: at', 'cg: [], sck: sck, owner: owner, at: at', 'realBoundaryNamesBundleBoundsLayerAndPIDRefusals'),
    ('refusal-sck', DIAGNOSTICS, 'cg: cg, sck: sck, owner: owner, at: at', 'cg: cg, sck: [], owner: owner, at: at', 'actualSCKConstructorRetainsNilOwnerAndPairedCGFacts'),
    ('identifier-length', DIAGNOSTICS, 'bytes.count <= 255', 'bytes.count <= 256', 'identifierCodecAndNullableFactsNeverEmitContent'),
    ('identifier-charset', DIAGNOSTICS, '&& allowed &&', '&& (allowed || true) &&', 'identifierCodecAndNullableFactsNeverEmitContent'),
    ('identifier-provenance', DIAGNOSTICS, 'owner?.verified == true && owner?.identifier == signingIdentifier', '(owner?.verified == true || true) && (owner?.identifier == signingIdentifier || true)', 'actualEncoderRetainsBoundedPairedFactsAndIdentifierProvenance'),
    ('refusal-pair-limit', DIAGNOSTICS, '"cg": cg.prefix(2)', '"cg": cg.prefix(1)', 'actualEncoderRetainsBoundedPairedFactsAndIdentifierProvenance'),
    ('clock-field', ALLOWANCE, '["marker": marker]', '["marker": "wrong"]', 'realJournalEncodesRefusalAndEarlyClockWithinExistingBounds'),
    ('watchdog-allowance', ALLOWANCE, 'watchdogSeconds: Int64 = 120', 'watchdogSeconds: Int64 = 40', 'setupAllowancesPreserveMeasuredRemainingBudget'),
    ('final-allowance', ALLOWANCE, 'finalSeconds: Int64 = 150', 'finalSeconds: Int64 = 45', 'setupAllowancesPreserveMeasuredRemainingBudget'),
    ('cleanup-allowance', ALLOWANCE, 'Double(finalSeconds) - elapsed', '45 - elapsed', 'setupAllowancesPreserveMeasuredRemainingBudget'),
]

if __name__ == '__main__':
    success = harness.main()
    fixture = harness.OUT / 'refusal-journal.ndjson'
    if success:
        data = fixture.read_bytes()
        rows = [json.loads(line) for line in data.splitlines()]
        assert len(rows) == 7 and [row['stage'] for row in rows] == ['inventory-refusal'] * 6 + ['clock-anchor']
        (harness.OUT / 'fixture.json').write_text(json.dumps({'path':fixture.name,'sha256':hashlib.sha256(data).hexdigest(),'rows':len(rows),'producer':DIAGNOSTICS,'journal':'Sources/Sliccy/Screen/ScreenRunnerJournal.swift','scope':'actual production constructors and Journal encoder; fabricated fields, no identity queries'},indent=2)+'\n')
    raise SystemExit(0 if success else 1)
