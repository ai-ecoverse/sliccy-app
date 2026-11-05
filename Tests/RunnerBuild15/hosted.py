from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('slice_hosted', ROOT / 'Tests/RunnerSlice/hosted.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
harness.OUT = ROOT / 'build15-results'
harness.FILTER = 'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests|ChildReceiptTests|OwnerEvidenceTests|JournalTests|InventoryDiagnosticsTests|SurfaceDiagnosticsTests)'
DIAG = 'Sources/Sliccy/Screen/ScreenRunnerSurfaceDiagnostics.swift'
OWNER = 'Sources/Sliccy/Screen/ScreenRunnerOwnedProcess.swift'
harness.PLAN = [
    ('surface-hash-admission', DIAG, 'actual == expected', 'true', 'actualHashBoundaryNamesFailureAndPreservesPositiveControl'),
    ('surface-hash-reason', DIAG, 'reject(.hash, .executableHash)', 'reject(.role, .executableHash)', 'actualHashBoundaryNamesFailureAndPreservesPositiveControl'),
    ('surface-first-refusal', DIAG, 'if first { output(', 'if first || true { output(', 'firstRefusalCannotBeOverwritten'),
    ('surface-refusal-drop', DIAG, 'if first { output(', 'if first && false { output(', 'firstRefusalCannotBeOverwritten'),
    ('surface-policy-reason', OWNER, 'identifier != "ai.sliccy.proof-helper" ? .identifier : team != "S8LB56P782" ? .team : .role', '.role', 'actualPreflightNamesPolicyAndRoleWithoutExtraNativeCalls'),
    ('surface-role-status', OWNER, 'diagnostics.reject(.role, .staticValidity, status: status)', 'diagnostics.reject(.role, .staticValidity, status: nil)', 'actualPreflightNamesPolicyAndRoleWithoutExtraNativeCalls'),
    ('surface-information-identifier', OWNER, 'diagnostics.reject(.identifier, .signingInformation)', 'diagnostics.reject(.role, .signingInformation)', 'actualPreflightNamesInformationIdentifierAndPath'),
    ('surface-information-path', OWNER, 'diagnostics.reject(.path, .signingInformation)', 'diagnostics.reject(.role, .signingInformation)', 'actualPreflightNamesInformationIdentifierAndPath'),
    ('surface-original-error', DIAG, 'catch { reject(predicate, operation); throw error }', 'catch { reject(predicate, operation); throw ScreenFailure.peerUntrusted }', 'observedReadFailureKeepsOriginalErrorAndFallbackCannotReplaceIt'),
    ('surface-encoder-status', DIAG, '"status": status.map { $0 as Any } ?? NSNull()', '"status": NSNull()', 'actualJournalEncodesOnlyFixedSurfaceFields'),
]

if __name__ == '__main__':
    raise SystemExit(0 if harness.main() else 1)
