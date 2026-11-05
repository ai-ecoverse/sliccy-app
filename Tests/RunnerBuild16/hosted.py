from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('slice_hosted', ROOT / 'Tests/RunnerSlice/hosted.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
harness.OUT = ROOT / 'build16-results'
harness.FILTER = 'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests|ChildReceiptTests|OwnerEvidenceTests|JournalTests|InventoryDiagnosticsTests|SurfaceDiagnosticsTests|StructuralRefusalTests|DisplayDiagnosticsTests)'
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

BOUNDARY = 'Sources/Sliccy/Screen/ScreenRunnerInventoryBoundary.swift'
PROBE = 'Sources/Sliccy/Screen/ScreenProofProtectedProbe.swift'
DISPLAY = 'Sources/Sliccy/Screen/ScreenRunnerDisplayDiagnostics.swift'
INDICATOR = 'Sources/Sliccy/Screen/ScreenIndicator.swift'
STRUCTURAL = 'Sources/Sliccy/Screen/ScreenRunnerStructuralRefusal.swift'
harness.PLAN += [
    ('c-boundary-rollback', BOUNDARY, 'right.bundle != owner.identifier && !(emptyWindowServer && right.bundle.isEmpty)', 'right.bundle != owner.identifier', 'actualBoundaryWitnessesOnlyPairedVerifiedWindowServer'),
    ('c-role-widened', BOUNDARY, 'kind == .system, owner.identifier == "com.apple.WindowServer", owner.appleAnchored,', 'kind == .system, true, owner.appleAnchored,', 'actualBoundaryWitnessesOnlyPairedVerifiedWindowServer'),
    ('c-pair-missing', BOUNDARY, 'right.bundle.isEmpty && c.contains(where: { $0.id == right.id })', 'right.bundle.isEmpty', 'actualBoundaryRequiresCompleteUnambiguousPairs'),
    ('c-witness-mismatch', PROBE, 'witness.matches(identity: identity, pid: pid, bundle: bundle, windows: windows)', 'true', 'actualProbeBoundaryMatchesWholeWitnessAndCallsEveryBuilder'),
    ('c-builder-not-called', PROBE, 'try requireRefusal(display)', '_ = display', 'actualProbeBoundaryMatchesWholeWitnessAndCallsEveryBuilder'),
    ('c-wrong-error-accepted', PROBE, 'refusal as? ScreenFailure == .protection', 'refusal as? ScreenFailure != .stopped', 'actualProbeRejectsWrongErrorAcceptanceAndConstruction'),
    ('c-construction-accepted', PROBE, 'guard !witness.reached else', 'guard !witness.reached || true else', 'actualProbeRejectsWrongErrorAcceptanceAndConstruction'),
    ('c-predicate-promoted', STRUCTURAL, '"predicateEvidence": false', '"predicateEvidence": true', 'actualStructuralEncoderKeepsTypedUnionAndMaximumRowBound'),
    ('display-stop-dropped', INDICATOR, 'invoke(.sourceChanged, origin: .displayChange)\n        observe()', 'observe()', 'actualNotificationAlwaysStopsBeforeObservationAndNeverDebounces'),
    ('display-startup-drop', DISPLAY, 'for observation in prior { output(.observation(observation)) }', 'for observation in prior { _ = observation }', 'startupBufferAndDelayedNotificationKeepSeparateActualTimes'),
    ('display-time-replaced', DISPLAY, 'Observation(ticket: actual, started: started, finished: at', 'Observation(ticket: actual, started: actual.requested, finished: at', 'startupBufferAndDelayedNotificationKeepSeparateActualTimes'),
    ('display-notification-cap', DISPLAY, 'notifications < Self.maximumNotifications', 'notifications <= Self.maximumNotifications', 'observationBoundsAndUnfinishedStatusCannotBecomeComplete'),
    ('display-count-cap', DISPLAY, 'displays.count <= Self.maximumDisplays', 'displays.count <= Self.maximumDisplays + 1', 'observationBoundsAndUnfinishedStatusCannotBecomeComplete'),
    ('display-unfinished-promoted', DISPLAY, 'status: .unfinished, reportedCount: nil', 'status: .complete, reportedCount: nil', 'observationBoundsAndUnfinishedStatusCannotBecomeComplete'),
    ('display-mode-lost', DISPLAY, '"mode": modeFields', '"mode": modeFields is NSNull ? modeFields : NSNull()', 'actualDisplayJournalRetainsModesGeometryAndTypedUnavailable'),
    ('display-dimension-normalized', DISPLAY, '"width": number(value.size.width), "height": number(value.size.height)', '"width": number(value.width), "height": number(value.height)', 'actualDisplayJournalRetainsModesGeometryAndTypedUnavailable'),
]

if __name__ == '__main__':
    raise SystemExit(0 if harness.main() else 1)
