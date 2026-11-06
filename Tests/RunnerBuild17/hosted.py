from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build16_hosted', ROOT / 'Tests/RunnerBuild16/hosted.py')
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
harness.OUT = ROOT / 'build17-results'
harness.FILTER = (
    'ScreenRunner(SliceTests|BSDTests|ChromeBoundaryTests|ReceiptTests|InventoryBoundaryTests|'
    'ChildReceiptTests|OwnerEvidenceTests|JournalTests|InventoryDiagnosticsTests|SurfaceDiagnosticsTests|'
    'StructuralRefusalTests|DisplayDiagnosticsTests|LaunchBarrierTests|LaunchInstanceTests|'
    'LaunchAsyncTests|WorkspaceDiagnosticsTests)'
)

INSTANCE = 'Sources/Sliccy/Screen/ScreenRunnerLaunchInstance.swift'
BARRIER = 'Sources/Sliccy/Screen/ScreenRunnerLaunchBarrier.swift'
SAMPLING = 'Sources/Sliccy/Screen/ScreenRunnerLaunchSampling.swift'
RELAY = 'Sources/Sliccy/Screen/ScreenIndicator.swift'

# Build16 PLAN is retained; append only launch/handshake faults with exact named assertions.
harness.PLAN += [
    ('launch-instance-equality', INSTANCE, 'current.isEqual(original)', 'true', 'actualFoundationSemanticEqualityNeverFallsBackToPIDOrPointer'),
    ('launch-instance-missing', INSTANCE, 'guard let current, let currentFacts, current.isEqual(original) else { return false }', 'guard let current, let currentFacts else { return false }', 'actualFoundationSemanticEqualityNeverFallsBackToPIDOrPointer'),
    ('launch-bsd-before', BARRIER, 'guard matches(original, observed.before) else { return false }', 'guard true else { return false }', 'bothLaterBSDReadsMustMatchOriginalEvenWithEqualInstance'),
    ('launch-bsd-after', BARRIER, 'guard matches(original, observed.after) else { return false }', 'guard true else { return false }', 'bothLaterBSDReadsMustMatchOriginalEvenWithEqualInstance'),
    ('launch-pending-arm', BARRIER, 'pending.isEmpty, !verificationPending, verified else', 'true, !verificationPending, verified else', 'pendingObservationAndVerificationPreventArming'),
    ('launch-revision-immutable', BARRIER, 'revision == value.revision, pending.isEmpty, !verificationPending, !verified else', 'true, pending.isEmpty, !verificationPending, !verified else', 'revisionLatchedBeforeRowsCannotBeRecapturedAfterMarker'),
    ('launch-recheck-original', BARRIER, 'observed.before == owner.observation.before,', 'true,', 'verificationCannotChangeIncarnationOrCompleteAfterInterveningEvent'),
    ('launch-intervening-event', BARRIER, 'revision == value.revision, let values, values.count == 4 else', 'true, let values, values.count == 4 else', 'verificationCannotChangeIncarnationOrCompleteAfterInterveningEvent'),
    ('launch-sampling-instance', SAMPLING, 'guard equal else { throw ScreenRunnerLaunchBarrier.Failure.instance }', 'guard true else { throw ScreenRunnerLaunchBarrier.Failure.instance }', 'actualSamplingAdapterRejectsInstanceReuseAndKeepsBothOriginalReads'),
    ('launch-armed-cannot-disarm', BARRIER, 'if phase == .armed, let relay { lock.unlock(); return .stop(relay) }', 'if phase == .armed, let relay { lock.unlock(); return .refuse }', 'armedStopSurvivesLaterInvalidBookkeeping'),
    ('workspace-stop-before-attribution', RELAY, 'invoke(.sourceChanged, origin: origin)\n        let after = ContinuousClock.now\n        proofWorkspaceDiagnostics?.record', 'let after = ContinuousClock.now\n        proofWorkspaceDiagnostics?.record\n        invoke(.sourceChanged, origin: origin)', 'actualWorkspaceCallbackStopsBeforeMissingPayloadEncoding'),
]

if __name__ == '__main__':
    raise SystemExit(0 if harness.main() else 1)
