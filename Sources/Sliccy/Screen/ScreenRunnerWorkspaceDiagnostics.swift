#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit

final class ScreenRunnerWorkspaceDiagnostics: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let journal: ScreenRunnerJournal
    init(journal: ScreenRunnerJournal) { self.journal = journal }
    /// Called only AFTER invoke. No role/identity authority is derived from userInfo.
    func record(_ notification: Notification, origin: ScreenStopRelay.Origin,
                before: ContinuousClock.Instant, after: ContinuousClock.Instant) {
        lock.lock(); count += 1; let sequence = count; lock.unlock()
        guard sequence <= 64 else { journal.rejectEvidence(); return }
        let payload = notification.userInfo?[NSWorkspace.applicationUserInfoKey]
        let application = payload as? NSRunningApplication
        let pid = application?.processIdentifier
        let validPID = pid.flatMap { $0 > 0 ? $0 : nil }
        let status = payload == nil ? "missing-application" : application == nil ? "invalid-application" : validPID == nil ? "invalid-pid" : "present"
        journal.emit("workspace-stop", ScreenRunnerLaunchDiagnostics.workspaceFields(sequence: sequence, origin: origin,
            beforeMS: ScreenRunnerJournal.ms(journal.began.duration(to: before)),
            afterMS: ScreenRunnerJournal.ms(journal.began.duration(to: after)), status: status,
            pid: validPID, bundle: application?.bundleIdentifier), at: before)
    }
}
#endif
