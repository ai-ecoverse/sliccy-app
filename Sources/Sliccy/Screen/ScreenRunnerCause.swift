#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerPhase: String, CaseIterable, Sendable {
    case preflight, preparing, inventory, consent, granting, capturing, stopping, cleanup, finished
}

enum ScreenRunnerInventoryIssue: String, CaseIterable, Error, Sendable {
    case permission, surfaceIdentity = "surface-identity", browserIdentity = "browser-identity"
    case shareableContent = "shareable-content", displayGeometry = "display-geometry", cgInventory = "cg-inventory"
    case ownerAttribution = "owner-attribution", completeness, surfaceGeometry = "surface-geometry"
    case browserWindowCount = "browser-window-count", windowIdentity = "window-identity", appWindows = "app-windows"
    case authorizationRequester = "authorization-requester", authorizationMissing = "authorization-missing"
    case authorizationAmbiguous = "authorization-ambiguous", authorizationIdentity = "authorization-identity"
    case sourceChanged = "source-changed", unclassifiedOwner = "unclassified-owner", unknown
}

enum ScreenRunnerCauseReason: Sendable {
    case screen(ScreenFailure), inventory(ScreenRunnerInventoryIssue), reaped, unreaped, unexpected
    var value: String {
        switch self {
        case .screen(let reason): "screen-" + reason.rawValue
        case .inventory(let issue): "inventory-" + issue.rawValue
        case .reaped: "reaped"
        case .unreaped: "unreaped"
        case .unexpected: "unexpected"
        }
    }
    static func error(_ error: any Error) -> Self {
        if let issue = error as? ScreenRunnerInventoryIssue { return .inventory(issue) }
        if let failure = error as? ScreenFailure { return .screen(failure) }
        return .unexpected
    }
}

final class ScreenRunnerCauseLedger: @unchecked Sendable {
    enum Kind: String, CaseIterable, Sendable { case stop, inventory, launcherReap = "launcher-reap", childLoss = "child-loss", failure }
    struct Notice: Sendable {
        let kind: Kind, reason: ScreenRunnerCauseReason, phase: ScreenRunnerPhase, origin: ScreenStopRelay.Origin
        let at: ContinuousClock.Instant
    }
    private let lock = NSLock()
    private var phase: ScreenRunnerPhase = .preflight
    private var seen = Set<Kind>()
    private var stoppedAt: ContinuousClock.Instant?
    private var stopPhase: ScreenRunnerPhase?
    private let emit: @Sendable (Notice) -> Void
    init(emit: @escaping @Sendable (Notice) -> Void) { self.emit = emit }
    func advance(_ phase: ScreenRunnerPhase) {
        lock.lock()
        if phase == .stopping, stopPhase == nil { stopPhase = self.phase }
        self.phase = phase; lock.unlock()
    }
    func noteStop(at: ContinuousClock.Instant) {
        lock.lock(); stoppedAt = stoppedAt.map { min($0, at) } ?? at
        if stopPhase == nil { stopPhase = phase }; lock.unlock()
    }
    var firstStopAt: ContinuousClock.Instant? { lock.lock(); defer { lock.unlock() }; return stoppedAt }
    func record(_ kind: Kind, reason: ScreenRunnerCauseReason, origin: ScreenStopRelay.Origin, at: ContinuousClock.Instant = .now) {
        lock.lock()
        if kind == .stop { stoppedAt = stoppedAt.map { min($0, at) } ?? at }
        guard seen.insert(kind).inserted else { lock.unlock(); return }
        let notice = Notice(kind: kind, reason: reason, phase: kind == .stop ? (stopPhase ?? phase) : phase, origin: origin, at: at)
        lock.unlock(); emit(notice)
    }
}
#endif
