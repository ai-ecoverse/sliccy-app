#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation

enum ScreenProofCase: String, Sendable {
    case base
    case parentExec = "parent-exec"
    case lifecycle
    case ancillary

    static func parse(_ arguments: [String]) throws -> Self {
        guard arguments.first == "--screen-proof" else { throw ScreenFailure.incompatible }
        if arguments.count == 1 { return .base }
        guard arguments.count == 3, arguments[1] == "--case", let value = Self(rawValue: arguments[2]),
              value != .base else { throw ScreenFailure.incompatible }
        return value
    }
}

/// Local observations only; the external driver must additionally prove a fresh
/// Pion peer-lost state before the earliest possible heartbeat lease expiry.
struct ScreenAncillaryObservation: Sendable {
    let started: ContinuousClock.Instant
    var fullWrite = false
    var loss: (ScreenFailure, ContinuousClock.Instant)?

    func completed(at now: ContinuousClock.Instant, childAlive: Bool) -> Bool {
        guard fullWrite, childAlive, let (reason, at) = loss, reason == .peerLost,
              at >= started, started.duration(to: at) <= .milliseconds(500),
              started.duration(to: now) >= .seconds(2) else { return false }
        return true
    }
}
#endif
