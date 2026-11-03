#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation

enum ScreenProofCase: String, Sendable {
    case base
    case parentExec = "parent-exec"
    case lifecycle
    case pidReuse = "pid-reuse"
    case frameHandoff = "frame-handoff"
    var isHandoff: Bool { self == .safetyHandoff || self == .frameHandoff }
    case safetyHandoff = "safety-handoff"
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
struct ScreenProofBaseline {
    private(set) var sequence: UInt64 = 0
    private(set) var confirmed = false
    private(set) var deadline: ContinuousClock.Instant?
    mutating func receive(_ command: String, now: ContinuousClock.Instant = .now) throws -> Bool {
        guard !confirmed, deadline.map({ now < $0 }) ?? true else { throw ScreenFailure.stalled }
        switch command {
        case "frame-next":
            guard sequence < 5 else { throw ScreenFailure.resourceLimit }
            if deadline == nil { deadline = now.advanced(by: .seconds(5)) }
            sequence += 1; return false
        case "frame-baseline":
            guard sequence > 0 else { throw ScreenFailure.incompatible }
            confirmed = true; return true
        default: throw ScreenFailure.incompatible
        }
    }
}
#endif
