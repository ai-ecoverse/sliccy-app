import Foundation

/// Value state used only under the transport's short state lock. No I/O or UI work.
struct ScreenSafetyState {
    enum Phase { case paired, linked, pending, active, revoked }
    let launch: String
    let connection: String
    private(set) var phase: Phase = .paired
    private(set) var link: String?
    private(set) var recipient: ScreenRecipient?
    private(set) var evidence: ScreenBrowserEvidence?
    private(set) var binding: ScreenBinding?
    private(set) var grantRequest: String?
    private(set) var revokeRequest: String?
    private(set) var peerRevokeRequest: String?
    private(set) var sent: UInt64 = 0
    private(set) var received: UInt64 = 0
    private(set) var echoed: UInt64 = 0
    private(set) var healthUntil: ContinuousClock.Instant
    private var echoUntil: ContinuousClock.Instant
    private var revokeUntil: ContinuousClock.Instant?
    private(set) var ready = false
    private let readyDeadline: ContinuousClock.Instant

    init(launch: String, connection: String, now: ContinuousClock.Instant = .now, readyDeadline: ContinuousClock.Instant? = nil) {
        self.launch = launch; self.connection = connection
        healthUntil = now.advanced(by: .milliseconds(1500)); echoUntil = healthUntil
        self.readyDeadline = readyDeadline ?? healthUntil
    }
    func base(_ type: String) -> ScreenSafety { .init(type: type, launch: launch, connection: connection) }
    func checkHealth(now: ContinuousClock.Instant = .now) throws {
        guard ready || now < readyDeadline else { throw ScreenFailure.leaseExpired }
        guard now < healthUntil, sent == echoed || now < echoUntil else { throw ScreenFailure.leaseExpired }
        if let revokeUntil, now >= revokeUntil { throw ScreenFailure.stalled }
    }
    mutating func heartbeat(now: ContinuousClock.Instant = .now) throws -> ScreenSafety {
        try checkHealth(now: now)
        guard received > 0, sent < UInt64.max else { throw ScreenFailure.incompatible }
        if sent == echoed { echoUntil = now.advanced(by: .milliseconds(1500)) }
        sent += 1
        var message = base("heartbeat"); message.seq = String(sent); message.echo = String(received)
        return message
    }

    /// Nil means no reply. Caller must invalidate output BEFORE applying any revoke,
    /// and must recheck source/indicator/identity BEFORE activating an acknowledged grant.
    mutating func receive(_ message: ScreenSafety, now: ContinuousClock.Instant = .now) throws -> ScreenSafety? {
        try checkHealth(now: now)
        guard message.launch == launch, message.connection == connection else { throw ScreenFailure.incompatible }
        switch message.type {
        case "heartbeat":
            guard let seq = message.seq, let echo = message.echo else { throw ScreenFailure.incompatible }
            let next = try ScreenID.counter(seq), ack = try ScreenID.counter(echo)
            guard next > received, received != 0 || next == 1, ack >= echoed, ack <= sent else { throw ScreenFailure.incompatible }
            if ack > echoed { echoUntil = now.advanced(by: .milliseconds(1500)) }
            received = next; echoed = ack
            healthUntil = now.advanced(by: .milliseconds(1500))
            if ack > 0 { ready = true }
        case "link":
            // The CLI may send its link directly after it receives our first echo.
            guard sent > 0, phase == .paired || (phase == .revoked && revokeUntil == nil),
                  let newLink = message.link else { throw ScreenFailure.incompatible }
            link = newLink; recipient = message.recipient; evidence = message.browserEvidence
            binding = nil; grantRequest = nil; revokeRequest = nil; peerRevokeRequest = nil; phase = .linked
        case "granted":
            guard message.request == grantRequest, message.binding == binding else { throw ScreenFailure.incompatible }
            if phase == .revoked { return nil } // A stopped pending grant stays stopped.
            guard phase == .pending, ready else { throw ScreenFailure.incompatible }
            phase = .active
        case "revoke":
            guard message.link == link, message.session == binding?.session, let request = message.request,
                  peerRevokeRequest == nil || peerRevokeRequest == request else { throw ScreenFailure.incompatible }
            peerRevokeRequest = request; phase = .revoked
            var reply = base("revoked"); reply.request = request; reply.link = link; reply.session = binding?.session
            return reply
        case "revoked":
            guard phase == .revoked, message.request == revokeRequest,
                  message.link == link, message.session == binding?.session else { throw ScreenFailure.incompatible }
            revokeUntil = nil // Keep request for duplicate ack validation until the next link.
        default: throw ScreenFailure.incompatible
        }
        return nil
    }
    mutating func grant(_ proposed: ScreenBinding, scope: String, now: ContinuousClock.Instant = .now) throws -> ScreenSafety {
        try checkHealth(now: now); try proposed.validate()
        guard phase == .linked, ready, proposed.link == link, ["display", "window"].contains(scope) else { throw ScreenFailure.incompatible }
        var message = base("grant"); message.request = try ScreenID.make(); message.binding = proposed
        message.scope = scope; message.limits = ScreenLimits()
        binding = proposed; grantRequest = message.request; phase = .pending
        return message
    }
    mutating func revoke(_ reason: ScreenFailure, now: ContinuousClock.Instant = .now) throws -> ScreenSafety {
        phase = .revoked
        var message = base("revoke")
        if revokeRequest == nil { revokeRequest = try ScreenID.make(); revokeUntil = now.advanced(by: .milliseconds(1500)) }
        message.request = revokeRequest; message.link = link; message.session = binding?.session; message.reason = reason.rawValue
        return message
    }
}
