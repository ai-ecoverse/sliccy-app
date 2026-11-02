import Foundation
import Testing
@testable import Sliccy

struct ScreenSafetyTests {
    func binding() throws -> ScreenBinding {
        .init(link: try ScreenID.make(), session: try ScreenID.make(), source: try ScreenID.make(), grantEpoch: "1", sourceEpoch: "1", protectionEpoch: "1")
    }
    @Test func delayedHeartbeatCannotReviveExpiredOutput() throws {
        let now = ContinuousClock.now
        let gate = ScreenOutputGate(), binding = try binding()
        try gate.renew(until: now.advanced(by: .seconds(1)), now: now)
        try gate.activate(binding, now: now)
        #expect(gate.allows(binding, now: now))
        let late = now.advanced(by: .seconds(2))
        #expect(throws: ScreenFailure.leaseExpired) { try gate.renew(until: late.advanced(by: .seconds(1)), now: late) }
        #expect(!gate.allows(binding, now: late))
        #expect(throws: ScreenFailure.leaseExpired) { try gate.renew(until: late.advanced(by: .seconds(1)), now: late) }
        #expect(throws: ScreenFailure.leaseExpired) { try gate.activate(binding, now: late) }
    }
    @Test func stopBeforeGrantAcknowledgementPermanentlyClosesGate() throws {
        let now = ContinuousClock.now, gate = ScreenOutputGate()
        let binding = try binding()
        try gate.renew(until: now.advanced(by: .seconds(1)), now: now)
        gate.invalidate() // No active binding yet: late ack must still be refused.
        #expect(throws: ScreenFailure.leaseExpired) { try gate.activate(binding, now: now) }
        #expect(throws: ScreenFailure.leaseExpired) { try gate.renew(until: now.advanced(by: .seconds(1)), now: now) }
        #expect(!gate.allows(binding, now: now))
    }
    @Test func pendingGrantAlsoCannotRenewAnExpiredLease() throws {
        let now = ContinuousClock.now, gate = ScreenOutputGate()
        try gate.renew(until: now.advanced(by: .seconds(1)), now: now)
        let late = now.advanced(by: .seconds(2))
        #expect(throws: ScreenFailure.leaseExpired) { try gate.renew(until: late.advanced(by: .seconds(1)), now: late) }
        #expect(throws: ScreenFailure.leaseExpired) { try gate.activate(binding(), now: late) }
    }
    @Test func strictJSONRejectsAmbiguityAndUnknownFields() throws {
        for json in [#"{"a":1,"a":2}"#, #"{"a":1,"\u0061":2}"#, #"{"a":{"b":1,"b":2}}"#, #"{"a":1}{}"#] {
            #expect(throws: (any Error).self) { try ScreenJSON.object(Data(json.utf8)) }
        }
        var heartbeat = ScreenSafety(type: "heartbeat", launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32))
        heartbeat.seq = "1"; heartbeat.echo = "0"
        #expect(try ScreenSafety.decode(heartbeat.data()).seq == "1")
        var json = try ScreenJSON.object(heartbeat.data()); json["extra"] = false
        #expect(throws: (any Error).self) { try ScreenSafety.decode(JSONSerialization.data(withJSONObject: json)) }
        heartbeat.seq = "01"
        #expect(throws: (any Error).self) { try ScreenSafety.decode(heartbeat.data()) }
        heartbeat.seq = nil
        #expect(throws: (any Error).self) { try ScreenSafety.decode(heartbeat.data()) }
    }
    @Test func adHocHostAndEmptyPinsAreNotScreenEligible() throws {
        #expect(ScreenReleasePolicy.cliCodeDirectoryHashes.isEmpty)
        #expect(!ScreenReleasePolicy.identityProofApproved)
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenPeerVerifier.verifySelf() }
        let token = try ScreenAuditIdentity.current()
        #expect(token.pid == getpid())
        #expect(try ScreenAuditIdentity(encoded: token.encoded) == token)
    }
    @Test func stopDuringPendingGrantDiscardsLateAcknowledgement() throws {
        let now = ContinuousClock.now
        var state = ScreenSafetyState(launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32), now: now)
        var heartbeat = state.base("heartbeat"); heartbeat.seq = "1"; heartbeat.echo = "0"
        _ = try state.receive(heartbeat, now: now)
        _ = try state.heartbeat(now: now)
        heartbeat.seq = "2"; heartbeat.echo = "1"
        _ = try state.receive(heartbeat, now: now)
        let binding = try binding()
        var link = state.base("link"); link.link = binding.link
        _ = try state.receive(link, now: now)
        let grant = try state.grant(binding, scope: "window", now: now)
        #expect(state.phase == .pending)
        let revoke = try state.revoke(.stopped, now: now)
        var ack = state.base("granted"); ack.request = grant.request; ack.binding = grant.binding
        _ = try state.receive(ack, now: now)
        #expect(state.phase == .revoked)
        var stopped = state.base("revoked"); stopped.request = revoke.request; stopped.link = revoke.link; stopped.session = revoke.session
        _ = try state.receive(stopped, now: now)
        _ = try state.receive(stopped, now: now) // Idempotent.
        stopped.session = nil
        #expect(throws: ScreenFailure.incompatible) { try state.receive(stopped, now: now) }
    }
    @Test func partialTrafficAndOneWayHeartbeatsCannotRenewLease() throws {
        let now = ContinuousClock.now
        var state = ScreenSafetyState(launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32), now: now)
        var heartbeat = state.base("heartbeat"); heartbeat.seq = "1"; heartbeat.echo = "0"
        _ = try state.receive(heartbeat, now: now)
        _ = try state.heartbeat(now: now)
        heartbeat.seq = "2"
        _ = try state.receive(heartbeat, now: now.advanced(by: .seconds(1)))
        #expect(throws: ScreenFailure.leaseExpired) { try state.checkHealth(now: now.advanced(by: .milliseconds(1500))) }
        heartbeat.seq = "3"; heartbeat.echo = "1"
        #expect(throws: ScreenFailure.leaseExpired) { try state.receive(heartbeat, now: now.advanced(by: .seconds(2))) }
    }
    @Test func settingsOptInDoesNotRemoveFixedProtections() {
        var protected = ScreenProtectedSet(hostBundleIDs: ["test.host"])
        #expect(protected.excludes(bundle: "com.apple.systempreferences", pid: 42))
        protected.allowSystemSettings = true
        #expect(!protected.excludes(bundle: "com.apple.systempreferences", pid: 42))
        for bundle in ["ai.sliccy.mac", "test.host", "test.host.helper", "com.apple.SecurityAgent"] {
            #expect(protected.excludes(bundle: bundle, pid: 42))
        }
        #expect(!protected.excludes(bundle: "test.otherbrowser", pid: 42))
    }
}
