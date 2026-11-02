import Foundation
import Darwin
import Testing
@testable import Sliccy

struct ScreenRevocationTests {
    @Test func quiescenceKeepsIdleLanesOpenForRevokeAcknowledgement() throws {
        func sockets() throws -> (ScreenSocket, ScreenSocket) {
            var fds: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw ScreenFailure.peerLost }
            return (try ScreenSocket(fds[0]), try ScreenSocket(fds[1]))
        }
        let (safety, safetyPeer) = try sockets(), (frames, framesPeer) = try sockets()
        let now = ContinuousClock.now
        let pair = ScreenHandshake.Pair(safety: safety, frames: frames, identity: try .current(),
            launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32),
            authenticatedAt: now, readyDeadline: now.advanced(by: .seconds(3)))
        let transport = ScreenTransport(pair: pair, verifier: .init(approvedHashes: []), currentProtection: { false }, event: { _ in })
        let binding = ScreenBinding(link: try ScreenID.make(), session: try ScreenID.make(), source: try ScreenID.make(), grantEpoch: "1", sourceEpoch: "1", protectionEpoch: "1")
        try transport.gate.renew(until: now.advanced(by: .seconds(10)), now: now)
        try transport.gate.activate(binding, now: now)
        transport.quiesceOutput()
        #expect(!transport.gate.allows(binding))
        #expect(throws: ScreenFailure.leaseExpired) { try transport.gate.nextFrame() }
        for peer in [framesPeer, safetyPeer] {
            var byte: UInt8 = 0
            let count = recv(peer.fd, &byte, 1, MSG_DONTWAIT)
            #expect(count == -1) // Idle and open, not EOF/association loss.
            if count < 0 { #expect(errno == EAGAIN || errno == EWOULDBLOCK) }
        }
        transport.close()
        var byte: UInt8 = 0
        #expect(recv(framesPeer.fd, &byte, 1, 0) == 0)
        #expect(recv(safetyPeer.fd, &byte, 1, 0) == 0)
    }

    @Test func duplicateRevokeCannotExtendDeadlineOrAllowAdmission() throws {
        let now = ContinuousClock.now
        var state = ScreenSafetyState(launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32), now: now)
        var heartbeat = state.base("heartbeat"); heartbeat.seq = "1"; heartbeat.echo = "0"
        _ = try state.receive(heartbeat, now: now)
        _ = try state.heartbeat(now: now)
        heartbeat.seq = "2"; heartbeat.echo = "1"
        _ = try state.receive(heartbeat, now: now)
        let binding = ScreenBinding(link: try ScreenID.make(), session: try ScreenID.make(), source: try ScreenID.make(), grantEpoch: "1", sourceEpoch: "1", protectionEpoch: "1")
        var link = state.base("link"); link.link = binding.link
        _ = try state.receive(link, now: now)
        _ = try state.grant(binding, scope: "window", now: now)
        let first = try state.revoke(.stopped, now: now)
        heartbeat.seq = "3"
        _ = try state.receive(heartbeat, now: now.advanced(by: .seconds(1)))
        let retryAt = now.advanced(by: .milliseconds(1250))
        let duplicate = try state.revoke(.stopped, now: retryAt)
        #expect(duplicate.request == first.request)
        #expect(throws: ScreenFailure.incompatible) { try state.grant(binding, scope: "window", now: retryAt) }
        #expect(throws: ScreenFailure.incompatible) { try state.receive(link, now: retryAt) }
        var wrongAck = state.base("revoked"); wrongAck.request = try ScreenID.make()
        wrongAck.link = binding.link; wrongAck.session = binding.session
        #expect(throws: ScreenFailure.incompatible) { try state.receive(wrongAck, now: retryAt) }
        try state.checkHealth(now: now.advanced(by: .milliseconds(1499)))
        // Heartbeat health lasts another second, but revoke confirmation is due now.
        #expect(throws: ScreenFailure.stalled) { try state.checkHealth(now: now.advanced(by: .milliseconds(1500))) }
    }

    @Test(arguments: [false, true])
    func rejectedGrantInvalidatesBeforeReturningAndClosesBothLanes(diagnostic: Bool) throws {
        func sockets() throws -> (ScreenSocket, ScreenSocket) {
            var fds: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw ScreenFailure.peerLost }
            return (try ScreenSocket(fds[0]), try ScreenSocket(fds[1]))
        }
        let (safety, safetyPeer) = try sockets(), (frames, framesPeer) = try sockets()
        let now = ContinuousClock.now
        // Test the transport's refusal path only; no claim of authenticated IPC.
        let pair = ScreenHandshake.Pair(safety: safety, frames: frames, identity: try .current(),
            launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32),
            authenticatedAt: now, readyDeadline: now.advanced(by: .seconds(3)))
        let transport = ScreenTransport(pair: pair, verifier: .init(approvedHashes: []), noCapture: diagnostic,
            currentProtection: { diagnostic }, event: { _ in })
        let binding = ScreenBinding(link: try ScreenID.make(), session: try ScreenID.make(), source: try ScreenID.make(), grantEpoch: "1", sourceEpoch: "1", protectionEpoch: "1")
        try transport.gate.renew(until: now.advanced(by: .seconds(10)), now: now)
        try transport.gate.activate(binding, now: now)
        if diagnostic {
            let header = ScreenFrameHeader(binding: binding, frameSeq: "1", capturedMonoMs: "1", width: 1, height: 1,
                launch: pair.launch, connection: pair.connection)
            #expect(throws: ScreenFailure.stopped) { try transport.submit(header, jpeg: Data([1]), captured: now) }
        }
        #expect(throws: ScreenFailure.protection) { try transport.grant(binding, scope: "window") }
        #expect(!transport.gate.allows(binding, now: now))
        var byte: UInt8 = 0
        #expect(recv(safetyPeer.fd, &byte, 1, 0) == 0)
        #expect(recv(framesPeer.fd, &byte, 1, 0) == 0)
        #expect(throws: ScreenFailure.leaseExpired) { try transport.gate.renew(until: now.advanced(by: .seconds(10)), now: now) }
    }
}
