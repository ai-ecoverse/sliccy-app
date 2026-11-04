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
        let firstValue = try state.revoke(.stopped, now: now)
        let first = try #require(firstValue)
        heartbeat.seq = "3"
        _ = try state.receive(heartbeat, now: now.advanced(by: .seconds(1)))
        let retryAt = now.advanced(by: .milliseconds(1250))
        let duplicate = try state.revoke(.stopped, now: retryAt)
        #expect(duplicate == nil)
        #expect(state.revokeRequest == first.request)
        #expect(state.revokeStartedAt == now && state.revokeOrdinal == 1)
        #expect(throws: ScreenFailure.incompatible) { try state.grant(binding, scope: "window", now: retryAt) }
        #expect(throws: ScreenFailure.incompatible) { try state.receive(link, now: retryAt) }
        var wrongAck = state.base("revoked"); wrongAck.request = try ScreenID.make()
        wrongAck.link = binding.link; wrongAck.session = binding.session
        #expect(throws: ScreenFailure.incompatible) { try state.receive(wrongAck, now: retryAt) }
        try state.checkHealth(now: now.advanced(by: .milliseconds(1499)))
        // Heartbeat health lasts another second, but revoke confirmation is due now.
        #expect(throws: ScreenFailure.stalled) { try state.checkHealth(now: now.advanced(by: .milliseconds(1500))) }
    }

    @Test func acknowledgedStopCreatesFreshRequestAndRejectsPriorAck() throws {
        let now = ContinuousClock.now
        var state = ScreenSafetyState(launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32), now: now)
        var heartbeat = state.base("heartbeat"); heartbeat.seq = "1"; heartbeat.echo = "0"
        _ = try state.receive(heartbeat, now: now)
        _ = try state.heartbeat(now: now)
        heartbeat.seq = "2"; heartbeat.echo = "1"
        _ = try state.receive(heartbeat, now: now)
        let firstValue = try state.revoke(.stopped, now: now)
        let first = try #require(firstValue)
        var ack = state.base("revoked"); ack.request = first.request
        _ = try state.receive(ack, now: now.advanced(by: .milliseconds(10)))
        heartbeat.seq = "3"
        _ = try state.receive(heartbeat, now: now.advanced(by: .seconds(1)))
        let next = now.advanced(by: .milliseconds(1001))
        let secondValue = try state.revoke(.sourceChanged, now: next)
        let second = try #require(secondValue)
        #expect(first.request != second.request && state.phase == .revoked)
        #expect(state.revokeStartedAt == next && state.revokeOrdinal == 2)
        #expect(throws: ScreenFailure.incompatible) { try state.receive(ack, now: next) }
        heartbeat.seq = "4"
        _ = try state.receive(heartbeat, now: next.advanced(by: .milliseconds(900)))
        let duplicate = try state.revoke(.stopped, now: next.advanced(by: .milliseconds(1400)))
        #expect(duplicate == nil)
        try state.checkHealth(now: next.advanced(by: .milliseconds(1499)))
        #expect(throws: ScreenFailure.stalled) { try state.checkHealth(now: next.advanced(by: .milliseconds(1500))) }
    }

    @Test func expiredPendingRevokeCannotChangeRequestClockOrOrdinal() throws {
        let now = ContinuousClock.now
        var state = ScreenSafetyState(launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32), now: now)
        var heartbeat = state.base("heartbeat"); heartbeat.seq = "1"; heartbeat.echo = "0"
        _ = try state.receive(heartbeat, now: now)
        _ = try state.heartbeat(now: now)
        heartbeat.seq = "2"; heartbeat.echo = "1"
        _ = try state.receive(heartbeat, now: now)
        let firstValue = try state.revoke(.stopped, now: now)
        let first = try #require(firstValue)
        heartbeat.seq = "3"
        _ = try state.receive(heartbeat, now: now.advanced(by: .seconds(1)))
        for elapsed in [1500, 1501, 2000, 3000] {
            let at = now.advanced(by: .milliseconds(elapsed))
            #expect(throws: ScreenFailure.stalled) { try state.revoke(.sourceChanged, now: at) }
            #expect(state.revokeRequest == first.request && state.revokeOrdinal == 1 && state.revokeStartedAt == now)
        }
    }

#if DEBUG
    @Test(arguments: [1500, 1501])
    func expiredStopClosesBothLanesWithoutHealthTickOrSecondAdmission(elapsed: Int) throws {
        let (safety, safetyPeer) = try ScreenSocketTests().pair(), (frames, framesPeer) = try ScreenSocketTests().pair()
        let now = ContinuousClock.now
        let pair = ScreenHandshake.Pair(safety: safety, frames: frames, identity: try .current(),
            launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32),
            authenticatedAt: now, readyDeadline: now.advanced(by: .seconds(3)))
        final class Events: @unchecked Sendable {
            private let lock = NSLock()
            private var admissions = 0, failures: [ScreenFailure] = []
            func add(_ event: ScreenTransport.Event) {
                lock.lock(); defer { lock.unlock() }
                switch event { case .revokeQueued: admissions += 1; case .stopped(let reason): failures.append(reason); default: break }
            }
            var snapshot: (Int, [ScreenFailure]) { lock.lock(); defer { lock.unlock() }; return (admissions, failures) }
        }
        let events = Events(), queue = DispatchQueue(label: "test.expired-stop")
        queue.suspend()
        let transport = ScreenTransport(pair: pair, verifier: .init(approvedHashes: []), controlQueue: queue,
            currentProtection: { false }, event: { events.add($0) })
        defer { transport.close(); queue.resume(); queue.sync {} }
        transport.testStop(.stopped, at: now)
        #expect(events.snapshot.0 == 1)
        transport.testStop(.sourceChanged, at: now.advanced(by: .milliseconds(elapsed)))
        #expect(events.snapshot.0 == 1 && events.snapshot.1 == [.stopped, .stalled])
        #expect(transport.gate.isInvalidated)
        var byte: UInt8 = 0
        #expect(recv(safetyPeer.fd, &byte, 1, MSG_DONTWAIT) == 0)
        #expect(recv(framesPeer.fd, &byte, 1, MSG_DONTWAIT) == 0)
        transport.testStop(.stopped, at: now.advanced(by: .seconds(4)))
        #expect(events.snapshot.0 == 1 && events.snapshot.1 == [.stopped, .stalled])
    }
#endif

    @Test func concurrentTransportStopsAdmitOneQueueEntryBeforeAnyWriterRuns() throws {
        let (safety, safetyPeer) = try ScreenSocketTests().pair(), (frames, framesPeer) = try ScreenSocketTests().pair()
        let now = ContinuousClock.now
        let pair = ScreenHandshake.Pair(safety: safety, frames: frames, identity: try .current(),
            launch: try ScreenID.make(bytes: 32), connection: try ScreenID.make(bytes: 32),
            authenticatedAt: now, readyDeadline: now.advanced(by: .seconds(3)))
        final class Counts: @unchecked Sendable {
            let lock = NSLock()
            var queued = 0, stopped = 0
            func add(_ event: ScreenTransport.Event) {
                lock.lock(); defer { lock.unlock() }
                switch event { case .revokeQueued: queued += 1; case .stopped: stopped += 1; default: break }
            }
            var snapshot: (Int, Int) { lock.lock(); defer { lock.unlock() }; return (queued, stopped) }
        }
        let counts = Counts(), queue = DispatchQueue(label: "test.stop-admission")
        queue.suspend()
        let transport = ScreenTransport(pair: pair, verifier: .init(approvedHashes: []), controlQueue: queue,
            currentProtection: { false }, event: { counts.add($0) })
        defer { transport.close(); queue.resume(); queue.sync {}; withExtendedLifetime((safetyPeer, framesPeer)) {} }
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            transport.stop(.sourceChanged)
            #expect(transport.gate.isInvalidated)
        }
        #expect(counts.snapshot.0 == 1 && counts.snapshot.1 == 1)
        var byte: UInt8 = 0
        #expect(recv(safetyPeer.fd, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK)
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
