#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
import ScreenSystem
@testable import Sliccy

struct ScreenRunnerLaunchBarrierTests {
    typealias B = ScreenRunnerLaunchBarrier
    static func sample(_ pid: Int32, seconds: UInt64 = 10) -> ScreenRunnerBSD.Sample {
        .init(.init(pid: pid, parent: 50, effective_uid: 501, real_uid: 501, saved_uid: 501, seconds: seconds, microseconds: 20))
    }
    static func original(_ pid: Int32) -> ScreenRunnerProcessSample {
        .init(pid: pid, parent: 50, uid: 501, seconds: 10, microseconds: 20)
    }
    static func observation(_ ticket: B.Ticket, pid: Int32, seconds: UInt64 = 10,
                            finished: Bool = true, bundle: String = "com.google.Chrome") -> B.Observation {
        .init(ticket: ticket, before: sample(pid, seconds: seconds), after: sample(pid, seconds: seconds),
              bundle: bundle, finished: finished, terminated: false, observedAt: .now, instanceEqual: true)
    }
    static func deliver(_ b: B, _ index: Int, seconds: UInt64 = 10, finished: Bool = true) throws {
        guard case .collect(let ticket) = b.begin() else { Issue.record("launch-fixture-admission"); return }
        b.complete(ticket, observation: observation(ticket, pid: Int32(100 + index), seconds: seconds, finished: finished))
    }
    static func setup(_ count: Int = 4) throws -> B {
        let b = B()
        for (i, label) in B.labels.enumerated() { b.register(label: label, original: original(Int32(100+i))) }
        for i in 0..<count { try deliver(b, i) }
        return b
    }
    static func verify(_ b: B, _ value: B.Candidate) throws {
        try b.beginVerification(value)
        try b.endVerification(value, observations: value.owners.map(\.observation))
    }
    @Test func actualBarrierNeedsEveryDeliveredOriginalAndRegistration() throws {
        let b = try Self.setup(3)
        #expect(try b.latch() == nil, "launch-four-events-required")
        try Self.deliver(b, 3)
        let ready = try #require(try b.latch())
        #expect(ready.owners.count == 4)
        try Self.verify(b, ready)
        let relay = ScreenStopRelay(gate: ScreenOutputGate(), stop: { _ in })
        try b.arm(relay)
        if case .stop = b.begin() {} else { Issue.record("launch-after-arm-unconditional") }
        #expect(b.close().pending == 0)
        for (seconds, finished) in [(UInt64(11), true), (10, false)] {
            let bad = try Self.setup(3)
            try Self.deliver(bad, 3, seconds: seconds, finished: finished)
            #expect(throws: (any Error).self, "launch-original-registration-required") { _ = try bad.latch() }
        }
    }
    @Test func revisionLatchedBeforeRowsCannotBeRecapturedAfterMarker() throws {
        let b = try Self.setup(), ready = try #require(try b.latch())
        _ = b.begin()
        #expect(throws: (any Error).self, "launch-ready-revision-immutable") { try Self.verify(b, ready) }
        #expect(throws: (any Error).self, "launch-failed-candidate-terminal") { _ = try b.latch() }
        #expect(throws: (any Error).self) { try b.arm(ScreenStopRelay(gate: ScreenOutputGate(), stop: { _ in })) }
    }
    @Test func pendingObservationAndVerificationPreventArming() throws {
        let b = try Self.setup()
        guard case .collect(let pending) = b.begin() else { Issue.record("launch-fixture-admission"); return }
        #expect(try b.latch() == nil, "launch-all-pending-accounted")
        b.complete(pending, observation: nil)
        let ready = try #require(try b.latch())
        try b.beginVerification(ready)
        #expect(throws: (any Error).self, "launch-verification-pending-blocks-arm") {
            try b.arm(ScreenStopRelay(gate: ScreenOutputGate(), stop: { _ in }))
        }
        #expect(throws: (any Error).self) { try b.endVerification(ready, observations: ready.owners.map(\.observation)) }
        #expect(b.close().failed)
    }
    @Test func eventBeforeOwnedRecordCanBindButWrongDuplicateCannot() throws {
        let b = B()
        for i in 0..<4 { try Self.deliver(b, i) }
        #expect(try b.latch() == nil)
        for (i, label) in B.labels.enumerated() { b.register(label: label, original: Self.original(Int32(100+i))) }
        #expect(try b.latch() != nil, "launch-before-record-preserved")
        let duplicate = try Self.setup(3)
        try Self.deliver(duplicate, 2)
        #expect(throws: (any Error).self, "launch-duplicate-refused") { _ = try duplicate.latch() }
    }
    @Test func eventCapAndClosedPendingNeverBecomeReady() throws {
        let b = B()
        for _ in 0..<B.maximumEvents {
            guard case .collect(let ticket) = b.begin() else { Issue.record("launch-fixture-admission"); return }
            b.complete(ticket, observation: nil)
        }
        _ = b.begin()
        #expect(throws: (any Error).self, "launch-event-cap") { _ = try b.latch() }
        let pending = B()
        _ = pending.begin()
        let closed = pending.close()
        #expect(closed.pending == 1 && closed.failed, "launch-closed-pending-retained")
        #expect(throws: (any Error).self) { _ = try pending.latch() }
    }
    @Test func armedStopSurvivesLaterInvalidBookkeeping() throws {
        let b = try Self.setup(), ready = try #require(try b.latch())
        try Self.verify(b, ready)
        let gate = ScreenOutputGate(), relay = ScreenStopRelay(gate: gate, stop: { _ in })
        try b.arm(relay)
        b.fail(.lifecycle)
        guard case .stop(let target) = b.begin() else { Issue.record("launch-armed-cannot-disarm"); return }
        target.invoke(.sourceChanged, origin: .workspaceLaunch)
        #expect(gate.isInvalidated, "launch-armed-cannot-disarm")
        #expect(b.close().failed)
    }
    @Test func verificationCannotChangeIncarnationOrCompleteAfterInterveningEvent() throws {
        let b = try Self.setup(), ready = try #require(try b.latch())
        try b.beginVerification(ready)
        var values = ready.owners.map(\.observation)
        values[3] = Self.observation(values[3].ticket, pid: 103, seconds: 11)
        #expect(throws: (any Error).self, "launch-recheck-original-required") { try b.endVerification(ready, observations: values) }
        let other = try Self.setup(), otherReady = try #require(try other.latch())
        try other.beginVerification(otherReady)
        _ = other.begin()
        #expect(throws: (any Error).self, "launch-intervening-event-terminal") {
            try other.endVerification(otherReady, observations: otherReady.owners.map(\.observation))
        }
    }
}
#endif
