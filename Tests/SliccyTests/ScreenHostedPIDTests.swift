#if SLICCY_HOSTED_PID_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenHostedPIDTests {
    @Test func pacingHasNoToleranceAndDeadlineCannotAdmit() {
        let began = ContinuousClock.now
        var budget = ScreenHostedPIDBudget(original: 100, started: began, selfCPU: .seconds(1), childrenCPU: .seconds(2))
        #expect(budget.decision(now: began.advanced(by: .milliseconds(10)), selfCPU: .seconds(1) + .milliseconds(11), childrenCPU: .seconds(2)) == .pace(.milliseconds(1)))
        #expect(budget.decision(now: began.advanced(by: .milliseconds(11)), selfCPU: .seconds(1) + .milliseconds(11), childrenCPU: .seconds(2)) == .spawnCycler)
        #expect(budget.decision(now: began.advanced(by: .seconds(1)), selfCPU: .seconds(1), childrenCPU: .seconds(2)) == .stop(.invalidLifecycle))
        var debt = ScreenHostedPIDBudget(original: 100, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(debt.decision(now: began.advanced(by: .seconds(900)), selfCPU: .seconds(901), childrenCPU: .zero) == .stop(.cpuDebtAtDeadline))
        #expect(debt.maximumTransientDebt == .seconds(1))
        var elapsed = ScreenHostedPIDBudget(original: 100, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(elapsed.decision(now: began.advanced(by: .seconds(900)), selfCPU: .seconds(100), childrenCPU: .seconds(100)) == .stop(.timeLimit))
    }
    @Test func childAdmissionRequiresDecisionAndReapAndNearTargetIsOneShot() throws {
        let began = ContinuousClock.now
        var state = ScreenHostedPIDBudget(original: 10, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(throws: ScreenFailure.incompatible) { try state.didSpawnCycler(pid: 9) }
        #expect(state.decision(now: began, selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
        try state.didSpawnCycler(pid: 9)
        #expect(throws: ScreenFailure.incompatible) { try state.didSpawnCycler(pid: 9) }
        #expect(throws: ScreenFailure.incompatible) { try state.didReapCycler(pid: 8) }
        try state.didReapCycler(pid: 9)
        #expect(state.spawned == 1 && state.reaped == 1)
        #expect(state.decision(now: began.advanced(by: .seconds(1)), selfCPU: .milliseconds(1), childrenCPU: .milliseconds(1)) == .attemptCLI)
        #expect(state.decision(now: began.advanced(by: .seconds(2)), selfCPU: .milliseconds(1), childrenCPU: .milliseconds(1)) == .stop(.invalidLifecycle))
        #expect(throws: ScreenFailure.incompatible) { try state.didSpawnCycler(pid: 9) }
    }
    @Test func skippedTargetIsNeverReuseAndAccountingMustRemainMonotonic() throws {
        let began = ContinuousClock.now
        var state = ScreenHostedPIDBudget(original: 10, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(state.decision(now: began, selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
        try state.didSpawnCycler(pid: 10); try state.didReapCycler(pid: 10)
        #expect(state.decision(now: began.advanced(by: .seconds(1)), selfCPU: .milliseconds(1), childrenCPU: .milliseconds(1)) == .spawnCycler)
        try state.didSpawnCycler(pid: 11); try state.didReapCycler(pid: 11)
        #expect(state.decision(now: began.advanced(by: .seconds(2)), selfCPU: .zero, childrenCPU: .milliseconds(2)) == .stop(.invalidAccounting))
        var invalid = ScreenHostedPIDBudget(original: 2, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(invalid.decision(now: began, selfCPU: .zero, childrenCPU: .zero) == .stop(.unsupportedTarget))
    }

    @Test func returnedPIDWrapArmsApproachBeforeExactAdmission() throws {
        let began = ContinuousClock.now
        var budget = ScreenHostedPIDBudget(original: 10000, started: began, selfCPU: .zero, childrenCPU: .zero)
        var rows: [ScreenHostedPIDBudget.Observation] = []
        for (index, returned) in [Int32(99998), 8500, 9999].enumerated() {
            #expect(budget.decision(now: began.advanced(by: .seconds(index)), selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
            try budget.didSpawnCycler(pid: returned)
            rows += try budget.didReapCycler(pid: returned)
        }
        #expect(rows.map(\.kind) == [.wrap, .approach])
        #expect(rows[0].previousPID == 99998 && rows[0].returnedPID == 8500 && rows[0].wrap == 1)
        #expect(rows[1].distance == 1500)
        #expect(budget.decision(now: began.advanced(by: .seconds(3)), selfCPU: .zero, childrenCPU: .zero) == .attemptCLI)
        #expect(budget.decision(now: began.advanced(by: .seconds(4)), selfCPU: .zero, childrenCPU: .zero) == .stop(.invalidLifecycle))
    }
    @Test func wrapOverTargetArmsHintButOnlySecondExactReturnAdmits() throws {
        let began = ContinuousClock.now
        var budget = ScreenHostedPIDBudget(original: 10000, started: began, selfCPU: .zero, childrenCPU: .zero)
        var rows: [ScreenHostedPIDBudget.Observation] = []
        for (index, returned) in [Int32(99998), 10001, 99998, 8500, 9999].enumerated() {
            #expect(budget.decision(now: began.advanced(by: .seconds(index)), selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
            try budget.didSpawnCycler(pid: returned); rows += try budget.didReapCycler(pid: returned)
        }
        #expect(rows.map(\.kind) == [.wrap, .approach, .missed, .wrap, .approach])
        #expect(rows[1].wrap == 1 && rows[1].returnedPID == 10001 && rows[1].distance == -1)
        #expect(rows[2].closestAbove == 1 && rows[2].closestBelow == nil)
        #expect(rows[3].closestAbove == 1)
        #expect(budget.wraps == 2)
        #expect(budget.decision(now: began.advanced(by: .seconds(5)), selfCPU: .zero, childrenCPU: .zero) == .attemptCLI)
    }
    @Test func secondCrossingEndsWithoutThirdWrapAndDebtStillBlocksAdmission() throws {
        let began = ContinuousClock.now
        var budget = ScreenHostedPIDBudget(original: 10000, started: began, selfCPU: .zero, childrenCPU: .zero)
        for (index, returned) in [Int32(99998), 10001, 99998, 8500, 10001].enumerated() {
            #expect(budget.decision(now: began.advanced(by: .seconds(index)), selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
            try budget.didSpawnCycler(pid: returned); try budget.didReapCycler(pid: returned)
        }
        #expect(budget.decision(now: began.advanced(by: .seconds(5)), selfCPU: .zero, childrenCPU: .zero) == .stop(.wrapLimit))
        #expect(throws: ScreenFailure.incompatible) { try budget.didSpawnCycler(pid: 9999) }
        var debt = ScreenHostedPIDBudget(original: 10000, started: began, selfCPU: .zero, childrenCPU: .zero)
        #expect(debt.decision(now: began, selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
        try debt.didSpawnCycler(pid: 9999); try debt.didReapCycler(pid: 9999)
        #expect(debt.decision(now: began.advanced(by: .seconds(1)), selfCPU: .seconds(1) + .milliseconds(1), childrenCPU: .zero) == .pace(.milliseconds(1)))
        #expect(debt.decision(now: began.advanced(by: .seconds(900)), selfCPU: .seconds(2), childrenCPU: .zero) == .stop(.timeLimit))
    }

    @Test func fakeSpawnReturnsDriveActualBudgetWithoutExternalPIDHint() throws {
        let began = ContinuousClock.now
        for sequence: [Int32] in [[99998, 8500, 9999], [99998, 10001, 99998, 8500, 9999], [99998, 10001, 99998, 10001]] {
            var returns = sequence.makeIterator(), owned: Int32?, actualReaps: [Int32] = []
            let fakePosixSpawn: () throws -> Int32 = {
                guard owned == nil, let pid = returns.next() else { throw ScreenFailure.incompatible }
                owned = pid; return pid
            }
            let fakeWaitpid: (Int32) throws -> Int32 = { pid in
                guard owned == pid else { throw ScreenFailure.incompatible }
                owned = nil; actualReaps.append(pid); return pid
            }
            var budget = ScreenHostedPIDBudget(original: 10000, started: began, selfCPU: .zero, childrenCPU: .zero)
            var observed: [ScreenHostedPIDBudget.Observation] = []
            for index in sequence.indices {
                #expect(budget.decision(now: began.advanced(by: .seconds(index)), selfCPU: .zero, childrenCPU: .zero) == .spawnCycler)
                let returned = try fakePosixSpawn()
                try budget.didSpawnCycler(pid: returned)
                #expect(try fakeWaitpid(returned) == returned)
                observed += try budget.didReapCycler(pid: returned)
            }
            #expect(owned == nil && actualReaps == sequence)
            #expect(observed.contains { $0.kind == .approach && $0.previousPID == 99998 && $0.returnedPID == sequence[1] })
            let decision = budget.decision(now: began.advanced(by: .seconds(sequence.count)), selfCPU: .zero, childrenCPU: .zero)
            #expect(decision == (sequence.last == 9999 ? .attemptCLI : .stop(.wrapLimit)))
            #expect(throws: ScreenFailure.incompatible) { try budget.didSpawnCycler(pid: 9999) }
        }
    }

    @Test func onlyTokenVersionMayDiffer() throws {
        func token(_ words: [UInt32]) throws -> ScreenAuditIdentity {
            try words.withUnsafeBytes { try ScreenAuditIdentity(native: Data($0)) }
        }
        let old: [UInt32] = [1, 501, 20, 501, 20, 99, 42, 7]
        var changed = old; changed[7] = 8
        #expect(ScreenHostedPIDBudget.sameCredentialPrefixAndNewVersion(saved: try token(old), current: try token(changed)))
        #expect(!ScreenHostedPIDBudget.sameCredentialPrefixAndNewVersion(saved: try token(old), current: try token(old)))
        for index in 0...6 {
            var wrong = changed; wrong[index] += 1
            #expect(!ScreenHostedPIDBudget.sameCredentialPrefixAndNewVersion(saved: try token(old), current: try token(wrong)))
        }
    }
    @Test func localHostAndOverridesRefuseBeforeAnySpawn() throws {
        let arguments = ["--screen-runner-proof", "--case", "pid-reuse-hosted"]
        let environment = ScreenHostedPIDHost.required
        try ScreenHostedPIDHost.validate(arguments: arguments, environment: environment, major: 27, arm: true)
        #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDHost.validate(arguments: arguments, environment: [:], major: 27, arm: true) }
        #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDHost.validate(arguments: arguments + ["--limit", "1"], environment: environment, major: 27, arm: true) }
        #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDHost.validate(arguments: arguments, environment: environment, major: 26, arm: true) }
        #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDHost.validate(arguments: arguments, environment: environment, major: 27, arm: false) }
        for key in environment.keys {
            var wrong = environment; wrong[key] = "unapproved"
            #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDHost.validate(arguments: arguments, environment: wrong, major: 27, arm: true) }
        }
        #expect(throws: ScreenFailure.incompatible) { try ScreenHostedPIDSpawn.spawn() }
    }
    @Test func mockedWaitNeverSignalsAnUnownedOrAlreadyReapedPID() throws {
        let now = ContinuousClock.now
        var signals = 0
        let unowned = ScreenHostedPIDSpawn.WaitCalls(now: { now }, wait: { _ in .unowned }, send: { _, _ in signals += 1; return true }, pause: {})
        #expect(throws: ScreenFailure.peerLost) { try ScreenHostedPIDSpawn.reap(123, deadline: now, cancelled: { true }, calls: unowned) }
        #expect(signals == 0)
        var reaped = unowned; reaped.wait = { _ in .reaped(0) }
        let result = try ScreenHostedPIDSpawn.reap(123, deadline: now, cancelled: { true }, calls: reaped)
        #expect(result.status == 0 && !result.interrupted && signals == 0)
    }
    @Test func mockedEscalationRetainsOwnershipUntilActualReap() throws {
        let start = ContinuousClock.now
        var ticks = 0, signals: [Int32] = []
        let calls = ScreenHostedPIDSpawn.WaitCalls(now: { start.advanced(by: .milliseconds(ticks * 500)) }, wait: { pid in
            #expect(pid == 123)
            return ticks == 4 ? .reaped(9) : .running
        }, send: { pid, signal in #expect(pid == 123); signals.append(signal); return true }, pause: { ticks += 1 })
        let result = try ScreenHostedPIDSpawn.reap(123, deadline: start, cancelled: { false }, calls: calls)
        #expect(result.status == 9 && result.interrupted)
        #expect(signals == [15, 9] && ticks == 4)
    }

    @Test func hardCleanupDeadlineCannotExtendTheTrial() throws {
        let start = ContinuousClock.now
        var signals: [Int32] = []
        let calls = ScreenHostedPIDSpawn.WaitCalls(now: { start }, wait: { _ in .running },
            send: { _, signal in signals.append(signal); return true }, pause: { Issue.record("No pacing after hard deadline") })
        #expect(throws: ScreenFailure.stalled) {
            try ScreenHostedPIDSpawn.reap(123, deadline: start, cancelled: { true }, cleanupDeadline: start, calls: calls)
        }
        #expect(signals == [9])
    }

}
#endif
