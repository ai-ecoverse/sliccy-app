#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit

final class ScreenRunnerLaunchApplication: @unchecked Sendable {
    let value: NSRunningApplication
    let pid: pid_t
    let bundle: String?
    init(_ value: NSRunningApplication) { self.value = value; pid = value.processIdentifier; bundle = value.bundleIdentifier }
}

/// The AppKit adapter is confined to the proof runner. Every task is covered by
/// a ledger ticket or the single verificationPending slot until it completes.
@MainActor
final class ScreenRunnerLaunchCoordinator {
    nonisolated let ledger = ScreenRunnerLaunchBarrier()
    private let journal: ScreenRunnerJournal
    private let deadline: ContinuousClock.Instant
    private var token: NSObjectProtocol?
    private var tasks: [Int: Task<Void, Never>] = [:]
    private var applications: [pid_t: ScreenRunnerLaunchApplication] = [:]
    private var closed = false
    private var closeResult = false
    private var failureRecorded = false
    init(journal: ScreenRunnerJournal) throws {
        _ = try ScreenRunnerHost.require()
        self.journal = journal
        deadline = journal.began.advanced(by: .seconds(ScreenRunnerSetupAllowance.watchdogSeconds))
        let ledger = self.ledger
        token = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: nil) { [weak self, ledger] notification in
            switch ledger.begin() {
            case .stop(let relay):
                relay.proofWorkspaceChange(notification, origin: .workspaceLaunch)
            case .collect(let ticket):
                // Only setup consumes payload before any stop observer has armed.
                let application = (notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication).map(ScreenRunnerLaunchApplication.init)
                Task { @MainActor [weak self] in
                    guard let self, !self.closed else { ledger.complete(ticket, observation: nil, failure: .cancelled); return }
                    let task = Task { @MainActor [weak self] in
                        guard let self else { ledger.complete(ticket, observation: nil, failure: .cancelled); return }
                        await self.collect(ticket, application: application)
                        self.tasks.removeValue(forKey: ticket.sequence)
                    }
                    self.tasks[ticket.sequence] = task
                }
            case .refuse: break
            }
        }
    }
    private func recordFailure(_ error: any Error) {
        let reason = error as? ScreenRunnerLaunchBarrier.Failure ?? .registration
        ledger.fail(reason)
        if !failureRecorded {
            failureRecorded = true
            journal.emit("runner-launches-failed", ["reason": reason.rawValue])
        }
    }
    func register(label: String, identity: ScreenRunnerProcessIdentity) {
        guard identity.role == .chrome else { ledger.fail(.identity); return }
        ledger.register(label: label, original: identity.sample)
    }
    private func finished(_ application: ScreenRunnerLaunchApplication) async throws {
        let waiter = ScreenRunnerLaunchCompletion()
        let observation = application.value.observe(\.isFinishedLaunching, options: [.initial, .new]) { value, _ in
            if value.isFinishedLaunching { waiter.finish(.success(())) }
        }
        defer { observation.invalidate(); waiter.finish(.failure(.cancelled)) }
        try await waiter.wait()
    }
    private func waitForFinished(_ application: ScreenRunnerLaunchApplication) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.finished(application) }
            let deadline = self.deadline
            group.addTask { try await ContinuousClock().sleep(until: deadline); throw ScreenRunnerLaunchBarrier.Failure.deadline }
            defer { group.cancelAll() }
            _ = try await group.next()
        }
    }
    private nonisolated static func sample(_ application: ScreenRunnerLaunchApplication, ticket: ScreenRunnerLaunchBarrier.Ticket) async throws -> ScreenRunnerLaunchBarrier.Observation {
        let pid = application.pid
        guard pid > 0, application.bundle == "com.google.Chrome" else { throw ScreenRunnerLaunchBarrier.Failure.invalidPayload }
        return try await ScreenRunnerLaunchSampling.observe(ticket: ticket, bundle: application.bundle ?? "", before: {
            try ScreenRunnerBSD.observe(pid, phase: "launch-before", role: "com.google.Chrome", record: { _ in }).sample
        }, registration: {
            await MainActor.run {
                let current = NSRunningApplication(processIdentifier: pid)
                func facts(_ value: NSRunningApplication) -> ScreenRunnerLaunchInstance.Facts {
                    .init(pid: value.processIdentifier, bundle: value.bundleIdentifier,
                          finished: value.isFinishedLaunching, terminated: value.isTerminated)
                }
                return ScreenRunnerLaunchInstance.matches(original: application.value, current: current,
                    originalFacts: facts(application.value), currentFacts: current.map(facts),
                    expectedPID: pid, expectedBundle: application.bundle ?? "")
            }
        }, after: {
            try ScreenRunnerBSD.observe(pid, phase: "launch-after", role: "com.google.Chrome", record: { _ in }).sample
        })
    }

    private func collect(_ ticket: ScreenRunnerLaunchBarrier.Ticket, application: ScreenRunnerLaunchApplication?) async {
        guard let application, application.pid > 0 else { ledger.complete(ticket, observation: nil, failure: .invalidPayload); return }
        guard application.bundle == "com.google.Chrome" else { ledger.complete(ticket, observation: nil); return }
        do {
            try await waitForFinished(application)
            try Task.checkCancellation()
            let value = try await Task.detached { try await Self.sample(application, ticket: ticket) }.value
            try Task.checkCancellation()
            guard !closed else { throw ScreenRunnerLaunchBarrier.Failure.cancelled }
            applications[value.before.pid] = application
            ledger.complete(ticket, observation: value)
        } catch {
            ledger.complete(ticket, observation: nil, failure: error as? ScreenRunnerLaunchBarrier.Failure ?? .registration)
        }
    }
    func ready() async throws -> ScreenRunnerLaunchBarrier.Candidate {
        do {
            let value = try await ledger.awaitCandidate(until: deadline)
            try Task.checkCancellation()
            // The revision is already latched. No recomputation after these rows.
            for owner in value.owners { journal.emit("runner-launch-owner", ScreenRunnerLaunchDiagnostics.ownerFields(owner, revision: value.revision, began: journal.began)) }
            guard journal.emit("runner-launches-ready", ["revision": String(value.revision), "count": 4]) else {
                ledger.fail(.marker); throw ScreenRunnerLaunchBarrier.Failure.marker
            }
            return value
        } catch { recordFailure(error); throw error }
    }
    func verify(_ candidate: ScreenRunnerLaunchBarrier.Candidate) async throws {
        try ledger.beginVerification(candidate)
        var values: [ScreenRunnerLaunchBarrier.Observation] = []
        do {
            for owner in candidate.owners {
                try Task.checkCancellation()
                guard let application = applications[owner.original.pid], .now < deadline else { throw ScreenRunnerLaunchBarrier.Failure.deadline }
                let value = try await Task.detached { try await Self.sample(application, ticket: owner.observation.ticket) }.value
                try Task.checkCancellation()
                values.append(value)
            }
            try ledger.endVerification(candidate, observations: values)
            for (owner, observed) in zip(candidate.owners, values) {
                let checked = ScreenRunnerLaunchBarrier.Owner(label: owner.label, original: owner.original, observation: observed)
                journal.emit("runner-launch-recheck", ScreenRunnerLaunchDiagnostics.ownerFields(checked, revision: candidate.revision, began: journal.began))
            }
            guard journal.emit("runner-launches-verified", ["revision": String(candidate.revision), "count": 4]) else {
                ledger.fail(.marker); throw ScreenRunnerLaunchBarrier.Failure.marker
            }
        } catch {
            try? ledger.endVerification(candidate, observations: nil)
            recordFailure(error)
            throw error
        }
    }
    func arm(_ relay: ScreenStopRelay) throws {
        guard !Task.isCancelled, !closed, .now < deadline else { ledger.fail(.deadline); throw ScreenRunnerLaunchBarrier.Failure.deadline }
        let revision: UInt64
        do { revision = try ledger.arm(relay) } catch { recordFailure(error); throw error }
        journal.emit("runner-launches-armed", ["revision": String(revision), "pending": 0])
    }
    @discardableResult func close() -> Bool {
        guard !closed else { return closeResult }
        closed = true
        if let token { NSWorkspace.shared.notificationCenter.removeObserver(token); self.token = nil }
        for task in tasks.values { task.cancel() }
        let result = ledger.close()
        journal.emit("runner-launches-closed", ["pending": result.pending, "failed": result.failed])
        closeResult = result.pending == 0 && !result.failed
        return closeResult
    }
}
#endif
