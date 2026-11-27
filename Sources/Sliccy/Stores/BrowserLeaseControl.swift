import Foundation
import Observation

/// A local review belongs to exactly one linked CLI child. Replacing the link
/// creates a new controller even if the CLI PID (or a request ID) is unchanged.
@MainActor @Observable
final class BrowserLeaseControl {
    // No user preference, environment variable or CLI version overrides this
    // gate. Enable only after the exclusive route and containment release tests
    // have passed against the real broker/adapter (see docs/CLI-CONTRACT.md).
    nonisolated static let verifiedForRelease = false
    nonisolated static let operations = ["status", "cdp-lease-list", "cdp-lease-approve", "cdp-lease-deny", "cdp-lease-revoke"]
    nonisolated static func hasOperations(_ ops: [String]) -> Bool { operations.allSatisfy(ops.contains) }

    private(set) var snapshot: BrowserLeaseSnapshot?
    private(set) var revision = UUID()
    private(set) var busy = false
    private(set) var message: String?
    @ObservationIgnored private(set) var task: Task<Void, Never>?
    private let pid: Int32
    private let route: BrowserLeaseRoute
    private let ownsLiveChild: @MainActor () -> Bool
    private let closeUnverifiedLink: @MainActor () -> Void
    typealias Exchange = @Sendable (Int32, CLIControlRequest) async throws -> BrowserLeaseReply
    nonisolated static let ownedSocket: Exchange = { try await CLIControlClient.request(pid: $0, request: $1, as: BrowserLeaseReply.self) }
    private let exchange: Exchange
    private var ended = false

    init(pid: Int32, route: BrowserLeaseRoute, ownsLiveChild: @escaping @MainActor () -> Bool,
         closeUnverifiedLink: @escaping @MainActor () -> Void, exchange: @escaping Exchange = ownedSocket) {
        self.pid = pid
        self.route = route
        self.ownsLiveChild = ownsLiveChild
        self.closeUnverifiedLink = closeUnverifiedLink
        self.exchange = exchange
    }

    func invalidate() {
        ended = true
        task?.cancel(); task = nil
        snapshot = nil; revision = UUID(); busy = false
        message = "The link changed. This review is no longer current."
    }

    func refresh() { run(nil) }

    func decide(_ decision: BrowserLeaseDecision, reviewed revision: UUID) {
        guard self.revision == revision, snapshot?.permits(decision, at: .now) == true else { return }
        run(decision)
    }

    private func checkOwner() throws {
        try Task.checkCancellation()
        guard !ended, ownsLiveChild() else { throw CLIControlError.unavailable }
    }

    private func send(_ command: CLIControlRequest) async throws -> BrowserLeaseReply {
        try checkOwner()
        let reply = try await exchange(pid, command)
        try checkOwner()
        guard reply.v == 1, reply.ok != false, reply.error == nil else { throw CLIControlError.refused }
        return reply
    }

    private func list() async throws -> BrowserLeaseSnapshot {
        try await BrowserLeaseSnapshot(send(.init(op: "cdp-lease-list")), route: route)
    }

    private func checkRoute() async throws {
        do {
            let status = try await send(.init(op: "status"))
            guard status.pid == pid, status.offers == ["cdp-lease-v1"], Self.hasOperations(status.ops ?? [])
            else { throw CLIControlError.unavailable }
        } catch {
            // Do not leave a possibly broad follower alive just because its UI is disabled.
            if !ended, !Task.isCancelled { closeUnverifiedLink() }
            throw error
        }
    }

    private func run(_ decision: BrowserLeaseDecision?) {
        guard !ended, !busy, ownsLiveChild() else { return }
        busy = true; message = nil; snapshot = nil; revision = UUID()
        task = Task {
            defer { if !ended { busy = false; task = nil } }
            do {
                try await checkRoute()
                let fresh = try await list()
                if let decision {
                    try await checkRoute() // recheck immediately before the mutation
                    guard fresh.permits(decision, at: .now) else {
                        snapshot = fresh
                        message = "The request or its lease changed. Nothing was sent. Review the current list."
                        return
                    }
                    // The broker must check the immutable ID/parent/epoch and
                    // still-exclusive route atomically, including at expiry.
                    let ack = try await send(decision.command)
                    guard ack.ok == true else { throw CLIControlError.invalid }
                    try await checkRoute()
                    snapshot = try await list() // never synthesize a grant/revoke locally
                } else { snapshot = fresh }
            } catch {
                guard !ended, !Task.isCancelled else { return }
                // No CLI-supplied error text, free-text reason, token or URL in
                // diagnostics, notices, stderr or persisted session history.
                message = decision == nil
                    ? "Browser lease control is unavailable. A compatible CLI on an exclusive lease-only link is required."
                    : "Change not confirmed. Refresh to check the broker; the action will not be retried."
            }
        }
    }
}
