import Foundation
import Observation

/// An exclusive follower, never a new browser launcher. The endpoint must come
/// from the already selected local browser session; never discover one or accept
/// an endpoint/join URL embedded in a request. Only the join secret is on stdin.
struct BrowserLeaseRoute: Equatable, Sendable {
    let endpoint: String
    let label: String

    static func loopbackOrigin(_ value: String) -> String? {
        guard let u = URLComponents(string: value, encodingInvalidCharacters: false),
              let host = u.host, ["127.0.0.1", "[::1]"].contains(host),
              let port = u.port, (1...65535).contains(port) else { return nil }
        let origin = "http://\(host):\(port)"
        return (value == origin || value == origin + "/") ? origin : nil
    }

    init?(endpoint: String, label: String) {
        guard let origin = Self.loopbackOrigin(endpoint),
              label.range(of: #"\A[A-Za-z0-9][A-Za-z0-9_-]{0,47}\z"#, options: .regularExpression) != nil else { return nil }
        self.endpoint = origin
        self.label = label
    }

    func invocation(join: String) -> CLIInvocation? {
        guard (1...4096).contains(join.utf8.count), join.utf8.allSatisfy({ (33...126).contains($0) }),
              !join.contains("\\"), let u = URLComponents(string: join, encodingInvalidCharacters: false),
              u.scheme == "https", let host = u.host, !host.isEmpty, u.user == nil, u.password == nil else { return nil }
        return .init(arguments: ["-", "follow", "--json", "--lease-browser", endpoint, "--name", label], input: Data((join + "\n").utf8))
    }
}

@MainActor @Observable
final class BrowserLeaseLink {
    let route: BrowserLeaseRoute
    private(set) var control: BrowserLeaseControl?
    private(set) var message = "Checking lease-only support…"
    private let child = CLIProcess()
    @ObservationIgnored private var reader: Task<Void, Never>?

    private let exchange: BrowserLeaseControl.Exchange
    init(route: BrowserLeaseRoute, exchange: @escaping BrowserLeaseControl.Exchange = BrowserLeaseControl.ownedSocket) {
        self.route = route
        self.exchange = exchange
    }

    func start(executable: String, join: String, browserIsCurrent: @escaping @MainActor () -> Bool) {
        guard reader == nil, let invocation = route.invocation(join: join) else { return }
        reader = Task { [self] in
            do {
                let caps = try await CLIClient.capabilities(at: executable)
                try Task.checkCancellation()
                guard caps.supportsBrowserLeaseControl, browserIsCurrent() else { throw CLIControlError.unavailable }
                message = "Waiting for the lease-only link…"
                // Do not collect human stderr, join metadata, general inventory,
                // credentials or Seven approvals for this process.
                let bytes = try child.start(executable: executable, invocation: invocation)
                var decoder = NDJSONDecoder()
                for try await chunk in bytes {
                    try Task.checkCancellation()
                    guard browserIsCurrent() else { throw CLIControlError.unavailable }
                    for event in try decoder.append(chunk) {
                        guard event.schema == 1 else { throw CLIControlError.invalid }
                        switch event.kind {
                        case "linked":
                            guard let pid = child.runningPID else { throw CLIControlError.unavailable }
                            control?.invalidate()
                            let control = BrowserLeaseControl(pid: pid, route: route, ownsLiveChild: { [weak self] in
                                self?.child.runningPID == pid && browserIsCurrent()
                            }, closeUnverifiedLink: { [weak self] in
                                self?.message = "Lease-only link unavailable: the broker did not confirm an exclusive route."
                                self?.stop()
                            }, exchange: exchange)
                            self.control = control
                            control.refresh()
                        case "link-lost", "connecting", "reconnecting":
                            control?.invalidate(); control = nil
                            message = "No current lease-only link. Waiting for the broker…"
                        case "closed", "error", "browser-gone": throw CLIControlError.unavailable
                        default: break
                        }
                    }
                }
                message = "The lease-only broker stopped."
            } catch {
                message = "Lease-only link unavailable. No ordinary browser link was opened instead."
            }
            stop()
        }
    }

    func stop() {
        control?.invalidate(); control = nil
        reader?.cancel(); reader = nil
        child.terminate()
    }
}

extension WorkspaceStore {
    /// Only allow the browser selected via the local browser/profile picker,
    /// launched by the still-connected owner child. Never attach to an unrelated
    /// browser merely because it has a localhost debug port.
    func canStartBrowserLeaseLink(_ id: UUID) -> Bool {
        BrowserLeaseControl.verifiedForRelease && browserLeaseCapable.contains(id) &&
        session(id)?.isLive == true && session(id)?.localBrowserProfile != nil && session(id)?.connection == .connected &&
        attachedBrowsers[id]?.owned == true && liveProcesses[id]?.runningPID != nil &&
        localBrowserEndpoints[id].flatMap(BrowserLeaseRoute.loopbackOrigin) != nil
    }

    func startBrowserLeaseLink(_ id: UUID, label: String, join: String) {
        guard canStartBrowserLeaseLink(id), browserLeaseLinks[id] == nil,
              let token = liveTokens[id], let executable = liveExecutables[id], let endpoint = localBrowserEndpoints[id],
              let route = BrowserLeaseRoute(endpoint: endpoint, label: label), route.invocation(join: join) != nil else { return }
        let link = BrowserLeaseLink(route: route)
        browserLeaseLinks[id] = link
        link.start(executable: executable, join: join, browserIsCurrent: { [weak self, weak link] in
            guard let self, let link else { return false }
            return self.browserLeaseLinks[id] === link && self.liveTokens[id] == token &&
                self.localBrowserEndpoints[id] == endpoint && self.canStartBrowserLeaseLink(id)
        })
    }

    func stopBrowserLeaseControl(_ id: UUID) { browserLeaseLinks.removeValue(forKey: id)?.stop() }
}
