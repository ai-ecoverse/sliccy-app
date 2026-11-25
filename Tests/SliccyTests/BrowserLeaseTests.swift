import CryptoKit
import Foundation
import Observation
import Testing
@testable import Sliccy

@MainActor
@Suite(.timeLimit(.minutes(1)))
struct BrowserLeaseTests {
    private let endpoint = "http://127.0.0.1:49999"
    private let join = "https://fixture.invalid/join/test-only"

    @Test func bundledContractAndPartialCapabilitiesCannotStartALeaseLink() throws {
        let file = Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities-approvals.json")
        var caps = try JSONDecoder().decode(CLICapabilities.self, from: Data(contentsOf: file))
        #expect(caps.supportsApprovals)
        #expect(!caps.supportsBrowserLeaseControl)
        caps.control.ops += BrowserLeaseControl.operations
        #expect(!caps.supportsBrowserLeaseControl)
        caps.commands["follow"]?.cdpLeaseV1 = true
        #expect(caps.supportsBrowserLeaseControl)
        for op in BrowserLeaseControl.operations {
            var incomplete = caps
            incomplete.control.ops.removeAll { $0 == op }
            #expect(!incomplete.supportsBrowserLeaseControl)
        }
        #expect(!BrowserLeaseControl.verifiedForRelease)
    }

    @Test func leaseRouteHasNoDiscoveryNoGeneralOffersAndNoSecretInArgv() throws {
        let route = try #require(BrowserLeaseRoute(endpoint: endpoint, label: "fixture-job"))
        let invocation = try #require(route.invocation(join: join))
        #expect(invocation.arguments == ["-", "follow", "--json", "--lease-browser", endpoint, "--name", "fixture-job"])
        #expect(invocation.input == Data((join + "\n").utf8))
        #expect(BrowserLeaseRoute.loopbackOrigin("http://[::1]:9876/") == "http://[::1]:9876")
        for bad in ["http://localhost:80", "http://127.0.0.1", "http://user@127.0.0.1:9999", "http://127.1:1234", endpoint + "?token=x", endpoint + "#x", endpoint + "/path", "https://fixture.invalid"] {
            #expect(BrowserLeaseRoute(endpoint: bad, label: "job") == nil)
        }
        // Same local identifier as `lease pair --link` and exclusive `follow --name` (slicc-cli#933).
        for label in ["work-2", String(repeating: "a", count: 48)] {
            #expect(BrowserLeaseRoute(endpoint: endpoint, label: label)?.label == label)
        }
        for invalid in ["", "9work", "-job", "Work", "work_2", "work team", "work.team", "work\n", String(repeating: "a", count: 49), join] {
            #expect(BrowserLeaseRoute(endpoint: endpoint, label: invalid) == nil)
        }
        #expect(route.invocation(join: join + "\n--other") == nil)
        #expect(route.invocation(join: "http://fixture.invalid/insecure") == nil)
    }

    @Test func ruleLabelsMatchExactWireValuesWithoutRewriting() {
        typealias Rule = BrowserLeaseRule
        let site = "https://billing.example"
        #expect(Rule(kind: .origin, url: site).reviewable)
        #expect(Rule(kind: .exact, url: site + "/?view=paid#two").reviewable)
        #expect(Rule(kind: .prefix, url: site + "/invoices").reviewable)
        #expect(!Rule(kind: .origin, url: site + "/invoices").reviewable)
        #expect(!Rule(kind: .exact, url: site + "/?access_token=fixture").reviewable)
        #expect(!Rule(kind: .exact, url: site + "/eyJ0eXAi.foo.bar").reviewable)
        for invalid in [site + "/invoices/**", site + "/invoices?x=1", site + "/invoices/", site + "/a%2fb", site + "/%2e./two", site + "/%xx", "https://u:p@billing.example/a", "https://BILLING.example/a", "http://billing.example/a"] {
            #expect(!Rule(kind: .prefix, url: invalid).reviewable)
        }
    }

    private func thumbprint() -> String {
        func b64(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        // Fresh test-only Ed25519 public JWK. The private key is never serialized.
        let x = b64(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"\(x)\"}"
        return b64(Data(SHA256.hash(data: Data(jwk.utf8))))
    }

    @Test func ambiguousOrMalformedSnapshotsAreNeverReviewable() throws {
        let route = try #require(BrowserLeaseRoute(endpoint: endpoint, label: "job"))
        let row: [String: Any] = ["request": "R1", "jkt": thumbprint(), "link": "job", "browser": endpoint,
                                  "allow": [["kind": "origin", "url": "https://billing.example"]], "ttlSeconds": 3600]
        func decode(_ rows: [[String: Any]]) throws -> BrowserLeaseSnapshot {
            let data = try JSONSerialization.data(withJSONObject: ["v": 1, "ok": true, "pending": rows, "active": []])
            return try BrowserLeaseSnapshot(JSONDecoder().decode(BrowserLeaseReply.self, from: data), route: route)
        }
        #expect(throws: (any Error).self) { try decode([row, row]) }
        for (key, invalid): (String, Any) in [("ttlSeconds", 0), ("ttlSeconds", NSNull()), ("parent", "L1"), ("parent", NSNull()), ("jkt", "short"), ("request", "header.payload.sig"), ("browser", "http://127.0.0.1:50000"), ("link", "Other job"), ("link", join), ("allow", [["kind": "other", "url": "https://site.example"]])] {
            var bad = row; bad[key] = invalid
            #expect(throws: (any Error).self) { try decode([bad]) }
        }
        var expansion = row; expansion.removeValue(forKey: "ttlSeconds"); expansion["parent"] = "L1"
        let orphan = try decode([expansion])
        let item = try #require(orphan.pending.first)
        #expect(!orphan.permits(.approve(item, parent: nil), at: .now))
        #expect(orphan.permits(.deny(item), at: .now))
    }

    private struct Fixture {
        let root: URL
        let link: BrowserLeaseLink
        func ops() throws -> [String] {
            try String(contentsOf: root.appending(path: "ops"), encoding: .utf8).split(separator: "\n").map(String.init)
        }
        @MainActor func close() { link.stop(); try? FileManager.default.removeItem(at: root) }
    }

    private func fixture(_ mode: String) throws -> Fixture {
        // Short private path for AF_UNIX; never use a user's actual control directory.
        let root = URL(fileURLWithPath: "/private/tmp").appending(path: "sliccy-lease-\(UUID())")
        let fm = FileManager.default
        try fm.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            let exe = root.appending(path: "slicc-fixture")
            try fm.copyItem(at: Bundle.module.resourceURL!.appending(path: "Fixtures/browser-lease-owner.py"), to: exe)
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: exe.path)
            try JSONSerialization.data(withJSONObject: ["mode": mode, "jkt": thumbprint(), "browser": endpoint])
                .write(to: root.appending(path: "fixture.json"))
            let route = try #require(BrowserLeaseRoute(endpoint: endpoint, label: "fixture-job"))
            let link = BrowserLeaseLink(route: route, exchange: { pid, command in
                try await Task.detached {
                    try CLIControlClient.exchange(pid: pid, request: command, socketDirectory: root.path, as: BrowserLeaseReply.self)
                }.value
            })
            link.start(executable: exe.path, join: join, browserIsCurrent: { true })
            return Fixture(root: root, link: link)
        } catch { try? fm.removeItem(at: root); throw error }
    }

    /// Event driven; no polling a PID, UI, clock or file. Both initial success
    /// and unavailable/failed handshake end the wait.
    private func settled(_ fixture: Fixture) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await Self.observeHandshake(fixture.link) }
            group.addTask {
                try await Task.sleep(for: .seconds(15))
                let ops = (try? fixture.ops()) ?? [] // op names only, never argv or stdin
                Issue.record("Fixture handshake did not settle. Last recorded ops: \(ops)")
                throw CLIControlError.timeout
            }
            _ = try await group.next()
        }
    }

    private static func observeHandshake(_ link: BrowserLeaseLink) async throws {
        let results = Observations {
            if let control = link.control { return !control.busy }
            return link.message.contains("unavailable") || link.message.contains("stopped")
        }
        for await done in results where done { return }
        throw CancellationError()
    }

    @Test(arguments: ["approve", "deny-expansion", "deny-initial"])
    func exclusiveChildRunsOnlyTheExplicitOwnerDecision(mode: String) async throws {
        let f = try fixture(mode)
        defer { f.close() }
        try await settled(f)
        let control = try #require(f.link.control, "Handshake ended after \((try? f.ops()) ?? [])")
        let first = try #require(control.snapshot?.pending.first)
        #expect(first.ttlSeconds == 3600 && first.parent == nil && first.jkt.count == 43)
        #expect(try f.ops() == ["capabilities", "exclusive-follow", "status", "cdp-lease-list"])
        let revision = control.revision
        let action = BrowserLeaseDecision.approve(first, parent: nil)
        control.decide(mode == "deny-initial" ? .deny(first) : action, reviewed: revision)
        control.decide(action, reviewed: revision) // double click/old sheet is not another decision
        await control.task?.value
        if mode == "deny-initial" {
            #expect(control.snapshot?.pending.isEmpty == true && control.snapshot?.active.isEmpty == true)
            #expect(try !f.ops().contains("cdp-lease-approve")); return
        }
        let state = try #require(control.snapshot)
        let parent = try #require(state.active.first), extra = try #require(state.pending.first)
        #expect(parent.id == "L1" && extra.parent == parent.id && extra.ttlSeconds == nil)
        #expect(extra.allow == [.init(kind: .exact, url: "https://receipts.example/r/1042?q=two#detail")])
        #expect(!state.permits(.approve(extra, parent: parent), at: parent.deadline))
        #expect(state.permits(.approve(extra, parent: parent), at: parent.deadline.addingTimeInterval(-1)))
        #expect(try f.ops().filter { $0 == "cdp-lease-approve" }.count == 1)
        control.decide(mode == "approve" ? .approve(extra, parent: parent) : .deny(extra), reviewed: control.revision)
        await control.task?.value
        let after = try #require(control.snapshot?.active.first)
        #expect(control.snapshot?.pending.isEmpty == true && parent.exp == after.exp)
        if mode == "approve" { #expect(after.lease == "L2" && after.allow == parent.allow + extra.allow) }
        else { #expect(after == parent) }
        control.decide(.revoke(after), reviewed: control.revision)
        await control.task?.value
        #expect(control.snapshot?.active.isEmpty == true)
        #expect(try f.ops().filter { $0 == "cdp-lease-revoke" }.count == 1)
    }

    @Test(arguments: ["old", "mixed", "wrong-pid", "missing"])
    func absentCapabilityOrNonexclusiveStatusNeverExposesAReview(mode: String) async throws {
        let f = try fixture(mode)
        defer { f.close() }
        try await settled(f)
        #expect(f.link.control == nil)
        #expect(try f.ops() == (mode == "old" ? ["capabilities"] : ["capabilities", "exclusive-follow", "status"]))
    }

    @Test(arguments: ["changed", "lost-ack", "invalidated", "lost-exclusive"])
    func staleReviewAndUnconfirmedMutationNeverReplay(mode: String) async throws {
        let f = try fixture(mode)
        defer { f.close() }
        try await settled(f)
        let control = try #require(f.link.control, "Handshake ended after \((try? f.ops()) ?? [])")
        let item = try #require(control.snapshot?.pending.first)
        let revision = control.revision
        if mode == "invalidated" {
            let store = WorkspaceStore(preview: true, defaults: nil)
            let id = store.sessions[0].id
            store.browserLeaseLinks[id] = f.link
            let encoded = String(decoding: try JSONEncoder().encode(store.sessions), as: UTF8.self)
            #expect(!encoded.contains(item.jkt) && !encoded.contains(join) && !encoded.contains(endpoint))
            store.clearLiveConnection(id)
            #expect(store.browserLeaseLinks[id] == nil && control.snapshot == nil)
        }
        control.decide(.approve(item, parent: nil), reviewed: revision)
        await control.task?.value
        control.decide(.approve(item, parent: nil), reviewed: revision)
        #expect(control.task == nil)
        #expect(try f.ops().filter { $0 == "cdp-lease-approve" }.count == (mode == "lost-ack" ? 1 : 0))
        if mode == "changed" { #expect(control.snapshot?.pending.first?.ttlSeconds == 7200) }
        else { #expect(control.snapshot == nil) }
    }
}
