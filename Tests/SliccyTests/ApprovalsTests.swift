import Foundation
import Testing
@testable import Sliccy

@MainActor
final class RecordingNotifier: ApprovalNotifying {
    var posted: [String] = []
    var withdrawn: [String] = []
    func post(_ item: ApprovalItem, session: UUID, title: String) { posted.append(item.id) }
    func withdraw(_ items: [String], session: UUID) { withdrawn += items }
}

@MainActor
struct ApprovalsTests {
    func events() throws -> [CLIEvent] {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/approvals.ndjson"))
        var decoder = NDJSONDecoder()
        return try decoder.append(data)
    }

    @Test func cliFixtureItemsOfferOnlyTheAnswersTheyAllow() throws {
        let items = try #require(try events()[0].approvals?.items)
        let sudo = items[0], tool = items[1], capture = items[2]
        #expect(sudo.answers == [.once, .always, .deny, .stop])
        #expect(tool.answers == [.once, .deny, .stop])
        #expect(capture.answers == [.once, .deny])
        #expect(sudo.detailText == "apt-get install -y ripgrep  (in /workspace)")
        #expect(sudo.verdictText == "Judge: level 2 · it installs software")
        #expect(sudo.agentLabel == "cone · cone")
        #expect(tool.detailText == "bash · curl https://example.com")
        #expect(tool.verdictText == "Judge checking…")
        #expect(tool.agentLabel == "research · Ada · sliccy.com")
        #expect(capture.detailText == "screen video · 30 s · by record")
        #expect(capture.verdictText == "No verdict: the judge gave no verdict")
        #expect(capture.agentLabel == "owner")
        let now = Date(timeIntervalSince1970: 1767268800)
        #expect(sudo.timeLeft(at: now) == "2:00 left")
        #expect(sudo.timeLeft(at: now.addingTimeInterval(121)) == "Expired")
    }

    @Test func guestMessagesNeverShowPrompts() throws {
        let message = try JSONDecoder().decode(ApprovalItem.self, from: Data(#"{"id":"apr-m","kind":"guest-message","requester":{"kind":"guest","name":"Ada"},"detail":{"text":"private guest prompt","attachments":[{"name":"notes.txt","mimeType":"text/plain","size":12}]},"tier":"user","always":true,"stoppable":false,"createdAt":1,"expiresAt":2}"#.utf8))
        #expect(!message.detailText.contains("private guest prompt"))
        #expect(message.detailText.contains("1 attachments"))
        #expect(message.answers == [.once, .always, .deny])
    }

    @Test func missingFlagsAreNotOffered() throws {
        let item = try JSONDecoder().decode(ApprovalItem.self, from: Data(#"{"id":"apr-x","kind":"owner-tool","requester":{"kind":"user","name":"you"},"detail":{"tool":"read","future":1},"tier":"user","createdAt":"2026-01-01T12:00:00Z","expiresAt":1767269100000,"verdict":{"aligned":0.9,"level":1,"reason":"ok","later":true}}"#.utf8))
        #expect(item.answers == [.once, .deny])
        #expect(item.createdAt.date != nil)
        #expect(item.verdict?.level == 1)
        let flag = try JSONDecoder().decode(ApprovalItem.self, from: Data(#"{"id":"--json","kind":"sudo","requester":{"kind":"agent","name":"cone"},"detail":{},"tier":"user","always":true,"stoppable":true,"createdAt":1,"expiresAt":2}"#.utf8))
        #expect(!flag.answerable)
    }

    @Test func snapshotsReplaceItemsAndNotifyOnlyNewOnes() throws {
        let store = WorkspaceStore(preview: true, defaults: nil)
        let notifier = RecordingNotifier()
        store.approvalNotifier = notifier
        let id = store.sessions[0].id
        let events = try events()
        store.applyApprovals(events[0], to: id)
        #expect(store.approvals[id]?.active == true)
        #expect(store.approvals[id]?.items.count == 3)
        #expect(notifier.posted.count == 3)
        store.applyApprovals(events[1], to: id)
        #expect(store.approvals[id]?.items.map(\.kind) == ["guest-tool", "capture"])
        #expect(notifier.posted.count == 3)
        #expect(notifier.withdrawn == [events[0].approvals!.items[0].id])
        store.applyApprovals(events[2], to: id)
        #expect(store.approvals[id]?.active == false)
        #expect(store.approvals[id]?.message?.contains("Reconnecting") == true)
        #expect(store.approvals[id]?.items.count == 2)
        // The same items after a reconnect are not new and are not notified again.
        store.applyApprovals(events[3], to: id)
        #expect(store.approvals[id]?.active == true)
        #expect(store.approvals[id]?.items.count == 2)
        #expect(notifier.posted.count == 3)
        var empty = events[3]; empty.approvals = []
        store.applyApprovals(empty, to: id)
        #expect(store.approvals[id]?.items.isEmpty == true)
        #expect(notifier.withdrawn.count == 3)
    }

    @Test func reconnectNotifiesStillPendingItemsAgain() throws {
        let store = WorkspaceStore(preview: true, defaults: nil)
        let notifier = RecordingNotifier()
        store.approvalNotifier = notifier
        let id = store.sessions[0].id
        store.applyApprovals(try events()[1], to: id)
        #expect(notifier.posted.count == 2)
        store.stopApprovals(id)
        #expect(notifier.withdrawn.count == 2)
        store.applyApprovals(try events()[3], to: id)
        #expect(notifier.posted.count == 4)
    }

    @Test func undecodableItemsAreCountedNotShown() throws {
        let line = #"{"schema":1,"event":"approvals","approvals":[{"id":"apr-ok","kind":"sudo","requester":{"kind":"agent","name":"cone"},"detail":{"command":"ls"},"tier":"user","always":false,"stoppable":false,"createdAt":1,"expiresAt":2},{"id":"apr-bad","kind":"future"}]}"#
        var decoder = NDJSONDecoder()
        let event = try #require(try decoder.append(Data((line + "\n").utf8)).first)
        var queue = ApprovalQueue()
        queue.apply(event)
        #expect(queue.active)
        #expect(queue.items.map(\.id) == ["apr-ok"])
        #expect(queue.skipped == 1)
    }

    @Test func stoppedStreamIsNotLiveAndCannotBeAnswered() throws {
        let store = WorkspaceStore(preview: true, defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.applyApprovals(try events()[0], to: id)
        store.clearLiveConnection(id)
        #expect(store.approvals[id]?.active == false)
        #expect(store.approvals[id]?.message == "Approvals disconnected.")
        let item = try #require(store.approvals[id]?.items.first)
        store.decide(item.id, answer: .once, for: id)
        #expect(store.decideProcesses.isEmpty)
        #expect(store.approvals[id]?.message?.contains("aren’t live") == true)
    }

    @Test func invocationsKeepTheJoinURLOnStdin() {
        let secret = "https://example.invalid/#join=private"
        let watch = CLIInvocation.approvals(join: secret)
        #expect(watch.arguments == ["-", "approvals", "--json", "--watch"])
        let decide = CLIInvocation.decide(join: secret, id: "apr-1", answer: .stop)
        #expect(decide.arguments == ["-", "decide", "--json", "--", "apr-1", "stop"])
        for call in [watch, decide] {
            #expect(!call.arguments.joined().contains(secret))
            #expect(String(decoding: call.input, as: UTF8.self) == secret + "\n")
        }
        #expect(CLIInvocation.decide(cdp: "http://127.0.0.1:9222", id: "apr-1", answer: .once).arguments ==
                ["decide", "--cdp", "http://127.0.0.1:9222", "--origin", CLIInvocation.localOrigin, "--json", "--", "apr-1", "once"])
    }

    @Test func capabilitiesGateOnApprovalsAndDecide() throws {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities.json"))
        var capabilities = try JSONDecoder().decode(CLICapabilities.self, from: data)
        #expect(!capabilities.supportsApprovals)
        capabilities.commands["approvals"] = .init(json: "events")
        #expect(!capabilities.supportsApprovals)
        capabilities.commands["decide"] = .init(json: "none")
        #expect(capabilities.supportsApprovals)
        let cli = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities-approvals.json"))
        capabilities = try JSONDecoder().decode(CLICapabilities.self, from: cli)
        #expect(capabilities.supportsApprovals)
        #expect(capabilities.supportsRemoteWorkspace)
        capabilities.agent?.ops = ["prompt", "watch", "abort", "inventory", "approvals"]
        #expect(!capabilities.supportsApprovals)
    }

    @Test func olderCLIShowsUpdateMessage() throws {
        let store = WorkspaceStore(preview: true, defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true; $0.connection = .connected }
        store.joinCredentials[id] = "join"
        store.liveExecutables[id] = "/usr/bin/true"
        store.startApprovals(id)
        #expect(store.approvalProcesses.isEmpty)
        #expect(store.approvals[id]?.message?.contains("Update slicc") == true)
    }

    @Test func notificationsNeverOfferAlways() {
        #expect(ApprovalNotifier.answers == [.once, .deny])
    }

    /// A fake CLI records its arguments and stdin, prints `stderr` and `line`, and exits with `status`.
    func fakeCLI(status: Int32, stderr: String, stdout: URL? = nil, line: String? = nil) throws -> (path: String, dir: URL) {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sliccy-approvals-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let script = dir.appending(path: "slicc")
        try """
        #!/bin/sh
        cat > "\(dir.path)/stdin"
        printf '%s\\n' "$@" > "\(dir.path)/args"
        printf '%s\\n' '\(stderr)' >&2
        \(stdout.map { "cat '\($0.path)'" } ?? "")
        \(line.map { "printf '%s\\n' '\($0)'" } ?? "")
        exit \(status)
        """.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        return (script.path, dir)
    }

    func decided(status: Int32, stderr: String, line: String?, answer: ApprovalAnswer = .deny) async throws -> (ApprovalQueue?, URL) {
        let secret = "https://example.invalid/#join=private"
        let (path, dir) = try fakeCLI(status: status, stderr: stderr, line: line)
        let store = WorkspaceStore(preview: true, defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true; $0.connection = .connected }
        store.joinCredentials[id] = secret
        store.liveExecutables[id] = path
        store.applyApprovals(try events()[0], to: id)
        let item = try #require(store.approvals[id]?.items.first)
        store.decide(item.id, answer: answer, for: id)
        #expect(store.approvals[id]?.deciding.contains(item.id) == true)
        let deadline = Date().addingTimeInterval(10)
        while store.approvals[id]?.deciding.isEmpty == false, Date() < deadline { try await Task.sleep(for: .milliseconds(20)) }
        #expect(String(decoding: try Data(contentsOf: dir.appending(path: "stdin")), as: UTF8.self) == secret + "\n")
        #expect(String(decoding: try Data(contentsOf: dir.appending(path: "args")), as: UTF8.self) == "-\ndecide\n--json\n--\n\(item.id)\n\(answer.rawValue)\n")
        return (store.approvals[id], dir)
    }

    @Test func watcherStreamsSnapshotsAndExplainsPermission() async throws {
        let fixture = Bundle.module.resourceURL!.appending(path: "Fixtures/approvals.ndjson")
        let (path, dir) = try fakeCLI(status: 3, stderr: "slicc approvals: not allowed", stdout: fixture)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = WorkspaceStore(preview: true, defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true; $0.connection = .connected }
        store.joinCredentials[id] = "join"
        store.liveExecutables[id] = path
        store.approvalsSupported.insert(id)
        store.startApprovals(id)
        #expect(store.approvalProcesses[id] != nil)
        let deadline = Date().addingTimeInterval(10)
        while store.approvalProcesses[id] != nil, Date() < deadline { try await Task.sleep(for: .milliseconds(20)) }
        #expect(String(decoding: try Data(contentsOf: dir.appending(path: "args")), as: UTF8.self) == "-\napprovals\n--json\n--watch\n")
        #expect(store.approvals[id]?.received == true)
        #expect(store.approvals[id]?.active == false)
        #expect(store.approvals[id]?.message?.contains("Linked devices") == true)
    }

    @Test func decideWaitsForTheAnswer() async throws {
        let (queue, dir) = try await decided(status: 0, stderr: "slicc: denied it and stopped the turn", line: #"{"schema":1,"event":"decided","id":"x","answer":"stop"}"#, answer: .stop)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.answered.count == 1)
        #expect(queue?.refusals.isEmpty == true)
    }

    @Test func refusalShowsTheAgentSentence() async throws {
        let (queue, dir) = try await decided(status: 1, stderr: "stderr is not read", line: #"{"schema":1,"event":"error","message":"This request was already answered.","code":"EINVAL","retryable":false}"#)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.answered.isEmpty == true)
        #expect(queue?.refusals.values.first == "This request was already answered.")
    }

    @Test func exitWithoutDecidedIsNotAnAnswer() async throws {
        let (queue, dir) = try await decided(status: 0, stderr: "", line: nil)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.answered.isEmpty == true)
        #expect(queue?.refusals.values.first?.contains("didn’t confirm") == true)
    }

    @Test func permissionRefusalExplainsLinkedDevices() async throws {
        let (queue, dir) = try await decided(status: 3, stderr: "slicc decide: not allowed", line: #"{"schema":1,"event":"error","message":"not allowed","code":"EACCES","retryable":false}"#)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.refusals.values.first?.contains("Linked devices") == true)
        #expect(queue?.refusals.values.first?.contains("not allowed") == false)
    }
}
