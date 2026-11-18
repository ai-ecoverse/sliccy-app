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

    @Test func itemsOfferOnlyTheAnswersTheyAllow() throws {
        let items = try #require(try events()[0].approvals)
        let sudo = items[0], tool = items[1]
        #expect(sudo.answers == [.once, .always, .deny, .stop])
        #expect(tool.answers == [.once, .deny])
        #expect(sudo.detailText.contains("apt-get install -y jq"))
        #expect(sudo.verdictText.contains("level 2"))
        #expect(sudo.agentLabel == "cone · cone")
        #expect(tool.detailText.hasPrefix("bash · "))
        #expect(tool.detailText.contains("ls /workspace"))
        #expect(tool.verdictText == "Judge checking…")
        #expect(tool.agentLabel.contains("Ada · sliccy.test"))
        let now = Date(timeIntervalSince1970: 1767268800)
        #expect(sudo.timeLeft(at: now) == "5:00 left")
        #expect(sudo.timeLeft(at: now.addingTimeInterval(301)) == "Expired")
    }

    @Test func captureAndGuestMessagesNeverShowPrompts() throws {
        let items = try #require(try events()[1].approvals)
        let capture = items[1], message = items[2]
        #expect(capture.detailText.contains("screen video"))
        #expect(capture.detailText.contains("system audio"))
        #expect(capture.detailText.contains("by record"))
        #expect(capture.verdictText.contains("the judge is not configured"))
        #expect(capture.agentLabel.hasPrefix("Agent x3Lk9aQe"))
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
        #expect(store.approvals[id]?.items.count == 2)
        #expect(notifier.posted.count == 2)
        store.applyApprovals(events[1], to: id)
        #expect(store.approvals[id]?.items.map(\.kind) == ["guest-tool", "capture", "guest-message"])
        #expect(notifier.posted.count == 4)
        #expect(notifier.withdrawn == [events[0].approvals![0].id])
        store.applyApprovals(events[2], to: id)
        #expect(store.approvals[id]?.active == false)
        #expect(store.approvals[id]?.message?.contains("Reconnecting") == true)
        #expect(store.approvals[id]?.items.count == 3)
        store.applyApprovals(events[3], to: id)
        #expect(store.approvals[id]?.active == true)
        #expect(store.approvals[id]?.items.isEmpty == true)
        #expect(notifier.posted.count == 4)
        #expect(notifier.withdrawn.count == 4)
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
        #expect(store.approvals[id]?.message == "That request is no longer pending.")
    }

    @Test func invocationsKeepTheJoinURLOnStdin() {
        let secret = "https://example.invalid/#join=private"
        let watch = CLIInvocation.approvals(join: secret)
        #expect(watch.arguments == ["-", "approvals", "--json", "--watch"])
        let decide = CLIInvocation.decide(join: secret, id: "apr-1", answer: .stop)
        #expect(decide.arguments == ["-", "decide", "apr-1", "stop"])
        for call in [watch, decide] {
            #expect(!call.arguments.joined().contains(secret))
            #expect(String(decoding: call.input, as: UTF8.self) == secret + "\n")
        }
        #expect(CLIInvocation.decide(cdp: "http://127.0.0.1:9222", id: "apr-1", answer: .once).arguments ==
                ["decide", "--cdp", "http://127.0.0.1:9222", "--origin", CLIInvocation.localOrigin, "apr-1", "once"])
    }

    @Test func capabilitiesGateOnApprovalsAndDecide() throws {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities.json"))
        var capabilities = try JSONDecoder().decode(CLICapabilities.self, from: data)
        #expect(!capabilities.supportsApprovals)
        capabilities.commands["approvals"] = .init(json: "events")
        #expect(!capabilities.supportsApprovals)
        capabilities.commands["decide"] = .init(json: "none")
        #expect(capabilities.supportsApprovals)
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

    @Test func decideSentenceIsTheOnlyStderrRead() {
        #expect(WorkspaceStore.decideSentence("decide: This request was already answered.") == "This request was already answered.")
        #expect(WorkspaceStore.decideSentence("Only a person can stop a turn.") == "Only a person can stop a turn.")
        #expect(WorkspaceStore.decideSentence("  ") == nil)
    }

    /// A fake CLI records its arguments and stdin, prints `stderr` and exits with `status`.
    func fakeCLI(status: Int32, stderr: String, stdout: URL? = nil) throws -> (path: String, dir: URL) {
        let dir = FileManager.default.temporaryDirectory.appending(path: "sliccy-approvals-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let script = dir.appending(path: "slicc")
        try """
        #!/bin/sh
        cat > "\(dir.path)/stdin"
        printf '%s\\n' "$@" > "\(dir.path)/args"
        printf '%s\\n' '\(stderr)' >&2
        \(stdout.map { "cat '\($0.path)'" } ?? "")
        exit \(status)
        """.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        return (script.path, dir)
    }

    func decided(status: Int32, stderr: String, answer: ApprovalAnswer = .deny) async throws -> (ApprovalQueue?, URL) {
        let secret = "https://example.invalid/#join=private"
        let (path, dir) = try fakeCLI(status: status, stderr: stderr)
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
        #expect(String(decoding: try Data(contentsOf: dir.appending(path: "args")), as: UTF8.self) == "-\ndecide\n\(item.id)\n\(answer.rawValue)\n")
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
        let (queue, dir) = try await decided(status: 0, stderr: "", answer: .stop)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.answered.count == 1)
        #expect(queue?.refusals.isEmpty == true)
    }

    @Test func refusalShowsTheAgentSentence() async throws {
        let (queue, dir) = try await decided(status: 1, stderr: "slicc decide: This request was already answered.")
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.answered.isEmpty == true)
        #expect(queue?.refusals.values.first == "This request was already answered.")
    }

    @Test func permissionRefusalExplainsLinkedDevices() async throws {
        let (queue, dir) = try await decided(status: 3, stderr: "slicc decide: not allowed")
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(queue?.refusals.values.first?.contains("Linked devices") == true)
        #expect(queue?.refusals.values.first?.contains("not allowed") == false)
    }
}
