import Foundation
import Testing
@testable import Sliccy

@MainActor
struct LinkWaitTests {
    func event(_ json: String) throws -> CLIEvent {
        try JSONDecoder().decode(CLIEvent.self, from: Data(json.utf8))
    }

    func localStore(profile: String = "six") -> (WorkspaceStore, UUID) {
        let store = WorkspaceStore(defaults: nil)
        let session = Session(name: "SLICC", device: "This Mac", kind: .browser, profile: "SLICC Chrome profile", connection: .connecting,
                              access: .init(), usesLiveRuntime: true, localBrowserProfile: profile)
        store.sessions = [session]
        store.liveTokens[session.id] = UUID()
        store.linkStallDelay = .milliseconds(20)
        return (store, session.id)
    }

    let attached = #"{"schema":1,"event":"attached","browser":"chrome","name":"Google Chrome","role":"seven","cdp":"http://127.0.0.1:55779"}"#

    func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
    }

    @Test func statusLinesAreBoundedPrintableAndSplitAcrossReads() {
        var lines = CLIStatusLines()
        #expect(lines.append(Data("slicc: Chrome is slo".utf8)).isEmpty)
        #expect(lines.append(Data("w to answer\n\n   \n\u{1B}[31mred\u{1B}[0m\tline\r\n".utf8)) == ["Chrome is slow to answer", "red line"])
        let long = lines.append(Data((String(repeating: "x", count: 5000) + "\nnext\n").utf8))
        #expect(long.count == 2)
        #expect(long[0].count == CLIStatusLines.lineLimit && long[0].hasSuffix("…"))
        #expect(long[1] == "next")
        #expect(lines.append(Data("slicc 1.67.14 is available (you have 1.67.12); run `slicc update`\n".utf8)).isEmpty)
        #expect(lines.append(Data("tail".utf8)).isEmpty)
        #expect(lines.finish() == ["tail"])
        #expect(lines.finish().isEmpty)
    }

    @Test func childStderrIsDeliveredAsStatusLines() async throws {
        let collected = Collected()
        let child = CLIProcess()
        let stream = try child.start(executable: "/bin/sh", invocation: .init(arguments: ["-c", "printf 'slicc: waiting for seven\\n' >&2; echo '{}'"]),
                                     status: { line in collected.add(line) })
        var output = Data()
        for try await chunk in stream { output.append(chunk) }
        #expect(String(decoding: output, as: UTF8.self) == "{}\n")
        try await waitUntil { !collected.lines.isEmpty }
        #expect(collected.lines == ["waiting for seven"])
    }

    @Test func attachedWithoutLinkExplainsTheStallWithoutStoppingTheLaunch() async throws {
        let (store, id) = localStore()
        store.applyStatus("Chrome is slow to answer", to: id)
        #expect(store.session(id)?.connectionMessage == "SLICC: Chrome is slow to answer")
        store.applyLifecycle(try event(attached), to: id)
        #expect(store.linkWaiting.isEmpty)
        try await waitUntil { store.linkWaiting.contains(id) }
        #expect(store.linkWaiting.contains(id))
        let message = try #require(store.session(id)?.connectionMessage)
        #expect(message.contains("hasn't linked"))
        #expect(message.contains("Close duplicate SLICC tabs"))
        #expect(message.contains("Last CLI status: Chrome is slow to answer."))
        #expect(store.session(id)?.entries.last?.text == message)
        // Still connecting and retryable: the CLI process is left alone.
        #expect(store.session(id)?.connection == .connecting)
        #expect(store.canRetryLocalConnection(id))
        store.applyStatus("still waiting", to: id)
        #expect(store.session(id)?.connectionMessage?.contains("Last CLI status: still waiting.") == true)
        store.applyLifecycle(try event(#"{"schema":1,"event":"linked","tab":"https://www.sliccy.ai"}"#), to: id)
        #expect(!store.linkWaiting.contains(id))
        #expect(store.session(id)?.connection == .connected)
        #expect(store.session(id)?.connectionMessage == nil)
        store.applyStatus("noise after linking", to: id)
        #expect(store.session(id)?.connectionMessage == nil)
    }

    @Test func linkingBeforeTheDeadlineNeverReportsAStall() async throws {
        let (store, id) = localStore()
        store.linkStallDelay = .milliseconds(100)
        store.applyLifecycle(try event(attached), to: id)
        store.applyLifecycle(try event(#"{"schema":1,"event":"linked"}"#), to: id)
        try await Task.sleep(for: .milliseconds(250))
        #expect(!store.linkWaiting.contains(id))
        #expect(store.session(id)?.connectionMessage == nil)
    }

    @Test func statusNeverReplacesAContractMessage() throws {
        let (store, id) = localStore()
        store.applyLifecycle(try event(#"{"schema":1,"event":"error","message":"no seven tab","retryable":true}"#), to: id)
        store.applyStatus("debug chatter", to: id)
        #expect(store.session(id)?.connectionMessage?.contains("no seven tab") == true)
        #expect(store.cliStatus[id] == ["debug chatter"])
        for index in 0..<5 { store.applyStatus("line \(index)", to: id) }
        #expect(store.cliStatus[id] == ["line 2", "line 3", "line 4"])
    }

    @Test func statusLinesAreRedacted() {
        let (store, id) = localStore()
        let secret = "https://example.invalid/#join-secret"
        store.joinCredentials[id] = secret
        store.applyStatus("dialing \(secret)", to: id)
        #expect(store.cliStatus[id] == ["dialing <join URL>"])
        #expect(store.session(id)?.connectionMessage?.contains(secret) == false)
    }

    @Test func waitingEventIsGatedOnCapabilitiesAndCarriesTheReason() async throws {
        let waiting = #"{"schema":1,"event":"waiting","reason":"no-ready-seven","candidates":2}"#
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities.json"))
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(try JSONDecoder().decode(CLICapabilities.self, from: data).supportsLinkWaitEvent == false)
        var events = try #require(json["events"] as? [String: Any])
        events["names"] = ((events["names"] as? [String]) ?? []) + ["waiting"]
        json["events"] = events
        #expect(try JSONDecoder().decode(CLICapabilities.self, from: JSONSerialization.data(withJSONObject: json)).supportsLinkWaitEvent)
        json["events"] = nil
        #expect(try JSONDecoder().decode(CLICapabilities.self, from: JSONSerialization.data(withJSONObject: json)).supportsLinkWaitEvent == false)

        // Unadvertised: ignored, so an older CLI keeps the timer-only behavior.
        let (old, oldID) = localStore()
        old.applyLifecycle(try event(waiting), to: oldID)
        #expect(old.linkWaitReasons[oldID] == nil)
        #expect(old.linkWaitTasks[oldID] == nil)

        let (store, id) = localStore()
        store.linkWaitSupported.insert(id)
        store.applyLifecycle(try event(waiting), to: id)
        #expect(store.linkWaitReasons[id] == "no SLICC tab is ready to link (2 SLICC tabs open)")
        #expect(store.session(id)?.connectionMessage == "SLICC: no SLICC tab is ready to link (2 SLICC tabs open).")
        try await waitUntil { store.linkWaiting.contains(id) }
        #expect(store.session(id)?.connectionMessage?.hasSuffix("The CLI reports: no SLICC tab is ready to link (2 SLICC tabs open).") == true)
        store.applyLifecycle(try event(#"{"schema":1,"event":"waiting","reason":"x","message":"Two seven tabs; neither is ready"}"#), to: id)
        #expect(store.session(id)?.connectionMessage?.hasSuffix("The CLI reports: Two seven tabs; neither is ready.") == true)
        // Shape confirmed by slicc-cli#782: candidates is 0 when no seven tab is open.
        store.applyLifecycle(try event(#"{"schema":1,"event":"waiting","reason":"no-seven-tab","candidates":0}"#), to: id)
        #expect(store.linkWaitReasons[id] == "no SLICC tab is open")
        store.clearLiveConnection(id)
        #expect(!store.linkWaiting.contains(id))
        #expect(store.linkWaitReasons[id] == nil)
    }

    @Test func aSupersededLaunchNeverReportsAStall() async throws {
        let (store, id) = localStore()
        store.applyLifecycle(try event(attached), to: id)
        store.liveTokens[id] = UUID()
        try await Task.sleep(for: .milliseconds(150))
        #expect(!store.linkWaiting.contains(id))
        #expect(store.session(id)?.connectionMessage == nil)
    }
}

final class Collected: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []
    var lines: [String] { lock.withLock { storage } }
    func add(_ line: String) { lock.withLock { storage.append(line) } }
}
