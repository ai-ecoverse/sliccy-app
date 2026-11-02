import Foundation
import Testing
@testable import Sliccy

@MainActor
struct LiveRuntimeTests {
    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/" + name))
    }

    @Test func releasedContractSupportsRemoteWorkspace() throws {
        var capabilities = try JSONDecoder().decode(CLICapabilities.self, from: fixture("capabilities.json"))
        #expect(capabilities.supportsRemoteWorkspace)
        capabilities.contract = 2
        #expect(!capabilities.supportsRemoteWorkspace)
        capabilities.contract = 1
        capabilities.control.ops = ["status"]
        #expect(!capabilities.supportsRemoteWorkspace)
    }

    @Test func lifecycleUsesEffectiveGrantsAndWaitsForClosed() throws {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true; $0.connection = .connecting }
        var decoder = NDJSONDecoder()
        let events = try decoder.append(fixture("follow.ndjson"))
        let linked = try #require(events.first { $0.kind == "linked" })
        store.applyLifecycle(linked, to: id)
        #expect(store.session(id)?.connection == .connected)
        #expect(store.session(id)?.access.folders.first?.readOnly == true)
        #expect(store.session(id)?.effectiveResources?.rejectedMounts.first?.reason == "not-a-folder")
        let retryable = try JSONDecoder().decode(CLIEvent.self, from: Data(#"{"schema":1,"event":"error","retryable":true,"message":"Offer failed"}"#.utf8))
        store.applyLifecycle(retryable, to: id)
        #expect(store.session(id)?.connection == .connected)
        #expect(store.session(id)?.entries.last?.text.contains("Waiting") == true)
        for event in try decoder.append(fixture("follow-error.ndjson")) where event.kind != "closed" {
            store.applyLifecycle(event, to: id)
        }
        #expect(store.session(id)?.connection != .disconnected)
        store.applyLifecycle(try #require(events.last), to: id)
        #expect(store.session(id)?.connection == .disconnected)
        #expect(store.session(id)?.effectiveResources == nil)
        #expect(store.session(id)?.access.folders.isEmpty == true)
    }

    @Test func credentialsTravelOnlyOnStdin() throws {
        let secret = "https://example.invalid/#join=private-token"
        let prompt = "Show `$(whoami)` literally"
        for call in [CLIInvocation.follow(join: secret), .prompt(join: secret, text: prompt, steer: true), .abort(join: secret)] {
            #expect(!call.arguments.joined().contains(secret))
            #expect(!call.arguments.joined().contains(prompt))
            #expect(String(decoding: call.input, as: UTF8.self).hasPrefix(secret + "\n"))
        }
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.joinCredentials[id] = secret
        store.update(id) { $0.usesLiveRuntime = true }
        store.notice("Failed to join " + secret, id: id)
        let persisted = try JSONEncoder().encode(store.sessions)
        #expect(!String(decoding: persisted, as: UTF8.self).contains(secret))
    }

    @Test func restoresLiveSessionsDisconnectedWithoutCredentials() throws {
        let name = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let store = WorkspaceStore(defaults: defaults)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.joinCredentials[id] = "https://example.invalid/#secret"
        store.save()
        let restored = WorkspaceStore(defaults: defaults)
        #expect(restored.session(id)?.connection == .disconnected)
        #expect(restored.session(id)?.access.folders.isEmpty == true)
        #expect(restored.joinCredentials.isEmpty)
        restored.reconnect(id)
        #expect(restored.credentialSession == id)
        #expect(restored.liveProcesses.isEmpty)
    }

    @Test func agentEntryIDsGroupDeltasWithoutInventingRunIDs() throws {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.entries = [] }
        var entries: [String: UUID] = [:]
        var decoder = NDJSONDecoder()
        let events = try decoder.append(Data("""
        {"t":"run","state":"start"}
        {"t":"text","id":"one","delta":"Hello "}
        {"t":"future-event","id":"one","text":"ignore"}
        {"t":"text","id":"one","delta":"world"}
        {"t":"text","id":"two","delta":"Next entry"}
        {"t":"end","reason":"stop"}

        """.utf8))
        for event in events { store.applyAgent(event, to: id, entries: &entries) }
        #expect(store.session(id)?.entries.map(\.text) == ["Hello world", "Next entry"])
    }

    @Test func subprocessPreservesPipeBytesAndExitStatus() async throws {
        let child = CLIProcess()
        let payload = Data(String(repeating: "Unicode 🥐\n", count: 10000).utf8)
        let stream = try child.start(executable: "/bin/cat", invocation: .init(arguments: [], input: payload), deadline: .seconds(5))
        var received = Data()
        for try await chunk in stream { received.append(chunk) }
        #expect(received == payload)
        let failing = CLIProcess()
        let failure = try failing.start(executable: "/usr/bin/false", invocation: .init(arguments: []), deadline: .seconds(5))
        do {
            for try await _ in failure { }
            Issue.record("Expected a nonzero exit error")
        } catch CLIError.exit(let status) { #expect(status == 1) }
    }
}
