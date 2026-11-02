import Foundation
import Testing
@testable import Sliccy

struct LiveFeedTests {
    func event(_ json: String) throws -> CLIEvent { try JSONDecoder().decode(CLIEvent.self, from: Data(json.utf8)) }

    @Test func restartReplacesReplayButReconnectAppendsTrimmedDeltas() throws {
        var feed = LiveFeed(entries: [.init(role: .assistant, text: "Hel", sourceID: "a1")], cursor: "a1")
        var replay = feed.cursor
        feed.apply(try event(#"{"t":"opened","head":"future-head"}"#), initialReplay: &replay)
        #expect(feed.cursor == "a1")
        feed.apply(try event(#"{"t":"text","id":"a1","delta":"Hello"}"#), initialReplay: &replay)
        #expect(feed.entries[0].text == "Hello")
        feed.apply(try event(#"{"t":"reconnecting","attempt":1,"wait":1250}"#), initialReplay: &replay)
        #expect(feed.state == .reconnecting)
        #expect(feed.retryDelay == 1250)
        feed.apply(try event(#"{"t":"opened","head":"a1"}"#), initialReplay: &replay)
        feed.apply(try event(#"{"t":"text","id":"a1","delta":" world"}"#), initialReplay: &replay)
        #expect(feed.entries.count == 1)
        #expect(feed.entries[0].text == "Hello world")
        #expect(feed.retryDelay == nil)
    }

    @Test func releasedWatchFixtureShowsGapsAndRetainsExistingActivity() throws {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/watch.ndjson"))
        var decoder = NDJSONDecoder()
        var feed = LiveFeed()
        var replay: String?
        for e in try decoder.append(data) { feed.apply(e, initialReplay: &replay) }
        #expect(feed.entries.map(\.text).prefix(3) == ["Hello", "ls", "Bye"])
        #expect(feed.entries.last?.text.contains("Some activity was missed") == true)
        #expect(feed.cursor == nil)
        #expect(feed.state == .watching)
        #expect(feed.busy == nil)
    }

    @Test func savedFeedResumesFromConsumedEntryNotServerHead() throws {
        var feed = LiveFeed()
        var replay: String?
        feed.apply(try event(#"{"t":"user","id":"u1","text":"Hi"}"#), initialReplay: &replay)
        feed.apply(try event(#"{"t":"user","id":"u1","text":"Hi"}"#), initialReplay: &replay)
        feed.apply(try event(#"{"t":"run","state":"start"}"#), initialReplay: &replay)
        feed.apply(try event(#"{"t":"future","id":"future-id"}"#), initialReplay: &replay)
        #expect(feed.entries.count == 1)
        #expect(feed.busy == true)
        let restored = try JSONDecoder().decode(LiveFeed.self, from: JSONEncoder().encode(feed))
        #expect(restored.cursor == "u1")
        #expect(restored.entries.first?.sourceID == "u1")
        let invocation = CLIInvocation.watch(join: "https://example.invalid/#secret", since: restored.cursor)
        #expect(invocation.arguments == ["-", "watch", "--json", "--since", "u1"])
        #expect(!invocation.arguments.joined().contains("secret"))
    }

    @Test func capabilityGateAcceptsNewWatchWithoutBreakingOlderPromptMode() throws {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities.json"))
        var capabilities = try JSONDecoder().decode(CLICapabilities.self, from: data)
        #expect(capabilities.supportsResumableWatch)
        capabilities.agent?.own = ["settled"]
        #expect(!capabilities.supportsResumableWatch)
        #expect(capabilities.supportsRemoteWorkspace)
    }

    @MainActor @Test func disconnectPreservesReplayCursorAndClearsBusyState() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) {
            $0.usesLiveRuntime = true
            $0.liveFeed = .init(entries: [.init(role: .assistant, text: "Saved", sourceID: "a1")], cursor: "a1", state: .watching, busy: true)
        }
        store.disconnectLive(id)
        #expect(store.session(id)?.liveFeed?.cursor == "a1")
        #expect(store.session(id)?.liveFeed?.state == .stopped)
        #expect(store.session(id)?.liveFeed?.busy == nil)
        #expect(store.watchTasks.isEmpty)
        #expect(store.watchProcesses.isEmpty)
    }
    @MainActor @Test func cursorNeverCrossesJoinCredentials() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.bindCredential("https://example.invalid/#one", to: id)
        store.update(id) { $0.liveFeed = .init(entries: [.init(role: .assistant, text: "Old", sourceID: "a1")], cursor: "a1") }
        store.bindCredential("https://example.invalid/#one", to: id)
        #expect(store.session(id)?.liveFeed?.cursor == "a1")
        store.bindCredential("https://example.invalid/#two", to: id)
        #expect(store.session(id)?.liveFeed?.cursor == nil)
        #expect(store.session(id)?.liveFeed?.entries.first?.sourceID == nil)
        #expect(store.session(id)?.liveFeed?.entries.first?.text == "Old")
    }

}
