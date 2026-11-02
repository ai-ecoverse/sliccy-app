import Foundation
import Testing
@testable import Sliccy

struct AgentInventoryTests {
    func events() throws -> [CLIEvent] {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/agents.ndjson"))
        var decoder = NDJSONDecoder()
        return try decoder.append(data)
    }

    @Test func shippedSnapshotsReplaceRowsWithoutInventingNamesOrModels() throws {
        let events = try events()
        var inventory = AgentInventory()
        inventory.apply(events[0])
        #expect(inventory.agents.count == 2)
        #expect(inventory.counts["running"] == 1)
        #expect(inventory.agents[1].parent == inventory.agents[0].id)
        #expect(inventory.agents[1].model == nil)
        inventory.apply(events[1])
        #expect(inventory.agents.count == 1)
        #expect(inventory.counts["running"] == 0)
        #expect(inventory.counts["error"] == 1)
        #expect(inventory.agents[0].model == nil)
    }

    @Test func reconnectAndRestartAcceptWholeSnapshotsAndMarkStaleness() throws {
        let events = try events()
        let now = Date(timeIntervalSince1970: 1767268802)
        var inventory = AgentInventory()
        inventory.apply(events[1], now: now)
        #expect(inventory.isFresh(at: now))
        #expect(!inventory.isFresh(at: now.addingTimeInterval(61)))
        inventory.apply(events[2], now: now)
        #expect(!inventory.isFresh(at: now))
        inventory.apply(events[3], now: now)
        #expect(inventory.isFresh(at: now))
        var restarted = events[1]; restarted.seq = 1; restarted.agents = []
        restarted.counts = ["running": 0, "queued": 0, "waiting": 0, "idle": 0, "error": 0]
        inventory.apply(restarted, now: now)
        #expect(inventory.seq == 1)
        #expect(inventory.agents.isEmpty)
    }

    @Test func errorsAndInvalidSnapshotsCannotPresentFreshCounts() throws {
        var inventory = AgentInventory()
        let event = try events()[1]
        inventory.apply(event)
        let error = try JSONDecoder().decode(CLIEvent.self, from: Data(#"{"schema":1,"event":"error","message":"the agent is not running","retryable":true}"#.utf8))
        inventory.apply(error)
        #expect(!inventory.active)
        #expect(inventory.message == "the agent is not running")
        var duplicate = event; duplicate.agents = [event.agents![0], event.agents![0]]
        inventory.apply(duplicate)
        #expect(!inventory.active)
        #expect(inventory.message?.contains("incompatible") == true)
    }

    @Test @MainActor func inventoryUsesSeparateReadOnlyProcessAndIsNotRestoredAsLive() throws {
        let invocation = CLIInvocation.agents(join: "private-join")
        #expect(invocation.arguments == ["-", "agents", "--json", "--watch"])
        #expect(!invocation.arguments.contains("private-join"))
        #expect(String(decoding: invocation.input, as: UTF8.self) == "private-join\n")
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.applyInventory(try events()[0], to: id)
        #expect(store.watchTasks.isEmpty)
        #expect(store.session(id)?.entries.contains { $0.text.contains("claude-opus-4-6") } == false)
        store.clearLiveConnection(id)
        #expect(store.inventories[id]?.active == false)
        #expect(store.inventoryProcesses.isEmpty)
    }
}
