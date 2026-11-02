import Foundation
import Testing
@testable import Sliccy

@MainActor
private final class ControlledRuntime: SessionRuntime {
    let isDemo = true
    var continuations: [AsyncStream<RuntimeEvent>.Continuation] = []
    func response(to prompt: String, sessionName: String) -> AsyncStream<RuntimeEvent> {
        AsyncStream { continuations.append($0) }
    }
}

@MainActor
struct WorkspaceTests {
    @Test func disconnectedSessionCannotSend() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[2].id
        let before = store.session(id)!.entries.count
        store.send("Do something", to: id)
        #expect(store.session(id)!.entries.count == before)
        #expect(!store.session(id)!.isWorking)
    }

    @Test func stoppingPreventsLateStreamEventsAndClearsQueue() async {
        let runtime = ControlledRuntime()
        let store = WorkspaceStore(runtime: runtime, defaults: nil)
        let id = store.sessions[0].id
        store.send("First", to: id)
        store.send("Second", to: id)
        #expect(store.session(id)!.queuedPrompts == ["Second"])
        store.stop(id)
        runtime.continuations[0].yield(.text("stale text"))
        runtime.continuations[0].finish()
        await Task.yield()
        #expect(!store.session(id)!.isWorking)
        #expect(store.session(id)!.queuedPrompts.isEmpty)
        #expect(!store.session(id)!.entries.contains { $0.text.contains("stale text") })
        #expect(store.session(id)!.connection == .connected)
    }

    @Test func steeringReplacesStreamWithoutChangingConnection() async {
        let runtime = ControlledRuntime()
        let store = WorkspaceStore(runtime: runtime, defaults: nil)
        let id = store.sessions[0].id
        store.send("First", to: id)
        store.send("New direction", to: id, mode: .steer)
        #expect(runtime.continuations.count == 2)
        runtime.continuations[0].yield(.text("obsolete response"))
        runtime.continuations[0].finish()
        await Task.yield()
        #expect(store.session(id)!.isWorking)
        #expect(!store.session(id)!.entries.contains { $0.text.contains("obsolete response") })
        store.stop(id)
    }

    @Test func restoreDoesNotResumeUnfinishedWork() {
        let name = "SliccyTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let store = WorkspaceStore(runtime: ControlledRuntime(), defaults: defaults)
        let id = store.sessions[0].id
        store.send("Unfinished", to: id)
        let restored = WorkspaceStore(defaults: defaults)
        #expect(!restored.session(id)!.isWorking)
        #expect(restored.session(id)!.queuedPrompts.isEmpty)
        #expect(restored.session(id)!.entries.last?.role == .notice)
        store.stop(id)
    }
}
