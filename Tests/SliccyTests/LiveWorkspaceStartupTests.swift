import Foundation
import Testing
@testable import Sliccy

@MainActor
struct LiveWorkspaceStartupTests {
    @Test func optionalNamesAreTrimmedAndGeneratedWithoutCollisions() {
        let store = WorkspaceStore(defaults: nil)
        #expect(store.sessionName(for: " \n ") == "SLICC")
        #expect(store.sessionName(for: "  Design review  ") == "Design review")
        var session = DemoData.sessions()[0]
        session.name = "slicc"
        store.sessions = [session]
        #expect(store.sessionName(for: "") == "SLICC 2")
        session.name = "SLICC 2"
        store.sessions.append(session)
        #expect(store.sessionName(for: "") == "SLICC 3")
    }

    @Test func ordinaryLaunchIsEmptyAndCannotCreateDemoSessions() {
        let store = WorkspaceStore(defaults: nil)
        #expect(!store.isDemo)
        #expect(store.sessions.isEmpty)
        #expect(store.create(name: "Fake", kind: .browser, browser: "Chrome", profile: "Default") == nil)
        store.resetDemo()
        #expect(store.sessions.isEmpty)
        #expect(store.connectedCount == 0)
    }

    @Test func previewExplicitlyOptsIntoSamples() {
        let preview = WorkspaceStore(preview: true, defaults: nil)
        #expect(preview.isDemo)
        #expect(preview.sessions.count == 3)
        #expect(preview.sessions.allSatisfy { !$0.isLive })
    }

    @Test func migrationRetainsOnlyRealSessionsAndNeverReconnectsAutomatically() throws {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        var real = DemoData.sessions()[0]
        real.usesLiveRuntime = true
        real.name = "My real instance"
        real.connection = .connected
        let legacy = try JSONEncoder().encode(DemoData.sessions() + [real])
        defaults.set(legacy, forKey: "sliccy.demo.sessions.v1")

        let store = WorkspaceStore(defaults: defaults)
        #expect(store.sessions.map(\.id) == [real.id])
        #expect(store.sessions[0].connection == .disconnected)
        #expect(store.sessions[0].access.browser == nil)
        #expect(store.sessions[0].access.folders.isEmpty)
        #expect(store.joinCredentials.isEmpty)
        #expect(store.liveProcesses.isEmpty)
        store.save()
        #expect(defaults.data(forKey: "sliccy.demo.sessions.v1") == legacy)

        let restored = WorkspaceStore(defaults: defaults)
        #expect(restored.sessions.map(\.id) == [real.id])
        restored.reconnect(real.id)
        #expect(restored.credentialSession == real.id)
        #expect(restored.liveProcesses.isEmpty)
    }

    @Test func emptyLiveStoreDoesNotResurrectLegacyConnections() throws {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        var real = DemoData.sessions()[0]
        real.usesLiveRuntime = true
        defaults.set(try JSONEncoder().encode([real]), forKey: "sliccy.demo.sessions.v1")
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = []
        store.save()
        #expect(WorkspaceStore(defaults: defaults).sessions.isEmpty)
    }

    @Test func normalSaveCannotPersistInjectedDemoRows() throws {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = DemoData.sessions()
        store.save()
        #expect(WorkspaceStore(defaults: defaults).sessions.isEmpty)
    }
}
