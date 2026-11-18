import Foundation
import Testing
@testable import Sliccy

@MainActor
struct SavedJoinsTests {
    static let join = "https://www.sliccy.ai/join/065a4282-b22c-4e0a-bc19-a18e679e9e64.secret"

    private func suite() throws -> (UserDefaults, String) {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defaults.set("/nonexistent/slicc", forKey: "sliccy.cli.path")
        return (defaults, domain)
    }

    private func remote(_ name: String = "Remote", connection: ConnectionState = .connecting) -> Session {
        Session(name: name, device: "Remote SLICC", kind: .remote, profile: "Remote", connection: connection,
                access: .init(browser: nil, network: false), usesLiveRuntime: true)
    }

    private func linked() throws -> CLIEvent {
        try JSONDecoder().decode(CLIEvent.self, from: Data(#"{"schema":1,"event":"linked"}"#.utf8))
    }

    private func sync(_ backend: InMemoryKeyValueBackend, device: String = "MAC-1", now: Date = Date()) -> ICloudJoinSync {
        ICloudJoinSync(backend: backend, deviceId: device, deviceName: "Lars’s Mac", clock: { now })
    }

    @Test func aLinkedJoinURLIsSavedAndRestoredAfterRelaunch() throws {
        let (defaults, domain) = try suite()
        defer { defaults.removePersistentDomain(forName: domain) }
        let vault = MemoryJoinURLVault()
        let backend = InMemoryKeyValueBackend()
        let session = remote()
        let store = WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend))
        store.sessions = [session]
        store.bindCredential("  \(Self.join)\n", to: session.id)

        // Nothing is saved until the URL actually links, so a typo never persists.
        #expect(vault.items.isEmpty)
        #expect(backend.storage.isEmpty)
        store.applyLifecycle(try linked(), to: session.id)
        #expect(vault.items[session.id] == Self.join)
        #expect(defaults.data(forKey: "sliccy.sessions.v1").map { String(decoding: $0, as: UTF8.self).contains("secret") } == false)

        // The iCloud entry uses slicc's RecentJoinStore format and key.
        let data = try #require(backend.storage["recentJoins.v1.MAC-1"])
        let records = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(records.count == 1)
        #expect(Set(records[0].keys) == ["id", "joinUrl", "label", "deviceId", "deviceName", "firstConnectedAt", "lastConnectedAt"])
        #expect(records[0]["id"] as? String == Session.joinIdentity(Self.join))
        #expect(records[0]["id"] as? String == store.session(session.id)?.watchIdentity)
        #expect(records[0]["label"] as? String == "Remote")
        store.shutdown()

        let relaunched = WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend))
        #expect(relaunched.joinCredentials[session.id] == Self.join)
        relaunched.reconnect(session.id)
        #expect(relaunched.credentialSession == nil)
        #expect(relaunched.liveTokens[session.id] != nil)
    }

    @Test func iCloudFillsAMissingKeychainEntryOnlyForTheSameIdentity() throws {
        let (defaults, domain) = try suite()
        defer { defaults.removePersistentDomain(forName: domain) }
        let backend = InMemoryKeyValueBackend()
        // Another Mac connected this URL.
        sync(backend, device: "MAC-2").record(joinURL: Self.join, label: "Work")

        var known = remote("Known", connection: .disconnected)
        known.watchIdentity = Session.joinIdentity(Self.join)
        var other = remote("Other", connection: .disconnected)
        other.watchIdentity = Session.joinIdentity("https://www.sliccy.ai/join/other")
        let seed = WorkspaceStore(defaults: defaults)
        seed.sessions = [known, other]
        seed.save()

        let vault = MemoryJoinURLVault()
        vault.items[other.id] = "https://www.sliccy.ai/join/replaced"
        let store = WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend))
        #expect(store.joinCredentials[known.id] == Self.join)
        #expect(vault.items[known.id] == Self.join)
        // A keychain item for a different URL than the session last used is not trusted.
        #expect(store.joinCredentials[other.id] == nil)
        // Bound URLs are not suggested again for New Session.
        #expect(store.iCloudSuggestions.isEmpty)
    }

    @Test func removingASessionForgetsItsJoinURL() throws {
        let (defaults, domain) = try suite()
        defer { defaults.removePersistentDomain(forName: domain) }
        let vault = MemoryJoinURLVault()
        let backend = InMemoryKeyValueBackend()
        let session = remote()
        let store = WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend))
        store.sessions = [session]
        store.bindCredential(Self.join, to: session.id)
        store.applyLifecycle(try linked(), to: session.id)
        store.remove(session.id)
        #expect(vault.items.isEmpty)
        #expect(backend.storage["recentJoins.v1.MAC-1"] == nil)
        #expect(store.joinSync?.joins.isEmpty == true)
    }

    @Test func turningICloudOffKeepsTheKeychainButSharesNothing() throws {
        let (defaults, domain) = try suite()
        defer { defaults.removePersistentDomain(forName: domain) }
        let vault = MemoryJoinURLVault()
        let backend = InMemoryKeyValueBackend()
        sync(backend, device: "MAC-2").record(joinURL: Self.join, label: "Work")
        let store = WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend))
        #expect(store.iCloudSuggestions.count == 1)
        store.iCloudJoins = false
        #expect(store.iCloudSuggestions.isEmpty)

        let session = remote()
        store.sessions = [session]
        store.bindCredential("https://www.sliccy.ai/join/private", to: session.id)
        store.applyLifecycle(try linked(), to: session.id)
        #expect(vault.items[session.id] == "https://www.sliccy.ai/join/private")
        #expect(backend.storage["recentJoins.v1.MAC-1"] == nil)
        #expect(WorkspaceStore(defaults: defaults, joinVault: vault, joinSync: sync(backend)).iCloudJoins == false)
    }

    @Test func withoutStorageJoinURLsStayInMemory() throws {
        let store = WorkspaceStore(defaults: nil)
        let session = remote()
        store.sessions = [session]
        store.bindCredential(Self.join, to: session.id)
        store.applyLifecycle(try linked(), to: session.id)
        #expect(!store.syncsJoinsWithICloud)
        #expect(store.joinStorageSummary.contains("memory"))
        #expect(WorkspaceStore(preview: true, defaults: nil, joinVault: MemoryJoinURLVault()).joinVault == nil)
    }

    @Test func iCloudReadsSliccAppsAndIgnoresStaleOrForgedEntries() throws {
        let backend = InMemoryKeyValueBackend()
        let now = Date()
        let encoder = JSONEncoder()
        func recent(_ url: String, id: String? = nil, age: TimeInterval = 60) -> RecentJoinRecord {
            .init(id: id ?? Session.joinIdentity(url), joinUrl: url, label: "", deviceId: "PHONE", deviceName: "iPhone",
                  firstConnectedAt: now.addingTimeInterval(-age), lastConnectedAt: now.addingTimeInterval(-age))
        }
        backend.storage["recentJoins.v1.PHONE"] = try encoder.encode([
            recent("https://www.sliccy.ai/join/phone"),
            recent("http://www.sliccy.ai/join/plain"),
            recent("https://user:pw@www.sliccy.ai/join/userinfo"),
            recent("https://www.sliccy.ai/join/forged", id: "abc"),
            recent("https://www.sliccy.ai/join/old", age: ICloudJoinSync.recentTTL + 1),
        ])
        // Sliccstart's live tray sessions use createdAt/lastSeenAt.
        let tray = """
        [{"id":"\(Session.joinIdentity("https://www.sliccy.ai/join/tray"))","joinUrl":"https://www.sliccy.ai/join/tray","label":"Chrome on Lars’s MacBook","deviceId":"MBP","deviceName":"MacBook","createdAt":\(now.timeIntervalSinceReferenceDate - 30),"lastSeenAt":\(now.timeIntervalSinceReferenceDate - 30)}]
        """
        backend.storage["traySessions.v2.MBP"] = Data(tray.utf8)
        backend.storage["recentJoins.v1.BROKEN"] = Data("not json".utf8)

        let store = sync(backend, now: now)
        #expect(store.joins.map(\.joinUrl) == ["https://www.sliccy.ai/join/tray", "https://www.sliccy.ai/join/phone"])
        #expect(store.joins[0].live)
        #expect(ICloudJoinPicker.title(store.joins[0]) == "Chrome on Lars’s MacBook · MacBook · running")
        #expect(ICloudJoinPicker.title(store.joins[1]) == "www.sliccy.ai · iPhone")
        #expect(!ICloudJoinPicker.title(store.joins[1]).contains("/join/"))
    }

    @Test func eachDeviceKeepsOnlyItsFiveNewestJoins() throws {
        let backend = InMemoryKeyValueBackend()
        var now = Date()
        let store = ICloudJoinSync(backend: backend, deviceId: "MAC-1", deviceName: "Mac", clock: { now })
        for index in 0..<7 {
            now = now.addingTimeInterval(1)
            store.record(joinURL: "https://www.sliccy.ai/join/\(index)", label: "")
        }
        let own = try JSONDecoder().decode([RecentJoinRecord].self, from: try #require(backend.storage["recentJoins.v1.MAC-1"]))
        #expect(own.map(\.joinUrl) == (2..<7).reversed().map { "https://www.sliccy.ai/join/\($0)" })
        // A reconnect keeps the first-connected date and a known label.
        store.record(joinURL: "https://www.sliccy.ai/join/6", label: "Named")
        store.record(joinURL: "https://www.sliccy.ai/join/6", label: "")
        let again = try JSONDecoder().decode([RecentJoinRecord].self, from: try #require(backend.storage["recentJoins.v1.MAC-1"]))
        #expect(again.first { $0.joinUrl.hasSuffix("/6") }?.label == "Named")
    }

    @Test func anUpdateRelaunchResumesRemoteSessionsWithASavedJoinURL() async throws {
        let (defaults, domain) = try suite()
        defer { defaults.removePersistentDomain(forName: domain) }
        let vault = MemoryJoinURLVault()
        let saved = remote("Saved", connection: .connecting)
        let unsaved = remote("Unsaved", connection: .connecting)
        let old = WorkspaceStore(defaults: defaults, joinVault: vault)
        old.sessions = [saved, unsaved]
        old.bindCredential(Self.join, to: saved.id)
        old.applyLifecycle(try linked(), to: saved.id)
        old.bindCredential("https://www.sliccy.ai/join/never-linked", to: unsaved.id)
        old.prepareUpdateRelaunch(build: "7")
        old.shutdown()

        let new = WorkspaceStore(defaults: defaults, joinVault: vault)
        let task = try #require(new.resumeAfterUpdate(build: "8", detachWait: .milliseconds(10)))
        await task.value
        #expect(new.liveTokens[saved.id] != nil)
        #expect(new.liveTokens[unsaved.id] == nil)
        #expect(new.credentialSession == nil)
        #expect(new.session(unsaved.id)?.entries.last?.text.contains("not saved") == true)
    }
}
