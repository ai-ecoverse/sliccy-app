import Foundation
import Testing
@testable import Sliccy

@MainActor
struct LocalBrowserTests {
    @Test func invocationUsesExistingProfileAndPreservesBrowserOnTermination() {
        let invocation = CLIInvocation.localBrowser(profile: "six")
        // Six's profile uses the CLI's own page (/7/), which only adopts tabs on six's app routes.
        #expect(invocation.arguments == ["--browser", "chrome", "--profile", "six", "--origin", "https://www.sliccy.ai", "--json", "--keep-browsers", "--no-fallback", "--no-jerk"])
        #expect(!invocation.arguments.contains("--page"))
        #expect(CLIInvocation.localBrowser(profile: "six:9333").arguments.contains("--page") == false)
        #expect(invocation.input.isEmpty)
    }

    @Test func otherProfilesOpenTheDocumentedPageNotTheRedirectingOrigin() throws {
        let invocation = CLIInvocation.localBrowser(profile: "work", browser: .edge)
        let page = try #require(invocation.arguments.firstIndex(of: "--page"))
        #expect(invocation.arguments[page + 1] == "https://www.sliccy.ai/7/")
        #expect(!invocation.arguments.contains("--origin"))
        // The page, inventory origin and tab matcher all agree on one origin.
        #expect(BrowserTabClient.isSLICCTab(CLIInvocation.localPage))
        #expect(BrowserTabClient.isSLICCTab(CLIInvocation.localOrigin))
        #expect(URL(string: CLIInvocation.localPage)?.host == URL(string: CLIInvocation.localOrigin)?.host)
        #expect(CLIInvocation.agents(cdp: "http://127.0.0.1:1").arguments.contains(CLIInvocation.localOrigin))
    }

    @Test func browserSelectionKeepsSafeDefaultsAndPersists() throws {
        for browser in LocalBrowserChoice.allCases {
            let invocation = CLIInvocation.localBrowser(profile: "work", browser: browser)
            #expect(Array(invocation.arguments.prefix(4)) == ["--browser", browser.rawValue, "--profile", "work"])
            #expect(!invocation.arguments.contains("--deny"))
            #expect(!invocation.arguments.contains("--runner"))
            #expect(!invocation.arguments.contains("--sftp"))
            #expect(invocation.arguments.contains("--no-jerk"))
        }
        #expect(LocalBrowserChoice.chrome.defaultProfile == "six")
        #expect(LocalBrowserChoice.edge.defaultProfile == "edge")
        var session = Session(name: "Work", device: "This Mac", kind: .browser, profile: "work",
                              access: .init(), usesLiveRuntime: true, localBrowserProfile: "work", localBrowser: .edge,
                              localAccess: .init())
        let roundtrip = try JSONDecoder().decode(Session.self, from: JSONEncoder().encode(session))
        #expect(roundtrip.localBrowserChoice == .edge)
        #expect(roundtrip.localBrowserProfile == "work")
        #expect(roundtrip.localAccess?.network == true)
        #expect(roundtrip.localAccess?.shell == false)
        #expect(roundtrip.localAccess?.sftp == false)
        session.localBrowser = nil
        #expect(try JSONDecoder().decode(Session.self, from: JSONEncoder().encode(session)).localBrowserChoice == .chrome)
    }

    @Test func profileChoicesUseValidDirectoriesOnly() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        for name in ["work", "personal", "bad..name", "six"] {
            try FileManager.default.createDirectory(at: root.appendingPathComponent(name), withIntermediateDirectories: true)
        }
        try Data().write(to: root.appendingPathComponent("file"))
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("linked"), withDestinationURL: root.appendingPathComponent("work"))
        #expect(LocalBrowserChoice.profiles(in: root) == ["personal", "work"])
        for name in ["", "../test", "/tmp/test", "two words", "-flag", String(repeating: "x", count: 65)] {
            #expect(!LocalBrowserChoice.validProfile(name))
        }
    }

    @Test func endpointComesOnlyFromLocalHostRoleAndIsClearedOnDisconnect() throws {
        let store = WorkspaceStore(defaults: nil)
        let local = Session(name: "SLICC", device: "This Mac", kind: .browser, profile: "SLICC Chrome profile", connection: .connecting,
                            access: .init(), usesLiveRuntime: true, localBrowserProfile: "six")
        var remote = local
        remote.id = UUID(); remote.localBrowserProfile = nil
        store.sessions = [local, remote]
        func event(_ endpoint: String, role: String = "seven") throws -> CLIEvent {
            try JSONDecoder().decode(CLIEvent.self, from: JSONSerialization.data(withJSONObject: ["schema": 1, "event": "attached", "role": role, "cdp": endpoint]))
        }
        for endpoint in ["https://127.0.0.1:1234", "http://external.invalid:1234", "http://user@localhost:1234", "http://localhost"] {
            store.applyLifecycle(try event(endpoint), to: local.id)
            #expect(store.inventoryInvocation(local.id) == nil)
        }
        store.applyLifecycle(try event("http://127.0.0.1:55779", role: "extra"), to: local.id)
        #expect(store.inventoryInvocation(local.id) == nil)
        store.applyLifecycle(try event("http://127.0.0.1:55779"), to: remote.id)
        #expect(store.inventoryInvocation(remote.id) == nil)
        store.applyLifecycle(try event("http://127.0.0.1:55779"), to: local.id)
        #expect(store.inventoryInvocation(local.id)?.arguments == ["agents", "--cdp", "http://127.0.0.1:55779", "--origin", "https://www.sliccy.ai", "--json", "--watch"])
        store.clearLiveConnection(local.id)
        #expect(store.inventoryInvocation(local.id) == nil)
    }

    @Test func savedLocalSessionKeepsProfileButNeverAutoLaunchesOrPersistsEndpoint() throws {
        let domain = "SliccyTests.\(UUID())"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let store = WorkspaceStore(defaults: defaults)
        let local = Session(name: "SLICC", device: "This Mac", kind: .browser, profile: "SLICC Chrome profile",
                            access: .init(), usesLiveRuntime: true, localBrowserProfile: "six")
        store.sessions = [local]
        store.localBrowserEndpoints[local.id] = "http://127.0.0.1:55779"
        store.save()
        let restored = WorkspaceStore(defaults: defaults)
        #expect(restored.session(local.id)?.localBrowserProfile == "six")
        #expect(restored.session(local.id)?.connection == .disconnected)
        #expect(restored.localBrowserEndpoints.isEmpty)
        #expect(restored.liveProcesses.isEmpty)
        #expect(restored.joinCredentials.isEmpty)
    }
}
