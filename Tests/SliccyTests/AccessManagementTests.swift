import Foundation
import Testing
@testable import Sliccy

@MainActor
struct AccessManagementTests {
    @Test func agentCountUsesInventoryInsteadOfPromptBusyState() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.isWorking = false }
        #expect(store.session(id)?.runningAgentCount == 2)
        store.update(id) { $0.isWorking = true }
        #expect(store.session(id)?.runningAgentCount == 2)
        store.update(id) { $0.usesLiveRuntime = true }
        #expect(store.session(id)?.runningAgentCount == nil)
        #expect(store.session(id)?.managementSnapshot == nil)
    }

    @Test func liveSessionsCannotBeGivenMockCredentialsOrScreenGrants() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.setDemoCredential("github", enabled: true, for: id)
        store.setDemoScreen("Example window", for: id)
        #expect(store.session(id)?.management == nil)
    }

    @Test func disconnectClearsScreenGrantButKeepsConfiguredCredentials() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.setDemoCredential("github", enabled: true, for: id)
        store.setDemoScreen("Sample window", for: id)
        #expect(store.session(id)?.managementSnapshot?.screenTarget == "Sample window")
        store.disconnect(id)
        #expect(store.session(id)?.managementSnapshot?.screenTarget == nil)
        #expect(store.session(id)?.managementSnapshot?.credentials.first { $0.id == "github" }?.enabled == true)
        #expect(store.session(id)?.runningAgentCount == 0)
    }

    @Test func linkedLifecycleDoesNotStartTranscriptWatch() throws {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.watchSupported.insert(id)
        let event = try JSONDecoder().decode(CLIEvent.self, from: Data(#"{"schema":1,"event":"linked","resources":{"browsers":[],"mounts":[],"rejectedMounts":[],"network":{"exit":false,"policy":"none"},"compute":{"ssh":false,"sftp":false},"jerk":{"offered":true,"seal":false}}}"#.utf8))
        store.applyLifecycle(event, to: id)
        #expect(store.watchProcesses.isEmpty)
        #expect(store.watchTasks.isEmpty)
        #expect(store.session(id)?.effectiveResources?.jerk?.offered == true)
        #expect(store.session(id)?.effectiveResources?.jerk?.seal == false)
    }
    @Test func disablingFolderRetainsItsConfigurationAcrossRelaunch() throws {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let store = WorkspaceStore(defaults: defaults)
        let id = store.sessions[0].id
        let folder = try #require(store.session(id)?.access.folders.first)
        store.setDemoFolder(folder.id, readOnly: false, for: id)
        store.setDemoFolder(folder.id, enabled: false, for: id)
        let restored = WorkspaceStore(defaults: defaults)
        let retained = try #require(restored.session(id)?.access.folders.first)
        #expect(retained.id == folder.id)
        #expect(retained.path == folder.path)
        #expect(!retained.isEnabled)
        #expect(!retained.readOnly)
    }

    @Test func screenScopesReplaceEachOtherAndNeverResumeOnRelaunch() throws {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let store = WorkspaceStore(defaults: defaults)
        let id = store.sessions[0].id
        store.setDemoScreen("Browser window", for: id)
        store.setDemoScreen("Full screen · All apps", for: id)
        #expect(store.session(id)?.managementSnapshot?.screenTarget == "Full screen · All apps")
        let restored = WorkspaceStore(defaults: defaults)
        #expect(restored.session(id)?.managementSnapshot?.screenTarget == nil)
    }

    @Test func disabledBrowserRestoresItsChoiceAndShellWithdrawalClearsSFTP() {
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.access.browser = "Microsoft Edge" }
        store.setDemoEntitlement(.browser, enabled: false, for: id)
        store.setDemoEntitlement(.browser, enabled: true, for: id)
        #expect(store.session(id)?.access.browser == "Microsoft Edge")
        store.setDemoEntitlement(.sftp, enabled: true, for: id)
        #expect(store.session(id)?.access.shell == true)
        store.setDemoEntitlement(.shell, enabled: false, for: id)
        #expect(store.session(id)?.access.sftp == false)
    }

}
