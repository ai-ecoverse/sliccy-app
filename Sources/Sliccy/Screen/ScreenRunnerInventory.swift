#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit
import Security
@preconcurrency import ScreenCaptureKit

@MainActor
final class ScreenRunnerInventory {
    struct Window {
        let label: String
        let profile: String
        let value: SCWindow
    }
    struct Fingerprint: Equatable {
        struct Window: Equatable { let id: CGWindowID, pid: pid_t, bundle: String, rect: CGRect, layer: Int }
        let display: CGDirectDisplayID, rect: CGRect, windows: [Window]
    }
    var fingerprint: Fingerprint {
        Fingerprint(display: display.displayID, rect: display.frame, windows: windows.map {
            .init(id: $0.value.windowID, pid: $0.value.owningApplication?.processID ?? -1,
                  bundle: $0.value.owningApplication?.bundleIdentifier ?? "", rect: $0.value.frame,
                  layer: $0.value.windowLayer)
        }.sorted { $0.id < $1.id })
    }
    let selected: ScreenRunnerCase
    let display: SCDisplay
    let windows: [Window]
    let protected: ScreenProtectedSet
    let allowed: SCWindow
    private let surface: ScreenRunnerOwnedProcess
    private let browsers: [ScreenRunnerOwnedProcess]
    private let content: SCShareableContent

    private init(selected: ScreenRunnerCase, display: SCDisplay, windows: [Window], protected: ScreenProtectedSet, allowed: SCWindow,
                 surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], content: SCShareableContent) {
        self.selected = selected; self.display = display; self.windows = windows; self.protected = protected; self.allowed = allowed
        self.surface = surface; self.browsers = browsers; self.content = content
    }
    static func read(surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], selected: ScreenRunnerCase, authorization: ScreenRunnerOwnedProcess? = nil) async throws -> ScreenRunnerInventory {
        guard try ScreenRunnerHost.require() == selected else { throw ScreenFailure.protection }

        guard CGPreflightScreenCaptureAccess() else { throw ScreenRunnerInventoryIssue.permission }
        guard surface.identifier == "ai.sliccy.proof-helper" else { throw ScreenRunnerInventoryIssue.surfaceIdentity }
        guard browsers.count == (selected.needsBrowser ? 2 : 0) else { throw ScreenRunnerInventoryIssue.browserIdentity }
        do { try surface.verifyLive() } catch { throw ScreenRunnerInventoryIssue.surfaceIdentity }
        do { for browser in browsers { try browser.verifyLive() } } catch { throw ScreenRunnerInventoryIssue.browserIdentity }
        let content: SCShareableContent
        do { content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true) }
        catch { throw ScreenRunnerInventoryIssue.shareableContent }
        let main = CGMainDisplayID()
        guard let display = content.displays.first(where: { $0.displayID == main }),
              display.frame.origin == .zero, display.frame.width >= 1024, display.frame.height >= 768,
              max(display.frame.width, display.frame.height) <= 2560,
              display.frame.width * display.frame.height <= 4_000_000 else { throw ScreenRunnerInventoryIssue.displayGeometry }
        guard let cg = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] else { throw ScreenRunnerInventoryIssue.cgInventory }
        func attributed(_ window: SCWindow, pid: pid_t, bundle: String) throws {
            let matching = cg.filter { ($0[kCGWindowNumber as String] as? NSNumber)?.uint32Value == window.windowID }
            guard let app = window.owningApplication, app.processID == pid, app.bundleIdentifier == bundle,
                  !bundle.isEmpty, matching.count == 1, let record = matching.first,
                  (record[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid,
                  (record[kCGWindowLayer as String] as? NSNumber)?.intValue == window.windowLayer,
                  let bounds = record[kCGWindowBounds as String] as? [String: Any],
                  let rect = CGRect(dictionaryRepresentation: bounds as CFDictionary), rect == window.frame,
                  let running = NSRunningApplication(processIdentifier: pid), running.bundleIdentifier == bundle else { throw ScreenRunnerInventoryIssue.ownerAttribution }
        }
        func requireCompleteOwnership(pid: pid_t, windows: [SCWindow]) throws {
            let owned = cg.filter { ($0[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid }
            let ids = owned.map { ($0[kCGWindowNumber as String] as? NSNumber)?.uint32Value }
            do { try ScreenRunnerWindowSets.requireComplete(cg: ids, sck: windows.map(\.windowID)) }
            catch { throw ScreenRunnerInventoryIssue.completeness }
            try ScreenRunnerWindowSets.requireUnambiguous(windows.map(candidate))
        }
        func candidate(_ window: SCWindow) -> ScreenRunnerWindowSets.Candidate {
            .init(id: window.windowID, pid: window.owningApplication?.processID ?? -1,
                  bundle: window.owningApplication?.bundleIdentifier ?? "", rect: window.frame, layer: window.windowLayer,
                  diagnosticTitle: window.title)
        }
        let surfaceWindows = content.windows.filter { $0.owningApplication?.processID == surface.pid }
        guard surfaceWindows.count == 1, let allowed = surfaceWindows.first,
              allowed.windowLayer == 0, allowed.frame == CGRect(x: 128, y: 128, width: 256, height: 256) else { throw ScreenRunnerInventoryIssue.surfaceGeometry }
        try requireCompleteOwnership(pid: surface.pid, windows: surfaceWindows)
        try attributed(allowed, pid: surface.pid, bundle: "ai.sliccy.proof-helper")
        var result = [Window(label: "allowed", profile: "none", value: allowed)]
        var protected = ScreenProtectedSet()
        if selected.needsBrowser {
            for (index, browser) in browsers.enumerated() {
                guard browser.identifier == "com.google.Chrome" else { throw ScreenRunnerInventoryIssue.browserIdentity }
                let profile = index == 0 ? "a" : "b"
                let expected = ScreenRunnerBrowserWindow.allCases.filter { $0.profile == profile }
                let actual = content.windows.filter { $0.owningApplication?.processID == browser.pid }
                guard actual.count == 2 else { throw ScreenRunnerInventoryIssue.browserWindowCount }
                try requireCompleteOwnership(pid: browser.pid, windows: actual)
                for layout in expected {
                    let id = try ScreenRunnerWindowSets.unique(actual.map(candidate), pid: browser.pid,
                        bundle: "com.google.Chrome", rect: layout.rect, layer: 0)
                    guard let window = actual.first(where: { $0.windowID == id }) else { throw ScreenRunnerInventoryIssue.windowIdentity }
                    try attributed(window, pid: browser.pid, bundle: "com.google.Chrome")
                    result.append(.init(label: "chrome-" + profile, profile: profile, value: window))
                }
                protected.hostBundleIDs.insert("com.google.Chrome"); protected.hostPIDs.insert(browser.pid)
            }
            let own = content.windows.filter { $0.owningApplication?.processID == getpid() }
            guard !own.isEmpty else { throw ScreenRunnerInventoryIssue.appWindows }
            try requireCompleteOwnership(pid: getpid(), windows: own)
            for window in own {
                try attributed(window, pid: getpid(), bundle: "ai.sliccy.mac")
                result.append(.init(label: "app", profile: "none", value: window))
            }
        }
        if selected == .authorizationExclusion {
            guard let authorization, authorization.isAlive else { throw ScreenRunnerInventoryIssue.authorizationRequester }
            do { try authorization.verifyLive() } catch { throw ScreenRunnerInventoryIssue.authorizationRequester }
            let prompts = content.windows.filter { ["com.apple.SecurityAgent", "com.apple.securityagent", "com.apple.AuthorizationHost", "com.apple.authorizationhost"].contains($0.owningApplication?.bundleIdentifier ?? "") }
            guard !prompts.isEmpty else { throw ScreenRunnerInventoryIssue.authorizationMissing }
            let owners = Set(prompts.compactMap { $0.owningApplication?.processID })
            for pid in owners {
                try requireCompleteOwnership(pid: pid, windows: prompts.filter { $0.owningApplication?.processID == pid })
            }
            for window in prompts {
                guard let owner = window.owningApplication else { throw ScreenRunnerInventoryIssue.authorizationIdentity }
                try attributed(window, pid: owner.processID, bundle: owner.bundleIdentifier)
                do { try verifyAppleService(pid: owner.processID, identifier: owner.bundleIdentifier) } catch { throw ScreenRunnerInventoryIssue.authorizationIdentity }
                result.append(.init(label: "authorization", profile: "none", value: window))
            }
            guard Set(prompts.compactMap { $0.owningApplication?.processID }).count == 1 else { throw ScreenRunnerInventoryIssue.authorizationAmbiguous }
        }
        do { try surface.verifyLive() } catch { throw ScreenRunnerInventoryIssue.surfaceIdentity }
        do { for browser in browsers { try browser.verifyLive() } } catch { throw ScreenRunnerInventoryIssue.browserIdentity }
        return ScreenRunnerInventory(selected: selected, display: display, windows: result, protected: protected, allowed: allowed,
                                     surface: surface, browsers: browsers, content: content)
    }
    static func authorizationWindowExists() async throws -> Bool {
        guard CGPreflightScreenCaptureAccess() else { throw ScreenFailure.permission }
        let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true)
        return content.windows.contains { ["com.apple.SecurityAgent", "com.apple.securityagent", "com.apple.AuthorizationHost", "com.apple.authorizationhost"].contains($0.owningApplication?.bundleIdentifier ?? "") }
    }
    private static func verifyAppleService(pid: pid_t, identifier: String) throws {
        var guest: SecCode?, rule: SecRequirement?
        guard SecRequirementCreateWithString(("anchor apple and identifier \"" + identifier + "\"") as CFString, [], &rule) == errSecSuccess,
              let rule, SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest) == errSecSuccess,
              let guest, SecCodeCheckValidity(guest, [], rule) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
    }
    func filter(selected: ScreenRunnerCase, refused: (ScreenProofProtectedProbe.Refusal) -> Void) throws -> SCContentFilter {
        guard selected == self.selected else { throw ScreenFailure.protection }
        try surface.verifyLive(); for browser in browsers { try browser.verifyLive() }
        if selected.needsBrowser {
            var targets: [ScreenProofProtectedProbe.Target] = []
            let labels: [ScreenProofProtectedProbe.Label] = selected == .authorizationExclusion ? [.app, .chromeA, .chromeB, .authorization] : [.app, .chromeA, .chromeB]
            for label in labels {
                let matching = windows.filter { $0.label == label.rawValue }.map(\.value)
                guard let application = matching.first?.owningApplication else { throw ScreenFailure.protection }
                targets.append(.init(label: label, application: application, windows: matching))
            }
            try ScreenProofProtectedProbe.check(display: display, targets: targets, protected: protected, refused: refused)
            guard let owner = allowed.owningApplication else { throw ScreenFailure.protection }
            return try ScreenFilterBuilder.display(display, selected: [owner], exceptingWindows: [], protected: protected)
        }
        return try ScreenFilterBuilder.window(allowed, protected: protected)
    }
}
#endif
