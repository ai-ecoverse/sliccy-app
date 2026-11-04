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
    typealias Fingerprint = ScreenRunnerInventoryBoundary.Fingerprint
    struct Authorization: Sendable {
        let before: Set<UInt32>
        let requestedAt: ContinuousClock.Instant
    }
    var fingerprint: Fingerprint { validated.fingerprint }
    let selected: ScreenRunnerCase
    let display: SCDisplay
    let windows: [Window]
    let protected: ScreenProtectedSet
    let allowed: SCWindow
    let validated: ScreenRunnerInventoryBoundary.Validated
    private let surface: ScreenRunnerOwnedProcess
    private let browsers: [ScreenRunnerOwnedProcess]
    private let content: SCShareableContent

    private init(selected: ScreenRunnerCase, display: SCDisplay, windows: [Window], protected: ScreenProtectedSet, allowed: SCWindow,
                 surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], content: SCShareableContent,
                 validated: ScreenRunnerInventoryBoundary.Validated) {
        self.selected = selected; self.display = display; self.windows = windows; self.protected = protected; self.allowed = allowed
        self.surface = surface; self.browsers = browsers; self.content = content; self.validated = validated
    }
    private static func cgRecords() throws -> [ScreenRunnerInventoryBoundary.CGRecord] {
        guard let values = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]], values.count <= 512 else {
            throw ScreenRunnerInventoryIssue.cgInventory
        }
        return try values.map { value in
            guard let id = value[kCGWindowNumber as String] as? NSNumber,
                  let pid = value[kCGWindowOwnerPID as String] as? NSNumber,
                  let layer = value[kCGWindowLayer as String] as? NSNumber,
                  let bounds = value[kCGWindowBounds as String] as? [String: Any],
                  let rect = CGRect(dictionaryRepresentation: bounds as CFDictionary),
                  (value[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true else {
                throw ScreenRunnerInventoryIssue.cgInventory
            }
            return .init(id: id.uint32Value, pid: pid.int32Value, rect: rect, layer: layer.intValue)
        }
    }
    private static func offMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        let work = Task.detached(operation: body)
        return try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }
    static func authorizationBaseline(surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], kernelRecord: @escaping @Sendable (ScreenRunnerKernelChild.Evidence) -> Void) async throws -> Set<UInt32> {
        let cg = try cgRecords()
        let pids = Set(cg.map(\.pid))
        let known = [surface] + browsers
        return try await offMain {
            var authorized = Set<pid_t>()
            for pid in pids.sorted() {
                try Task.checkCancellation()
                if pid == getpid() { _ = try ScreenRunnerSystemOwner.own(pid) }
                else if let owner = known.first(where: { $0.pid == pid }) { _ = try owner.inventoryIdentity() }
                else {
                    let identifier = try ScreenRunnerSystemOwner.identifier(pid)
                    guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" else {
                        throw ScreenRunnerInventoryIssue.unclassifiedOwner
                    }
                    _ = try ScreenRunnerSystemOwner.verify(pid, identifier: identifier, kernelRecord: kernelRecord)
                    if identifier == "com.apple.SecurityAgent" { authorized.insert(pid) }
                }
            }
            return Set(cg.filter { authorized.contains($0.pid) }.map(\.id))
        }
    }
    static func read(surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], selected: ScreenRunnerCase,
                     authorization: ScreenRunnerOwnedProcess? = nil, correlation: Authorization? = nil,
                     kernelRecord: @escaping @Sendable (ScreenRunnerKernelChild.Evidence) -> Void) async throws -> ScreenRunnerInventory {
        guard try ScreenRunnerHost.require() == selected else { throw ScreenFailure.protection }
        guard CGPreflightScreenCaptureAccess() else { throw ScreenRunnerInventoryIssue.permission }
        guard surface.identifier == "ai.sliccy.proof-helper" else { throw ScreenRunnerInventoryIssue.surfaceIdentity }
        guard browsers.count == (selected.needsBrowser ? 4 : 0) else { throw ScreenRunnerInventoryIssue.browserIdentity }
        let content: SCShareableContent
        do { content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true) }
        catch { throw ScreenRunnerInventoryIssue.shareableContent }
        guard let display = content.displays.first(where: { $0.displayID == CGMainDisplayID() }) else {
            throw ScreenRunnerInventoryIssue.displayGeometry
        }
        let cg = try cgRecords()
        let sck: [ScreenRunnerInventoryBoundary.SCKRecord] = try content.windows.map { value in
            guard let owner = value.owningApplication else { throw ScreenRunnerInventoryIssue.ownerAttribution }
            return .init(id: value.windowID, pid: owner.processID, bundle: owner.bundleIdentifier, rect: value.frame,
                         layer: value.windowLayer, diagnosticTitle: value.title)
        }
        var browserPIDs: [ScreenRunnerBrowserWindow: pid_t] = [:]
        if selected.needsBrowser {
            for (layout, browser) in zip(ScreenRunnerBrowserWindow.allCases, browsers) { browserPIDs[layout] = browser.pid }
        }
        let observedAt = ContinuousClock.now
        let known = [surface] + browsers, pids = Set(cg.map(\.pid)).union(sck.map(\.pid))
        let owners = try await offMain {
            var result: [pid_t: ScreenRunnerInventoryBoundary.Identity] = [:]
            for pid in pids.sorted() {
                try Task.checkCancellation()
                if pid == getpid() { result[pid] = try ScreenRunnerSystemOwner.own(pid) }
                else if let owned = known.first(where: { $0.pid == pid }) { result[pid] = try owned.inventoryIdentity() }
                else {
                    let identifier = try ScreenRunnerSystemOwner.identifier(pid)
                    guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" else {
                        throw ScreenRunnerInventoryIssue.unclassifiedOwner
                    }
                    result[pid] = try ScreenRunnerSystemOwner.verify(pid, identifier: identifier, kernelRecord: kernelRecord)
                }
            }
            if selected == .authorizationExclusion {
                guard let authorization, authorization.identifier == "com.apple.osascript", authorization.isAlive else {
                    throw ScreenRunnerInventoryIssue.authorizationRequester
                }
                try authorization.verifyLive()
            }
            for owned in known { try owned.verifyLive() }
            return result
        }
        try Task.checkCancellation()
        let context = ScreenRunnerInventoryBoundary.Context(app: getpid(), surface: surface.pid, browsers: browserPIDs,
            selected: selected, authorizationBefore: correlation?.before, authorizationRequesterVerified: authorization != nil,
            authorizationRequestedAt: correlation?.requestedAt, observedAt: observedAt)
        let validated = try ScreenRunnerInventoryBoundary.validate(display: display.displayID, rect: display.frame, cg: cg, sck: sck,
            context: context, verify: { pid in
                guard let value = owners[pid] else { throw ScreenRunnerInventoryIssue.ownerAttribution }
                return value
            })
        guard let allowed = content.windows.first(where: { $0.windowID == validated.allowed }) else { throw ScreenRunnerInventoryIssue.surfaceIdentity }
        var protected = ScreenProtectedSet(), windows: [Window] = []
        for window in validated.fingerprint.windows {
            if window.kind != .allowed {
                protected.hostPIDs.insert(window.pid); protected.hostBundleIDs.insert(window.bundle)
            }
            if let actual = content.windows.first(where: { $0.windowID == window.id }) {
                let label = window.kind == .system ? Self.systemLabel(window.bundle).rawValue : window.kind.rawValue
                let profile = label.hasPrefix("chrome-") ? String(label.dropFirst("chrome-".count)) : "none"
                windows.append(.init(label: label, profile: profile, value: actual))
            }
        }
        return .init(selected: selected, display: display, windows: windows, protected: protected, allowed: allowed,
                     surface: surface, browsers: browsers, content: content, validated: validated)
    }
    private static func systemLabel(_ identifier: String) -> ScreenProofProtectedProbe.Label {
        switch identifier {
        case "com.apple.WindowManager": .windowManager
        case "com.apple.dock": .dock
        case "com.apple.finder": .finder
        case "com.apple.WindowServer": .windowServer
        default: preconditionFailure("unclassified system owner")
        }
    }
    func filter(selected: ScreenRunnerCase, refused: (ScreenProofProtectedProbe.Refusal) -> Void) throws -> SCContentFilter {
        guard selected == self.selected else { throw ScreenFailure.protection }
        try validated.requireSelection([allowed.windowID])
        try surface.verifyLive(); for browser in browsers { try browser.verifyLive() }
        var targets: [ScreenProofProtectedProbe.Target] = []
        for pid in Set(windows.filter { $0.label != "allowed" }.compactMap { $0.value.owningApplication?.processID }).sorted() {
            let matching = windows.filter { $0.value.owningApplication?.processID == pid }
            guard let first = matching.first, let label = ScreenProofProtectedProbe.Label(rawValue: first.label),
                  let application = first.value.owningApplication else { throw ScreenFailure.protection }
            targets.append(.init(label: label, application: application, windows: matching.map(\.value)))
        }
        try ScreenProofProtectedProbe.check(display: display, targets: targets, protected: protected, refused: refused)
        if selected.needsBrowser {
            guard let owner = allowed.owningApplication else { throw ScreenFailure.protection }
            return try ScreenFilterBuilder.display(display, selected: [owner], exceptingWindows: [], protected: protected)
        }
        return try ScreenFilterBuilder.window(allowed, protected: protected)
    }
}
#endif
