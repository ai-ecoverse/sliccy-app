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
    private static func cgRecords(diagnostics: ScreenRunnerInventoryDiagnostics.Attempt) throws -> [ScreenRunnerInventoryBoundary.CGRecord] {
        guard let values = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]], values.count <= 512 else {
            throw diagnostics.reject(.cgInventory, .cgList)
        }
        return try values.map { value in
            guard let id = value[kCGWindowNumber as String] as? NSNumber,
                  let pid = value[kCGWindowOwnerPID as String] as? NSNumber,
                  let layer = value[kCGWindowLayer as String] as? NSNumber,
                  let bounds = value[kCGWindowBounds as String] as? [String: Any],
                  let rect = CGRect(dictionaryRepresentation: bounds as CFDictionary),
                  (value[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true else {
                throw diagnostics.reject(.cgInventory, .cgFields, pid: (value[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value,
                    windowID: (value[kCGWindowNumber as String] as? NSNumber)?.uint32Value)
            }
            return .init(id: id.uint32Value, pid: pid.int32Value, rect: rect, layer: layer.intValue)
        }
    }
    private static func offMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        let work = Task.detached(operation: body)
        return try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }
    static func authorizationBaseline(surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], diagnostics: ScreenRunnerInventoryDiagnostics.Attempt, identityRecord: @escaping @Sendable (ScreenRunnerBSD.Evidence) -> Void,
                                      sliceRecord: @escaping @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) async throws -> Set<UInt32> {
        let cg = try cgRecords(diagnostics: diagnostics)
        let pids = Set(cg.map(\.pid))
        let known = [surface] + browsers
        return try await offMain {
            var authorized = Set<pid_t>()
            for pid in pids.sorted() {
                try Task.checkCancellation()
                if pid == getpid() { _ = try diagnostics.observe(.ownerVerification, pid: pid, cg: cg.filter { $0.pid == pid }, operation: { try ScreenRunnerSystemOwner.own(pid, sliceRecord: sliceRecord) }) }
                else if let owner = known.first(where: { $0.pid == pid }) { _ = try diagnostics.observe(.ownedVerification, pid: pid, cg: cg.filter { $0.pid == pid }, operation: { try owner.inventoryIdentity() }) }
                else {
                    let identifier = try diagnostics.observe(.ownerIdentifier, pid: pid, cg: cg.filter { $0.pid == pid }, operation: { try ScreenRunnerSystemOwner.identifier(pid) })
                    guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" else {
                        throw diagnostics.reject(.unclassifiedOwner, .ownerRole, pid: pid, signingIdentifier: identifier, cg: cg.filter { $0.pid == pid })
                    }
                    _ = try diagnostics.observe(.ownerVerification, pid: pid, signingIdentifier: identifier, cg: cg.filter { $0.pid == pid }, operation: { try ScreenRunnerSystemOwner.verify(pid, identifier: identifier, identityRecord: identityRecord, sliceRecord: sliceRecord) })
                    if identifier == "com.apple.SecurityAgent" { authorized.insert(pid) }
                }
            }
            return Set(cg.filter { authorized.contains($0.pid) }.map(\.id))
        }
    }
    static func read(surface: ScreenRunnerOwnedProcess, browsers: [ScreenRunnerOwnedProcess], selected: ScreenRunnerCase,
                     authorization: ScreenRunnerOwnedProcess? = nil, correlation: Authorization? = nil,
                     diagnostics: ScreenRunnerInventoryDiagnostics.Attempt, identityRecord: @escaping @Sendable (ScreenRunnerBSD.Evidence) -> Void,
                                      sliceRecord: @escaping @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) async throws -> ScreenRunnerInventory {
        guard try ScreenRunnerHost.require() == selected else { diagnostics.reject(.unknown, .host); throw ScreenFailure.protection }
        guard CGPreflightScreenCaptureAccess() else { throw diagnostics.reject(.permission, .permission) }
        guard surface.identifier == "ai.sliccy.proof-helper" else { throw diagnostics.reject(.surfaceIdentity, .surfaceRole, pid: surface.pid, signingIdentifier: surface.identifier) }
        guard browsers.count == (selected.needsBrowser ? 4 : 0) else { throw diagnostics.reject(.browserIdentity, .browserCount) }
        let content: SCShareableContent
        do { content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true) }
        catch { throw diagnostics.reject(.shareableContent, .shareableContent) }
        guard let display = content.displays.first(where: { $0.displayID == CGMainDisplayID() }) else {
            throw diagnostics.reject(.displayGeometry, .mainDisplay)
        }
        let cg = try cgRecords(diagnostics: diagnostics)
        let sck: [ScreenRunnerInventoryBoundary.SCKRecord] = try content.windows.map { value in
            let owner = value.owningApplication
            return try ScreenRunnerInventoryBoundary.sckRecord(id: value.windowID, pid: owner?.processID, bundle: owner?.bundleIdentifier,
                rect: value.frame, layer: value.windowLayer, diagnosticTitle: value.title, cg: cg, diagnostics: diagnostics)
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
                if pid == getpid() { result[pid] = try diagnostics.observe(.ownerVerification, pid: pid, cg: cg.filter { $0.pid == pid }, sck: sck.filter { $0.pid == pid }.map(ScreenRunnerInventoryDiagnostics.SCKFact.init), operation: { try ScreenRunnerSystemOwner.own(pid, sliceRecord: sliceRecord) }) }
                else if let owned = known.first(where: { $0.pid == pid }) { result[pid] = try diagnostics.observe(.ownedVerification, pid: pid, cg: cg.filter { $0.pid == pid }, sck: sck.filter { $0.pid == pid }.map(ScreenRunnerInventoryDiagnostics.SCKFact.init), operation: { try owned.inventoryIdentity() }) }
                else {
                    let identifier = try diagnostics.observe(.ownerIdentifier, pid: pid, cg: cg.filter { $0.pid == pid }, sck: sck.filter { $0.pid == pid }.map(ScreenRunnerInventoryDiagnostics.SCKFact.init), operation: { try ScreenRunnerSystemOwner.identifier(pid) })
                    guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" else {
                        throw diagnostics.reject(.unclassifiedOwner, .ownerRole, pid: pid, signingIdentifier: identifier, cg: cg.filter { $0.pid == pid }, sck: sck.filter { $0.pid == pid }.map(ScreenRunnerInventoryDiagnostics.SCKFact.init))
                    }
                    result[pid] = try diagnostics.observe(.ownerVerification, pid: pid, signingIdentifier: identifier, cg: cg.filter { $0.pid == pid }, sck: sck.filter { $0.pid == pid }.map(ScreenRunnerInventoryDiagnostics.SCKFact.init), operation: { try ScreenRunnerSystemOwner.verify(pid, identifier: identifier, identityRecord: identityRecord, sliceRecord: sliceRecord) })
                }
            }
            if selected == .authorizationExclusion {
                guard let authorization, authorization.identifier == "com.apple.osascript", authorization.isAlive else {
                    throw diagnostics.reject(.authorizationRequester, .requester, pid: authorization?.pid)
                }
                try diagnostics.observe(.requester, pid: authorization.pid, operation: { try authorization.verifyLive() })
            }
            for owned in known { try diagnostics.observe(.ownedVerification, pid: owned.pid, operation: { try owned.verifyLive() }) }
            return result
        }
        try Task.checkCancellation()
        let context = ScreenRunnerInventoryBoundary.Context(app: getpid(), surface: surface.pid, browsers: browserPIDs,
            selected: selected, authorizationBefore: correlation?.before, authorizationRequesterVerified: authorization != nil,
            authorizationRequestedAt: correlation?.requestedAt, observedAt: observedAt)
        let validated = try ScreenRunnerInventoryBoundary.validate(display: display.displayID, rect: display.frame, cg: cg, sck: sck,
            context: context, diagnostics: diagnostics, verify: { pid in
                guard let value = owners[pid] else { throw diagnostics.reject(.ownerAttribution, .ownerVerification, pid: pid) }
                return value
            })
        guard let allowed = content.windows.first(where: { $0.windowID == validated.allowed }) else { throw diagnostics.reject(.surfaceIdentity, .allowedLookup, pid: surface.pid, windowID: validated.allowed) }
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
            targets.append(.init(label: label, application: application, windows: matching.map(\.value),
                inventoryIdentity: validated.fingerprint.owners.first { $0.pid == pid },
                windowServerWitness: validated.windowServerEmptyBundle.flatMap { $0.owner.pid == pid ? $0 : nil }))
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
