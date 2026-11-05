#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerInventoryBoundary {
    static let systemRoles: Set<String> = ["com.apple.WindowManager", "com.apple.dock", "com.apple.finder", "com.apple.WindowServer"]
    struct CGRecord: Equatable, Sendable {
        let id: UInt32, pid: pid_t, rect: CGRect, layer: Int
    }
    struct SCKRecord: Equatable, Sendable {
        let id: UInt32, pid: pid_t, bundle: String, rect: CGRect, layer: Int
        var diagnosticTitle: String? = nil
    }
    struct Identity: Equatable, Sendable {
        let pid: pid_t, parent: pid_t, uid: uid_t, seconds: UInt64, microseconds: UInt64
        let identifier: String, path: String, hash: Data
        let appleAnchored: Bool, verified: Bool, sysctlBound: Bool
        var realUID: uid_t? = nil, savedUID: uid_t? = nil
    }
    struct Context: Sendable {
        let app: pid_t, surface: pid_t, browsers: [ScreenRunnerBrowserWindow: pid_t]
        let selected: ScreenRunnerCase
        var authorizationBefore: Set<UInt32>? = nil
        var authorizationRequesterVerified = false
        var authorizationRequestedAt: ContinuousClock.Instant? = nil
        var observedAt: ContinuousClock.Instant = .now
    }
    enum Kind: String, Equatable, Sendable {
        case allowed, app, chromeA1 = "chrome-a-1", chromeA2 = "chrome-a-2", chromeB1 = "chrome-b-1", chromeB2 = "chrome-b-2"
        case authorization, system
        var selectable: Bool { self == .allowed }
    }
    struct Window: Equatable, Sendable {
        let id: UInt32, pid: pid_t, bundle: String, rect: CGRect, layer: Int, kind: Kind
        let inCG: Bool, inSCK: Bool
    }
    struct Fingerprint: Equatable, Sendable {
        let display: UInt32, rect: CGRect, windows: [Window], owners: [Identity]
    }
    struct Validated: Sendable {
        let fingerprint: Fingerprint
        let allowed: UInt32
        let authorizationNew: Set<UInt32>
        func requireSelection(_ ids: [UInt32]) throws {
            guard ids == [allowed], fingerprint.windows.contains(where: { $0.id == allowed && $0.kind.selectable && $0.inCG && $0.inSCK }) else {
                throw ScreenFailure.protection
            }
        }
    }
    static func sckRecord(id: UInt32, pid: pid_t?, bundle: String?, rect: CGRect, layer: Int, diagnosticTitle: String?,
                          cg: [CGRecord], diagnostics: ScreenRunnerInventoryDiagnostics.Attempt) throws -> SCKRecord {
        guard let pid, let bundle else {
            throw diagnostics.reject(.ownerAttribution, .sckOwner, windowID: id, cg: cg.filter { $0.id == id },
                sck: [.init(id: id, pid: pid, bundle: bundle, rect: rect, layer: layer)], checks: [(.present, false)])
        }
        return .init(id: id, pid: pid, bundle: bundle, rect: rect, layer: layer, diagnosticTitle: diagnosticTitle)
    }
    static func validate(display: UInt32, rect: CGRect, cg: [CGRecord], sck: [SCKRecord], context: Context,
                         diagnostics: ScreenRunnerInventoryDiagnostics.Attempt? = nil, verify: (pid_t) throws -> Identity) throws -> Validated {
        func refuse(_ issue: ScreenRunnerInventoryIssue, _ branch: ScreenRunnerInventoryDiagnostics.Branch, pid: pid_t? = nil, id: UInt32? = nil, owner: Identity? = nil, checks: [(ScreenRunnerInventoryDiagnostics.Check, Bool)] = []) -> ScreenRunnerInventoryIssue {
            let c = cg.filter { id != nil ? $0.id == id : pid != nil && $0.pid == pid }
            let s = sck.filter { id != nil ? $0.id == id : pid != nil && $0.pid == pid }
            return diagnostics?.reject(issue, branch, pid: pid, windowID: id, signingIdentifier: owner?.identifier,
                cg: c, sck: s.map(ScreenRunnerInventoryDiagnostics.SCKFact.init), owner: owner, checks: checks) ?? issue
        }
        guard display != 0, rect.origin == .zero, rect.width >= 1024, rect.height >= 768,
              max(rect.width, rect.height) <= 2560, rect.width * rect.height <= 4_000_000,
              !cg.isEmpty, cg.count <= 512, sck.count <= 512 else { throw refuse(.displayGeometry, .display) }
        guard context.app > 0, context.surface > 0, context.app != context.surface,
              context.browsers.count == (context.selected.needsBrowser ? 4 : 0),
              Set(context.browsers.values).count == context.browsers.count,
              context.browsers.values.allSatisfy({ $0 > 0 && $0 != context.app && $0 != context.surface }) else { throw refuse(.ownerAttribution, .context, pid: context.app <= 0 ? context.app : context.surface <= 0 ? context.surface : nil, checks: [(.pid, context.app > 0 && context.surface > 0 && context.browsers.values.allSatisfy { $0 > 0 }), (.count, context.browsers.count == (context.selected.needsBrowser ? 4 : 0)), (.unique, context.app != context.surface && Set(context.browsers.values).count == context.browsers.count && context.browsers.values.allSatisfy { $0 != context.app && $0 != context.surface })]) }
        let cgIDs = cg.map(\.id), sckIDs = sck.map(\.id)
        guard !cgIDs.contains(0), !sckIDs.contains(0), Set(cgIDs).count == cgIDs.count,
              Set(sckIDs).count == sckIDs.count else { throw refuse(.completeness, .windowIDs, checks: [(.nonzero, !cgIDs.contains(0) && !sckIDs.contains(0)), (.unique, Set(cgIDs).count == cgIDs.count && Set(sckIDs).count == sckIDs.count)]) }
        let pids = Set(cg.map(\.pid)).union(sck.map(\.pid))
        guard pids.allSatisfy({ $0 > 0 }), pids.count <= 128 else { throw refuse(.ownerAttribution, .ownerPIDs, pid: pids.filter { $0 <= 0 }.sorted().first, checks: [(.pid, pids.allSatisfy { $0 > 0 }), (.count, pids.count <= 128)]) }
        var owners: [Identity] = [], windows: [Window] = []
        for pid in pids.sorted() {
            let owner: Identity
            do { owner = try verify(pid) }
            catch { _ = refuse(error as? ScreenRunnerInventoryIssue ?? .unknown, .ownerVerification, pid: pid); throw error }
            guard owner.pid == pid, owner.verified, owner.seconds > 0, owner.microseconds < 1_000_000,
                  !owner.identifier.isEmpty, owner.path.hasPrefix("/"), owner.hash.count == 20 else { throw refuse(.ownerAttribution, .ownerFields, pid: pid, owner: owner, checks: [(.pid, owner.pid == pid), (.verified, owner.verified), (.startSeconds, owner.seconds > 0), (.startMicroseconds, owner.microseconds < 1_000_000), (.identifier, !owner.identifier.isEmpty), (.absolutePath, owner.path.hasPrefix("/")), (.hashLength, owner.hash.count == 20)]) }
            let kind: Kind
            if pid == context.surface {
                guard owner.identifier == "ai.sliccy.proof-helper" else { throw refuse(.surfaceIdentity, .surfaceIdentity, pid: pid, owner: owner, checks: [(.identifier, false)]) }
                kind = .allowed
            } else if pid == context.app {
                guard owner.identifier == "ai.sliccy.mac" else { throw refuse(.appWindows, .appIdentity, pid: pid, owner: owner, checks: [(.identifier, false)]) }
                kind = .app
            } else if let layout = context.browsers.first(where: { $0.value == pid })?.key {
                guard owner.identifier == "com.google.Chrome" else { throw refuse(.browserIdentity, .browserIdentity, pid: pid, owner: owner, checks: [(.identifier, false)]) }
                kind = Kind(rawValue: "chrome-" + layout.profile)!
            } else if owner.identifier == "com.apple.SecurityAgent", owner.appleAnchored {
                kind = .authorization
            } else if systemRoles.contains(owner.identifier), owner.appleAnchored {
                guard owner.identifier != "com.apple.WindowServer" || (owner.sysctlBound && owner.parent == 1 && owner.uid == 88 && owner.realUID == 0 && owner.savedUID == 0) else { throw refuse(.ownerAttribution, .windowServer, pid: pid, owner: owner, checks: [(.sysctlBound, owner.sysctlBound), (.parent, owner.parent == 1), (.effectiveUID, owner.uid == 88), (.realUID, owner.realUID == 0), (.savedUID, owner.savedUID == 0)]) }
                kind = .system
            } else { throw refuse(.unclassifiedOwner, .ownerClass, pid: pid, owner: owner, checks: [(.identifier, systemRoles.contains(owner.identifier) || owner.identifier == "com.apple.SecurityAgent"), (.appleAnchor, owner.appleAnchored)]) }
            owners.append(owner)
            let c = cg.filter { $0.pid == pid }, s = sck.filter { $0.pid == pid }
            if kind != .system, Set(c.map(\.id)) != Set(s.map(\.id)) { throw refuse(.completeness, .completeness, pid: pid, id: Set(c.map(\.id)).symmetricDifference(Set(s.map(\.id))).sorted().first, owner: owner) }
            for id in Set(c.map(\.id)).union(s.map(\.id)).sorted() {
                let left = c.first { $0.id == id }, right = s.first { $0.id == id }
                if let left, let right {
                    guard left.rect == right.rect, left.layer == right.layer else { throw refuse(.ownerAttribution, .geometryPair, pid: pid, id: id, owner: owner, checks: [(.rect, left.rect == right.rect), (.layer, left.layer == right.layer)]) }
                }
                guard !cg.contains(where: { $0.id == id && $0.pid != pid }), !sck.contains(where: { $0.id == id && $0.pid != pid }) else { throw refuse(.ownerAttribution, .pidPair, pid: pid, id: id, owner: owner, checks: [(.cgPID, !cg.contains { $0.id == id && $0.pid != pid }), (.sckPID, !sck.contains { $0.id == id && $0.pid != pid })]) }
                if let right, right.bundle != owner.identifier { throw refuse(.ownerAttribution, .bundlePair, pid: pid, id: id, owner: owner, checks: [(.bundle, false)]) }
                let frame = left?.rect ?? right!.rect, layer = left?.layer ?? right!.layer
                guard frame.origin.x.isFinite, frame.origin.y.isFinite, frame.width.isFinite, frame.height.isFinite,
                      frame.width > 0, frame.height > 0 else { throw refuse(.windowIdentity, .geometry, pid: pid, id: id, owner: owner, checks: [(.finite, frame.origin.x.isFinite && frame.origin.y.isFinite && frame.width.isFinite && frame.height.isFinite), (.positiveSize, frame.width > 0 && frame.height > 0)]) }
                guard !windows.contains(where: { $0.pid == pid && $0.rect == frame }) else { throw refuse(.windowIdentity, .duplicateGeometry, pid: pid, id: id, owner: owner) }
                windows.append(.init(id: id, pid: pid, bundle: owner.identifier, rect: frame, layer: layer, kind: kind, inCG: left != nil, inSCK: right != nil))
            }
        }
        let allowed = windows.filter { $0.kind == .allowed }
        guard allowed.count == 1, let selected = allowed.first, selected.layer == 0,
              selected.rect == CGRect(x: 128, y: 128, width: 256, height: 256), selected.inCG, selected.inSCK else { throw refuse(.surfaceGeometry, .allowed, pid: context.surface) }
        guard windows.contains(where: { $0.kind == .app }) else { throw refuse(.appWindows, .appWindow, pid: context.app) }
        for (layout, pid) in context.browsers {
            let matches = windows.filter { $0.pid == pid }
            guard matches.count == 1, matches[0].rect == layout.rect, matches[0].layer == 0 else { throw refuse(.browserWindowCount, .browserWindow, pid: pid) }
        }
        var newPrompts = Set<UInt32>()
        if context.selected == .authorizationExclusion {
            guard context.authorizationRequesterVerified, let before = context.authorizationBefore,
                  let requested = context.authorizationRequestedAt, requested < context.observedAt else { throw refuse(.authorizationRequester, .authorizationRequest) }
            newPrompts = Set(windows.filter { $0.kind == .authorization }.map(\.id)).subtracting(before)
            guard newPrompts.count == 1 else { throw refuse(.authorizationAmbiguous, .authorizationWindow) }
        }
        let result = Validated(fingerprint: .init(display: display, rect: rect, windows: windows.sorted { $0.id < $1.id }, owners: owners), allowed: selected.id, authorizationNew: newPrompts)
        try result.requireSelection([selected.id])
        return result
    }
}
#endif
