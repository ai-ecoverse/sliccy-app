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
    static func validate(display: UInt32, rect: CGRect, cg: [CGRecord], sck: [SCKRecord], context: Context,
                         verify: (pid_t) throws -> Identity) throws -> Validated {
        guard display != 0, rect.origin == .zero, rect.width >= 1024, rect.height >= 768,
              max(rect.width, rect.height) <= 2560, rect.width * rect.height <= 4_000_000,
              !cg.isEmpty, cg.count <= 512, sck.count <= 512 else { throw ScreenRunnerInventoryIssue.displayGeometry }
        guard context.app > 0, context.surface > 0, context.app != context.surface,
              context.browsers.count == (context.selected.needsBrowser ? 4 : 0),
              Set(context.browsers.values).count == context.browsers.count,
              context.browsers.values.allSatisfy({ $0 > 0 && $0 != context.app && $0 != context.surface }) else { throw ScreenRunnerInventoryIssue.ownerAttribution }
        let cgIDs = cg.map(\.id), sckIDs = sck.map(\.id)
        guard !cgIDs.contains(0), !sckIDs.contains(0), Set(cgIDs).count == cgIDs.count,
              Set(sckIDs).count == sckIDs.count else { throw ScreenRunnerInventoryIssue.completeness }
        let pids = Set(cg.map(\.pid)).union(sck.map(\.pid))
        guard pids.allSatisfy({ $0 > 0 }), pids.count <= 128 else { throw ScreenRunnerInventoryIssue.ownerAttribution }
        var owners: [Identity] = [], windows: [Window] = []
        for pid in pids.sorted() {
            let owner = try verify(pid)
            guard owner.pid == pid, owner.verified, owner.seconds > 0, owner.microseconds < 1_000_000,
                  !owner.identifier.isEmpty, owner.path.hasPrefix("/"), owner.hash.count == 20 else { throw ScreenRunnerInventoryIssue.ownerAttribution }
            let kind: Kind
            if pid == context.surface {
                guard owner.identifier == "ai.sliccy.proof-helper" else { throw ScreenRunnerInventoryIssue.surfaceIdentity }
                kind = .allowed
            } else if pid == context.app {
                guard owner.identifier == "ai.sliccy.mac" else { throw ScreenRunnerInventoryIssue.appWindows }
                kind = .app
            } else if let layout = context.browsers.first(where: { $0.value == pid })?.key {
                guard owner.identifier == "com.google.Chrome" else { throw ScreenRunnerInventoryIssue.browserIdentity }
                kind = Kind(rawValue: "chrome-" + layout.profile)!
            } else if owner.identifier == "com.apple.SecurityAgent", owner.appleAnchored {
                kind = .authorization
            } else if systemRoles.contains(owner.identifier), owner.appleAnchored {
                guard owner.identifier != "com.apple.WindowServer" || (owner.sysctlBound && owner.parent == 1 && owner.uid == 88 && owner.realUID == 0 && owner.savedUID == 0) else { throw ScreenRunnerInventoryIssue.ownerAttribution }
                kind = .system
            } else { throw ScreenRunnerInventoryIssue.unclassifiedOwner }
            owners.append(owner)
            let c = cg.filter { $0.pid == pid }, s = sck.filter { $0.pid == pid }
            if kind != .system, Set(c.map(\.id)) != Set(s.map(\.id)) { throw ScreenRunnerInventoryIssue.completeness }
            for id in Set(c.map(\.id)).union(s.map(\.id)).sorted() {
                let left = c.first { $0.id == id }, right = s.first { $0.id == id }
                if let left, let right {
                    guard left.rect == right.rect, left.layer == right.layer else { throw ScreenRunnerInventoryIssue.ownerAttribution }
                }
                guard !cg.contains(where: { $0.id == id && $0.pid != pid }), !sck.contains(where: { $0.id == id && $0.pid != pid }) else { throw ScreenRunnerInventoryIssue.ownerAttribution }
                if let right, right.bundle != owner.identifier { throw ScreenRunnerInventoryIssue.ownerAttribution }
                let frame = left?.rect ?? right!.rect, layer = left?.layer ?? right!.layer
                guard frame.origin.x.isFinite, frame.origin.y.isFinite, frame.width.isFinite, frame.height.isFinite,
                      frame.width > 0, frame.height > 0 else { throw ScreenRunnerInventoryIssue.windowIdentity }
                guard !windows.contains(where: { $0.pid == pid && $0.rect == frame }) else { throw ScreenRunnerInventoryIssue.windowIdentity }
                windows.append(.init(id: id, pid: pid, bundle: owner.identifier, rect: frame, layer: layer, kind: kind, inCG: left != nil, inSCK: right != nil))
            }
        }
        let allowed = windows.filter { $0.kind == .allowed }
        guard allowed.count == 1, let selected = allowed.first, selected.layer == 0,
              selected.rect == CGRect(x: 128, y: 128, width: 256, height: 256), selected.inCG, selected.inSCK else { throw ScreenRunnerInventoryIssue.surfaceGeometry }
        guard windows.contains(where: { $0.kind == .app }) else { throw ScreenRunnerInventoryIssue.appWindows }
        for (layout, pid) in context.browsers {
            let matches = windows.filter { $0.pid == pid }
            guard matches.count == 1, matches[0].rect == layout.rect, matches[0].layer == 0 else { throw ScreenRunnerInventoryIssue.browserWindowCount }
        }
        var newPrompts = Set<UInt32>()
        if context.selected == .authorizationExclusion {
            guard context.authorizationRequesterVerified, let before = context.authorizationBefore,
                  let requested = context.authorizationRequestedAt, requested < context.observedAt else { throw ScreenRunnerInventoryIssue.authorizationRequester }
            newPrompts = Set(windows.filter { $0.kind == .authorization }.map(\.id)).subtracting(before)
            guard newPrompts.count == 1 else { throw ScreenRunnerInventoryIssue.authorizationAmbiguous }
        }
        let result = Validated(fingerprint: .init(display: display, rect: rect, windows: windows.sorted { $0.id < $1.id }, owners: owners), allowed: selected.id, authorizationNew: newPrompts)
        try result.requireSelection([selected.id])
        return result
    }
}
#endif
