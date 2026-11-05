#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerInventoryDiagnostics: @unchecked Sendable {
    enum Site: String, Sendable { case initial, refresh, monitor, authorizationBaseline = "authorization-baseline" }
    enum Branch: String, Sendable {
        case operation, host, permission, surfaceRole = "surface-role", browserCount = "browser-count"
        case shareableContent = "shareable-content", mainDisplay = "main-display", cgList = "cg-list", cgFields = "cg-fields"
        case sckOwner = "sck-owner", ownerIdentifier = "owner-identifier", ownerRole = "owner-role", ownerVerification = "owner-verification"
        case requester, ownedVerification = "owned-verification", display, context, windowIDs = "window-ids", ownerPIDs = "owner-pids"
        case ownerFields = "owner-fields", surfaceIdentity = "surface-identity", appIdentity = "app-identity", browserIdentity = "browser-identity"
        case windowServer = "windowserver", ownerClass = "owner-class", completeness, geometryPair = "geometry-pair", pidPair = "pid-pair"
        case bundlePair = "bundle-pair", geometry, duplicateGeometry = "duplicate-geometry", allowed, appWindow = "app-window"
        case browserWindow = "browser-window", authorizationRequest = "authorization-request", authorizationWindow = "authorization-window"
        case allowedLookup = "allowed-lookup"
    }
    enum Check: String, Sendable {
        case operation, present, count, pid, parent, effectiveUID = "effective-uid", realUID = "real-uid", savedUID = "saved-uid"
        case verified, startSeconds = "start-seconds", startMicroseconds = "start-microseconds", identifier, absolutePath = "absolute-path", hashLength = "hash-length"
        case sysctlBound = "sysctl-bound", appleAnchor = "apple-anchor", unique, nonzero, rect, layer, cgPID = "cg-pid", sckPID = "sck-pid"
        case bundle, finite, positiveSize = "positive-size", cgPresence = "cg-presence", sckPresence = "sck-presence", requester, baseline, requestedAt = "requested-at"
    }
    struct SCKFact: Sendable {
        let id: UInt32, pid: pid_t?, bundle: String?, rect: CGRect, layer: Int
        init(id: UInt32, pid: pid_t?, bundle: String?, rect: CGRect, layer: Int) {
            self.id = id; self.pid = pid; self.bundle = bundle; self.rect = rect; self.layer = layer
        }
        init(_ value: ScreenRunnerInventoryBoundary.SCKRecord) {
            self.init(id: value.id, pid: value.pid, bundle: value.bundle, rect: value.rect, layer: value.layer)
        }
    }
    struct Notice: Sendable {
        let attempt: Int, site: Site, issue: ScreenRunnerInventoryIssue, branch: Branch, comparison: Check
        let pid: pid_t?, windowID: UInt32?, signingIdentifier: String?
        let cg: [ScreenRunnerInventoryBoundary.CGRecord], sck: [SCKFact]
        let owner: ScreenRunnerInventoryBoundary.Identity?
        let at: ContinuousClock.Instant
        var fields: [String: Any] {
            ["attempt": attempt, "site": site.rawValue, "issue": issue.rawValue, "branch": branch.rawValue,
             "comparison": comparison.rawValue, "pid": pid.map { $0 as Any } ?? NSNull(),
             "windowID": windowID.map { $0 as Any } ?? NSNull(), "signingIdentifier": Self.identifier(signingIdentifier),
             "signingIdentifierSource": signingIdentifier == nil ? "unavailable" : owner?.verified == true && owner?.identifier == signingIdentifier ? "verified" : "tentative",
             "owner": owner.map { Self.ownerFields($0) as Any } ?? NSNull(),
             "cgCount": cg.count, "sckCount": sck.count,
             "cg": cg.prefix(2).map { ["windowID": $0.id, "pid": $0.pid, "layer": $0.layer, "rect": Self.rect($0.rect)] as [String: Any] },
             "sck": sck.prefix(2).map { ["windowID": $0.id, "pid": $0.pid.map { $0 as Any } ?? NSNull(),
                 "ownerPresent": $0.pid != nil, "bundle": Self.identifier($0.bundle), "layer": $0.layer, "rect": Self.rect($0.rect)] as [String: Any] }]
        }
        static func ownerFields(_ value: ScreenRunnerInventoryBoundary.Identity) -> [String: Any] {
            ["pid": value.pid, "parent": value.parent, "effectiveUID": value.uid,
             "realUID": value.realUID.map { $0 as Any } ?? NSNull(), "savedUID": value.savedUID.map { $0 as Any } ?? NSNull(),
             "startSeconds": value.seconds, "startMicroseconds": value.microseconds, "verified": value.verified,
             "appleAnchored": value.appleAnchored, "sysctlBound": value.sysctlBound, "hashBytes": value.hash.count]
        }
        static func identifier(_ value: String?) -> [String: Any] {
            guard let value else { return ["status": "unavailable", "value": NSNull(), "bytes": NSNull()] }
            let bytes = value.utf8
            let allowed = bytes.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 46 }
            let labels = value.split(separator: ".", omittingEmptySubsequences: false)
            let valid = !bytes.isEmpty && bytes.count <= 255 && allowed && labels.count >= 2 && labels.allSatisfy { !$0.isEmpty && $0.first != "-" && $0.last != "-" }
            return ["status": valid ? "present" : "invalid-identifier", "value": valid ? value as Any : NSNull(), "bytes": bytes.count]
        }
        static func rect(_ value: CGRect) -> [String: Any] {
            func number(_ x: CGFloat) -> Any { x.isFinite ? Double(x) as Any : NSNull() }
            return ["x": number(value.origin.x), "y": number(value.origin.y), "width": number(value.width), "height": number(value.height)]
        }
    }
    final class Attempt: @unchecked Sendable {
        private let lock = NSLock()
        private var reported = false
        let ordinal: Int, site: Site
        private let output: @Sendable (Notice) -> Void
        init(ordinal: Int, site: Site, output: @escaping @Sendable (Notice) -> Void) {
            self.ordinal = ordinal; self.site = site; self.output = output
        }
        @discardableResult
        func reject(_ issue: ScreenRunnerInventoryIssue, _ branch: Branch, pid: pid_t? = nil, windowID: UInt32? = nil,
                    signingIdentifier: String? = nil, cg: [ScreenRunnerInventoryBoundary.CGRecord] = [], sck: [SCKFact] = [],
                    owner: ScreenRunnerInventoryBoundary.Identity? = nil, checks: [(Check, Bool)] = []) -> ScreenRunnerInventoryIssue {
            let at = ContinuousClock.now
            lock.lock(); let first = !reported; reported = true; lock.unlock()
            if first {
                output(.init(attempt: ordinal, site: site, issue: issue, branch: branch,
                    comparison: checks.first(where: { !$0.1 })?.0 ?? .operation, pid: pid, windowID: windowID,
                    signingIdentifier: signingIdentifier, cg: cg, sck: sck, owner: owner, at: at))
            }
            return issue
        }
        func observe<T>(_ branch: Branch, pid: pid_t? = nil, signingIdentifier: String? = nil,
                        cg: [ScreenRunnerInventoryBoundary.CGRecord] = [], sck: [SCKFact] = [],
                        operation: () throws -> T) throws -> T {
            do { return try operation() }
            catch {
                reject(error as? ScreenRunnerInventoryIssue ?? .unknown, branch, pid: pid,
                    signingIdentifier: signingIdentifier, cg: cg, sck: sck)
                throw error
            }
        }
    }
    private let lock = NSLock()
    private var ordinal = 0
    private let output: @Sendable (Notice) -> Void
    init(output: @escaping @Sendable (Notice) -> Void) { self.output = output }
    func begin(_ site: Site) -> Attempt {
        lock.lock(); ordinal += 1; let next = ordinal; lock.unlock()
        return .init(ordinal: next, site: site, output: output)
    }
}
#endif
