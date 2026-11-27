import Foundation

// This is a display projection, not a grant. Nothing here is persisted or used to
// match navigation. The broker owns URL authorization and the exclusive deadline.
struct BrowserLeaseRule: Decodable, Hashable, Sendable {
    enum Kind: String, Decodable {
        case origin, exact, prefix = "path-prefix"

        var label: String {
            switch self {
            case .origin: "Origin (all paths)"
            case .exact: "Exact URL (including query and fragment)"
            case .prefix: "Path prefix (including descendants)"
            }
        }
    }
    let kind: Kind
    let url: String

    /// Never fix up, elide or decode a rule as part of asking for consent. Show
    /// the ASCII URL the broker supplied, or refuse this version of the offer.
    var reviewable: Bool {
        guard url.utf8.count <= 2048, url.utf8.allSatisfy({ (33...126).contains($0) }),
              !url.contains("\\"), !url.contains("*"), url.hasPrefix("https://"),
              let u = URLComponents(string: url, encodingInvalidCharacters: false),
              u.scheme == "https", let host = u.percentEncodedHost, !host.isEmpty,
              !host.contains("%"), host == host.lowercased(), u.user == nil, u.password == nil,
              u.port.map({ (1...65535).contains($0) && $0 != 443 }) ?? true else { return false }
        let origin = "https://" + host + (u.port.map { ":\($0)" } ?? "")
        if kind == .origin { return url == origin }
        // Exact URLs can legitimately include a query or hash route. Refuse
        // common credential-bearing forms instead of redacting (and reviewing a
        // different URL). The broker must never put secrets in this projection.
        guard let decoded = url.removingPercentEncoding,
              decoded.range(of: #"(?i)[?&#](?:access_token|refresh_token|id_token|token|jwt|password|client_secret)="#,
                            options: .regularExpression) == nil,
              decoded.range(of: #"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#,
                            options: .regularExpression) == nil else { return false }
        let path = u.percentEncodedPath
        guard path.hasPrefix("/"), !path.lowercased().contains("%2f"), !path.lowercased().contains("%5c"),
              !path.components(separatedBy: "/").contains(where: { [".", ".."].contains($0.removingPercentEncoding) }) else { return false }
        let suffix = (u.percentEncodedQuery.map { "?" + $0 } ?? "") + (u.percentEncodedFragment.map { "#" + $0 } ?? "")
        guard url == origin + path + suffix else { return false }
        return kind == .exact || (suffix.isEmpty && (path == "/" || !path.hasSuffix("/")))
    }
}

struct PendingBrowserLease: Decodable, Equatable, Identifiable, Sendable {
    let request: String
    let jkt: String
    let browser: String
    let link: String
    let allow: [BrowserLeaseRule] // for expansion, additions only
    let ttlSeconds: Int?
    let parent: String?
    var id: String { request }

    enum CodingKeys: CodingKey { case request, jkt, browser, link, allow, ttlSeconds, parent }
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // No nulls, contradictory time changes, or silently inferred defaults.
        guard c.contains(.parent) != c.contains(.ttlSeconds) else { throw CLIControlError.invalid }
        parent = c.contains(.parent) ? try c.decode(String.self, forKey: .parent) : nil
        ttlSeconds = c.contains(.ttlSeconds) ? try c.decode(Int.self, forKey: .ttlSeconds) : nil
        request = try c.decode(String.self, forKey: .request)
        jkt = try c.decode(String.self, forKey: .jkt)
        browser = try c.decode(String.self, forKey: .browser)
        link = try c.decode(String.self, forKey: .link)
        allow = try c.decode([BrowserLeaseRule].self, forKey: .allow)
    }
}

struct ActiveBrowserLease: Decodable, Equatable, Identifiable, Sendable {
    let lease: String
    let jkt: String
    let browser: String
    let link: String
    let allow: [BrowserLeaseRule]
    let exp: Int64 // Unix seconds, exclusive
    var id: String { lease }
    var deadline: Date { Date(timeIntervalSince1970: Double(exp)) }
}

// Decode only the metadata this surface understands. In particular, don't route
// these replies through the credential leases list or Seven's event stream.
struct BrowserLeaseReply: OwnedCLIControlReply {
    var v: Int
    var pid: Int32?
    var ok: Bool?
    var error: String?
    var ops: [String]?
    var offers: [String]?
    var pending: [PendingBrowserLease]?
    var active: [ActiveBrowserLease]?
}

struct BrowserLeaseSnapshot: Equatable, Sendable {
    let pending: [PendingBrowserLease]
    let active: [ActiveBrowserLease]

    init(_ reply: BrowserLeaseReply, route: BrowserLeaseRoute) throws {
        guard reply.v == 1, reply.ok == true, let pending = reply.pending, let active = reply.active,
              pending.count <= 128, active.count <= 128,
              Set(pending.map(\.id)).count == pending.count, Set(active.map(\.id)).count == active.count,
              active.allSatisfy({ $0.browser == route.endpoint && $0.link == route.label &&
                  Self.valid($0.lease, $0.jkt, $0.allow) &&
                  (1...253402300799).contains($0.exp) }),
              pending.allSatisfy({ $0.browser == route.endpoint && $0.link == route.label &&
                  Self.valid($0.request, $0.jkt, $0.allow) &&
                  ($0.parent.map(Self.identifier) ?? true) &&
                  ($0.parent != nil ? $0.ttlSeconds == nil : ($0.ttlSeconds.map { (1...31_536_000).contains($0) } ?? false)) })
        else { throw CLIControlError.invalid }
        self.pending = pending
        self.active = active
    }

    private static func identifier(_ value: String) -> Bool {
        (1...128).contains(value.utf8.count) && value.utf8.allSatisfy {
            alphanumeric($0) || $0 == 45 || $0 == 95 // no compact JWTs, links or controls
        }
    }

    private static func alphanumeric(_ b: UInt8) -> Bool {
        (65...90).contains(b) || (97...122).contains(b) || (48...57).contains(b)
    }

    private static func valid(_ id: String, _ jkt: String, _ rules: [BrowserLeaseRule]) -> Bool {
        guard identifier(id), jkt.utf8.count == 43, identifier(jkt),
              (1...32).contains(rules.count), Set(rules).count == rules.count, rules.allSatisfy(\.reviewable) else { return false }
        // A canonical unpadded 32-byte SHA-256 thumbprint has two zero padding bits.
        return "AEIMQUYcgkosw048".utf8.contains(jkt.utf8.last!)
    }

    func parent(of item: PendingBrowserLease) -> ActiveBrowserLease? {
        guard let parent = item.parent else { return nil }
        return active.first { $0.id == parent && $0.jkt == item.jkt && $0.browser == item.browser && $0.link == item.link }
    }

    func permits(_ action: BrowserLeaseDecision, at now: Date) -> Bool {
        switch action {
        case .deny(let item): return pending.contains(item)
        case .revoke(let item): return active.contains(item) && now < item.deadline
        case .approve(let item, let reviewedParent):
            guard pending.contains(item) else { return false }
            if item.parent == nil { return reviewedParent == nil && item.ttlSeconds != nil }
            guard let parent = parent(of: item), parent == reviewedParent, now < parent.deadline else { return false }
            return Set(parent.allow).isDisjoint(with: item.allow)
        }
    }
}

/// Carry the whole reviewed projection, not just an ID. An expansion cannot be
/// approved against a different holder, tab binding, parent scope or deadline.
enum BrowserLeaseDecision: Equatable, Sendable {
    case approve(PendingBrowserLease, parent: ActiveBrowserLease?)
    case deny(PendingBrowserLease)
    case revoke(ActiveBrowserLease)

    var command: CLIControlRequest {
        switch self {
        case .approve(let item, _): .init(op: "cdp-lease-approve", request: item.id)
        case .deny(let item): .init(op: "cdp-lease-deny", request: item.id)
        case .revoke(let item): .init(op: "cdp-lease-revoke", lease: item.id)
        }
    }
}
