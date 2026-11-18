import Foundation
import Observation
import Security

/// Key/value transport for iCloud sync. iCloud in the app; memory in tests.
@MainActor
protocol KeyValueSyncBackend: AnyObject {
    func data(forKey key: String) -> Data?
    func setData(_ data: Data?, forKey key: String)
    func keys(withPrefix prefix: String) -> [String]
    @discardableResult func synchronize() -> Bool
    /// Posted when another device changed the store.
    var externalChange: (name: Notification.Name, object: AnyObject?)? { get }
}

@MainActor
final class UbiquitousKeyValueBackend: KeyValueSyncBackend {
    private let store: NSUbiquitousKeyValueStore
    init(store: NSUbiquitousKeyValueStore = .default) { self.store = store }
    func data(forKey key: String) -> Data? { store.data(forKey: key) }
    func setData(_ data: Data?, forKey key: String) {
        if let data { store.set(data, forKey: key) } else { store.removeObject(forKey: key) }
    }
    func keys(withPrefix prefix: String) -> [String] { store.dictionaryRepresentation.keys.filter { $0.hasPrefix(prefix) } }
    @discardableResult func synchronize() -> Bool { store.synchronize() }
    var externalChange: (name: Notification.Name, object: AnyObject?)? {
        (NSUbiquitousKeyValueStore.didChangeExternallyNotification, store)
    }
}

@MainActor
final class InMemoryKeyValueBackend: KeyValueSyncBackend {
    var storage: [String: Data] = [:]
    func data(forKey key: String) -> Data? { storage[key] }
    func setData(_ data: Data?, forKey key: String) { storage[key] = data }
    func keys(withPrefix prefix: String) -> [String] { storage.keys.filter { $0.hasPrefix(prefix) } }
    @discardableResult func synchronize() -> Bool { true }
    var externalChange: (name: Notification.Name, object: AnyObject?)? { nil }
}

/// A join URL known to this iCloud account, from Sliccy, Sliccstart or the iOS follower.
struct ICloudJoin: Identifiable, Equatable, Sendable {
    /// SHA-256 hex of the join URL, the same identity as `Session.watchIdentity`.
    var id: String
    /// Carries the session secret. Never shown or logged; `displayHost` is.
    var joinUrl: String
    var label: String
    var deviceId: String
    var deviceName: String
    var lastSeen: Date
    /// Advertised now by a running leader (Sliccstart's tray sessions), not only history.
    var live: Bool

    var displayHost: String {
        guard let components = URLComponents(string: joinUrl), let host = components.host else { return "" }
        return components.port.map { "\(host):\($0)" } ?? host
    }
}

/// The record of a join URL that connected, in the format of slicc's `RecentJoinStore`
/// (`packages/swift-traysession`), so Sliccstart and the iOS follower read Sliccy's
/// entries and Sliccy reads theirs.
struct RecentJoinRecord: Codable, Equatable {
    var id: String
    var joinUrl: String
    var label: String
    var deviceId: String
    var deviceName: String
    var firstConnectedAt: Date
    var lastConnectedAt: Date
}

/// A live leader advertised by Sliccstart (`TraySessionSyncStore`). Read only.
struct TraySessionRecord: Decodable {
    var id: String
    var joinUrl: String
    var label: String
    var deviceId: String?
    var deviceName: String
    var lastSeenAt: Date
}

/// Join URLs synced through iCloud key-value storage, shared with slicc's Apple apps.
///
/// It uses the same container (`S8LB56P782.ai.sliccy.trays`), key prefixes, per-device
/// keys and limits as `RecentJoinStore`: each device writes only
/// `recentJoins.v1.<deviceId>`, keeps its five newest entries for 30 days, and
/// reads every device's key. Sliccy records a join URL only after it linked, so a typo
/// never reaches other devices. Without the iCloud entitlement this is not created at
/// all, so secrets are never written to the unsynced local fallback store.
@MainActor @Observable
final class ICloudJoinSync {
    static let recentPrefix = "recentJoins.v1."
    static let trayPrefix = "traySessions.v2."
    static let deviceIdKey = "traySyncDeviceId"
    static let containerEntitlement = "com.apple.developer.ubiquity-kvstore-identifier"
    static let recentTTL: TimeInterval = 30 * 24 * 60 * 60
    static let trayTTL: TimeInterval = 12 * 60 * 60
    static let maxOwn = 5
    static let maxPooled = 20

    /// Merged entries from every device, newest first.
    private(set) var joins: [ICloudJoin] = []
    @ObservationIgnored let deviceId: String
    @ObservationIgnored let deviceName: String
    @ObservationIgnored private let backend: KeyValueSyncBackend
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private var observer: NSObjectProtocol?
    private var ownKey: String { Self.recentPrefix + deviceId }

    init(backend: KeyValueSyncBackend, deviceId: String, deviceName: String, clock: @escaping () -> Date = Date.init) {
        self.backend = backend
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.clock = clock
        if let external = backend.externalChange {
            observer = NotificationCenter.default.addObserver(forName: external.name, object: external.object, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.reload() }
            }
        }
        backend.synchronize()
        reload()
    }

    /// The app's iCloud store, when this build is signed with the key-value entitlement.
    static func app(defaults: UserDefaults = .standard) -> ICloudJoinSync? {
        guard entitled else { return nil }
        return ICloudJoinSync(backend: UbiquitousKeyValueBackend(), deviceId: deviceId(defaults: defaults),
                              deviceName: Host.current().localizedName ?? "Mac")
    }

    static var entitled: Bool {
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(task, containerEntitlement as CFString, nil) else { return false }
        return (value as? String)?.isEmpty == false
    }

    static func deviceId(defaults: UserDefaults) -> String {
        if let existing = defaults.string(forKey: deviceIdKey), !existing.isEmpty { return existing }
        let fresh = UUID().uuidString
        defaults.set(fresh, forKey: deviceIdKey)
        return fresh
    }

    func reload() {
        let now = clock()
        var merged: [String: ICloudJoin] = [:]
        func keep(_ join: ICloudJoin) {
            if let existing = merged[join.id] {
                var winner = join.lastSeen > existing.lastSeen ? join : existing
                winner.live = join.live || existing.live
                if winner.label.isEmpty { winner.label = join.label.isEmpty ? existing.label : join.label }
                merged[join.id] = winner
            } else { merged[join.id] = join }
        }
        for key in backend.keys(withPrefix: Self.recentPrefix) {
            for record in decode([RecentJoinRecord].self, key) where Self.valid(record.id, record.joinUrl)
                && now.timeIntervalSince(record.lastConnectedAt) <= Self.recentTTL {
                keep(.init(id: record.id, joinUrl: record.joinUrl, label: record.label, deviceId: record.deviceId,
                           deviceName: record.deviceName, lastSeen: record.lastConnectedAt, live: false))
            }
        }
        for key in backend.keys(withPrefix: Self.trayPrefix) {
            for record in decode([TraySessionRecord].self, key) where Self.valid(record.id, record.joinUrl)
                && now.timeIntervalSince(record.lastSeenAt) <= Self.trayTTL {
                keep(.init(id: record.id, joinUrl: record.joinUrl, label: record.label, deviceId: record.deviceId ?? "",
                           deviceName: record.deviceName, lastSeen: record.lastSeenAt, live: true))
            }
        }
        joins = Array(merged.values.sorted { $0.lastSeen != $1.lastSeen ? $0.lastSeen > $1.lastSeen : $0.id < $1.id }.prefix(Self.maxPooled))
    }

    func joinURL(identity: String) -> String? { joins.first { $0.id == identity }?.joinUrl }

    /// Remembers a join URL that just linked. Writes only this device's key.
    func record(joinURL: String, label: String) {
        let url = joinURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !url.isEmpty else { return }
        let now = clock()
        let id = Session.joinIdentity(url)
        var own = decode([RecentJoinRecord].self, ownKey)
        let existing = own.first { $0.id == id }
        own.removeAll { $0.id == id }
        own.append(.init(id: id, joinUrl: url, label: label.isEmpty ? existing?.label ?? "" : label, deviceId: deviceId,
                         deviceName: deviceName, firstConnectedAt: existing?.firstConnectedAt ?? now, lastConnectedAt: now))
        persistOwn(own, now: now)
    }

    /// Drops an entry from this device's key. Copies other devices wrote stay.
    func forget(identity: String) {
        persistOwn(decode([RecentJoinRecord].self, ownKey).filter { $0.id != identity }, now: clock())
    }

    private func persistOwn(_ list: [RecentJoinRecord], now: Date) {
        let kept = list.filter { now.timeIntervalSince($0.lastConnectedAt) <= Self.recentTTL }
            .sorted { $0.lastConnectedAt > $1.lastConnectedAt }.prefix(Self.maxOwn)
        if kept.isEmpty { backend.setData(nil, forKey: ownKey) }
        else if let data = try? JSONEncoder().encode(Array(kept)) { backend.setData(data, forKey: ownKey) }
        backend.synchronize()
        reload()
    }

    private func decode<T: Decodable>(_ type: [T].Type, _ key: String) -> [T] {
        guard let data = backend.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode(type, from: data)) ?? []
    }

    /// Accepts only HTTPS join URLs without credentials whose id matches, as the
    /// join URL fields do; anything else another device wrote is ignored.
    private static func valid(_ id: String, _ joinUrl: String) -> Bool {
        guard let url = URL(string: joinUrl), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, !joinUrl.contains("\n") else { return false }
        return Session.joinIdentity(joinUrl) == id
    }
}
