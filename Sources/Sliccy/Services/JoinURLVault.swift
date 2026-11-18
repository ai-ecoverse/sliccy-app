import Foundation
import OSLog
import Security

/// Where Sliccy keeps the join URL of each remote session between launches.
///
/// A join URL carries the session secret, so it lives in the keychain, never in
/// UserDefaults, argv or logs. Tests use `MemoryJoinURLVault` and never touch the
/// user's keychain.
@MainActor
protocol JoinURLVault: AnyObject {
    func read(_ session: UUID) -> String?
    func write(_ joinURL: String, for session: UUID)
    func delete(_ session: UUID)
}

/// Generic-password items in the login keychain, one per session.
/// Signed releases keep their access across updates because the item is bound to
/// the app's designated requirement, not its exact binary.
@MainActor
final class KeychainJoinURLVault: JoinURLVault {
    static let service = "ai.sliccy.mac.join-url"
    private let service: String

    init(service: String = KeychainJoinURLVault.service) { self.service = service }

    private func query(_ session: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: session.uuidString]
    }

    func read(_ session: UUID) -> String? {
        var query = query(session)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, let url = String(data: data, encoding: .utf8), !url.isEmpty else { return nil }
        return url
    }

    func write(_ joinURL: String, for session: UUID) {
        let data = Data(joinURL.utf8)
        var status = SecItemUpdate(query(session) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query(session)
            item[kSecValueData as String] = data
            item[kSecAttrLabel as String] = "Sliccy join URL"
            status = SecItemAdd(item as CFDictionary, nil)
        }
        // Only the status is logged, never the URL.
        if status != errSecSuccess { Self.log.error("Saving a join URL failed: OSStatus \(status, privacy: .public)") }
    }

    func delete(_ session: UUID) {
        let status = SecItemDelete(query(session) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            Self.log.error("Deleting a join URL failed: OSStatus \(status, privacy: .public)")
        }
    }

    private static let log = Logger(subsystem: "ai.sliccy.mac", category: "JoinURLs")
}

@MainActor
final class MemoryJoinURLVault: JoinURLVault {
    var items: [UUID: String] = [:]
    func read(_ session: UUID) -> String? { items[session] }
    func write(_ joinURL: String, for session: UUID) { items[session] = joinURL }
    func delete(_ session: UUID) { items[session] = nil }
}
