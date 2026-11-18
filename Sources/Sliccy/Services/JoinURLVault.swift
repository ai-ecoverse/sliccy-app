import Foundation
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
        let status = SecItemUpdate(query(session) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        guard status == errSecItemNotFound else { return }
        var item = query(session)
        item[kSecValueData as String] = data
        item[kSecAttrLabel as String] = "Sliccy join URL"
        SecItemAdd(item as CFDictionary, nil)
    }

    func delete(_ session: UUID) {
        SecItemDelete(query(session) as CFDictionary)
    }
}

@MainActor
final class MemoryJoinURLVault: JoinURLVault {
    var items: [UUID: String] = [:]
    func read(_ session: UUID) -> String? { items[session] }
    func write(_ joinURL: String, for session: UUID) { items[session] = joinURL }
    func delete(_ session: UUID) { items[session] = nil }
}
