import Foundation

enum ScreenFailure: String, Error, LocalizedError, Sendable {
    case incompatible, protection, permission, indicator, shortcut, audit
    case peerUntrusted = "peer-untrusted", peerLost = "peer-lost", linkLost = "link-lost"
    case leaseExpired = "lease-expired", sourceChanged = "source-changed"
    case stopped, stalled, resourceLimit = "resource-limit"
    var errorDescription: String? {
        switch self {
        case .peerUntrusted: "Screen sharing requires an approved signed app and bundled CLI."
        case .protection: "This source’s protected surfaces cannot be safely excluded."
        case .permission: "Allow Screen Recording for Sliccy to share a selected source."
        default: "Screen sharing stopped (\(rawValue))."
        }
    }
}
