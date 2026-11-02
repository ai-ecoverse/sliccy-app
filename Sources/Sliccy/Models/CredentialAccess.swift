import Foundation

/// Metadata for one owned CLI process. Never persisted or confused with vault inventory.
struct CredentialLease: Decodable, Equatable, Identifiable, Sendable {
    var provider: String
    var leaseId: String
    var expiresAt: String?
    var sealedAt: String?
    var id: String { leaseId }
    var expiry: Date? { expiresAt.flatMap { ISO8601DateFormatter().date(from: $0) } }
}

struct CredentialAccess: Equatable {
    var leases: [CredentialLease] = []
    var ops: Set<String> = []
    var sealing: Bool?
    var complete = false
    var busy = false
    var revision = 0
    var message: String?
    var releasedLeases: Set<String> = []

    mutating func replaceSnapshot(_ leases: [CredentialLease], sealing: Bool) {
        // v1.56 can briefly list a lease after a concurrent unseal (#601).
        self.leases = leases.filter { !releasedLeases.contains($0.leaseId) }
        self.sealing = sealing
        complete = true
    }

    mutating func released(_ leaseID: String, upstream: Bool?) {
        releasedLeases.insert(leaseID)
        leases.removeAll { $0.leaseId == leaseID }
        message = Self.revocationMessage(upstream: upstream)
    }

    mutating func apply(_ event: CLIEvent) {
        guard event.schema == 1, event.event == "credential",
              let provider = event.provider, let leaseID = event.leaseId,
              ["seal", "unseal", "revoked"].contains(event.op),
              ["seven", "host"].contains(event.by) else { return }
        revision += 1
        if event.op == "seal" {
            releasedLeases.remove(leaseID)
            leases.removeAll { $0.leaseId == leaseID }
            leases.append(.init(provider: provider, leaseId: leaseID, expiresAt: event.expiresAt))
        } else {
            released(leaseID, upstream: event.upstream)
        }
    }

    static func revocationMessage(upstream: Bool?) -> String {
        switch upstream {
        case true: "The broker confirmed provider revocation. Seven has not confirmed removal from its vault."
        case false: "Lease released by the broker. The provider credential remains valid until expiry; seven has not confirmed removal."
        case nil: "Lease released by the broker. Provider revocation and removal from seven are unconfirmed."
        }
    }
}
