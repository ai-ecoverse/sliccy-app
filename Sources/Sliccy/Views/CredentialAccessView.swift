import SwiftUI

struct CredentialAccessView: View {
    let store: WorkspaceStore
    let session: Session
    private var access: CredentialAccess { store.credentialAccess[session.id] ?? .init() }
    private var connected: Bool { session.connection == .connected }
    private var canOffer: Bool { connected && access.ops.contains("status") && store.leaseSupported.contains(session.id) && !store.credentialOffers.contains(session.id) }
    private var canSwitch: Bool {
        connected && !access.busy && (canOffer || access.ops.contains(access.sealing == true ? "seal-off" : "seal-on"))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "key.horizontal").foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Allow new credentials").font(.callout).fontWeight(.medium)
                    Text(canOffer ? "Enables the Mac broker · Reconnects this instance" : "Turning off keeps existing leases")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("Allow new credentials", isOn: Binding(
                    get: { access.sealing == true },
                    set: { store.setCredentialSealing($0, for: session.id) }
                )).labelsHidden().toggleStyle(.switch).controlSize(.small).disabled(!canSwitch)
            }
            if canOffer {
                Text("Allows seven to request this Mac’s credentials through the broker. Vault rules and recipient scopes are not reported here.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Divider()
            HStack {
                Text(access.complete ? "Issued leases" : "Observed leases · List may be incomplete").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if access.busy { ProgressView().controlSize(.mini) }
                Button { store.refreshCredentials(session.id) } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless).help("Refresh credential leases")
                    .disabled(!connected || access.busy)
            }
            if access.leases.isEmpty {
                Text(access.complete ? "No live leases reported" : "No leases reported")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(access.leases) { lease in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(lease.provider).font(.callout).fontWeight(.medium)
                        Text(lease.leaseId).font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                        if let expiry = lease.expiry {
                            Text("Expires \(expiry.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption).foregroundStyle(.secondary)
                        } else { Text("Expiry not reported").font(.caption).foregroundStyle(.secondary) }
                    }
                    Spacer()
                    Toggle("Lease for \(lease.provider)", isOn: Binding(
                        get: { true },
                        set: { if !$0 { store.revokeCredential(lease.leaseId, for: session.id) } }
                    )).labelsHidden().toggleStyle(.switch).controlSize(.small)
                        .help("Turn off to ask the broker to revoke this lease. This may take 75 seconds.")
                        .disabled(!connected || access.busy || !access.ops.contains("unseal"))
                }.padding(.vertical, 3)
            }
            if let message = access.message {
                Text(message).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if connected, !access.ops.contains("leases"), !access.busy {
                Text(store.credentialOffers.contains(session.id) ? "The Mac broker is unavailable. Install a compatible slicc-jerk on this Mac, then reconnect." : "Credential leasing is not offered by this process.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Process-local metadata only. Seven’s vault inventory is not reported; a refreshed list may briefly include a concurrently revoked lease.")
                .font(.caption2).foregroundStyle(.secondary)
        }.padding(.vertical, 10)
    }
}
