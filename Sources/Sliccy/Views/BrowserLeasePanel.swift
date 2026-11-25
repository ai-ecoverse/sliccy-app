import SwiftUI

/// The containing local session is the owner's browser/profile selection. Never
/// start an ordinary follow or use a peer-supplied browser as a substitute.
struct BrowserLeasePanel: View {
    let store: WorkspaceStore
    let session: Session
    @State private var setup = false
    @State private var linkLabel = ""
    @State private var join = ""

    private var browserLabel: String { "\(session.localBrowserChoice.name) / \(session.localBrowserProfile ?? session.profile)" }
    private var canOpen: Bool {
        guard store.canStartBrowserLeaseLink(session.id), let endpoint = store.localBrowserEndpoints[session.id],
              let route = BrowserLeaseRoute(endpoint: endpoint, label: linkLabel) else { return false }
        return route.invocation(join: join) != nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let link = store.browserLeaseLinks[session.id] {
                Text(verbatim: "Selected: \(browserLabel) · \(link.route.label)").font(.headline)
                if let control = link.control {
                    BrowserLeasesView(control: control, selectedBrowser: browserLabel)
                } else { Text(link.message).font(.callout) }
                Button("Close lease-only link") { store.stopBrowserLeaseControl(session.id) }
            } else if store.canStartBrowserLeaseLink(session.id) {
                Text(verbatim: "Selected browser: \(browserLabel)")
                Button("Open lease-only link…") { setup = true }
            } else {
                Label("Browser leases unavailable", systemImage: "lock")
                Text(BrowserLeaseControl.verifiedForRelease
                        ? "Requires a compatible CLI, a connected browser launched by Sliccy, and a dedicated lease-only link."
                        : "This build cannot grant browser leases. Updating the CLI or enabling ordinary browser control does not turn them on.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }.padding(.vertical, 12)
        .sheet(isPresented: $setup, onDismiss: { join = ""; linkLabel = "" }) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Connect a lease-only link").font(.title2.bold())
                Text(verbatim: "Use \(browserLabel). No task tab opens until you approve a specific job.")
                TextField("Local link label", text: $linkLabel, prompt: Text("ledger-job"))
                Text("Use the paired link’s local label: letters, numbers, hyphens or underscores.").font(.caption)
                SecureField("Job’s dedicated tray join URL", text: $join)
                Text("In the requester’s Seven, choose Network → Link a device. Use only that job’s dedicated tray. The broker must already trust the verified peer fingerprint under this local link label. Sliccy does not pair devices or save this join URL.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button("Cancel") { setup = false }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Connect for review") {
                        store.startBrowserLeaseLink(session.id, label: linkLabel, join: join)
                        setup = false
                    }.disabled(!canOpen)
                }
            }.padding(24).frame(width: 460)
        }
    }
}
