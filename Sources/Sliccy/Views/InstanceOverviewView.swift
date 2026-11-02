import SwiftUI

struct InstanceOverviewView: View {
    let store: WorkspaceStore
    let session: Session
    @State private var window = "Browser · Website preview"
    private let fullScreen = "Full screen · All apps"
    private var snapshot: InstanceManagement? { session.managementSnapshot }
    private var connected: Bool { session.connection == .connected }
    private var agents: [InstanceManagement.Agent] { connected ? snapshot?.agents ?? [] : [] }
    private var editable: Bool { !session.isLive }
    private var screen: String? { snapshot?.screenTarget }
    private var windowEnabled: Bool { screen != nil && screen != fullScreen }

    var body: some View {
        GeometryReader { geometry in
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                TimelineView(.periodic(from: .now, by: 5)) { context in
                HStack {
                    Label(agentSummary(at: context.date), systemImage: "circle.hexagongrid")
                    Text("·").foregroundStyle(.tertiary)
                    Text(modelSummary(at: context.date))
                    Spacer()
                    Text(editable ? "Demo switches" : "Live access")
                        .font(.caption).foregroundStyle(.secondary)
                }.font(.callout)
                }
                if geometry.size.width >= 760 {
                    HStack(alignment: .top, spacing: 20) {
                        deviceColumn.frame(minWidth: 340, maxWidth: .infinity)
                        accessColumn.frame(minWidth: 340, maxWidth: .infinity)
                    }
                } else {
                    VStack(alignment: .leading, spacing: 20) { deviceColumn; accessColumn }
                }
                agentsSection
            }.padding(24)
        }
        }
    }

    private var deviceColumn: some View {
        VStack(alignment: .leading, spacing: 18) {
            section("This Mac") {
                entitlement("Browser control", detail: session.access.browser ?? session.access.preferredBrowser ?? "Separate browser", symbol: "macwindow", value: session.access.browser != nil, kind: .browser)
                Divider()
                entitlement("Network", detail: session.kind == .remote ? "Public internet" : "This Mac, local network & internet", symbol: "network", value: session.access.network, kind: .network)
                Divider()
                entitlement("Shell execution", detail: "Commands run as your Mac user", symbol: "terminal", value: session.access.shell, kind: .shell)
                Divider()
                entitlement("SFTP", detail: "File transfer · Also enables shell access", symbol: "arrow.up.arrow.down", value: session.access.sftp, kind: .sftp)
            }
            section("Screen access") {
                switchRow("Full screen", detail: "All eligible apps · View only", symbol: "display", binding: Binding(
                    get: { screen == fullScreen },
                    set: { store.setDemoScreen($0 ? fullScreen : nil, for: session.id) }
                ), enabled: editable && connected)
                Divider()
                switchRow("Selected window", detail: "One window · View only", symbol: "macwindow", binding: Binding(
                    get: { windowEnabled },
                    set: { store.setDemoScreen($0 ? window : nil, for: session.id) }
                ), enabled: editable && connected)
                if windowEnabled {
                    Picker("Window", selection: $window) {
                        Text("Browser · Website preview").tag("Browser · Website preview")
                        Text("Xcode · Project window").tag("Xcode · Project window")
                    }.controlSize(.small).padding(.bottom, 10)
                        .onChange(of: window) { _, value in store.setDemoScreen(value, for: session.id) }
                }
            }
            Text(editable ? "Screen switches are simulated; nothing is captured. Choose full screen or one window." : "Screen sharing is unavailable in this development build.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var accessColumn: some View {
        VStack(alignment: .leading, spacing: 18) {
            section("Keys & credentials") {
                if session.isLive {
                    CredentialAccessView(store: store, session: session)
                } else if let snapshot {
                    ForEach(snapshot.credentials) { credential in
                        switchRow(credential.provider, detail: "\(credential.name) · \(credential.scope)", symbol: "key.horizontal", binding: Binding(
                            get: { credential.enabled },
                            set: { store.setDemoCredential(credential.id, enabled: $0, for: session.id) }
                        ), enabled: editable)
                        .help("\(credential.source) · \(credential.delivery)")
                        if credential.id != snapshot.credentials.last?.id { Divider() }
                    }
                } else {
                    Text("Credential inventory not reported").font(.callout).padding(.vertical, 12)
                    if let broker = session.effectiveResources?.jerk {
                        LabeledContent("Mac broker", value: broker.offered ? "Available" : "Not offered").font(.caption)
                        LabeledContent("Credential leasing", value: broker.seal ? "Enabled" : "Not offered").font(.caption).padding(.bottom, 12)
                    }
                }
            }
            section("Folders") {
                if session.access.folders.isEmpty {
                    Text("No folders added").font(.callout).foregroundStyle(.secondary).padding(.vertical, 12)
                }
                ForEach(session.access.folders) { folder in
                    switchRow(folder.name, detail: folder.path, symbol: "folder", binding: Binding(
                        get: { folder.isEnabled },
                        set: { store.setDemoFolder(folder.id, enabled: $0, for: session.id) }
                    ), enabled: editable)
                    switchRow("Allow changes", detail: folder.readOnly ? "Read only" : "Read & write", symbol: "pencil", binding: Binding(
                        get: { !folder.readOnly },
                        set: { store.setDemoFolder(folder.id, readOnly: !$0, for: session.id) }
                    ), enabled: editable && folder.isEnabled)
                    if folder.id != session.access.folders.last?.id { Divider() }
                }
                Button {
                    FolderPicker.choose { url in if let url { store.addDemoFolder(url, for: session.id) } }
                } label: { Label("Add Folder…", systemImage: "plus") }
                    .buttonStyle(.borderless).padding(.vertical, 10).disabled(!editable)
            }
            Text(editable ? "Changes apply immediately to the demo. No real permissions or credentials change." : "Credential controls apply to this CLI process. Other resource grants are read-only.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var agentsSection: some View {
        section("Agents & models") {
            if session.isLive {
                AgentInventoryView(store: store, session: session)
            } else if snapshot == nil {
                Text("Agent inventory is not reported by this runtime yet.")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 12)
            } else if agents.isEmpty {
                Text("Instance disconnected").font(.callout).foregroundStyle(.secondary).padding(.vertical, 12)
            } else {
                ForEach(agents) { agent in
                    HStack(spacing: 10) {
                        Circle().fill(agent.running ? Color.green : Color.secondary.opacity(0.4)).frame(width: 6, height: 6)
                        Text(agent.name)
                        Spacer()
                        Text(agent.model).foregroundStyle(.secondary)
                        Text(agent.running ? "Running" : "Idle").font(.caption).foregroundStyle(.secondary).frame(width: 52, alignment: .trailing)
                    }.font(.callout).padding(.vertical, 8)
                    if agent.id != agents.last?.id { Divider() }
                }
            }
        }
    }

    private func agentSummary(at now: Date) -> String {
        guard session.isLive else { return session.runningAgentCount.map { "\($0) running agents" } ?? "Agents not reported" }
        guard let inventory = store.inventories[session.id], inventory.isFresh(at: now), let running = inventory.counts["running"] else { return "Agents not reported live" }
        return "\(running) running agents"
    }

    private func modelSummary(at now: Date) -> String {
        guard session.isLive else { return "\(Set(agents.filter(\.running).map(\.model)).count) models in use" }
        guard let inventory = store.inventories[session.id], inventory.isFresh(at: now) else { return "Models not reported live" }
        let models = Set(inventory.agents.filter { $0.status == "running" }.compactMap { agent in
            agent.model.map { (agent.provider ?? "") + "/" + $0 }
        })
        if inventory.agents.contains(where: { $0.status == "running" && $0.model == nil }) {
            return models.isEmpty ? "Models not reported" : "Models partly reported (\(models.count))"
        }
        return "\(models.count) models reported in use"
    }

    private func entitlement(_ title: String, detail: String, symbol: String, value: Bool, kind: WorkspaceStore.Entitlement) -> some View {
        switchRow(title, detail: session.isLive && session.effectiveResources == nil ? "Not reported" : detail, symbol: symbol,
                  binding: Binding(get: { value }, set: { store.setDemoEntitlement(kind, enabled: $0, for: session.id) }), enabled: editable)
    }
    private func switchRow(_ title: String, detail: String, symbol: String, binding: Binding<Bool>, enabled: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.callout).fontWeight(.medium)
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Toggle(title, isOn: binding).labelsHidden().toggleStyle(.switch).controlSize(.small).disabled(!enabled)
        }.padding(.vertical, 9)
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.headline)
            GroupBox { VStack(alignment: .leading, spacing: 0, content: content).padding(.horizontal, 8).frame(maxWidth: .infinity, alignment: .leading) }
        }
    }
}
