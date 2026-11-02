import SwiftUI

struct NewSessionView: View {
    let store: WorkspaceStore
    @Environment(\.dismiss) private var dismiss
    @State private var live = false
    @State private var name = ""
    @State private var kind = SessionKind.browser
    @State private var browser = "Google Chrome"
    @State private var profile = "Default"
    @State private var joinURL = ""

    private var valid: Bool {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        if kind == .remote { return validJoinURL }
        return kind != .browser || !profile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    private var validJoinURL: Bool {
        guard let url = URL(string: joinURL.trimmingCharacters(in: .whitespacesAndNewlines)) else { return false }
        return url.scheme == "https" && url.host != nil && url.user == nil && url.password == nil && !joinURL.contains("\n")
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "A new connection", subtitle: "Give seven a place to work with your Mac.", symbol: "circle.hexagongrid")
            Form {
                Toggle("Connect to a real remote session", isOn: $live)
                    .onChange(of: live) { _, enabled in if enabled { kind = .remote } }
                TextField("Session name", text: $name, prompt: Text("e.g. Design review"))
                Picker("Connect using", selection: $kind) {
                    ForEach(live ? [.remote] : SessionKind.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                if kind == .browser {
                    Picker("Browser", selection: $browser) {
                        Text("Google Chrome").tag("Google Chrome")
                        Text("Microsoft Edge").tag("Microsoft Edge")
                    }
                    TextField("Profile", text: $profile)
                    Text("A separate profile keeps this session apart from everyday browsing. Seven can control this browser.")
                        .font(.caption).foregroundStyle(.secondary)
                } else if kind == .everyday {
                    Label("Pair in your default browser", systemImage: "safari")
                    Text("Pairing connects seven to your Mac without enabling browser automation.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    SecureField("Join URL", text: $joinURL, prompt: Text("https://…"))
                    Text(live ? "The join URL stays in memory for this app session. You’ll enter it again after relaunching Sliccy." : "Use an HTTPS join URL. In this preview it is discarded after creating the session; it is never saved or opened.")
                        .font(.caption).foregroundStyle(.secondary)
                    if !joinURL.isEmpty && !validJoinURL {
                        Text("Enter a valid HTTPS URL without a username or password.").font(.caption).foregroundStyle(.red)
                    }
                }
                Section {
                    Label(live ? "Live remote connection" : "Demo mode", systemImage: live ? "network" : "flask").fontWeight(.medium)
                    Text(live ? "Connects this instance to Sliccy without offering Mac resources. You can enable credential leasing from the access view. Agent inventory appears when seven supports it." : "You’ll get a simulated connection to explore the interface. No browser is launched and nothing is shared.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }.formStyle(.grouped)
            Divider()
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(live ? "Connect to seven" : "Create Demo Session") {
                    if live { store.createLive(name: name, join: joinURL) }
                    else { _ = store.create(name: name, kind: kind, browser: browser, profile: profile) }
                    joinURL = ""
                    dismiss()
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!valid)
            }.padding(20)
        }
        .frame(width: 510, height: 600)
        .onAppear {
            if ProcessInfo.processInfo.arguments.contains("--show-live-setup") { live = true; kind = .remote; name = "Remote workspace" }
            if let preferred = store.newSessionBrowser {
                if preferred == "Safari" { kind = .everyday }
                else { browser = preferred }
            }
        }
    }
}

struct SheetHeader: View {
    let title: String
    let subtitle: String
    let symbol: String
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol).font(.system(size: 28, weight: .light)).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.title2).fontWeight(.semibold)
                Text(subtitle).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }.padding(24)
    }
}

struct ReconnectView: View {
    let store: WorkspaceStore
    let id: UUID
    @State private var join = ""
    @Environment(\.dismiss) private var dismiss
    private var valid: Bool {
        guard let url = URL(string: join.trimmingCharacters(in: .whitespacesAndNewlines)) else { return false }
        return url.scheme == "https" && url.host != nil && url.user == nil && url.password == nil && !join.contains("\n")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Reconnect to seven").font(.title2).fontWeight(.semibold)
            Text("Enter the join URL again. Sliccy keeps it in memory only.").foregroundStyle(.secondary)
            SecureField("Join URL", text: $join)
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Connect") { store.supplyCredential(join, for: id); join = ""; dismiss() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!valid)
            }
        }.padding(24).frame(width: 460)
    }
}
