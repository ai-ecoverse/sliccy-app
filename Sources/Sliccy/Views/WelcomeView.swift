import SwiftUI

struct WelcomeView: View {
    let store: WorkspaceStore
    @State private var browser: LocalBrowserChoice = .chrome
    @State private var profile = "six"
    var body: some View {
        VStack(alignment: .leading, spacing: 28) {
            Image(systemName: "circle.hexagongrid.fill")
                .font(.system(size: 48, weight: .light)).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 10) {
                Text("Your browser. Ready for SLICC.").font(.largeTitle).fontWeight(.semibold)
                Text("Start a browser for your agent, then manage its access from here.")
                    .font(.title3).foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 18) {
                LocalBrowserPicker(browser: $browser, profile: $profile)
                Label("Keeps your existing SLICC tabs and sign-ins", systemImage: "arrow.trianglehead.clockwise")
                Label("You choose when to offer shell access or credentials", systemImage: "switch.2")
            }.font(.callout)
            HStack(spacing: 16) {
                Button { store.createLocalBrowser(name: "", browser: browser, profile: profile) } label: {
                    Label("Start SLICC in \(browser.name)", systemImage: "arrow.up.forward.app")
                }.buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(!browser.isInstalled || !LocalBrowserChoice.validProfile(profile))
                Button("Join an existing session…") { store.startNew(remote: true) }.buttonStyle(.link)
            }
            Text("Browser control and the network relay start enabled. Shell, SFTP, credentials and screen capture start off. Your browser stays open when you disconnect.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: 580, alignment: .leading)
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Welcome to Sliccy")
    }
}
