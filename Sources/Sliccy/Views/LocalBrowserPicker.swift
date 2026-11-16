import SwiftUI

struct LocalBrowserPicker: View {
    @Binding var browser: LocalBrowserChoice
    @Binding var profile: String
    @State private var selection = "default"
    @State private var customName = ""
    @State private var profiles: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("Browser", selection: $browser) {
                ForEach(LocalBrowserChoice.allCases) { choice in
                    Text(choice.name + (choice.isInstalled ? "" : " — not installed"))
                        .tag(choice).disabled(!choice.isInstalled)
                }
            }
            Picker("Profile", selection: $selection) {
                Text("Dedicated SLICC profile (default)").tag("default")
                ForEach(profiles.filter { $0 != browser.defaultProfile }, id: \.self) { name in
                    Text(name).tag("existing:" + name)
                }
                Text("New profile…").tag("new")
            }
            if selection == "new" {
                TextField("Profile name", text: $customName, prompt: Text("e.g. work"))
                if !customName.isEmpty && !LocalBrowserChoice.validProfile(customName) {
                    Text("Use 1–64 letters, digits, dots, hyphens or underscores; start with a letter or digit. No consecutive dots.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Text("SLICC profiles keep their tabs and sign-ins, separate from everyday browsing.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .pickerStyle(.menu)
        .onAppear { profiles = LocalBrowserChoice.profiles(); updateProfile() }
        .onChange(of: browser) { _, _ in selection = "default"; updateProfile() }
        .onChange(of: selection) { _, _ in updateProfile() }
        .onChange(of: customName) { _, _ in updateProfile() }
    }

    private func updateProfile() {
        if selection == "default" { profile = browser.defaultProfile }
        else if selection == "new" { profile = customName == "six" ? "" : customName }
        else { profile = String(selection.dropFirst("existing:".count)) }
    }
}
