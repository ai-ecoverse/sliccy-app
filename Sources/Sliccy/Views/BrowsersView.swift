import AppKit
import SwiftUI

struct BrowsersView: View {
    let store: WorkspaceStore
    let search: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                PageHeading(title: "Browsers & Apps", subtitle: "A browser for every kind of work.")
                Text("Start seven in a separate browser profile, pair your everyday browser, or offer an app to an existing session.")
                    .font(.callout).foregroundStyle(.secondary)
                ForEach(DemoData.browsers.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) }) { browser in
                    HStack(spacing: 14) {
                        AppIcon(browser: browser)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(browser.name).font(.headline)
                            Text(browser.subtitle).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if browser.canHost {
                            Button("New Session…") { store.startNew(browser: browser.name) }.controlSize(.small)
                        } else {
                            Text("CLI integration pending").font(.caption2).foregroundStyle(.secondary)
                        }
                    }.padding(.vertical, 10)
                    Divider()
                }
                Label("Sample catalog. App icons are loaded locally when available; discovery is mocked.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(28)
        }.navigationTitle("Browsers & Apps")
    }
}

private struct AppIcon: View {
    let browser: BrowserTarget
    var body: some View {
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: browser.bundleID) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: url.path)).resizable().frame(width: 42, height: 42)
        } else {
            Image(systemName: browser.symbol).font(.title).foregroundStyle(.tint).frame(width: 42, height: 42)
        }
    }
}

struct PageHeading: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.largeTitle).fontWeight(.semibold)
            Text(subtitle).font(.title3).foregroundStyle(.secondary)
        }
    }
}
