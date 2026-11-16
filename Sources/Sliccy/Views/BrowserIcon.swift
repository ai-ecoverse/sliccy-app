import AppKit
import SwiftUI

/// Uses the installed application's artwork, without persisting a copy in the session.
struct BrowserIcon: View {
    let bundleID: String?
    var fallback = "globe"
    var size: CGFloat = 20

    var body: some View {
        Group {
            if let bundleID, let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                    .resizable().scaledToFit()
            } else {
                Image(systemName: fallback).resizable().scaledToFit().foregroundStyle(.secondary)
                    .padding(size * 0.12)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
