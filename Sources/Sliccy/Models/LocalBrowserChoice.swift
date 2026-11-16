import AppKit
import Foundation

/// Browser identifiers supported by the bundled CLI's Chromium launcher.
enum LocalBrowserChoice: String, Codable, CaseIterable, Identifiable {
    case chrome, edge, brave, chromium
    var id: String { rawValue }
    var name: String {
        switch self {
        case .chrome: "Chrome"
        case .edge: "Microsoft Edge"
        case .brave: "Brave"
        case .chromium: "Chromium"
        }
    }
    var bundleID: String {
        switch self {
        case .chrome: "com.google.Chrome"
        case .edge: "com.microsoft.edgemac"
        case .brave: "com.brave.Browser"
        case .chromium: "org.chromium.Chromium"
        }
    }
    @MainActor var isInstalled: Bool { NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) != nil }
    // Preserve the existing SLICC Chrome profile and its sign-ins.
    var defaultProfile: String { self == .chrome ? "six" : rawValue }

    static func validProfile(_ name: String) -> Bool {
        name.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil && !name.contains("..")
    }

    static func profiles(in directory: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/slicc/seven-profiles")) -> [String] {
        let entries = (try? FileManager.default.contentsOfDirectory(at: directory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])) ?? []
        return entries.filter {
            let facts = try? $0.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            return facts?.isDirectory == true && facts?.isSymbolicLink != true &&
                validProfile($0.lastPathComponent) && $0.lastPathComponent != "six"
        }.map(\.lastPathComponent).sorted()
    }
}

extension Session {
    var localBrowserChoice: LocalBrowserChoice { localBrowser ?? .chrome }
}
