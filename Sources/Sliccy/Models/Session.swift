import Foundation

enum Destination: String, CaseIterable, Identifiable {
    case browsers, folders
    var id: String { rawValue }
    var title: String { self == .browsers ? "Browsers & Apps" : "Shared Folders" }
    var symbol: String { self == .browsers ? "macwindow.on.rectangle" : "folder" }
}

enum ConnectionState: String, Codable, CaseIterable {
    case connected, connecting, reconnecting, disconnected
    var title: String { rawValue.capitalized }
    var symbol: String {
        switch self {
        case .connected: "circle.fill"
        case .connecting, .reconnecting: "arrow.trianglehead.2.clockwise.rotate.90"
        case .disconnected: "circle"
        }
    }
}

enum SessionKind: String, Codable, CaseIterable {
    case browser = "Separate browser", everyday = "Everyday browser", remote = "Remote session"
    var symbol: String {
        switch self {
        case .browser: "macwindow"
        case .everyday: "globe"
        case .remote: "desktopcomputer"
        }
    }
}

enum MessageRole: String, Codable { case user, assistant, tool, notice }

struct ActivityEntry: Identifiable, Codable, Equatable {
    var id = UUID()
    var role: MessageRole
    var text: String
    var date = Date()
    var sourceID: String?
}

struct FolderGrant: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String
    var path: String
    var readOnly = true
    var enabled: Bool?
    var isEnabled: Bool { enabled != false }
}

struct SessionAccess: Codable, Equatable {
    var browser: String?
    var preferredBrowser: String?
    var folders: [FolderGrant] = []
    var network = true
    var shell = false
    var sftp = false
}

struct Session: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String
    var device: String
    var kind: SessionKind
    var profile: String
    var connection: ConnectionState = .connected
    var isWorking = false
    var isFavorite = false
    var entries: [ActivityEntry] = []
    var access: SessionAccess
    var queuedPrompts: [String] = []
    var draft = ""
    var lastActivity = Date()
    // Optional additions preserve older demo workspaces. Join credentials are never Codable.
    var usesLiveRuntime: Bool?
    var management: InstanceManagement?
    var effectiveResources: CLIResources?
    var connectionMessage: String?
    var liveFeed: LiveFeed?
    var watchIdentity: String?
    var isLive: Bool { usesLiveRuntime == true }

    var summary: String { "\(device) · \(connection.title)" }
}

struct BrowserTarget: Identifiable {
    var id: String
    var name: String
    var bundleID: String
    var subtitle: String
    var symbol: String
    var canHost: Bool
}

enum DeliveryMode: String, CaseIterable, Identifiable {
    case followUp = "Follow-up", steer = "Steer"
    var id: String { rawValue }
}
