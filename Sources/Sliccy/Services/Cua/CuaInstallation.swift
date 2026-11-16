import Foundation

/// External installations only. Never loads a Cua library into Sliccy or starts a direct runtime.
struct CuaInstallation: Identifiable, Equatable, Sendable {
    let app: URL
    let name: String
    let executable: URL
    let arguments: [String]
    var id: String { app.path }

    static func discover(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [Self] {
        [home.appending(path: "Applications"), URL(fileURLWithPath: "/Applications")].flatMap { directory in
            ["Cua Spaces.app", "CuaDriver.app"].compactMap { name in
                inspect(app: directory.appending(path: name), home: home)
            }
        }
    }

    static func inspect(app: URL, home: URL) -> Self? {
        guard let data = try? Data(contentsOf: app.appending(path: "Contents/Info.plist")),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        let id = info["CFBundleIdentifier"] as? String
        if app.lastPathComponent == "Cua Spaces.app", id == "com.trycua.spaces.macos" {
            // Stable Spaces' public MCP wiring. A nonstandard channel/home needs explicit support.
            guard (info["CuaChannel"] as? String ?? "stable") == "stable",
                  (info["CuaHome"] as? String ?? "~/.cua") == "~/.cua" else { return nil }
            let binary = app.appending(path: "Contents/Helpers/cua-driver")
            guard FileManager.default.isExecutableFile(atPath: binary.path) else { return nil }
            return .init(app: app, name: "Cua Spaces", executable: binary,
                         arguments: ["mcp", "--embedded", "--socket", home.appending(path: ".cua/run/cua-driver.sock").path,
                                     "--host-bundle-id", "com.trycua.spaces.macos"])
        }
        if app.lastPathComponent == "CuaDriver.app", id == "com.trycua.driver" {
            let binary = app.appending(path: "Contents/MacOS/cua-driver")
            guard FileManager.default.isExecutableFile(atPath: binary.path) else { return nil }
            return .init(app: app, name: "Cua Driver", executable: binary, arguments: ["mcp"])
        }
        return nil
    }
}

enum CuaError: LocalizedError, Equatable {
    case unavailable, protocolFailure, timeout, stopped, busy
    var errorDescription: String? {
        switch self {
        case .unavailable: "Open Cua and finish its driver and permission setup, then try again."
        case .protocolFailure: "Cua returned an unsupported or oversized MCP response. Computer access has stopped."
        case .timeout: "Cua did not respond in time. Computer access has stopped; an action may already have run."
        case .stopped: "Computer access is off."
        case .busy: "Too many computer requests are pending. Try again after the current action finishes."
        }
    }
}
