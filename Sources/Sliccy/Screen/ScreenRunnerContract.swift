#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import CoreGraphics

enum ScreenRunnerCase: String, CaseIterable, Sendable {
    case selectedWindow = "selected-window", displayExclusion = "display-exclusion"
    case authorizationExclusion = "authorization-exclusion", reciprocalRevoke = "reciprocal-revoke"
    case activeStop = "active-stop", hotkeyStop = "hotkey-stop"
    var needsBrowser: Bool { self == .displayExclusion || self == .authorizationExclusion }
    var scope: String { needsBrowser ? "display" : "window" }
}

enum ScreenRunnerHost {
    static let assertions = ["GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ai-ecoverse/sliccy-app",
        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/proof/runner-capture-v1",
        "SLICCY_RUNNER_ENVIRONMENT": "github-hosted"]
    static func validate(arguments: [String], environment: [String: String], major: Int, arm: Bool) throws -> ScreenRunnerCase {
        guard arm, major == 27, arguments.count == 3, arguments[0] == "--screen-runner-proof", arguments[1] == "--case",
              let selected = ScreenRunnerCase(rawValue: arguments[2]),
              assertions.allSatisfy({ environment[$0.key] == $0.value }) else { throw ScreenFailure.incompatible }
        return selected
    }
    static func require() throws -> ScreenRunnerCase {
#if arch(arm64)
        let arm = true
#else
        let arm = false
#endif
        return try validate(arguments: Array(CommandLine.arguments.dropFirst()), environment: ProcessInfo.processInfo.environment,
                            major: ProcessInfo.processInfo.operatingSystemVersion.majorVersion, arm: arm)
    }
}

enum ScreenRunnerBrowserWindow: String, CaseIterable, Sendable {
    case a1 = "host-a-1", a2 = "host-a-2", b1 = "host-b-1", b2 = "host-b-2"
    var profile: String { self == .a1 || self == .a2 ? "a" : "b" }
    var title: String {
        switch self { case .a1: "Sliccy proof host A1"; case .a2: "Sliccy proof host A2"
        case .b1: "Sliccy proof host B1"; case .b2: "Sliccy proof host B2" }
    }
    var rect: CGRect {
        switch self {
        case .a1: CGRect(x: 416, y: 64, width: 288, height: 224)
        case .a2: CGRect(x: 720, y: 64, width: 288, height: 224)
        case .b1: CGRect(x: 416, y: 320, width: 288, height: 224)
        case .b2: CGRect(x: 720, y: 320, width: 288, height: 224)
        }
    }
    func page(join: String) throws -> URL {
        guard let input = URLComponents(string: join), input.scheme == "http", input.host == "127.0.0.1",
              let port = input.port, (1024...65535).contains(port), !(9222...9229).contains(port),
              input.user == nil, input.password == nil, !join.contains("\n"), !join.contains("\r"), join.utf8.count <= 4096 else { throw ScreenFailure.incompatible }
        var output = URLComponents()
        output.scheme = "http"; output.host = "127.0.0.1"; output.port = port
        output.path = "/screen-proof/" + rawValue
        guard let result = output.url else { throw ScreenFailure.incompatible }
        return result
    }
}
#endif
