import Foundation
import Testing
@testable import Sliccy

struct LocalAccessTests {
    private func linked(_ caps: [String], _ policy: String) throws -> CLIEvent {
        try JSONDecoder().decode(CLIEvent.self, from: JSONSerialization.data(withJSONObject: ["schema": 1, "event": "linked", "caps": caps, "policy": policy]))
    }

    @Test func localStatusRequiresReportedCapabilitiesAndRecognizedPolicy() throws {
        let browser = CLIResources.Browser(id: "chrome", name: "Google Chrome", role: "seven", owned: false)
        let access = LocalAccessOptions(network: false, shell: true, sftp: true)
        let actual = try #require(access.resources(from: linked(["cdp", "net", "ssh", "jerk", "jerk-seal"], LocalAccessOptions.localPolicy), browser: browser))
        // Requested off must not override a live report that still allows network.
        #expect(actual.network.exit)
        #expect(actual.access.browser == "Google Chrome")
        #expect(actual.compute.ssh && actual.compute.sftp)
        #expect(actual.jerk?.seal == true)
        let blocked = try #require(access.resources(from: linked(["net"], LocalAccessOptions.blockedPolicy), browser: browser))
        #expect(!blocked.network.exit)
        #expect(blocked.browsers.isEmpty)
        #expect(!blocked.compute.ssh && !blocked.compute.sftp)
        #expect(access.resources(from: try linked(["net"], "future policy"), browser: browser) == nil)
    }

    @Test func networkOffCoversDefaultRoutesAndSpecificLocalAllows() {
        let invocation = CLIInvocation.localBrowser(profile: "six", access: .init(network: false))
        #expect(invocation.arguments.contains("--no-kernel"))
        let deny = invocation.arguments[invocation.arguments.firstIndex(of: "--deny")! + 1]
        #expect(Set(deny.split(separator: ",").map(String.init)) == Set(["0.0.0.0/0", "::/0", "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]))
        #expect(!invocation.arguments.contains("--allow"))
        #expect(!invocation.arguments.contains("--runner"))
    }

    @Test func shellAndSftpAreIndependentExplicitStartupOptions() {
        let shell = CLIInvocation.localBrowser(profile: "six", access: .init(shell: true))
        #expect(Array(shell.arguments.suffix(5)) == ["--no-sftp", "--runner", "/bin/zsh", "-c", "--"])
        #expect(shell.arguments.contains("--no-jerk"))
        let sftp = CLIInvocation.localBrowser(profile: "six", access: .init(shell: true, sftp: true), offerCredentials: true)
        #expect(sftp.arguments.contains("--sftp"))
        #expect(!sftp.arguments.contains("--no-sftp"))
        #expect(!sftp.arguments.contains("--no-jerk"))
        #expect(!sftp.arguments.contains("--jerk-seal")) // Follow-only flag is invalid for local launches.
        #expect(sftp.arguments.contains("--keep-browsers"))
    }

    @Test func browserActivationSelectsExactPageAndRejectsAmbiguity() throws {
        let page = "https://www.sliccy.ai/7/"
        func data(_ targets: [[String: String]]) throws -> Data { try JSONSerialization.data(withJSONObject: targets) }
        let target = ["id": "ABC-123", "type": "page", "url": page]
        let chosen = try BrowserTabClient.target(in: data([target, ["id": "other", "type": "page", "url": "https://example.com"]]), matching: page)
        #expect(chosen.id == "ABC-123")
        #expect(try BrowserTabClient.target(in: data([["id": "OS-1", "type": "page", "url": "https://www.sliccy.ai/os/"]]), matching: "https://www.sliccy.ai").id == "OS-1")
        #expect(try BrowserTabClient.target(in: data([target]), matching: "https://www.sliccy.ai").id == "ABC-123")
        #expect(throws: (any Error).self) { try BrowserTabClient.target(in: data([target, target]), matching: page) }
        #expect(throws: (any Error).self) { try BrowserTabClient.target(in: data([]), matching: page) }
        #expect(!BrowserTabClient.isSLICCTab("https://www.sliccy.ai.evil.invalid/7/"))
        #expect(!BrowserTabClient.isSLICCTab("https://www.sliccy.ai/blog"))
        #expect(throws: (any Error).self) { try BrowserTabClient.endpointURL("http://example.com:9222") }
        #expect(throws: (any Error).self) { try BrowserTabClient.endpointURL("http://user@localhost:9222") }
        #expect(throws: (any Error).self) { try BrowserTabClient.endpointURL("http://localhost:9222/redirect") }
        #expect(try BrowserTabClient.endpointURL("http://127.0.0.1:9222").port == 9222)
    }
}
