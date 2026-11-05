import Foundation
import CoreGraphics
import Darwin

enum ScreenFailure: Error { case protection, incompatible, resourceLimit, stalled }
enum ScreenRunnerInventoryIssue: String, Error {
    case permission, surfaceIdentity = "surface-identity", browserIdentity = "browser-identity"
    case shareableContent = "shareable-content", displayGeometry = "display-geometry", cgInventory = "cg-inventory"
    case ownerAttribution = "owner-attribution", completeness, surfaceGeometry = "surface-geometry"
    case browserWindowCount = "browser-window-count", windowIdentity = "window-identity", appWindows = "app-windows"
    case authorizationRequester = "authorization-requester", authorizationMissing = "authorization-missing"
    case authorizationAmbiguous = "authorization-ambiguous", authorizationIdentity = "authorization-identity"
    case sourceChanged = "source-changed", unclassifiedOwner = "unclassified-owner", unknown
}

@main struct Build16Fixture {
    static func main() throws {
        var pipeFD: [Int32] = [0, 0]
        guard pipe(&pipeFD) == 0 else { exit(2) }
        defer { close(pipeFD[0]); close(pipeFD[1]) }
        guard fcntl(pipeFD[0], F_SETFL, O_NONBLOCK) == 0 else { exit(2) }
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: pipeFD[1], authorityFailed: { exit(3) })
        func drain() {
            var buffer = [UInt8](repeating: 0, count: 32768)
            while true {
                let count = read(pipeFD[0], &buffer, buffer.count)
                if count < 0 { guard errno == EAGAIN else { exit(4) }; return }
                guard count > 0 else { exit(4) }
                FileHandle.standardOutput.write(Data(buffer.prefix(count)))
            }
        }
        typealias B = ScreenRunnerInventoryBoundary
        let surface = CGRect(x: 128, y: 128, width: 256, height: 256)
        let app = CGRect(x: 64, y: 512, width: 320, height: 128)
        var cg: [B.CGRecord] = [.init(id: 1, pid: 10, rect: app, layer: 0), .init(id: 2, pid: 11, rect: surface, layer: 0)]
        var sck: [B.SCKRecord] = [.init(id: 1, pid: 10, bundle: "ai.sliccy.mac", rect: app, layer: 0), .init(id: 2, pid: 11, bundle: "ai.sliccy.proof-helper", rect: surface, layer: 0)]
        for index in 0..<64 {
            let id = UInt32.max - UInt32(63 - index)
            let rect = CGRect(x: CGFloat(index), y: 0, width: 1024, height: 768)
            cg.append(.init(id: id, pid: 42, rect: rect, layer: -2147483626))
            sck.append(.init(id: id, pid: 42, bundle: "", rect: rect, layer: -2147483626))
        }
        let checked = try B.validate(display: 1, rect: CGRect(x: 0, y: 0, width: 1024, height: 768), cg: cg, sck: sck,
            context: .init(app: 10, surface: 11, browsers: [:], selected: .selectedWindow)) { pid in
                .init(pid: pid, parent: 1, uid: pid == 42 ? 88 : 501, seconds: UInt64.max, microseconds: 999999,
                      identifier: pid == 42 ? "com.apple.WindowServer" : pid == 10 ? "ai.sliccy.mac" : "ai.sliccy.proof-helper",
                      path: "/fixture", hash: Data(repeating: 1, count: 20), appleAnchored: pid == 42, verified: true,
                      sysctlBound: pid == 42, realUID: pid == 42 ? 0 : 501, savedUID: pid == 42 ? 0 : 501)
            }
        guard let witness = checked.windowServerEmptyBundle else { exit(5) }
        journal.emit("protected-structural-refused", ScreenRunnerStructuralRefusal(witness: witness, windowID: nil).fields); drain()
        for pair in witness.pairs {
            journal.emit("protected-structural-refused", ScreenRunnerStructuralRefusal(witness: witness, windowID: pair.sck.id).fields); drain()
        }
        let began = ContinuousClock.now.advanced(by: .seconds(-1))
        let recorder = ScreenRunnerDisplayDiagnostics(began: began)
        recorder.install(output: { recorder.deliver($0, to: journal) }, loss: { exit(6) }); drain()
        let screens = (0..<8).map { index in
            ScreenRunnerDisplayDiagnostics.Display(id: index == 0 ? nil : UInt32.max - UInt32(index),
                frame: CGRect(x: CGFloat.infinity, y: -1, width: -2, height: -3), visibleFrame: CGRect(x: -10, y: 0, width: 1024, height: 768),
                cgBounds: index == 0 ? nil : CGRect(x: 0, y: 0, width: 1024, height: 768), scale: 2.0000000000000004,
                color: .other, colorModel: Int32.min, colorComponents: Int.max, colorNameBytes: Int.max,
                mode: .init(id: Int32.min, flags: UInt32.max, width: Int.max, height: Int.max,
                            pixelWidth: Int.max, pixelHeight: Int.max, refreshRate: 59.94005994005994))
        }
        var tickets: [ScreenRunnerDisplayDiagnostics.Ticket] = []
        for trigger in ScreenRunnerDisplayDiagnostics.Trigger.allCases where trigger != .notification {
            guard let ticket = recorder.begin(trigger, at: began) else { exit(7) }; tickets.append(ticket)
        }
        for _ in 0..<16 { guard let ticket = recorder.begin(.notification, at: began) else { exit(7) }; tickets.append(ticket) }
        for ticket in tickets.reversed() {
            recorder.complete(ticket, started: began.advanced(by: .milliseconds(1)), status: .complete, reportedCount: 8,
                              displays: screens, at: began.advanced(by: .milliseconds(2))); drain()
        }
        recorder.finish(at: began.advanced(by: .milliseconds(3))); drain()
        guard !journal.failed else { exit(8) }
    }
}
