#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin
import Testing
@testable import Sliccy

struct ScreenRunnerDisplayDiagnosticsTests {
    typealias D = ScreenRunnerDisplayDiagnostics
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var delivered: [D.Delivery] = []
        private var failed = 0
        func append(_ value: D.Delivery) { lock.lock(); delivered.append(value); lock.unlock() }
        func fail() { lock.lock(); failed += 1; lock.unlock() }
        var values: [D.Delivery] { lock.lock(); defer { lock.unlock() }; return delivered }
        var losses: Int { lock.lock(); defer { lock.unlock() }; return failed }
    }
    static func display(_ id: UInt32? = 1) -> D.Display {
        .init(id: id, frame: CGRect(x: -100, y: 0, width: 1024, height: 768),
            visibleFrame: CGRect(x: -100, y: 30, width: 1024, height: 738),
            cgBounds: CGRect(x: 0, y: 0, width: 1024, height: 768), scale: 2,
            color: .displayP3, colorModel: 1, colorComponents: 3, colorNameBytes: 12,
            mode: .init(id: 42, flags: 7, width: 1024, height: 768, pixelWidth: 2048, pixelHeight: 1536, refreshRate: 60))
    }
    @Test func actualNotificationAlwaysStopsBeforeObservationAndNeverDebounces() {
        let gate = ScreenOutputGate(), sink = Sink(), stopped = DispatchSemaphore(value: 0)
        let relay = ScreenStopRelay(gate: gate, cause: { reason, origin, _ in
            #expect(reason == .sourceChanged && origin == .displayChange)
        }, stop: { reason in #expect(reason == .sourceChanged); stopped.signal() })
        for _ in 0..<2 {
            relay.proofDisplayChange {
                #expect(gate.isInvalidated && stopped.wait(timeout: .now()) == .success, "display-stop-before-diagnostics")
                sink.fail()
            }
        }
        #expect(sink.losses == 2, "display-notification-not-suppressed")
    }
    @Test func startupBufferAndDelayedNotificationKeepSeparateActualTimes() throws {
        let start = ContinuousClock.now, recorder = D(began: start), sink = Sink()
        let startup = try #require(recorder.begin(.beforeActivationPolicy, at: start))
        recorder.complete(startup, started: start, status: .complete, reportedCount: 1, displays: [Self.display()], at: start.advanced(by: .milliseconds(1)))
        #expect(sink.values.isEmpty)
        recorder.install(output: { sink.append($0) }, loss: { sink.fail() })
        let ticket = try #require(recorder.begin(.notification, at: start.advanced(by: .milliseconds(2))))
        recorder.complete(ticket, started: start.advanced(by: .milliseconds(5)), status: .complete,
            reportedCount: 1, displays: [Self.display()], at: start.advanced(by: .milliseconds(6)))
        recorder.finish(at: start.advanced(by: .milliseconds(7)))
        let values = sink.values.compactMap { value -> D.Observation? in if case .observation(let observation) = value { observation } else { nil } }
        #expect(values.count == 2 && sink.losses == 0, "display-startup-buffer-delivered")
        guard values.count == 2 else { return }
        #expect(values[1].ticket.requested < values[1].started! && values[1].started! < values[1].finished, "display-delayed-sample-times")
        #expect(values[0].ticket.ordinal == 1 && values[1].ticket.ordinal == 2)
    }
    @Test func observationBoundsAndUnfinishedStatusCannotBecomeComplete() throws {
        let recorder = D(), sink = Sink()
        recorder.install(output: { sink.append($0) }, loss: { sink.fail() })
        for _ in 0..<D.maximumNotifications { #expect(recorder.begin(.notification) != nil) }
        #expect(recorder.begin(.notification) == nil && sink.losses == 1, "display-notification-cap")
        recorder.finish()
        let unfinished = sink.values.compactMap { value -> D.Observation? in if case .observation(let observation) = value { observation } else { nil } }
        #expect(unfinished.count == 16 && unfinished.allSatisfy { $0.status == .unfinished && $0.started == nil && $0.displays.isEmpty }, "display-unfinished-never-complete")
        #expect(recorder.begin(.preflight) == nil)
        let other = D(), otherSink = Sink()
        other.install(output: { otherSink.append($0) }, loss: { otherSink.fail() })
        let ticket = try #require(other.begin(.preflight))
        other.complete(ticket, started: .now, status: .complete, reportedCount: 9, displays: Array(repeating: Self.display(), count: 9))
        #expect(otherSink.losses == 1, "display-count-cap")
        other.finish()
        #expect(!other.shouldSample(ticket), "display-closed-does-not-query")
    }
    @Test func actualDisplayJournalRetainsModesGeometryAndTypedUnavailable() throws {
        var descriptors: [Int32] = [-1, -1]
        try #require(pipe(&descriptors) == 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        try #require(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
        let recorder = D(), journal = try ScreenRunnerJournal(.selectedWindow, descriptor: descriptors[1], authorityFailed: {})
        recorder.install(output: { recorder.deliver($0, to: journal) }, loss: { journal.rejectEvidence() })
        let ticket = try #require(recorder.begin(.preflight))
        recorder.complete(ticket, started: .now, status: .complete, reportedCount: 1, displays: [Self.display()])
        recorder.finish()
        var bytes = [UInt8](repeating: 0, count: 16384)
        let count = read(descriptors[0], &bytes, bytes.count)
        try #require(count > 0)
        let rows = try Data(bytes.prefix(count)).split(separator: 10).map { try JSONSerialization.jsonObject(with: Data($0)) as! [String: Any] }
        let row = try #require(rows.first { $0["stage"] as? String == "display-observation-screen" })
        let encodedMode = row["mode"] as? [String: Any]
        #expect(encodedMode != nil, "display-mode-encoded")
        guard let mode = encodedMode else { return }
        #expect(mode["pixelWidth"] as? Int == 2048 && mode["id"] as? Int == 42 && mode["refreshRate"] as? Double == 60, "display-mode-encoded")
        #expect(row["color"] as? String == "display-p3" && row["scale"] as? Double == 2, "display-color-scale-encoded")
        #expect(rows.count == 4 && !journal.failed)
        let invalid = D.Display(id: nil, frame: CGRect(x: CGFloat.infinity, y: 0, width: -1, height: -2), visibleFrame: .zero,
            cgBounds: nil, scale: .nan, color: .unavailable, colorModel: nil, colorComponents: nil, colorNameBytes: nil, mode: nil).fields
        #expect(invalid["displayID"] is NSNull && invalid["mode"] is NSNull && invalid["scale"] is NSNull)
        let frame = try #require(invalid["frame"] as? [String: Any])
        #expect(frame["x"] is NSNull && frame["width"] as? Double == -1 && frame["height"] as? Double == -2, "display-raw-dimensions")
        #expect(try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]).count <= 4096)
    }
}
#endif
