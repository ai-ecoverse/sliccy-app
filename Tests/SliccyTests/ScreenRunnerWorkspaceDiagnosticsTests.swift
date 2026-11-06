#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit
import Darwin
import Testing
@testable import Sliccy

struct ScreenRunnerWorkspaceDiagnosticsTests {
    @Test func actualWorkspaceCallbackStopsBeforeMissingPayloadEncoding() throws {
        var fd: [Int32] = [-1, -1]
        try #require(pipe(&fd) == 0)
        defer { close(fd[0]); close(fd[1]) }
        try #require(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0)
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: fd[1], authorityFailed: {})
        let readFD = fd[0]
        let gate = ScreenOutputGate()
        let relay = ScreenStopRelay(gate: gate, stop: { _ in
            #expect(gate.isInvalidated, "workspace-gate-first")
            var bytes = [UInt8](repeating: 0, count: 128)
            #expect(read(readFD, &bytes, bytes.count) == -1 && errno == EAGAIN, "workspace-stop-before-attribution")
        })
        relay.proofWorkspaceDiagnostics = ScreenRunnerWorkspaceDiagnostics(journal: journal)
        relay.proofWorkspaceChange(Notification(name: NSWorkspace.didLaunchApplicationNotification), origin: .workspaceLaunch)
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = read(fd[0], &bytes, bytes.count)
        try #require(count > 0)
        let row = try #require(try JSONSerialization.jsonObject(with: Data(bytes.prefix(count))) as? [String: Any])
        #expect(row["applicationStatus"] as? String == "missing-application" && row["pid"] is NSNull,
                "workspace-missing-payload-explicit")
        #expect(row["origin"] as? String == "workspace-launch")
    }
    @Test func workspaceProducerBoundsIdentifiersAndKeepsTimesDistinct() throws {
        let fields = ScreenRunnerLaunchDiagnostics.workspaceFields(sequence: 1, origin: .workspaceLaunch,
            beforeMS: 10, afterMS: 12, status: "present", pid: Int32.max, bundle: "com.google.Chrome")
        let row = try #require(fields["bundle"] as? [String: Any])
        #expect(row["value"] as? String == "com.google.Chrome", "workspace-identifier-retained")
        #expect(fields["stopCallBeforeMs"] as? Double == 10 && fields["stopCallAfterMs"] as? Double == 12,
                "workspace-stop-bracket-retained")
        let invalid = ScreenRunnerLaunchDiagnostics.workspaceFields(sequence: 64, origin: .workspaceTerminate,
            beforeMS: 10, afterMS: 12, status: "present", pid: 100, bundle: String(repeating: "x", count: 256))
        let bad = try #require(invalid["bundle"] as? [String: Any])
        #expect(bad["status"] as? String == "invalid-identifier" && bad["value"] is NSNull,
                "workspace-identifier-bounded")
        #expect(try JSONSerialization.data(withJSONObject: invalid).count < 4096)
    }
    @Test @MainActor func actualLaunchProducerSeparatesNotificationSampleAndRecheckTimes() throws {
        typealias F = ScreenRunnerLaunchBarrierTests
        let began = ContinuousClock.now
        let ticket = ScreenRunnerLaunchBarrier.Ticket(sequence: 4, at: began.advanced(by: .milliseconds(1)))
        let observation = ScreenRunnerLaunchBarrier.Observation(ticket: ticket, before: F.sample(103), after: F.sample(103),
            bundle: "com.google.Chrome", finished: true, terminated: false, observedAt: began.advanced(by: .milliseconds(6)),
            instanceEqual: true, beforeBegan: began.advanced(by: .milliseconds(2)), beforeEnded: began.advanced(by: .milliseconds(3)),
            instanceCompared: began.advanced(by: .milliseconds(4)), afterBegan: began.advanced(by: .milliseconds(5)))
        let owner = ScreenRunnerLaunchBarrier.Owner(label: "b-2", original: F.original(103), observation: observation)
        let fields = ScreenRunnerLaunchDiagnostics.ownerFields(owner, revision: 42, began: began)
        #expect(fields["notificationMs"] as? Double == 1 && fields["sampleBeforeBeganMs"] as? Double == 2 &&
                fields["sampleBeforeEndedMs"] as? Double == 3 && fields["instanceComparedMs"] as? Double == 4 &&
                fields["sampleAfterBeganMs"] as? Double == 5 && fields["sampleAfterEndedMs"] as? Double == 6,
                "launch-producer-distinct-sample-times")
        #expect(fields["revision"] as? String == "42" && fields["instanceEqual"] as? Bool == true)
        #expect(try JSONSerialization.data(withJSONObject: fields).count < 4096)
    }
}
#endif
