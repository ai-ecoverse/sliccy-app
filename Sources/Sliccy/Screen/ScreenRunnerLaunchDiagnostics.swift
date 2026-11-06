#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerLaunchDiagnostics {
    static func ownerFields(_ owner: ScreenRunnerLaunchBarrier.Owner, revision: UInt64, began: ContinuousClock.Instant) -> [String: Any] {
        let value = owner.observation
        return ["revision": String(revision), "label": owner.label, "pid": owner.original.pid,
                "parent": owner.original.parent, "uid": owner.original.uid, "startSeconds": String(owner.original.seconds),
                "startMicroseconds": owner.original.microseconds, "eventSequence": value.ticket.sequence,
                "notificationMs": ScreenRunnerJournal.ms(began.duration(to: value.ticket.at)),
                "sampleAfterEndedMs": ScreenRunnerJournal.ms(began.duration(to: value.observedAt)),
                "sampleBeforeBeganMs": value.beforeBegan.map { ScreenRunnerJournal.ms(began.duration(to: $0)) as Any } ?? NSNull(),
                "sampleBeforeEndedMs": value.beforeEnded.map { ScreenRunnerJournal.ms(began.duration(to: $0)) as Any } ?? NSNull(),
                "instanceComparedMs": value.instanceCompared.map { ScreenRunnerJournal.ms(began.duration(to: $0)) as Any } ?? NSNull(),
                "sampleAfterBeganMs": value.afterBegan.map { ScreenRunnerJournal.ms(began.duration(to: $0)) as Any } ?? NSNull(),
                "instanceEqual": value.instanceEqual,
                "before": value.before.fields, "after": value.after.fields,
                "bundleIdentifier": value.bundle, "finished": value.finished, "terminated": value.terminated]
    }
    static func workspaceFields(sequence: Int, origin: ScreenStopRelay.Origin, beforeMS: Double, afterMS: Double,
                       status: String, pid: pid_t?, bundle: String?) -> [String: Any] {
        ["sequence": sequence, "origin": origin.rawValue, "stopCallBeforeMs": beforeMS, "stopCallAfterMs": afterMS,
         "applicationStatus": status, "pid": pid.map { $0 as Any } ?? NSNull(),
         "bundle": ScreenRunnerInventoryDiagnostics.Notice.identifier(bundle)]
    }
}
#endif
