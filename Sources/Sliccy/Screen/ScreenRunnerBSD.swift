#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin
import ScreenSystem

enum ScreenRunnerBSD {
    struct Sample: Equatable, Sendable {
        let pid: pid_t, parent: pid_t, effectiveUID: uid_t, realUID: uid_t, savedUID: uid_t
        let seconds: UInt64, microseconds: UInt64
        init(_ value: sliccy_runner_bsd_value) {
            pid = value.pid; parent = value.parent; effectiveUID = value.effective_uid
            realUID = value.real_uid; savedUID = value.saved_uid; seconds = value.seconds; microseconds = value.microseconds
        }
        var raw: sliccy_runner_bsd_value {
            .init(pid: pid, parent: parent, effective_uid: effectiveUID, real_uid: realUID, saved_uid: savedUID, seconds: seconds, microseconds: microseconds)
        }
        var fields: [String: Any] {
            ["pid": pid, "parent": parent, "effectiveUID": effectiveUID, "realUID": realUID, "savedUID": savedUID,
             "seconds": String(seconds), "microseconds": microseconds]
        }
    }
    struct Evidence: @unchecked Sendable {
        let fields: [String: Any]
        let at: ContinuousClock.Instant
    }
    struct Resolved: Equatable, Sendable {
        let sample: Sample, usedSysctl: Bool, controlsAgreed: Bool
    }
    static func resolve(_ observation: sliccy_runner_bsd_observation, pid: pid_t) throws -> Resolved {
        var observation = observation, value = sliccy_runner_bsd_value(), used: Int32 = 0
        guard sliccy_runner_bsd_select(&observation, pid, &value, &used) == 0 else { throw ScreenFailure.peerUntrusted }
        return .init(sample: .init(value), usedSysctl: used == 1, controlsAgreed: sliccy_bsd_controls(observation) != 0)
    }
    static func readFields(_ value: sliccy_runner_bsd_read) -> [String: Any] {
        ["status": value.status, "count": value.count, "expected": value.expected,
         "value": value.status == 0 && value.count == value.expected ? Sample(value.value).fields as Any : NSNull()]
    }
    static func bracketFields(_ value: sliccy_runner_bsd_bracket) -> [String: Any] {
        ["before": readFields(value.before), "proc": readFields(value.proc), "after": readFields(value.after)]
    }
    static func observe(_ pid: pid_t, phase: String, record: @Sendable (Evidence) -> Void) throws -> Resolved {
        var raw = sliccy_runner_bsd_observation()
        let status = sliccy_runner_bsd_observe(pid, &raw)
        let observed = ContinuousClock.now
        let resolved = status == 0 ? (try? resolve(raw, pid: pid)) : nil
        record(.init(fields: ["phase": phase, "pid": pid, "status": status, "selfPID": raw.self_pid, "parentPID": raw.parent_pid,
            "controls": [bracketFields(raw.controls.0), bracketFields(raw.controls.1)], "target": bracketFields(raw.target),
            "accepted": resolved != nil, "usedSysctl": resolved.map { $0.usedSysctl as Any } ?? NSNull(),
            "controlsAgreed": resolved.map { $0.controlsAgreed as Any } ?? NSNull()], at: observed))
        guard let resolved else { throw ScreenFailure.peerUntrusted }
        return resolved
    }
    static func bind(_ before: Resolved, _ after: Resolved, windowServer: Bool) throws -> Sample {
        guard before.sample == after.sample else { throw ScreenFailure.peerUntrusted }
        if windowServer {
            var a = before.sample.raw, b = after.sample.raw
            guard before.controlsAgreed, after.controlsAgreed,
                  sliccy_runner_bsd_windowserver(&a, &b) != 0 else { throw ScreenFailure.peerUntrusted }
        }
        return before.sample
    }
}
#endif
