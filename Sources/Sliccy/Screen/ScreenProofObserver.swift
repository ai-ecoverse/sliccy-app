#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation

struct ScreenProofReport: Codable, Sendable {
    let schema: Int
    let event: String
    let seq: Int
    let stage: String
    let lane: String?
    let outcome: String?
    let tokenMatched: Bool?
    let pidAgreed: Bool?
    let uidAgreed: Bool?
    let lost: Bool

    var acceptedSafety: Bool {
        stage == "check" && lane == "safety" && outcome == "accepted" &&
        tokenMatched == true && pidAgreed == true && uidAgreed == true && !lost
    }
    var acceptedFrames: Bool {
        stage == "check" && lane == "frames" && outcome == "accepted" &&
        tokenMatched == true && pidAgreed == true && uidAgreed == true && !lost
    }
    var refusedFrames: Bool {
        stage == "check" && lane == "frames" && outcome == "refused" && tokenMatched == false && !lost
    }
    var refusedSafety: Bool {
        stage == "check" && lane == "safety" && outcome == "refused" && tokenMatched == false && !lost
    }
    var metadata: [String: Any] {
        var result: [String: Any] = ["schema": schema, "event": event, "seq": seq, "stage": stage,
            "tokenMatched": tokenMatched.map { $0 as Any } ?? NSNull(),
            "pidAgreed": pidAgreed.map { $0 as Any } ?? NSNull(),
            "uidAgreed": uidAgreed.map { $0 as Any } ?? NSNull(), "lost": lost]
        if let lane { result["lane"] = lane }
        if let outcome { result["outcome"] = outcome }
        return result
    }
}

/// One stdout-reader owner. Retains at most one bounded line; forwards only
/// reconstructed typed diagnostic fields, never arbitrary child output.
struct ScreenProofObserver {
    private var line = Data()
    private var bytes = 0
    private var next = 1
    private var seen = Set<String>()
    private(set) var complete = false
    private(set) var invalid = false

    mutating func feed(_ data: Data) throws -> [ScreenProofReport] {
        guard !invalid, data.count <= 65536 - bytes else { invalid = true; throw ScreenFailure.incompatible }
        bytes += data.count
        var reports: [ScreenProofReport] = []
        do {
            for byte in data {
                if byte == 10 {
                    if let value = try decode(line) { reports.append(value) }
                    line.removeAll(keepingCapacity: true)
                } else {
                    guard line.count < 4096 else { throw ScreenFailure.resourceLimit }
                    line.append(byte)
                }
            }
        } catch { invalid = true; line.removeAll(); throw error }
        return reports
    }
    mutating func finish() -> Bool {
        invalid = invalid || !line.isEmpty || !complete
        line.removeAll()
        return !invalid
    }
    private mutating func decode(_ data: Data) throws -> ScreenProofReport? {
        let object = try ScreenJSON.object(data)
        // Ordinary follow events are drained, not copied into diagnostic output.
        guard object["event"] as? String == "native-screen-verification" else { return nil }
        let stage = object["stage"] as? String
        let common = ["schema", "event", "seq", "stage", "tokenMatched", "pidAgreed", "uidAgreed", "lost"]
        try ScreenJSON.keys(object, exact: common + (stage == "check" ? ["lane", "outcome"] : []))
        let row = try JSONDecoder().decode(ScreenProofReport.self, from: data)
        guard !complete, row.schema == 1, row.seq == next, next <= 5 else { throw ScreenFailure.incompatible }
        switch row.stage {
        case "check":
            guard next <= 4, let lane = row.lane, ["safety", "frames"].contains(lane),
                  let outcome = row.outcome, ["accepted", "refused"].contains(outcome),
                  seen.insert(lane + ":" + outcome).inserted else { throw ScreenFailure.incompatible }
        case "complete":
            guard row.tokenMatched == nil, row.pidAgreed == nil, row.uidAgreed == nil else { throw ScreenFailure.incompatible }
            complete = true
        default: throw ScreenFailure.incompatible
        }
        next += 1
        if row.lost { invalid = true }
        return row
    }
}
#endif
