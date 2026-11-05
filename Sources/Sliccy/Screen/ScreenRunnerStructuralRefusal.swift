#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

struct ScreenRunnerStructuralRefusal: Sendable {
    enum Reason: String, Sendable {
        case windowServerEmptyBundle = "verified-windowserver-empty-sck-bundle"
    }
    let witness: ScreenRunnerInventoryBoundary.WindowServerEmptyBundleWitness
    let windowID: UInt32?
    var fields: [String: Any] {
        var result: [String: Any] = ["reason": Reason.windowServerEmptyBundle.rawValue,
            "role": witness.owner.identifier, "label": "window-server", "type": windowID == nil ? "display" : "window",
            "pid": witness.owner.pid, "startSeconds": String(witness.owner.seconds),
            "startMicroseconds": witness.owner.microseconds, "predicateEvidence": false, "rawSCKBundleEmpty": true]
        if let windowID { result["windowID"] = windowID }
        else { result["pairedWindowIDs"] = witness.pairs.map { $0.sck.id } }
        return result
    }
}
#endif
