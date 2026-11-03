#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerWindowSets {
    struct Candidate {
        let id: UInt32, pid: pid_t, bundle: String, rect: CGRect, layer: Int
        var diagnosticTitle: String? = nil
    }
    static func unique(_ candidates: [Candidate], pid: pid_t, bundle: String, rect: CGRect, layer: Int) throws -> UInt32 {
        let matching = candidates.filter { $0.pid == pid && $0.bundle == bundle && $0.rect == rect && $0.layer == layer }
        guard pid > 0, !bundle.isEmpty, matching.count == 1, let match = matching.first, match.id != 0 else {
            throw ScreenRunnerInventoryIssue.windowIdentity
        }
        return match.id
    }
    static func requireUnambiguous(_ candidates: [Candidate]) throws {
        guard candidates.allSatisfy({ candidate in
            candidate.id != 0 && candidate.pid > 0 && !candidate.bundle.isEmpty &&
            candidates.filter { $0.id == candidate.id }.count == 1 &&
            candidates.filter { $0.pid == candidate.pid && $0.rect == candidate.rect }.count == 1
        }) else { throw ScreenRunnerInventoryIssue.windowIdentity }
    }

    static func requireComplete(cg: [UInt32?], sck: [UInt32]) throws {
        let ids = cg.compactMap { $0 }
        guard ids.count == cg.count, !ids.contains(0), !sck.contains(0),
              Set(ids).count == ids.count, Set(sck).count == sck.count,
              Set(ids) == Set(sck) else { throw ScreenFailure.protection }
    }
}
#endif
