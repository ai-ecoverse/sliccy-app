#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerWindowSets {
    static func requireComplete(cg: [UInt32?], sck: [UInt32]) throws {
        let ids = cg.compactMap { $0 }
        guard ids.count == cg.count, !ids.contains(0), !sck.contains(0),
              Set(ids).count == ids.count, Set(sck).count == sck.count,
              Set(ids) == Set(sck) else { throw ScreenFailure.protection }
    }
}
#endif
