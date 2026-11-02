#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation

enum ScreenProofCase: String, Sendable {
    case base
    case parentExec = "parent-exec"
    case lifecycle

    static func parse(_ arguments: [String]) throws -> Self {
        guard arguments.first == "--screen-proof" else { throw ScreenFailure.incompatible }
        if arguments.count == 1 { return .base }
        guard arguments.count == 3, arguments[1] == "--case", let value = Self(rawValue: arguments[2]),
              value != .base else { throw ScreenFailure.incompatible }
        return value
    }
}
#endif
