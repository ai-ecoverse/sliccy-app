import Foundation
import CoreGraphics

struct SurfacePresence {
    enum Decision { case waiting, ready, unavailable }

    static func decision(rows: [[String: Any]]?, pid: Int32, windowID: Int, visible: Bool,
                         onActiveSpace: Bool, occlusionVisible: Bool, attempts: Int, elapsed: Duration) -> Decision {
        guard attempts > 0, attempts <= 40, elapsed < .seconds(2) else { return .unavailable }
        if let rows, ready(rows: rows, pid: pid, windowID: windowID, visible: visible,
                           onActiveSpace: onActiveSpace, occlusionVisible: occlusionVisible) { return .ready }
        return attempts == 40 ? .unavailable : .waiting
    }
    static let expected = CGRect(x: 128, y: 128, width: 256, height: 256)

    static func number(_ value: Any?) -> NSNumber? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return number
    }

    static func integer(_ value: Any?) -> Int64? {
        guard let number = number(value), number.doubleValue.isFinite,
              number.doubleValue == Double(number.int64Value) else { return nil }
        return number.int64Value
    }

    static func ready(rows: [[String: Any]], pid: Int32, windowID: Int,
                      visible: Bool, onActiveSpace: Bool, occlusionVisible: Bool) -> Bool {
        guard pid > 0, windowID > 0, visible, onActiveSpace, occlusionVisible else { return false }
        let owned = rows.filter { integer($0[kCGWindowOwnerPID as String]) == Int64(pid) }
        guard owned.count == 1, let row = owned.first,
              integer(row[kCGWindowNumber as String]) == Int64(windowID),
              integer(row[kCGWindowLayer as String]) == 0,
              number(row[kCGWindowAlpha as String])?.doubleValue == 1,
              let present = row[kCGWindowIsOnscreen as String] as? NSNumber,
              CFGetTypeID(present) == CFBooleanGetTypeID(), present.boolValue,
              let bounds = row[kCGWindowBounds as String] as? [String: Any],
              bounds.count == 4,
              let x = number(bounds["X"]), let y = number(bounds["Y"]),
              let width = number(bounds["Width"]), let height = number(bounds["Height"]) else { return false }
        return x.doubleValue == expected.minX && y.doubleValue == expected.minY &&
            width.doubleValue == expected.width && height.doubleValue == expected.height
    }
}
