import Foundation
import CoreGraphics
import Darwin

@main
struct PresenceTests {
    static func expect(_ value: Bool) {
        if !value { fputs("Synthetic surface presence boundary: FAIL\n", stderr); exit(1) }
    }
    static func main() {
        let original: [String: Any] = [kCGWindowOwnerPID as String: 42, kCGWindowNumber as String: 17,
            kCGWindowLayer as String: 0, kCGWindowAlpha as String: 1.0,
            kCGWindowIsOnscreen as String: true,
            kCGWindowBounds as String: ["X": 128, "Y": 128, "Width": 256, "Height": 256]]
        func accepts(_ rows: [[String: Any]], visible: Bool = true, space: Bool = true, occlusion: Bool = true) -> Bool {
            SurfacePresence.ready(rows: rows, pid: 42, windowID: 17, visible: visible, onActiveSpace: space, occlusionVisible: occlusion)
        }
        expect(accepts([original]))
        expect(!accepts([]))
        expect(!accepts([original, original]))
        expect(!accepts([original], visible: false))
        expect(!accepts([original], space: false))
        expect(!accepts([original], occlusion: false))
        for (key, value) in [(kCGWindowOwnerPID as String, 43 as Any), (kCGWindowNumber as String, 18),
                             (kCGWindowLayer as String, 1), (kCGWindowAlpha as String, 0.5),
                             (kCGWindowIsOnscreen as String, false), (kCGWindowIsOnscreen as String, 1),
                             (kCGWindowOwnerPID as String, true), (kCGWindowOwnerPID as String, 42.5),
                             (kCGWindowNumber as String, 17.5), (kCGWindowLayer as String, 0.5)] {
            var changed = original; changed[key] = value
            expect(!accepts([changed]))
        }
        for key in ["X", "Y", "Width", "Height"] {
            var changed = original
            var bounds = original[kCGWindowBounds as String] as! [String: Int]
            bounds[key]! += 1; changed[kCGWindowBounds as String] = bounds
            expect(!accepts([changed]))
        }
        var extra = original; extra[kCGWindowOwnerPID as String] = 43
        expect(accepts([extra, original]))
        func decision(_ rows: [[String: Any]]?, _ attempt: Int, _ elapsed: Duration) -> SurfacePresence.Decision {
            SurfacePresence.decision(rows: rows, pid: 42, windowID: 17, visible: true, onActiveSpace: true,
                occlusionVisible: true, attempts: attempt, elapsed: elapsed)
        }
        expect(decision([original], 1, .milliseconds(50)) == .ready)
        expect(decision([original], 40, .milliseconds(1999)) == .ready)
        expect(decision([original], 40, .seconds(2)) == .unavailable)
        expect(decision([], 1, .milliseconds(50)) == .waiting)
        expect(decision(nil, 1, .milliseconds(50)) == .waiting)
        expect(decision([], 40, .milliseconds(1999)) == .unavailable)
        expect(decision([original], 41, .milliseconds(1999)) == .unavailable)
        print("Synthetic surface presence boundary: PASS")
    }
}
