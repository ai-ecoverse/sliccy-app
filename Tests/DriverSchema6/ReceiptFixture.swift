import Foundation
import Darwin

enum ScreenFailure: Error { case incompatible, resourceLimit, stalled }
enum ScreenRunnerCase: String { case selectedWindow = "selected-window" }

@main struct ReceiptFixture {
    static func main() throws {
        let output = try ScreenRunnerJournal(.selectedWindow, authorityFailed: { exit(2) })
        let ledger = ScreenRunnerReceiptLedger(output: { delivery in
            var fields = delivery.journalFields
            fields["receiptCount"] = delivery.count
            fields["firstEventElapsedMs"] = ScreenRunnerJournal.ms(output.began.duration(to: delivery.first))
            fields["lastEventElapsedMs"] = ScreenRunnerJournal.ms(output.began.duration(to: delivery.last))
            output.emit(delivery.stage, fields, at: delivery.last)
        }, loss: { exit(3) })
        func sample(_ pid: Int, _ parent: Int) -> [Any] { [pid, parent, 501, 501, 501, "20", 1] }
        func bracket(_ value: [Any]) -> [Any] { [[0, 648, 648, value], [0, 136, 136, value], [0, 648, 648, value]] }
        let controls: [Any] = [bracket(sample(70, 69)), bracket(sample(69, 1))]
        let bsd: [String: Any] = ["role": "com.apple.dock", "phase": "before", "pid": 42, "status": 0, "selfPID": 70, "parentPID": 69,
            "controls": controls, "target": bracket(sample(42, 1)), "accepted": true, "usedSysctl": false, "controlsAgreed": true]
        for _ in 0..<3 { ledger.record("bsd-identity", fields: bsd, at: .now) }
        ledger.flush()
        let child: [String: Any] = ["role": "ai.sliccy.slicc", "site": "child-initial", "passed": true, "step": "child-complete", "statuses": [[Int]](), "selected": NSNull(),
            "compared": ["pid": 42, "signal": NSNull(), "incarnation": [42, 70, 501, "20", "1"], "expected": Data([0x5d,0xa1,0xa3,0x19,0x9b,0xd3,0xf8,0x95,0xbc,0xe2,0xe5,0x30,0x23,0xc2,0x8c,0xa1,0xc3,0x3d,0x24,0x9e]).base64EncodedString()] as [String: Any]]
        for _ in 0..<2 { ledger.record("code-binding", fields: child, at: .now) }
        ledger.flush()
        let hash = Data(repeating: 1, count: 20).base64EncodedString(), full = Data(repeating: 1, count: 32).base64EncodedString()
        let member: [Any] = [16777228, 0, "0", "4096", 2, hash, full]
        let identity: [Any] = [2, hash, full]
        let file = ["1", "2", "4096", "33188", "20", "0", "20", "0"]
        func requirement(_ role: String) -> String {
            "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"" + role + "\" and certificate leaf[subject.OU] = \"S8LB56P782\""
        }
        let preflight: [String: Any] = ["role": "ai.sliccy.mac", "site": "preflight", "passed": true, "step": "complete", "statuses": [[25,0]], "selected": NSNull(),
            "compared": ["pid": NSNull(), "path": "/fixture/Sliccy", "requirement": requirement("ai.sliccy.mac"), "file": file, "members": [member],
                "operations": [[5,0,1],[1,0,1],[6,0,1],[4,0,1,0]], "information": [[hash, "/fixture/Sliccy", "ai.sliccy.mac", identity, "0"]], "failure": [:]] as [String: Any]]
        ledger.record("code-binding", fields: preflight, at: .now)
        let raw: [Any] = [70,69,controls[0],controls[1],bracket(sample(42,70))]
        let text = String(data: try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys]), encoding: .utf8)!
        let incarnation = ["42","70","501","501","501","20","1","proc",text]
        let live: [String: Any] = ["role": "ai.sliccy.proof-helper", "site": "initial-live", "passed": true, "step": "complete", "statuses": [[16,0],[25,0],[16,0]], "selected": member,
            "compared": ["pid": 42, "expected": NSNull(), "expectedCatalogue": [member], "requirement": requirement("ai.sliccy.proof-helper"), "file": file, "members": [member],
                "incarnationBefore": incarnation, "incarnationAfter": incarnation, "kernelBefore": ["/fixture/Surface",hash,"0"], "kernelAfter": ["/fixture/Surface",hash,"0"], "live": identity,
                "operations": [[8,0,1],[1,0,1],[2,0,1],[7,0,1],[3,0,1],[4,0,1,0],[5,0,1],[6,0,1],[4,0,1,0],[4,0,1,0],[3,0,1],[4,0,1,0],[7,0,1],[8,0,1]],
                "information": [[hash,"/fixture/Surface","ai.sliccy.proof-helper",identity,"0"]], "failure": [:]] as [String: Any]]
        ledger.record("code-binding", fields: live, at: .now)
        ledger.finish()
        if output.failed { exit(4) }
    }
}
