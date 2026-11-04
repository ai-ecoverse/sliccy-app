#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import CoreFoundation
import CryptoKit

final class ScreenRunnerReceiptLedger: @unchecked Sendable {
    struct Delivery: @unchecked Sendable {
        let stage: String, fields: [String: Any], first: ContinuousClock.Instant, last: ContinuousClock.Instant, count: Int
        let key: String, aggregate: Bool
        var journalFields: [String: Any] {
            var value: [String: Any] = aggregate ? [:] : fields
            value["receiptKey"] = key; value["receiptAggregate"] = aggregate
            return value
        }
    }
    private struct Entry {
        let stage: String, fields: [String: Any], key: Data
        var first: ContinuousClock.Instant, last: ContinuousClock.Instant, count: Int
    }
    private let lock = NSLock()
    private var entries: [String: Entry] = [:]
    private var retired = false, closed = false
    private var delivering = 0
    private let output: @Sendable (Delivery) -> Void, loss: @Sendable () -> Void
    init(output: @escaping @Sendable (Delivery) -> Void, loss: @escaping @Sendable () -> Void) {
        self.output = output; self.loss = loss
    }
    private func digest(_ key: Data) -> String { SHA256.hash(data: key).map { String(format: "%02x", $0) }.joined() }
    private func pending(_ entry: Entry) -> Delivery? {
        entry.count > 0 ? .init(stage: entry.stage, fields: entry.fields, first: entry.first, last: entry.last, count: entry.count, key: digest(entry.key), aggregate: true) : nil
    }
    private func drainLocked() -> [Delivery] {
        var result: [Delivery] = []
        for key in entries.keys.sorted() {
            if let entry = entries[key], let row = pending(entry) { result.append(row) }
            entries[key]?.count = 0
        }
        return result
    }
    func record(_ stage: String, fields: [String: Any], at: ContinuousClock.Instant) {
        var deliveries: [Delivery] = [], failed = false
        lock.lock()
        do {
            guard !retired, !closed, ["code-binding", "bsd-identity"].contains(stage),
                  let role = fields["role"] as? String,
                  let site = (fields["site"] ?? fields["phase"]) as? String,
                  let boolean = (fields["passed"] ?? fields["accepted"]) as? NSNumber,
                  CFGetTypeID(boolean) == CFBooleanGetTypeID() else { throw ScreenFailure.incompatible }
            let success = boolean.boolValue
            let pid = (fields["compared"] as? [String: Any])?["pid"] ?? fields["pid"] ?? NSNull()
            let stream = try JSONSerialization.data(withJSONObject: [stage, role, site, pid], options: [.sortedKeys]).base64EncodedString()
            let key = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
            guard key.count <= 3584, let fields = try JSONSerialization.jsonObject(with: key) as? [String: Any] else { throw ScreenFailure.resourceLimit }
            if !success {
                deliveries = drainLocked()
                deliveries.append(.init(stage: stage, fields: fields, first: at, last: at, count: 1, key: digest(key), aggregate: false))
                entries.removeValue(forKey: stream)
            } else if var previous = entries[stream], previous.key == key {
                guard previous.count < 100000 else { throw ScreenFailure.resourceLimit }
                if previous.count == 0 { previous.first = at; previous.last = at }
                else { previous.first = min(previous.first, at); previous.last = max(previous.last, at) }
                previous.count += 1; entries[stream] = previous
            } else {
                if let previous = entries[stream], let row = pending(previous) { deliveries.append(row) }
                guard entries[stream] != nil || entries.count < 256 else { throw ScreenFailure.resourceLimit }
                deliveries.append(.init(stage: stage, fields: fields, first: at, last: at, count: 1, key: digest(key), aggregate: false))
                entries[stream] = .init(stage: stage, fields: fields, key: key, first: at, last: at, count: 0)
            }
        } catch { retired = true; failed = true; deliveries = drainLocked() }
        delivering += deliveries.count
        lock.unlock()
        if failed { loss() }
        deliver(deliveries)
    }
    private func deliver(_ deliveries: [Delivery]) {
        for row in deliveries {
            output(row)
            lock.lock(); delivering -= 1; lock.unlock()
        }
    }
    func flush() {
        lock.lock(); let deliveries = drainLocked(); delivering += deliveries.count; lock.unlock()
        deliver(deliveries)
    }
    func finish() {
        lock.lock()
        closed = true
        let failed = delivering != 0
        if failed { retired = true }
        let deliveries = drainLocked(); delivering += deliveries.count
        lock.unlock()
        if failed { loss() }
        deliver(deliveries)
    }
}
#endif
