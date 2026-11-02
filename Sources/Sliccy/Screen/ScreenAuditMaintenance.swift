import Foundation
import OSLog

/// App-lifetime maintenance, independent of capture, connections and audit writes.
@MainActor
final class ScreenAuditMaintenance {
    private let audit: ScreenAudit
    private let queue = DispatchQueue(label: "ai.sliccy.mac.audit-maintenance", qos: .utility)
    private let timer: DispatchSourceTimer

    init(audit: ScreenAudit) {
        self.audit = audit
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { Self.perform(audit) }
        timer.schedule(deadline: .now(), repeating: .seconds(300), leeway: .seconds(1))
        timer.resume()
    }

    func sweepAfterWake() {
        queue.async { [audit] in Self.perform(audit) }
    }

    func stop() { timer.cancel() }

    private nonisolated static func perform(_ audit: ScreenAudit) {
        do {
            if try !audit.sweep() {
                Logger(subsystem: "ai.sliccy.mac", category: "Audit")
                    .notice("Audit maintenance deferred: shared journal is busy")
            }
        } catch {
            // Fixed metadata only: never log paths, records or underlying errors.
            Logger(subsystem: "ai.sliccy.mac", category: "Audit")
                .error("Audit maintenance failed; cleanup will retry")
        }
    }
}
