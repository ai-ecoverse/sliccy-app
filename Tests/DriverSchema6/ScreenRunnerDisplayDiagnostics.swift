#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerDisplayDiagnostics: @unchecked Sendable {
    static let shared = ScreenRunnerDisplayDiagnostics()
    static let maximumDisplays = 8
    static let maximumNotifications = 16
    enum Trigger: String, Sendable, CaseIterable {
        case beforeActivationPolicy = "before-activation-policy", afterActivationPolicy = "after-activation-policy"
        case didFinishLaunching = "did-finish-launching", preflight, helperSpawned = "helper-spawned"
        case beforeIndicator = "before-indicator", indicatorOrdered = "indicator-ordered", indicatorPlaced = "indicator-placed"
        case notification
    }
    enum Status: String, Sendable { case complete, unavailable, tooManyDisplays = "too-many-displays", unfinished }
    enum Color: String, Sendable { case sRGB = "srgb", displayP3 = "display-p3", linearSRGB = "linear-srgb", other, unavailable }
    struct Mode: Sendable {
        let id: Int32, flags: UInt32
        let width: Int, height: Int, pixelWidth: Int, pixelHeight: Int
        let refreshRate: Double
    }
    struct Display: Sendable {
        let id: UInt32?
        let frame: CGRect, visibleFrame: CGRect, cgBounds: CGRect?
        let scale: Double
        let color: Color, colorModel: Int32?, colorComponents: Int?, colorNameBytes: Int?
        let mode: Mode?
        var fields: [String: Any] {
            let modeFields: Any
            if let mode {
                modeFields = ["id": mode.id, "flags": mode.flags, "width": mode.width, "height": mode.height,
                    "pixelWidth": mode.pixelWidth, "pixelHeight": mode.pixelHeight, "refreshRate": Self.number(mode.refreshRate)] as [String: Any]
            } else { modeFields = NSNull() }
            return ["displayID": id.map { $0 as Any } ?? NSNull(), "frame": Self.rect(frame),
                "visibleFrame": Self.rect(visibleFrame), "cgBounds": cgBounds.map { Self.rect($0) as Any } ?? NSNull(),
                "scale": Self.number(scale), "color": color.rawValue,
                "colorModel": colorModel.map { $0 as Any } ?? NSNull(),
                "colorComponents": colorComponents.map { $0 as Any } ?? NSNull(),
                "colorNameBytes": colorNameBytes.map { $0 as Any } ?? NSNull(), "mode": modeFields]
        }
        private static func number(_ value: Double) -> Any { value.isFinite ? value as Any : NSNull() }
        private static func rect(_ value: CGRect) -> [String: Any] {
            ["x": number(value.origin.x), "y": number(value.origin.y),
             "width": number(value.size.width), "height": number(value.size.height)]
        }
    }
    struct Ticket: Sendable {
        let ordinal: Int, trigger: Trigger, requested: ContinuousClock.Instant
    }
    struct Observation: Sendable {
        let ticket: Ticket
        let started: ContinuousClock.Instant?, finished: ContinuousClock.Instant
        let status: Status, reportedCount: Int?
        let displays: [Display]
    }
    enum Delivery: Sendable {
        case origin(ContinuousClock.Instant)
        case observation(Observation)
        case closed(admitted: Int, completed: Int, unfinished: Int, overflow: Bool)
    }
    let began: ContinuousClock.Instant
    private let lock = NSLock()
    private var milestones = Set<Trigger>(), notifications = 0, admitted = 0, completed = 0
    private var pending: [Int: Ticket] = [:], buffered: [Observation] = []
    private var output: (@Sendable (Delivery) -> Void)?
    private var loss: (@Sendable () -> Void)?
    private var overflow = false, closed = false
    init(began: ContinuousClock.Instant = .now) { self.began = began }
    func install(output: @escaping @Sendable (Delivery) -> Void, loss: @escaping @Sendable () -> Void) {
        lock.lock()
        guard self.output == nil, !closed else { lock.unlock(); loss(); return }
        self.output = output; self.loss = loss
        let prior = buffered; buffered.removeAll(); let lost = overflow
        lock.unlock()
        output(.origin(began))
        for observation in prior { output(.observation(observation)) }
        if lost { loss() }
    }
    func begin(_ trigger: Trigger, at: ContinuousClock.Instant = .now) -> Ticket? {
        lock.lock()
        if closed { lock.unlock(); return nil }
        let valid = trigger == .notification ? notifications < Self.maximumNotifications : !milestones.contains(trigger)
        guard valid else {
            let first = !overflow; overflow = true; let fail = loss
            lock.unlock(); if first { fail?() }; return nil
        }
        if trigger == .notification { notifications += 1 } else { milestones.insert(trigger) }
        admitted += 1
        let ticket = Ticket(ordinal: admitted, trigger: trigger, requested: at)
        pending[ticket.ordinal] = ticket
        lock.unlock()
        return ticket
    }
    func shouldSample(_ ticket: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !closed && pending[ticket.ordinal]?.requested == ticket.requested
    }
    func complete(_ ticket: Ticket, started: ContinuousClock.Instant, status: Status, reportedCount: Int?, displays: [Display], at: ContinuousClock.Instant = .now) {
        lock.lock()
        guard !closed, let actual = pending[ticket.ordinal], actual.trigger == ticket.trigger, actual.requested == ticket.requested else { lock.unlock(); return }
        guard displays.count <= Self.maximumDisplays, started >= actual.requested, at >= started,
              status != .complete || reportedCount == displays.count else {
            let first = !overflow; overflow = true; let fail = loss
            lock.unlock(); if first { fail?() }; return
        }
        pending.removeValue(forKey: ticket.ordinal); completed += 1
        let value = Observation(ticket: actual, started: started, finished: at, status: status, reportedCount: reportedCount, displays: displays)
        let send = output
        if send == nil { buffered.append(value) }
        let firstLoss = status == .tooManyDisplays && !overflow
        if status == .tooManyDisplays { overflow = true }
        let fail = loss
        lock.unlock()
        send?(.observation(value))
        if firstLoss { fail?() }
    }
    func finish(at: ContinuousClock.Instant = .now) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let unfinished = pending.values.sorted { $0.ordinal < $1.ordinal }
        pending.removeAll()
        let send = output, fail = loss
        let total = admitted, done = completed, lost = overflow
        lock.unlock()
        for ticket in unfinished {
            send?(.observation(.init(ticket: ticket, started: nil, finished: at, status: .unfinished, reportedCount: nil, displays: [])))
        }
        send?(.closed(admitted: total, completed: done, unfinished: unfinished.count, overflow: lost))
        if !unfinished.isEmpty || lost { fail?() }
    }
    func deliver(_ delivery: Delivery, to journal: ScreenRunnerJournal) {
        switch delivery {
        case .origin(let origin):
            journal.emit("display-diagnostic-origin", ["originBeforeJournalMs": Self.ms(origin.duration(to: journal.began)),
                "maximumDisplays": Self.maximumDisplays, "maximumNotifications": Self.maximumNotifications,
                "maximumMilestones": Trigger.allCases.count - 1])
        case .observation(let value):
            let ticket = value.ticket
            journal.emit("display-observation", ["ordinal": ticket.ordinal, "trigger": ticket.trigger.rawValue,
                "requestedMs": Self.ms(began.duration(to: ticket.requested)),
                "startedMs": value.started.map { Self.ms(began.duration(to: $0)) as Any } ?? NSNull(),
                "finishedMs": Self.ms(began.duration(to: value.finished)), "status": value.status.rawValue,
                "reportedCount": value.reportedCount.map { $0 as Any } ?? NSNull(), "retainedCount": value.displays.count])
            for (index, display) in value.displays.enumerated() {
                var fields = display.fields; fields["ordinal"] = ticket.ordinal; fields["index"] = index
                journal.emit("display-observation-screen", fields)
            }
        case .closed(let admitted, let completed, let unfinished, let overflow):
            journal.emit("display-diagnostic-closed", ["admitted": admitted, "completed": completed,
                "unfinished": unfinished, "overflow": overflow])
        }
    }
    private static func ms(_ value: Duration) -> Double { Double(value.components.seconds) * 1000 + Double(value.components.attoseconds) / 1e15 }
}
#endif
