import AppKit
import Carbon

/// Shared, synchronous stop target for the local button, hotkey and OS monitors.
final class ScreenStopRelay: @unchecked Sendable {
    enum Origin: String, CaseIterable, Sendable {
        case button, hotkey, other
        case workspaceLaunch = "workspace-launch", workspaceTerminate = "workspace-terminate"
        case willSleep = "will-sleep", sessionInactive = "session-inactive", spaceChange = "space-change"
        case displayChange = "display-change", indicator, windowClose = "window-close"
        case sourceMonitor = "source-monitor", captureFailure = "capture-failure", captureLimit = "capture-limit"
        case watchdog, cancelled, inventory, launcher, nativeChild = "native-child", remote, fixture, diagnostic
    }
    let gate: ScreenOutputGate
    private let stop: @Sendable (ScreenFailure) -> Void
    private let entered: @Sendable (Origin, ContinuousClock.Instant) -> Void
    private let observed: @Sendable (ContinuousClock.Instant, ContinuousClock.Instant) -> Void
    private let cause: @Sendable (ScreenFailure, Origin, ContinuousClock.Instant) -> Void
    init(gate: ScreenOutputGate, entered: @escaping @Sendable (Origin, ContinuousClock.Instant) -> Void = { _, _ in }, observed: @escaping @Sendable (ContinuousClock.Instant, ContinuousClock.Instant) -> Void = { _, _ in },
         cause: @escaping @Sendable (ScreenFailure, Origin, ContinuousClock.Instant) -> Void = { _, _, _ in },
         stop: @escaping @Sendable (ScreenFailure) -> Void) { self.gate = gate; self.stop = stop; self.observed = observed; self.entered = entered; self.cause = cause }
    func invoke(_ reason: ScreenFailure, origin: Origin = .other) {
        let start = ContinuousClock.now
        gate.invalidate()
        let invalidated = ContinuousClock.now
        stop(reason)
        cause(reason, origin, start)
        entered(origin, start)
        observed(start, invalidated)
    }
}

final class ScreenIndicatorHealth: @unchecked Sendable {
    private let lock = NSLock()
    private var until: ContinuousClock.Instant?
    private var invalid = false
    func renew(visible: Bool, now: ContinuousClock.Instant = .now) {
        lock.lock(); defer { lock.unlock() }
        if !visible || until.map({ now >= $0 }) == true { invalid = true }
        if !invalid { until = now.advanced(by: .milliseconds(1500)) }
    }
    func check(now: ContinuousClock.Instant = .now) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if until.map({ now >= $0 }) == true { invalid = true }
        return !invalid && until.map { now < $0 } == true
    }
    func invalidate() { lock.lock(); invalid = true; lock.unlock() }
}

/// A persistent local stop surface. UI stalls expire health; closing this panel
/// invalidates first. Ordinary workspace window closure does not stop sharing.
@MainActor
final class ScreenIndicator: NSObject, NSWindowDelegate {
    let health = ScreenIndicatorHealth()
    private let relay: ScreenStopRelay
    private let panel: NSPanel
    private var status: NSStatusItem?
    private var stopButton: NSButton?
    private var shortcut: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []

    init(recipient: String, scope: String, relay: ScreenStopRelay, diagnostic: Bool = false) throws {
        self.relay = relay
        panel = NSPanel(contentRect: NSRect(x: 40, y: 60, width: 430, height: 84),
            styleMask: [.titled, .nonactivatingPanel], backing: .buffered, defer: false)
        super.init()
        panel.title = diagnostic ? "Sliccy connection diagnostic · No capture" : "Sliccy is sharing your screen"
        panel.isReleasedWhenClosed = false; panel.hidesOnDeactivate = false
        panel.level = .floating; panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.delegate = self
        let text = NSTextField(labelWithString: diagnostic ? "Local connection test · No screen access\nStops automatically after 30 seconds" : "\(scope) · View only\n\(recipient.prefix(64))")
        text.font = .systemFont(ofSize: 12)
        let button = NSButton(title: diagnostic ? "Stop Test" : "Stop Sharing", target: self, action: #selector(stopPressed))
        stopButton = button
        button.bezelStyle = .rounded
        let stack = NSStackView(views: [text, button]); stack.orientation = .horizontal; stack.spacing = 18
        stack.edgeInsets = NSEdgeInsets(top: 12, left: 16, bottom: 12, right: 16)
        stack.distribution = .fill; stack.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView?.addSubview(stack)
        if let content = panel.contentView {
            NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: content.leadingAnchor), stack.trailingAnchor.constraint(equalTo: content.trailingAnchor), stack.topAnchor.constraint(equalTo: content.topAnchor), stack.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        }
        var type = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let pointer = Unmanaged.passUnretained(relay).toOpaque()
        guard InstallEventHandler(GetApplicationEventTarget(), { _, _, context in
            guard let context else { return OSStatus(eventNotHandledErr) }
            Unmanaged<ScreenStopRelay>.fromOpaque(context).takeUnretainedValue().invoke(.stopped, origin: .hotkey)
            return noErr
        }, 1, &type, pointer, &handler) == noErr else { throw ScreenFailure.shortcut }
        let identity = EventHotKeyID(signature: 0x534C4359, id: 1)
        guard RegisterEventHotKey(UInt32(kVK_Escape), UInt32(controlKey | optionKey | cmdKey), identity, GetApplicationEventTarget(), 0, &shortcut) == noErr else {
            if let handler { RemoveEventHandler(handler); self.handler = nil }
            throw ScreenFailure.shortcut
        }
        let status = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        status.button?.title = diagnostic ? "Test · Stop" : "Sharing · Stop"; status.button?.target = self; status.button?.action = #selector(stopPressed)
        self.status = status
        panel.orderFrontRegardless()
        health.renew(visible: panel.isVisible)
        let center = NSWorkspace.shared.notificationCenter
        let changes: [(Notification.Name, ScreenStopRelay.Origin)] = [
            (NSWorkspace.willSleepNotification, .willSleep), (NSWorkspace.sessionDidResignActiveNotification, .sessionInactive),
            (NSWorkspace.activeSpaceDidChangeNotification, .spaceChange), (NSWorkspace.didLaunchApplicationNotification, .workspaceLaunch),
            (NSWorkspace.didTerminateApplicationNotification, .workspaceTerminate)]
        for (name, origin) in changes {
            observers.append(center.addObserver(forName: name, object: nil, queue: nil) { [relay] _ in relay.invoke(.sourceChanged, origin: origin) })
        }
        observers.append(NotificationCenter.default.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: nil) { [relay] _ in relay.invoke(.sourceChanged, origin: .displayChange) })
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.health.renew(visible: self.panel.isVisible && self.panel.isOnActiveSpace && self.status?.isVisible == true)
                if !self.health.check() { self.relay.invoke(.indicator, origin: .indicator) }
            }
        }
    }
    @objc private func stopPressed() { relay.invoke(.stopped, origin: .button) }
#if SLICCY_CAPTURE_RUNNER_PROOF
    func proofPlace() throws {
        _ = try ScreenRunnerHost.require()
        guard let screen = NSScreen.screens.first(where: { ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID() }),
              screen.frame.width >= 1024, screen.frame.height >= 768 else { throw ScreenFailure.protection }
        panel.setFrame(NSRect(x: screen.frame.minX + 64, y: screen.frame.maxY - 512 - 128, width: 320, height: 128), display: true)
    }
    func proofPressStop() throws {
        guard panel.isVisible, health.check(), let stopButton else { throw ScreenFailure.indicator }
        stopButton.performClick(nil)
    }
#endif
    func windowShouldClose(_ sender: NSWindow) -> Bool { relay.invoke(.stopped, origin: .windowClose); return true }
    func dismiss() {
        relay.gate.invalidate(); health.invalidate()
        timer?.invalidate(); timer = nil
        if let shortcut { UnregisterEventHotKey(shortcut); self.shortcut = nil }
        if let handler { RemoveEventHandler(handler); self.handler = nil }
        for observer in observers { NSWorkspace.shared.notificationCenter.removeObserver(observer); NotificationCenter.default.removeObserver(observer) }
        observers.removeAll()
        if let status { NSStatusBar.system.removeStatusItem(status); self.status = nil }
        panel.orderOut(nil)
    }
}
