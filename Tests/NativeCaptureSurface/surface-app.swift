import AppKit
import Darwin

@MainActor
private final class PatternView: NSView {
    var pulse = false
    override var isFlipped: Bool { true }
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        let values: [(NSRect, [CGFloat])] = [
            (NSRect(x: 0, y: 0, width: 128, height: 128), [220, 48, 48]),
            (NSRect(x: 128, y: 0, width: 128, height: 128), [48, 180, 80]),
            (NSRect(x: 0, y: 128, width: 128, height: 128), [48, 96, 220]),
            (NSRect(x: 128, y: 128, width: 128, height: 128), [224, 192, 48])
        ]
        NSColor.black.setFill(); bounds.fill()
        for (rect, rgb) in values {
            NSColor(srgbRed: rgb[0] / 255, green: rgb[1] / 255, blue: rgb[2] / 255, alpha: 1).setFill()
            rect.fill()
        }
        (pulse ? NSColor.white : NSColor.black).setFill()
        NSRect(x: 8, y: 8, width: 16, height: 16).fill()
    }
}

@main
@MainActor
private final class SurfaceApp: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var animation: Timer?
    private var presence: Timer?
    private var spaceObserver: NSObjectProtocol?
    private let began = ContinuousClock.now
    private var rows = 0
    private var attempts = 0
    private var ready = false
    private var displayHeight: CGFloat = 0

    private func emit(_ stage: String, extra: [String: Any] = [:]) {
        guard rows < 96 else { exit(1) }
        rows += 1
        let duration = began.duration(to: .now).components
        var row: [String: Any] = ["schema": 1, "stage": stage, "pid": getpid(), "seq": rows,
            "elapsedMs": Double(duration.seconds) * 1000 + Double(duration.attoseconds) / 1e15,
            "windowID": window?.windowNumber ?? 0, "visible": window?.isVisible ?? false,
            "onActiveSpace": window?.isOnActiveSpace ?? false,
            "occlusionVisible": window?.occlusionState.contains(.visible) ?? false,
            "applicationActive": NSApp.isActive, "attempt": attempts]
        if let window {
            row["windowFrameCG"] = ["x": window.frame.minX, "y": displayHeight - window.frame.maxY,
                "width": window.frame.width, "height": window.frame.height]
        }
        row.merge(extra) { _, new in new }
        guard var data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]), data.count < 4095 else { exit(1) }
        data.append(10)
        let written = data.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress, $0.count) }
        guard written == data.count else { exit(1) }
    }
    static func main() {
        let required = ["GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ai-ecoverse/sliccy-app",
                        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/proof/runner-capture-v1",
                        "SLICCY_RUNNER_ENVIRONMENT": "github-hosted"]
        guard CommandLine.arguments.count == 1, required.allSatisfy({ ProcessInfo.processInfo.environment[$0.key] == $0.value }),
              ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 27,
              Bundle.main.bundleIdentifier == "ai.sliccy.proof-helper" else { exit(2) }
#if !arch(arm64)
        exit(2)
#endif
        signal(SIGPIPE, SIG_IGN)
        let flags = fcntl(STDOUT_FILENO, F_GETFL)
        guard flags >= 0, fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { exit(1) }
        let delegate = SurfaceApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard let screen = NSScreen.screens.first, screen.frame.origin == .zero,
              screen.frame.width >= 1024, screen.frame.height >= 768 else { exit(2) }
        displayHeight = screen.frame.height
        let frame = NSRect(x: 128, y: screen.frame.height - 128 - 256, width: 256, height: 256)
        let owned = NSWindow(contentRect: frame, styleMask: .borderless, backing: .buffered, defer: false)
        owned.isReleasedWhenClosed = false; owned.isOpaque = true; owned.hasShadow = false
        owned.backgroundColor = .black; owned.title = "Sliccy synthetic surface"
        let pattern = PatternView(frame: NSRect(x: 0, y: 0, width: 256, height: 256))
        owned.contentView = pattern
        window = owned
        emit("surface-window-created")
        spaceObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.activeSpaceDidChangeNotification,
            object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.emit("surface-space-changed") }
            }
        owned.orderFrontRegardless()
        emit("surface-window-ordered")
        animation = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak pattern] _ in
            MainActor.assumeIsolated { pattern?.pulse.toggle(); pattern?.needsDisplay = true }
        }
        presence = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkPresence() }
        }
    }
    private func checkPresence() {
        guard !ready, let window else { exit(1) }
        attempts += 1
        let raw = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]]
        let owned = raw?.filter { SurfacePresence.integer($0[kCGWindowOwnerPID as String]) == Int64(getpid()) } ?? []
        let decision = SurfacePresence.decision(rows: raw, pid: getpid(), windowID: window.windowNumber,
            visible: window.isVisible, onActiveSpace: window.isOnActiveSpace, occlusionVisible: window.occlusionState.contains(.visible),
            attempts: attempts, elapsed: began.duration(to: .now))
        emit("surface-presence", extra: ["cgAvailable": raw != nil, "ownedOnScreenCount": owned.count,
            "observedWindows": owned.prefix(8).map { row -> [String: Any] in
                ["windowID": SurfacePresence.integer(row[kCGWindowNumber as String]) ?? 0,
                 "layer": SurfacePresence.integer(row[kCGWindowLayer as String]) ?? -1,
                 "bounds": row[kCGWindowBounds as String] as? [String: NSNumber] ?? [:]]
            },
            "presenceVerified": decision == .ready])
        guard decision == .ready else {
            if decision == .unavailable {
                emit("surface-unavailable", extra: ["reason": "presence-unproved"])
                exit(2)
            }
            return
        }
        ready = true; presence?.invalidate(); presence = nil
        emit("surface-ready", extra: ["bundleIdentifier": "ai.sliccy.proof-helper",
            "rect": ["x": 128, "y": 128, "width": 256, "height": 256], "presenceVerified": true])
        startControl()
    }
    private func startControl() {
        let deadline = began.advanced(by: .seconds(50))
        DispatchQueue.global().async {
            let expected = Array("stop\n".utf8)
            var offset = 0, code: Int32 = 1, reason = "control-deadline"
            while ContinuousClock.now < deadline {
                var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
                let ready = poll(&descriptor, 1, 25)
                if ready == 0 || (ready < 0 && errno == EINTR) { continue }
                var byte: UInt8 = 0
                let count = ready > 0 ? read(STDIN_FILENO, &byte, 1) : -1
                if count == 0 { code = 0; reason = "control-eof"; break }
                guard count == 1, byte == expected[offset] else { reason = "control-invalid"; break }
                offset += 1
                if offset == expected.count { code = 0; reason = "control-stop"; break }
            }
            let result = code, outcome = reason
            Task { @MainActor [weak self] in
                self?.emit("surface-control-ended", extra: ["reason": outcome])
                Darwin.exit(result)
            }
        }
    }
}
