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
        let delegate = SurfaceApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard let screen = NSScreen.screens.first, screen.frame.origin == .zero,
              screen.frame.width >= 1024, screen.frame.height >= 768 else { exit(2) }
        let frame = NSRect(x: 128, y: screen.frame.height - 128 - 256, width: 256, height: 256)
        let owned = NSWindow(contentRect: frame, styleMask: .borderless, backing: .buffered, defer: false)
        owned.isReleasedWhenClosed = false; owned.isOpaque = true; owned.hasShadow = false
        owned.backgroundColor = .black; owned.title = "Sliccy synthetic surface"
        let pattern = PatternView(frame: NSRect(x: 0, y: 0, width: 256, height: 256))
        owned.contentView = pattern
        owned.orderFrontRegardless(); window = owned
        animation = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak pattern] _ in
            MainActor.assumeIsolated { pattern?.pulse.toggle(); pattern?.needsDisplay = true }
        }
        let row: [String: Any] = ["schema": 1, "stage": "surface-ready", "pid": getpid(),
            "bundleIdentifier": "ai.sliccy.proof-helper", "rect": ["x": 128, "y": 128, "width": 256, "height": 256]]
        do {
            var data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]); data.append(10)
            try FileHandle.standardOutput.write(contentsOf: data)
        } catch { exit(1) }
        DispatchQueue.global().async {
            let expected = Array("stop\n".utf8), deadline = ContinuousClock.now.advanced(by: .seconds(50))
            var offset = 0, code: Int32 = 1
            while ContinuousClock.now < deadline {
                var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
                let ready = poll(&descriptor, 1, 25)
                if ready == 0 || (ready < 0 && errno == EINTR) { continue }
                var byte: UInt8 = 0
                let count = ready > 0 ? read(STDIN_FILENO, &byte, 1) : -1
                if count == 0 { code = 0; break }
                guard count == 1, byte == expected[offset] else { break }
                offset += 1
                if offset == expected.count { code = 0; break }
            }
            let result = code
            Task { @MainActor in Darwin.exit(result) }
        }
    }
}
