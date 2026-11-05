#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit

@MainActor
enum ScreenRunnerDisplaySampler {
    static func record(_ trigger: ScreenRunnerDisplayDiagnostics.Trigger) {
        let recorder = ScreenRunnerDisplayDiagnostics.shared
        guard let ticket = recorder.begin(trigger) else { return }
        sample(ticket, recorder: recorder)
    }
    nonisolated static func notification() {
        let recorder = ScreenRunnerDisplayDiagnostics.shared
        guard let ticket = recorder.begin(.notification) else { return }
        Task { @MainActor in sample(ticket, recorder: recorder) }
    }
    static func sample(_ ticket: ScreenRunnerDisplayDiagnostics.Ticket, recorder: ScreenRunnerDisplayDiagnostics) {
        guard recorder.shouldSample(ticket) else { return }
        let started = ContinuousClock.now
        let screens = NSScreen.screens
        guard screens.count <= ScreenRunnerDisplayDiagnostics.maximumDisplays else {
            recorder.complete(ticket, started: started, status: .tooManyDisplays, reportedCount: screens.count, displays: [])
            return
        }
        let displays = screens.map { screen -> ScreenRunnerDisplayDiagnostics.Display in
            let id = (screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value
            let mode = id.flatMap { $0 == 0 ? nil : CGDisplayCopyDisplayMode($0) }
            let space = screen.colorSpace?.cgColorSpace
            let name = space?.name
            let color: ScreenRunnerDisplayDiagnostics.Color
            if name == CGColorSpace.sRGB { color = .sRGB }
            else if name == CGColorSpace.displayP3 { color = .displayP3 }
            else if name == CGColorSpace.linearSRGB { color = .linearSRGB }
            else { color = space == nil ? .unavailable : .other }
            return .init(id: id, frame: screen.frame, visibleFrame: screen.visibleFrame,
                cgBounds: id.flatMap { $0 == 0 ? nil : CGDisplayBounds($0) }, scale: screen.backingScaleFactor,
                color: color, colorModel: space?.model.rawValue, colorComponents: space?.numberOfComponents,
                colorNameBytes: name.map { ($0 as String).utf8.count },
                mode: mode.map { .init(id: $0.ioDisplayModeID, flags: $0.ioFlags, width: $0.width,
                    height: $0.height, pixelWidth: $0.pixelWidth, pixelHeight: $0.pixelHeight, refreshRate: $0.refreshRate) })
        }
        recorder.complete(ticket, started: started, status: screens.isEmpty ? .unavailable : .complete,
            reportedCount: screens.count, displays: displays)
    }
}
#endif
