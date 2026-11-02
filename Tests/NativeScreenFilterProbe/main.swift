import AppKit
@preconcurrency import ScreenCaptureKit

// Identified native host for the actual production SCContentFilter builder.
// No SCStream, recording permission request, or screenshot is created here.
@MainActor
final class Probe: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(contentRect: NSRect(x: 80, y: 80, width: 320, height: 180),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Sliccy filter constructor test"
        window.contentView = NSTextField(labelWithString: "Synthetic fixture — no capture")
        window.orderFront(nil); self.window = window
        Task { @MainActor in
            do {
                let content = try await SCShareableContent.currentProcess
                guard let display = content.displays.first,
                      let app = content.applications.first(where: { $0.processID == getpid() }),
                      app.bundleIdentifier == "ai.sliccy.filter-probe" else { throw ScreenFailure.protection }
                let fixture = try JSONDecoder().decode(ScreenFilterBuilder.Fixture.self,
                    from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
                guard fixture.v == 1, fixture.nativeBuilderMustConsume, fixture.vectors.count >= 2 else { throw ScreenFailure.incompatible }
                for vector in fixture.vectors {
                    do {
                        let filter = try ScreenFilterBuilder.consume(vector, display: display,
                            applications: ["eligible.fixture": app], windows: [:], protected: .init())
                        guard vector.allowed, !filter.includeMenuBar,
                              filter.includedApplications.map(\.processID) == [getpid()] else { throw ScreenFailure.incompatible }
                    } catch ScreenFailure.protection {
                        guard !vector.allowed else { throw ScreenFailure.protection }
                    }
                }
                print("PASS: \(fixture.vectors.count) upstream vectors consumed by real ScreenCaptureKit builder; no capture or compositor proof")
                window.close(); exit(0)
            } catch {
                print("FAIL: native filter fixture (\(error))")
                window.close(); exit(1)
            }
        }
    }
}
let app = NSApplication.shared
let delegate = Probe()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
