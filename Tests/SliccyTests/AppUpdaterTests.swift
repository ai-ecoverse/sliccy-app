import Testing
@testable import Sliccy

@MainActor
struct AppUpdaterTests {
    @Test func testsAndDevelopmentDoNotStartAnUpdater() {
        let updater = AppUpdater()
        #expect(!updater.available)
        #expect(!updater.canCheck)
        updater.check()
        #expect(!updater.canCheck)
    }
}
