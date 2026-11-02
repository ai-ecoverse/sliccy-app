// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Sliccy",
    platforms: [.macOS("27.0")],
    products: [.executable(name: "Sliccy", targets: ["Sliccy"])],
    targets: [
        .target(name: "ScreenSystem", path: "Sources/ScreenSystem", publicHeadersPath: "include"),
        .executableTarget(name: "Sliccy", dependencies: ["ScreenSystem"]),
        .testTarget(name: "SliccyTests", dependencies: ["Sliccy"], resources: [.copy("Fixtures")])
    ]
)
