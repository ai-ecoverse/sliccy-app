// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Sliccy",
    platforms: [.macOS("27.0")],
    products: [.executable(name: "Sliccy", targets: ["Sliccy"])],
    dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1")],
    targets: [
        .target(name: "ScreenSystem", path: "Sources/ScreenSystem", publicHeadersPath: "include"),
        .executableTarget(name: "Sliccy", dependencies: ["ScreenSystem", .product(name: "Sparkle", package: "Sparkle")], linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]),
        .testTarget(name: "SliccyTests", dependencies: ["Sliccy"], resources: [.copy("Fixtures")])
    ]
)
