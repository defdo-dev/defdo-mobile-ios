// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DefdoThemeMobile",
    platforms: [.iOS(.v16), .macOS(.v14)],
    products: [
        .library(name: "DefdoThemeMobile", targets: ["DefdoThemeMobile"])
    ],
    targets: [
        .target(name: "DefdoThemeMobile", path: "Sources/DefdoThemeMobile"),
        .testTarget(
            name: "DefdoThemeMobileTests",
            dependencies: ["DefdoThemeMobile"],
            path: "Tests/DefdoThemeMobileTests"
        )
    ]
)
