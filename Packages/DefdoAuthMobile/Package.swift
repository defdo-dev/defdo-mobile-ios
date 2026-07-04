// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DefdoAuthMobile",
    platforms: [.iOS(.v16), .macOS(.v14)],
    products: [
        .library(name: "DefdoAuthMobile", targets: ["DefdoAuthMobile"])
    ],
    targets: [
        .target(name: "DefdoAuthMobile", path: "Sources/DefdoAuthMobile"),
        .testTarget(
            name: "DefdoAuthMobileTests",
            dependencies: ["DefdoAuthMobile"],
            path: "Tests/DefdoAuthMobileTests"
        )
    ]
)
