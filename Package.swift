// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WireGuard",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "WireGuard",
            targets: ["WireGuard"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/OperatorFoundation/swift-sodium.git", from: "0.6.10"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "0.7.2"),
        .package(url: "https://github.com/OperatorFoundation/HKDFKit.git", from: "1.0.1"),
        .package(url: "https://github.com/OperatorFoundation/Blake2.git", from: "1.0.1"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", from: "1.0.1")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "WireGuard",
            dependencies: ["Sodium", "CryptoSwift", "HKDFKit", "Blake2", "Datable"]),
        .testTarget(
            name: "WireGuardTests",
            dependencies: ["WireGuard", "Datable"]),
    ]
)
