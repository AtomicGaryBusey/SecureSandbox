// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "SecureSandboxControlCenter",
    platforms: [.macOS(.v27)],
    products: [.executable(name: "SecureSandboxControlCenter", targets: ["SecureSandboxControlCenter"])],
    dependencies: [
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", revision: "9eccf3548a563f6f91d8e9a06dd98db3086a68d1"),
    ],
    targets: [
        .executableTarget(name: "SecureSandboxControlCenter", dependencies: [
            .product(name: "SwiftTerm", package: "SwiftTerm"),
        ]),
    ]
)
