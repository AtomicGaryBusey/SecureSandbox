// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureSandboxTouchIDAuthorization",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AuthorizationCore", targets: ["AuthorizationCore"]),
        .executable(name: "SecureSandboxAuthorizationUI", targets: ["SecureSandboxAuthorizationUI"]),
    ],
    targets: [
        .target(name: "AuthorizationCore"),
        .executableTarget(
            name: "SecureSandboxAuthorizationUI",
            dependencies: ["AuthorizationCore"]
        ),
        .testTarget(name: "AuthorizationCoreTests", dependencies: ["AuthorizationCore"]),
    ]
)
