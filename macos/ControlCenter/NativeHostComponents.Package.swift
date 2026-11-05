// swift-tools-version: 6.4
//
// Release-only dependency-free package for the four native Host products.
// The carrier builder copies this file and the closed source inventory into a
// private package root. Keep this manifest free of remote package dependencies.

import PackageDescription

let package = Package(
    name: "SecureSandboxNativeHostComponents",
    platforms: [.macOS(.v27)],
    products: [
        .executable(
            name: "SecureSandboxNativeCredentialXPCService",
            targets: ["SecureSandboxNativeCredentialXPCService"]
        ),
        .executable(
            name: "SecureSandboxNativeStackBackend",
            targets: ["SecureSandboxNativeStackBackend"]
        ),
        .executable(
            name: "SecureSandboxNativeProjectionConsumer",
            targets: ["SecureSandboxNativeProjectionConsumer"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(name: "SecureSandboxNativeAuthCore"),
        .target(
            name: "SecureSandboxNativeXPCTransport",
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-fobjc-arc"])]
        ),
        .target(
            name: "SecureSandboxNativeCredentialHelper",
            dependencies: [
                "SecureSandboxNativeAuthCore",
                "SecureSandboxNativeXPCTransport",
            ],
            exclude: [
                "SecureSandboxNativeCredentialHelper.entitlements",
                "SecureSandboxNativeCredentialHelper-Info.plist",
                "org.zebeth.SecureSandbox.NativeCredentialHelper.plist.template",
            ],
            linkerSettings: [.linkedLibrary("bsm")]
        ),
        .executableTarget(
            name: "SecureSandboxNativeCredentialXPCService",
            dependencies: ["SecureSandboxNativeCredentialHelper"]
        ),
        .executableTarget(
            name: "SecureSandboxNativeStackBackend",
            dependencies: ["SecureSandboxNativeCredentialHelper"]
        ),
        .executableTarget(
            name: "SecureSandboxNativeProjectionConsumer"
        ),
    ]
)
