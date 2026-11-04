// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "SecureSandboxControlCenter",
    platforms: [.macOS(.v27)],
    products: [
        .executable(name: "SecureSandboxControlCenter", targets: ["SecureSandboxControlCenter"]),
        .executable(
            name: "SecureSandboxNativeCredentialXPCService",
            targets: ["SecureSandboxNativeCredentialXPCService"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", revision: "9eccf3548a563f6f91d8e9a06dd98db3086a68d1"),
    ],
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
        .target(name: "SecureSandboxUpdateCore"),
        .executableTarget(name: "SecureSandboxUpdateInstaller", dependencies: [
            "SecureSandboxUpdateCore",
        ]),
        .executableTarget(name: "SecureSandboxUpdateSigner", dependencies: [
            "SecureSandboxUpdateCore",
        ]),
        .executableTarget(name: "SecureSandboxControlCenter", dependencies: [
            "SecureSandboxUpdateCore",
            .product(name: "SwiftTerm", package: "SwiftTerm"),
        ]),
        .testTarget(name: "SecureSandboxNativeAuthCoreTests", dependencies: [
            "SecureSandboxNativeAuthCore",
        ]),
        .testTarget(name: "SecureSandboxNativeCredentialHelperTests", dependencies: [
            "SecureSandboxNativeCredentialHelper",
            "SecureSandboxNativeAuthCore",
        ]),
        .testTarget(name: "SecureSandboxUpdateCoreTests", dependencies: [
            "SecureSandboxUpdateCore",
        ]),
    ]
)
