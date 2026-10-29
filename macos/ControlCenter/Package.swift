// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "SecureSandboxControlCenter",
    platforms: [.macOS(.v27)],
    products: [.executable(name: "SecureSandboxControlCenter", targets: ["SecureSandboxControlCenter"])],
    targets: [.executableTarget(name: "SecureSandboxControlCenter")]
)
