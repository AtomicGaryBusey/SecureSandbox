import Foundation
import Testing

@Suite struct ControlCenterSecurityContractTests {
    @Test func nativeStackInspectionUsesSharedDescriptorAndPeerControls() throws {
        let source = try controlCenterSource(
            "Services/NativeStackControlClient.swift"
        )

        #expect(source.contains(
            "NativeDescriptorInheritanceGate.makeUnixStreamSocket()"
        ))
        #expect(source.contains("NativeBrokerPeerIdentity.requireRoot(descriptor)"))
        #expect(!source.contains("socket(AF_UNIX, SOCK_STREAM, 0)"))
        for checkedResult in [
            "guard noSignalResult == 0",
            "guard receiveTimeoutResult == 0",
            "guard sendTimeoutResult == 0",
        ] {
            #expect(source.contains(checkedResult))
        }
        for stableError in [
            "native_stack_inspect_socket_unavailable",
            "native_stack_inspect_socket_nosigpipe_failed",
            "native_stack_inspect_socket_receive_timeout_failed",
            "native_stack_inspect_socket_send_timeout_failed",
            "native_stack_inspect_peer_identity_invalid",
        ] {
            #expect(source.contains(stableError))
        }
    }

    @Test func touchIDLaunchersAreNotDefaultKeyboardActions() throws {
        for (path, expectedSafeCancelCount) in [
            ("Views/ModelProfilesSettingsView.swift", 1),
            ("Views/ModelStackSettingsView.swift", 6),
            ("Views/NativeDeploymentControlView.swift", 3),
        ] {
            let source = try controlCenterSource(path)
            #expect(
                source.components(separatedBy: ".keyboardShortcut(.cancelAction)")
                    .count - 1 >= expectedSafeCancelCount
            )
            let lines = source.components(separatedBy: .newlines)
            for index in lines.indices where lines[index].contains(
                ".keyboardShortcut(.defaultAction)"
            ) {
                let lowerBound = max(lines.startIndex, index - 12)
                let context = lines[lowerBound...index].joined(separator: "\n")
                #expect(!context.localizedCaseInsensitiveContains("touch id"))
                #expect(!context.contains("onAuthorize"))
                #expect(!context.contains("approve()"))
            }
        }
    }

    @Test func directBrokerTreatsSSARAsRejectionOnly() throws {
        let source = try controlCenterSource(
            "Services/NativeSessionBrokerClient.swift"
        )
        #expect(source.contains("NativeBrokerRejectionFrame.hasMagic(response)"))
        #expect(source.contains("NativeBrokerRejectionFrame.decodeRejectedError("))
        #expect(source.contains("native_broker_rejection_frame_invalid"))
        #expect(source.contains("throw NativeSessionBrokerError.rejected(rejection)"))
    }

    private func controlCenterSource(_ relativePath: String) throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/SecureSandboxControlCenter")
            .appendingPathComponent(relativePath)
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
