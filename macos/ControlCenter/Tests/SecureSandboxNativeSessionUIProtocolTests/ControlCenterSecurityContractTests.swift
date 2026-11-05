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

    @Test func updateReleaseValidatesSigningBeforeNotarizationAndTrustAfterStapling() throws {
        let build = try controlCenterFile("script/build_update_release.sh")
        let validation = try controlCenterFile("script/validate_bundle.sh")
        let preflight = try #require(build.range(of: "--pre-notarization"))
        let submission = try #require(build.range(of: "notarytool submit"))
        let accepted = try #require(
            build.range(of: "control_center_notarization_not_accepted")
        )
        let log = try #require(build.range(of: "notarytool log"))
        let cleanLog = try #require(
            build.range(of: "control_center_notary_log_not_clean")
        )
        let staple = try #require(build.range(of: "stapler staple"))
        let distribution = try #require(
            build.range(of: "--distribution", range: staple.upperBound..<build.endIndex)
        )

        #expect(preflight.lowerBound < submission.lowerBound)
        #expect(submission.lowerBound < accepted.lowerBound)
        #expect(accepted.lowerBound < log.lowerBound)
        #expect(log.lowerBound < cleanLog.lowerBound)
        #expect(cleanLog.lowerBound < staple.lowerBound)
        #expect(staple.lowerBound < distribution.lowerBound)
        #expect(build.contains("--output-format json"))
        #expect(build.contains("value.get(\"status\") != \"Accepted\""))
        #expect(build.contains("re.fullmatch("))
        #expect(build.contains(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
                "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ))
        #expect(build.contains("value.get(\"statusCode\")"))
        #expect(build.contains("isinstance(value[\"statusCode\"], bool)"))
        #expect(build.contains("\"issues\" not in value"))
        #expect(build.contains("value[\"issues\"] not in (None, [])"))
        #expect(build.contains("symbolic-ref --quiet --short HEAD"))
        #expect(build.contains("status --porcelain=v1 --untracked-files=all"))
        #expect(build.contains("if ! release_status="))
        #expect(build.contains("if ! current_status="))
        #expect(!build.contains("-z \"$(/usr/bin/git"))
        #expect(
            build.components(separatedBy: "require_unchanged_release_source")
                .count - 1 == 4
        )
        #expect(build.contains("archive --format=tar"))
        #expect(build.contains("\"$release_commit\""))
        #expect(build.contains("source_root=\"$release_workspace/source\""))
        #expect(build.contains("candidate_control=\"$source_root/macos/ControlCenter\""))
        #expect(build.contains("Package.resolved"))
        #expect(build.contains("--scratch-path \"$swift_scratch\""))
        #expect(build.contains("--disable-dependency-cache"))
        #expect(build.contains("--disable-build-manifest-caching"))
        #expect(build.contains("--manifest-cache none"))
        #expect(build.contains("--only-use-versions-from-resolved-file"))
        #expect(build.contains("--disable-prefetching"))
        #expect(build.contains("--disable-experimental-prebuilts"))
        #expect(build.contains("--disable-index-store"))
        #expect(build.contains("set +x\nset +a"))
        #expect(build.hasPrefix("#!/bin/bash -p\n"))
        #expect(build.contains("[[ \"$-\" == *p* ]]"))
        #expect(build.contains("[[ \"$-\" == *p* ]]"))
        #expect(build.contains("Execute this release builder directly"))
        #expect(build.contains("umask 077"))
        #expect(build.contains("export -n update_signing_key"))
        #expect(build.contains("unset PYTHONHOME PYTHONPATH"))
        #expect(build.contains("unset CODESIGN_ALLOCATE"))
        #expect(build.contains("\"${!DYLD_@}\" \"${!LD_@}\""))
        #expect(build.components(separatedBy: "/usr/bin/python3 -I -c")
            .count - 1 == 4)
        let inheritedKeyUnset = try #require(
            build.range(of: "unset SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64")
        )
        let rootResolution = try #require(build.range(of: "root_dir="))
        #expect(inheritedKeyUnset.lowerBound < rootResolution.lowerBound)
        #expect(!build.contains("swift run"))
        let signerBuild = try #require(
            build.range(of: "--product SecureSandboxUpdateSigner")
        )
        let signerExposure = try #require(build.range(of:
            "SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64=\"$update_signing_key\""
        ))
        #expect(signerBuild.lowerBound < signerExposure.lowerBound)
        #expect(
            build.components(separatedBy:
                "SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64=\"$update_signing_key\""
            ).count - 1 == 1
        )
        #expect(build.contains("unset update_signing_key"))
        #expect(build.contains("control_center_artifact_layout_invalid"))
        #expect(
            build.components(separatedBy: "--distribution >/dev/null")
                .count - 1 == 5
        )
        #expect(build.contains("artifact_app=\"$artifact_stage/SecureSandbox.app\""))
        #expect(build.contains("expected=root/\"SecureSandbox.app\""))
        #expect(!build.contains("expected=root/\"SecureSandboxControlCenter.app\""))
        let roundTrip = try #require(build.range(of: "artifact-roundtrip"))
        let publication = try #require(
            build.range(of: "publish_stage=\"$(/usr/bin/mktemp")
        )
        #expect(roundTrip.lowerBound < publication.lowerBound)

        let updateStore = try controlCenterSource("Services/UpdateStore.swift")
        #expect(updateStore.contains("entries == [\"SecureSandbox.app\"]"))
        #expect(updateStore.contains(
            "extraction.appendingPathComponent(\"SecureSandbox.app\""
        ))

        for helperScript in [
            try controlCenterFile("script/build_and_run.sh"),
            try repositoryFile("scripts/build-native-credential-components.sh"),
        ] {
            #expect(helperScript.hasPrefix("#!/bin/bash -p\n"))
            #expect(helperScript.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
            #expect(helperScript.contains("SECURE_SANDBOX_SWIFT_HERMETIC"))
            #expect(helperScript.contains("SECURE_SANDBOX_SWIFT_SCRATCH_PATH"))
            #expect(helperScript.contains("--disable-dependency-cache"))
            #expect(helperScript.contains("--disable-build-manifest-caching"))
            #expect(helperScript.contains("--manifest-cache none"))
            #expect(helperScript.contains("--only-use-versions-from-resolved-file"))
            #expect(helperScript.contains("--disable-index-store"))
        }
        let bundleBuilder = try controlCenterFile("script/build_and_run.sh")
        #expect(bundleBuilder.contains(
            "$swift_build_root/checkouts/SwiftTerm/LICENSE"
        ))
        #expect(bundleBuilder.contains(
            "icon_info=\"$swift_build_root/AppIcon.partial-info.plist\""
        ))
        #expect(validation.contains("--pre-notarization"))
        #expect(validation.hasPrefix("#!/bin/bash -p\n"))
        #expect(validation.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
        #expect(validation.contains("/usr/bin/dirname"))
        #expect(validation.contains("$mode\" != --local"))
        #expect(validation.contains("authorized_team=\"389K3H8Y32\""))
        #expect(validation.contains(
            "certificate leaf[subject.OU] = \\\"$authorized_team\\\""
        ))
        #expect(validation.contains(
            "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        ))
        #expect(
            validation.components(separatedBy: "-R=\"$").count - 1 == 2
        )
        #expect(validation.contains(
            "$app_identifier\" == org.zebeth.SecureSandbox.ControlCenter"
        ))
        #expect(validation.contains(
            "$helper_identifier\" == SecureSandboxUpdateInstaller"
        ))
        #expect(validation.contains("$app_team\" == \"$authorized_team"))
        #expect(validation.contains("$helper_team\" == \"$authorized_team"))
        #expect(validation.contains("app_timestamp="))
        #expect(validation.contains("helper_timestamp="))
        #expect(validation.contains("$app_timestamp\" != none"))
        #expect(validation.contains("$helper_timestamp\" != none"))
        #expect(validation.contains("$mode\" == --distribution"))
        let staplerValidation = try #require(
            validation.range(of: "stapler validate")
        )
        let gatekeeper = try #require(
            validation.range(of: "/usr/sbin/spctl -a -vv")
        )
        #expect(staplerValidation.lowerBound < gatekeeper.lowerBound)

        let installer = try controlCenterFile("script/install_local.sh")
        #expect(installer.hasPrefix("#!/bin/bash -p\n"))
        #expect(installer.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
        #expect(installer.contains("/usr/bin/dirname"))
        #expect(installer.contains("pwd -P"))
        #expect(installer.contains("validation_mode=\"${1:---local}\""))
        #expect(installer.contains("Usage: $0 [--local|--distribution]"))
        let runningFence = try #require(
            installer.range(of: "/usr/bin/pgrep -x SecureSandboxControlCenter")
        )
        let firstMutation = try #require(installer.range(of: "mkdir -m 755"))
        #expect(runningFence.lowerBound < firstMutation.lowerBound)
        #expect(!installer.contains("pkill"))
        #expect(
            installer.components(separatedBy: "require_control_center_stopped")
                .count - 1 == 6
        )
        for absoluteCommand in [
            "/bin/mkdir", "/usr/bin/stat", "/usr/bin/mktemp",
            "/bin/mv", "/bin/rm",
        ] {
            #expect(installer.contains(absoluteCommand))
        }
        #expect(installer.contains("require_local_mode_ad_hoc"))
        #expect(installer.contains("$signature\" == adhoc"))
        #expect(installer.contains("$team\" == \"not set\""))
        #expect(!installer.contains("$candidate\" --pre-notarization"))
        #expect(
            installer.components(
                separatedBy: "\"$validation_mode\" >/dev/null"
            ).count - 1 == 5
        )
        #expect(
            installer.components(
                separatedBy: "require_local_mode_ad_hoc \"$"
            ).count - 1 == 5
        )
    }

    private func controlCenterSource(_ relativePath: String) throws -> String {
        try controlCenterFile(
            "Sources/SecureSandboxControlCenter/\(relativePath)"
        )
    }

    private func controlCenterFile(_ relativePath: String) throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent(relativePath)
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }

    private func repositoryFile(_ relativePath: String) throws -> String {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }
}
