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
        let notaryHistory = try #require(build.range(of: "notarytool history"))
        let sourceArchive = try #require(build.range(of: "archive --format=tar"))
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

        #expect(notaryHistory.lowerBound < sourceArchive.lowerBound)
        #expect(sourceArchive.lowerBound < preflight.lowerBound)
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
                .count - 1 == 5
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
            .count - 1 >= 9)
        let inheritedKeyUnset = try #require(
            build.range(of: "unset SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64")
        )
        let notaryInputsCaptured = try #require(
            build.range(of: "notary_keychain_profile=\"${SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE:-}\"")
        )
        let notaryInputsUnset = try #require(build.range(of:
            "unset SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE SECURE_SANDBOX_NOTARY_KEYCHAIN"
        ))
        let appOnlyKeyRejection = try #require(
            build.range(of: "notarized-app-only path must not receive the update signing key")
        )
        let firstPythonChild = try #require(
            build.range(of: "/usr/bin/python3 -I -c")
        )
        let rootResolution = try #require(build.range(of: "root_dir="))
        #expect(inheritedKeyUnset.lowerBound < rootResolution.lowerBound)
        #expect(notaryInputsCaptured.lowerBound < notaryInputsUnset.lowerBound)
        #expect(build.contains("export -n notary_keychain_profile notary_keychain"))
        #expect(notaryInputsUnset.lowerBound < firstPythonChild.lowerBound)
        #expect(appOnlyKeyRejection.lowerBound < firstPythonChild.lowerBound)
        #expect(build.contains(
            "SECURE_SANDBOX_NOTARY_KEYCHAIN must be an absolute path."
        ))
        #expect(build.contains("notary_keychain_args=("))
        #expect(build.contains(
            "--keychain-profile \"$notary_keychain_profile\"\n" +
                "  --keychain \"$notary_keychain\""
        ))
        #expect(
            build.components(separatedBy: "\"${notary_keychain_args[@]}\"")
                .count - 1 == 3
        )
        for protectedCall in [
            "require_trusted_notary_keychain\n" +
                "if ! /usr/bin/xcrun notarytool history \\",
            "require_trusted_notary_keychain\n" +
                "/usr/bin/xcrun notarytool submit \"$submission\" \\",
            "require_trusted_notary_keychain\n" +
                "/usr/bin/xcrun notarytool log \"$submission_id\" \\",
        ] {
            #expect(build.contains(protectedCall))
        }
        #expect(!build.contains(
            "--keychain-profile \"$SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE\""
        ))
        #expect(build.components(
            separatedBy: "require_trusted_notary_keychain"
        ).count - 1 == 4)
        #expect(build.contains(
            "explicit notarization Keychain profile is unavailable; " +
                "no release artifact work began"
        ))
        let keychainValidatorStart = try #require(build.range(of:
            "require_trusted_notary_keychain() {"
        ))
        let keychainArgumentsStart = try #require(build.range(
            of: "notary_keychain_args=(",
            range: keychainValidatorStart.upperBound..<build.endIndex
        ))
        let keychainValidator = String(
            build[keychainValidatorStart.lowerBound..<keychainArgumentsStart.lowerBound]
        )
        for requiredControl in [
            "not os.path.isabs(path)",
            "\"\\n\" in path",
            "os.path.normpath(path) != path",
            "os.path.realpath(path) != path",
            "os.path.dirname(path) != keychains",
            "basename in {\"\",\".\",\"..\"}",
            "nofollow=getattr(os,\"O_NOFOLLOW\",None)",
            "nonblock=getattr(os,\"O_NONBLOCK\",None)",
            "if nofollow is None or directory is None or nonblock is None",
            "follow_symlinks=False",
            "keychain_before=os.lstat(basename,dir_fd=keychains_fd)",
            "if not stat.S_ISREG(keychain_before.st_mode)",
            "keychain_opened=os.fstat(keychain_fd)",
            "keychain_after=os.lstat(basename,dir_fd=keychains_fd)",
            "not same_inode(home_before,home_opened,home_after)",
            "stat.S_ISDIR(item.st_mode)",
            "not item.st_mode & 0o022",
            "not stat.S_ISREG(keychain_opened.st_mode)",
            "keychain_opened.st_uid != euid",
            "keychain_opened.st_nlink != 1",
            "keychain_opened.st_mode & 0o022",
        ] {
            #expect(keychainValidator.contains(requiredControl))
        }
        #expect(!keychainValidator.contains("0o600"))
        #expect(!keychainValidator.contains("st_mtime"))
        #expect(!keychainValidator.contains("st_size"))
        #expect(!build.contains("swift run"))
        let signerBuild = try #require(
            build.range(of: "--product SecureSandboxUpdateSigner")
        )
        let signerModeGuard = try #require(build.range(of:
            "if [[ \"$release_mode\" == update ]]; then\n" +
                "  /usr/bin/swift build -c release"
        ))
        let signerModeEnd = try #require(build.range(
            of: "\nfi\n\nsubmission=",
            range: signerBuild.upperBound..<build.endIndex
        ))
        #expect(signerModeGuard.lowerBound < signerBuild.lowerBound)
        #expect(signerBuild.upperBound < signerModeEnd.lowerBound)
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
        let artifactModeGuard = try #require(build.range(of:
            "artifact=\"\"\nenvelope=\"\"\n" +
                "if [[ \"$release_mode\" == update ]]; then\nartifact="
        ))
        let artifactCreation = try #require(build.range(of:
            "artifact=\"$output_dir/SecureSandbox-$version-$build.zip\""
        ))
        let manifestCreation = try #require(build.range(of:
            "manifest=\"$output_dir/manifest.json\""
        ))
        let artifactModeEnd = try #require(build.range(
            of: "\nfi\n\nrequire_app_only_manual_admission",
            range: signerExposure.upperBound..<build.endIndex
        ))
        #expect(artifactModeGuard.lowerBound < artifactCreation.lowerBound)
        #expect(artifactCreation.lowerBound < manifestCreation.lowerBound)
        #expect(manifestCreation.lowerBound < signerExposure.lowerBound)
        #expect(signerExposure.upperBound < artifactModeEnd.lowerBound)
        #expect(
            build.components(separatedBy: "--distribution >/dev/null")
                .count - 1 >= 6
        )
        #expect(build.contains("artifact_app=\"$artifact_stage/SecureSandbox.app\""))
        #expect(build.contains("expected=root/\"SecureSandbox.app\""))
        #expect(!build.contains("expected=root/\"SecureSandboxControlCenter.app\""))
        let roundTrip = try #require(build.range(of: "artifact-roundtrip"))
        let publication = try #require(
            build.range(of: "publish_stage=\"$(/usr/bin/mktemp")
        )
        #expect(roundTrip.lowerBound < publication.lowerBound)
        #expect(build.contains("[[ \"$#\" == 4"))
        #expect(build.contains("[[ \"$#\" == 3"))
        #expect(build.contains("${!SECURE_SANDBOX_UPDATE_@}"))
        #expect(build.contains(
            "notarized-app-only path requires a SHA1-pinned Developer ID identity"
        ))
        #expect(build.contains(
            "output_dir=\"$evidence_dir/$version-$build-$sequence\""
        ))
        let expectedEvidenceRouting = """
        if [[ "$release_mode" == update ]]; then
          evidence_dir="$dist_dir/update"
          output_dir="$evidence_dir/$version-$build"
        else
          evidence_dir="$dist_dir/notarized-app"
          output_dir="$evidence_dir/$version-$build-$sequence"
        """
        #expect(build.contains(expectedEvidenceRouting))
        #expect(build.contains("require_app_only_manual_admission"))
        #expect(build.components(
            separatedBy: "require_app_only_manual_admission"
        ).count - 1 == 3)
        #expect(build.contains("notarized_app_sequence_must_advance"))
        #expect(build.contains("notarized_app_only_requires_disabled_update_policy"))
        #expect(build.contains("value.get(\"enabled\") is not False"))
        #expect(build.contains("value.get(\"manifest_url\") is not None"))
        #expect(build.contains("value.get(\"public_key_base64\") is not None"))
        #expect(build.contains("value.get(\"artifact_redirect_hosts\") != []"))
        #expect(build.contains("SECURE_SANDBOX_RELEASE_COMMIT=\"$release_commit\""))
        #expect(build.contains("Print :SSReleaseCommit"))
        #expect(build.contains("value.get(\"jobId\""))
        #expect(build.contains("[0-9a-fA-F]{64}"))
        #expect(build.contains("value[\"sha256\"]"))
        #expect(build.contains("notarized-app-receipt.json"))
        #expect(build.contains(
            "secure-sandbox-control-center-notarized-app-receipt-v1"
        ))
        #expect(build.contains("source_archive_sha256"))
        #expect(build.contains("notary_submission_sha256"))
        #expect(build.contains("notary_log_sha256"))
        #expect(build.contains("evidence.st_uid != os.geteuid()"))
        #expect(build.contains("evidence.st_nlink != 1"))
        #expect(build.contains("stat.S_IMODE(evidence.st_mode) != 0o600"))
        #expect(build.contains("published_app_cdhash"))
        #expect(build.contains("published_helper_cdhash"))
        #expect(build.contains(
            "secure-sandbox-control-center-notarized-app-build-v1"
        ))
        #expect(build.contains(
            "secure-sandbox-control-center-release-build-v1"
        ))
        let legacyOutput = try #require(build.range(of:
            "if [[ \"$release_mode\" == update ]]; then\n" +
                "  printf '{\"schema\":\"secure-sandbox-control-center-release-build-v1\""
        ))
        let appOnlyOutputBranch = try #require(build.range(
            of: "\nelse\n  /usr/bin/python3 -I -c '",
            range: legacyOutput.upperBound..<build.endIndex
        ))
        let appOnlyOutputSchema = try #require(build.range(
            of: "secure-sandbox-control-center-notarized-app-build-v1",
            range: appOnlyOutputBranch.upperBound..<build.endIndex
        ))
        #expect(legacyOutput.lowerBound < appOnlyOutputBranch.lowerBound)
        #expect(appOnlyOutputBranch.lowerBound < appOnlyOutputSchema.lowerBound)
        let appOnlyReceiptGuard = try #require(build.range(of:
            "if [[ \"$release_mode\" == notarized-app-only ]]; then\nnotary_log_sha256="
        ))
        let receiptWrite = try #require(build.range(of:
            "receipt=\"$output_dir/notarized-app-receipt.json\""
        ))
        #expect(appOnlyReceiptGuard.lowerBound < receiptWrite.lowerBound)
        let publishComplete = try #require(
            build.range(of: "publish_complete=true", range: receiptWrite.upperBound..<build.endIndex)
        )
        let publishPreviousRemoval = try #require(
            build.range(
                of: "/bin/rm -rf -- \"$publish_previous\"",
                range: publishComplete.upperBound..<build.endIndex
            )
        )
        #expect(publishComplete.lowerBound < publishPreviousRemoval.lowerBound)

        let updateStore = try controlCenterSource("Services/UpdateStore.swift")
        #expect(updateStore.contains("entries == [\"SecureSandbox.app\"]"))
        #expect(updateStore.contains(
            "extraction.appendingPathComponent(\"SecureSandbox.app\""
        ))

        let bundleBuilder = try controlCenterFile("script/build_and_run.sh")
        let nativeComponentBuilder = try repositoryFile(
            "scripts/build-native-credential-components.sh"
        )
        for helperScript in [bundleBuilder, nativeComponentBuilder] {
            #expect(helperScript.hasPrefix("#!/bin/bash -p\n"))
            #expect(helperScript.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
            #expect(helperScript.contains("SECURE_SANDBOX_SWIFT_HERMETIC"))
            #expect(helperScript.contains("SECURE_SANDBOX_SWIFT_SCRATCH_PATH"))
            #expect(helperScript.contains("--disable-dependency-cache"))
            #expect(helperScript.contains("--disable-build-manifest-caching"))
            #expect(helperScript.contains("--manifest-cache none"))
            #expect(helperScript.contains("--disable-index-store"))
        }
        #expect(bundleBuilder.contains("--only-use-versions-from-resolved-file"))
        #expect(nativeComponentBuilder.contains(
            "NativeHostComponents.Package.swift"
        ))
        #expect(nativeComponentBuilder.contains("--disable-automatic-resolution"))
        #expect(!nativeComponentBuilder.contains(
            "--only-use-versions-from-resolved-file"
        ))
        #expect(bundleBuilder.contains("--product \"$APP_NAME\""))
        #expect(bundleBuilder.contains("--product \"$UPDATE_HELPER_NAME\""))
        #expect(!bundleBuilder.contains(
            "/usr/bin/swift build -c \"$BUILD_CONFIGURATION\" \"${swift_options[@]}\"\n"
                + "bin_path="
        ))
        #expect(bundleBuilder.contains(
            "Developer ID builds require SECURE_SANDBOX_RELEASE_COMMIT"
        ))
        #expect(bundleBuilder.contains("Add :SSReleaseCommit string $RELEASE_COMMIT"))
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
        #expect(installer.contains("require_distribution_floor_absent"))
        #expect(installer.components(
            separatedBy: "require_distribution_floor_absent"
        ).count - 1 == 6)
        #expect(installer.contains("distribution_sequence_must_advance"))
        #expect(installer.contains("distribution_release_commit_invalid"))
        #expect(installer.contains("Print :SSReleaseCommit"))
        #expect(installer.contains("s/^CDHash=//p"))
        #expect(installer.components(
            separatedBy: "require_distribution_evidence_matches_source"
        ).count - 1 == 4)
        let finalEvidence = try #require(installer.range(of:
            "require_distribution_evidence_matches_source \"$installed_app\""
        ))
        let installCommitted = try #require(
            installer.range(of: "complete=true", range: finalEvidence.upperBound..<installer.endIndex)
        )
        let predecessorRemoval = try #require(
            installer.range(
                of: "/bin/rm -rf -- \"$previous_app\"",
                range: installCommitted.upperBound..<installer.endIndex
            )
        )
        #expect(finalEvidence.lowerBound < installCommitted.lowerBound)
        #expect(installCommitted.lowerBound < predecessorRemoval.lowerBound)
    }

    @Test func notaryKeychainValidatorRejectsHostileFilesystemObjects() throws {
        let validator = try embeddedNotaryKeychainValidator()

        do {
            let fixture = try makeNotaryValidatorFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let result = try runNotaryValidator(
                validator,
                path: fixture.keychain.path,
                home: fixture.home.path
            )
            #expect(
                result.status == 0,
                "fixture home was \(fixture.home.path)"
            )
            #expect(!result.timedOut)
            #expect(result.standardOutput.isEmpty)
            #expect(result.standardError.isEmpty)
        }

        try expectNotaryValidatorRejection(validator, caseName: "outside") {
            fixture in
            let outside = fixture.root.appendingPathComponent("outside.keychain")
            try Data([0]).write(to: outside)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: outside.path
            )
            return outside.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "relative") {
            _ in "Library/Keychains/login.keychain-db"
        }
        try expectNotaryValidatorRejection(validator, caseName: "noncanonical") {
            fixture in
            fixture.home.path
                + "/Library/Keychains/../Keychains/login.keychain-db"
        }
        try expectNotaryValidatorRejection(validator, caseName: "terminal-symlink") {
            fixture in
            let target = fixture.keychains.appendingPathComponent("target.keychain")
            try Data([0]).write(to: target)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: target.path
            )
            try FileManager.default.removeItem(at: fixture.keychain)
            try FileManager.default.createSymbolicLink(
                at: fixture.keychain,
                withDestinationURL: target
            )
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "parent-symlink") {
            fixture in
            try FileManager.default.removeItem(at: fixture.keychains)
            let target = fixture.root.appendingPathComponent(
                "alternate-keychains", isDirectory: true
            )
            try FileManager.default.createDirectory(
                at: target, withIntermediateDirectories: false
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: target.path
            )
            let targetKeychain = target.appendingPathComponent("login.keychain-db")
            try Data([0]).write(to: targetKeychain)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: targetKeychain.path
            )
            try FileManager.default.createSymbolicLink(
                at: fixture.keychains,
                withDestinationURL: target
            )
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "hard-link") {
            fixture in
            try FileManager.default.linkItem(
                at: fixture.keychain,
                to: fixture.keychains.appendingPathComponent("second.keychain")
            )
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "writable-file") {
            fixture in
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o664], ofItemAtPath: fixture.keychain.path
            )
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "writable-parent") {
            fixture in
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o770], ofItemAtPath: fixture.keychains.path
            )
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "fifo") {
            fixture in
            try FileManager.default.removeItem(at: fixture.keychain)
            let mkfifo = Process()
            mkfifo.executableURL = URL(fileURLWithPath: "/usr/bin/mkfifo")
            mkfifo.arguments = [fixture.keychain.path]
            try mkfifo.run()
            mkfifo.waitUntilExit()
            try #require(mkfifo.terminationStatus == 0)
            return fixture.keychain.path
        }
        try expectNotaryValidatorRejection(validator, caseName: "nonregular") {
            fixture in
            try FileManager.default.removeItem(at: fixture.keychain)
            try FileManager.default.createDirectory(
                at: fixture.keychain, withIntermediateDirectories: false
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: fixture.keychain.path
            )
            return fixture.keychain.path
        }

        // An unprivileged test process cannot chown this file. Mutate only the
        // exact terminal fstat record so the production ownership branch runs.
        let ownershipNeedle = "keychain_opened=os.fstat(keychain_fd)"
        let wrongOwnerValidator = validator.replacingOccurrences(
            of: ownershipNeedle,
            with: ownershipNeedle
                + "\n    _wrong_owner=list(keychain_opened)"
                + "\n    _wrong_owner[4]=keychain_opened.st_uid+1"
                + "\n    keychain_opened=os.stat_result(_wrong_owner)"
        )
        #expect(wrongOwnerValidator != validator)
        try expectNotaryValidatorRejection(
            wrongOwnerValidator,
            caseName: "wrong-owner"
        ) { fixture in
            fixture.keychain.path
        }

        try expectNotaryValidatorRejection(validator, caseName: "newline") {
            fixture in
            let newline = fixture.keychains.appendingPathComponent(
                "line\nbreak.keychain"
            )
            try Data([0]).write(to: newline)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: newline.path
            )
            return newline.path
        }
    }

    private struct NotaryValidatorFixture {
        let root: URL
        let home: URL
        let keychains: URL
        let keychain: URL
    }

    private struct NotaryValidatorResult {
        let status: Int32
        let timedOut: Bool
        let standardOutput: String
        let standardError: String
    }

    private func embeddedNotaryKeychainValidator() throws -> String {
        let build = try controlCenterFile("script/build_update_release.sh")
        let functionStart = try #require(build.range(of:
            "require_trusted_notary_keychain() {"
        ))
        let pythonStart = try #require(build.range(
            of: "/usr/bin/python3 -I -c '\n",
            range: functionStart.upperBound..<build.endIndex
        ))
        let pythonEnd = try #require(build.range(
            of: "\n' \"$notary_keychain\" \"$operator_home\" || {",
            range: pythonStart.upperBound..<build.endIndex
        ))
        return String(build[pythonStart.upperBound..<pythonEnd.lowerBound])
    }

    private func makeNotaryValidatorFixture() throws -> NotaryValidatorFixture {
        let manager = FileManager.default
        // Python canonicalizes /var to /private/var. Begin with the canonical
        // spelling so the accepted fixture tests policy instead of that alias.
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent(
                "secure-sandbox-notary-validator-\(UUID().uuidString)",
                isDirectory: true
            )
        try manager.createDirectory(
            at: root, withIntermediateDirectories: false
        )
        let home = root.appendingPathComponent("home", isDirectory: true)
        let library = home.appendingPathComponent("Library", isDirectory: true)
        let keychains = library.appendingPathComponent(
            "Keychains", isDirectory: true
        )
        try manager.createDirectory(
            at: keychains, withIntermediateDirectories: true
        )
        for directory in [root, home, library, keychains] {
            try manager.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: directory.path
            )
        }
        let keychain = keychains.appendingPathComponent("login.keychain-db")
        try Data([0]).write(to: keychain)
        try manager.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: keychain.path
        )
        return NotaryValidatorFixture(
            root: root,
            home: home,
            keychains: keychains,
            keychain: keychain
        )
    }

    private func runNotaryValidator(
        _ source: String,
        path: String,
        home: String
    ) throws -> NotaryValidatorResult {
        let process = Process()
        let standardOutput = Pipe()
        let standardError = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-c", source, path, home]
        process.currentDirectoryURL = URL(fileURLWithPath: home)
        process.standardOutput = standardOutput
        process.standardError = standardError
        try process.run()
        let deadline = Date().addingTimeInterval(2)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        let timedOut = process.isRunning
        if timedOut {
            process.terminate()
        }
        process.waitUntilExit()
        return NotaryValidatorResult(
            status: process.terminationStatus,
            timedOut: timedOut,
            standardOutput: String(
                data: standardOutput.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? "",
            standardError: String(
                data: standardError.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
        )
    }

    private func expectNotaryValidatorRejection(
        _ source: String,
        caseName: String,
        mutate: (NotaryValidatorFixture) throws -> String
    ) throws {
        let fixture = try makeNotaryValidatorFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let path = try mutate(fixture)
        let result = try runNotaryValidator(
            source,
            path: path,
            home: fixture.home.path
        )
        #expect(!result.timedOut, "\(caseName): validator blocked")
        #expect(result.status == 1, "\(caseName): expected rejection")
        #expect(result.standardOutput.isEmpty, "\(caseName): unexpected stdout")
        #expect(
            result.standardError == "control_center_notary_keychain_untrusted\n",
            "\(caseName): failure was not stable"
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
