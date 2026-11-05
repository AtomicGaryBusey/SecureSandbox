#!/usr/bin/env python3
"""Source contracts for release-signing child builders.

These tests deliberately stop before Xcode, SwiftPM, Keychain, signing, or
notarization.  Live signing evidence belongs to the attended release ceremony.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
TOUCHID = REPO / "scripts/build-touchid-authorization-ui.sh"
COMPONENTS = REPO / "scripts/build-native-credential-components.sh"
NATIVE_HOST_PACKAGE = (
    REPO / "macos/ControlCenter/NativeHostComponents.Package.swift"
)
FIXED_TEAM = "389K3H8Y32"


class NativeChildBuilderSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.touchid = TOUCHID.read_text(encoding="utf-8")
        cls.components = COMPONENTS.read_text(encoding="utf-8")

    def test_both_builders_require_direct_privileged_bash_and_sanitize(self):
        required = (
            "#!/bin/bash -p",
            '[[ "$-" == *p* ]]',
            "set +x",
            "set +a",
            "umask 077",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "unset BASH_ENV CDPATH ENV TAR_OPTIONS",
            "GIT_CONFIG_NOSYSTEM=1",
            "unset DEVELOPER_DIR TOOLCHAINS SDKROOT SWIFT_EXEC SWIFTC_EXEC",
            "unset CC CXX LD AR NM CFLAGS CPPFLAGS CXXFLAGS LDFLAGS",
            "unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT",
            '"${!DYLD_@}" "${!LD_@}"',
            '"${!SWIFTPM_@}" "${!XCODE_@}"',
        )
        for source in (self.touchid, self.components):
            for value in required:
                self.assertIn(value, source)

    def test_no_concrete_certificate_fingerprint_is_tracked(self):
        literal = re.compile(r'(?<![A-Za-z0-9])[0-9A-Fa-f]{40}(?![A-Za-z0-9])')
        self.assertIsNone(literal.search(self.touchid))
        self.assertIsNone(literal.search(self.components))

    def test_touchid_release_selects_and_proves_exact_leaf(self):
        required = (
            f'fixed_team="{FIXED_TEAM}"',
            "SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint",
            "touchid_developer_id_requires_release_candidate_contract",
            '"CODE_SIGN_IDENTITY=$developer_id"',
            "-insert signingCertificate -string \"$developer_id\"",
            "-insert teamID -string \"$fixed_team\"",
            'certificate leaf = H\\"$developer_id\\"',
            "--extract-certificates",
            "SHA1 Fingerprint=",
            "flags=0x10000(runtime)",
            'values("Timestamp=")',
            'profile.get("DeveloperCertificates")',
            'profile.get("ProvisionsAllDevices") is not True',
            'profile.get("Platform")!=["OSX"]',
            "touchid_developer_id_profile_certificate_mismatch",
        )
        for value in required:
            self.assertIn(value, self.touchid)
        self.assertNotIn(
            "SECURE_SANDBOX_DEVELOPER_ID_must_be_a_Developer_ID_name_or_SHA1",
            self.touchid,
        )

    def test_touchid_pins_exact_external_team_config(self):
        required = (
            "SECURE_SANDBOX_SIGNING_CONFIG",
            "touchid_release_contract_invalid",
            'expected=b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\\n"',
            "os.O_NOFOLLOW",
            "opened.st_nlink!=1",
            "mode & (0o222 if release else 0o022)",
            "release and os.access(source,os.W_OK)",
            "touchid_signing_config_digest_mismatch",
            "touchid_pinned_signing_config_changed",
            "touchid_signing_config_changed",
            '-xcconfig "$pinned_signing_config"',
        )
        for value in required:
            self.assertIn(value, self.touchid)

    def test_release_children_share_the_parent_candidate_contract(self):
        required = (
            "SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY",
            "SECURE_SANDBOX_RELEASE_OUTPUT_ROOT",
            "SECURE_SANDBOX_RELEASE_COMMIT",
            "SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256",
            "SECURE_SANDBOX_EXPECTED_TEAM_ID",
            "SECURE_SANDBOX_SIGNING_CONFIG_SHA256",
            "SECURE_SANDBOX_RELEASE_SOURCE_ROOT",
        )
        for source in (self.touchid, self.components):
            for value in required:
                self.assertIn(value, source)
            self.assertIn('repo="$release_source_root"', source)
            self.assertIn('directory_record "$repo" 1', source)
            self.assertIn('validate_directory_record "$repo"', source)
            self.assertIn('unset SECURE_SANDBOX_RELEASE_SOURCE_ROOT', source)
        self.assertIn("touchid_release_source_root_untrusted", self.touchid)
        self.assertIn(
            "native_component_release_source_root_untrusted", self.components,
        )

    def test_component_build_is_fresh_hermetic_and_exact_product_scoped(self):
        required = (
            "SECURE_SANDBOX_SWIFT_HERMETIC_must_be_1",
            "native_component_swift_scratch_not_fresh",
            "NativeHostComponents.Package.swift",
            "dependencies: []",
            "sandbox-exec",
            "(deny network*)",
            "--disable-sandbox",
            "--disable-automatic-resolution",
            "--disable-netrc",
            "--disable-keychain",
            "--skip-update",
            "--disable-prefetching",
            "native_component_external_dependency_material_present",
            "--product SecureSandboxNativeCredentialXPCService",
            "--product SecureSandboxNativeStackBackend",
            "--product SecureSandboxNativeProjectionConsumer",
        )
        combined = self.components + NATIVE_HOST_PACKAGE.read_text(encoding="utf-8")
        for value in required:
            self.assertIn(value, combined)
        self.assertNotIn("SwiftTerm", NATIVE_HOST_PACKAGE.read_text(encoding="utf-8"))
        self.assertNotIn(".package(", NATIVE_HOST_PACKAGE.read_text(encoding="utf-8"))

    def test_dependency_free_package_describes_with_network_denied(self):
        source_root = REPO / "macos/ControlCenter/Sources"
        targets = (
            "SecureSandboxNativeAuthCore",
            "SecureSandboxNativeXPCTransport",
            "SecureSandboxNativeCredentialHelper",
            "SecureSandboxNativeCredentialXPCService",
            "SecureSandboxNativeStackBackend",
            "SecureSandboxNativeProjectionConsumer",
        )
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "package"
            (package / "Sources").mkdir(parents=True)
            shutil.copy2(NATIVE_HOST_PACKAGE, package / "Package.swift")
            for target in targets:
                shutil.copytree(source_root / target, package / "Sources" / target)
            completed = subprocess.run(
                [
                    "/usr/bin/sandbox-exec", "-p",
                    "(version 1)(allow default)(deny network*)",
                    "/usr/bin/swift", "package", "--disable-sandbox",
                    "--package-path", str(package), "describe", "--type", "json",
                ],
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                check=False, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            description = json.loads(completed.stdout)
            self.assertEqual(description["name"], "SecureSandboxNativeHostComponents")
            self.assertEqual(description.get("dependencies"), [])

    def test_release_paths_are_identity_bound_and_cleanup_is_non_destructive(self):
        common = (
            "directory_record",
            "validate_directory_record",
            "run_in_recorded_directory",
            "os.O_DIRECTORY|os.O_NOFOLLOW",
            "(opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)",
            "cleanup_root_changed",
            "renameatx_np",
            ".secure-sandbox-retained-",
        )
        for source in (self.touchid, self.components):
            for value in common:
                self.assertIn(value, source)
            for destructive in (
                "os.unlink(", "os.rmdir(", "/bin/rm -f", "/bin/rm -rf",
                "shutil.rmtree",
            ):
                self.assertNotIn(destructive, source)

    def test_embedded_cleanup_retires_complete_tree_intact(self):
        marker = (
            "import ctypes,errno,json,os,stat,sys\n"
            "path=sys.argv[1]; expected=json.loads(sys.argv[2])\n"
        )
        for label, source, terminator in (
            ("touchid", self.touchid, "\n' \"$derived\" \"$derived_record\""),
            (
                "components", self.components,
                "\n' \"$build_root\" \"$build_root_record\"",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = parent / "build-root"
                root.mkdir(mode=0o700)
                (root / "must-survive").write_text(
                    "retained evidence\n", encoding="ascii",
                )
                info = root.stat()
                record = json.dumps({
                    "dev": info.st_dev, "gid": info.st_gid,
                    "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                }, separators=(",", ":"), sort_keys=True)
                start = source.index(marker)
                end = source.index(terminator, start)
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", "-c", source[start:end],
                     str(root), record],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertFalse(root.exists())
                retained = list(parent.glob(".secure-sandbox-retained-*"))
                self.assertEqual(len(retained), 1)
                self.assertEqual(
                    (retained[0] / "must-survive").read_text(encoding="ascii"),
                    "retained evidence\n",
                )

    def test_existing_nonrelease_output_is_retired_without_deletion(self):
        marker = (
            "import ctypes,errno,json,os,stat,sys\n"
            "path,encoded,name,failure=sys.argv[1:]\n"
        )
        terminator = "\n' \"$1\" \"$2\" \"$3\" \"$4\""
        for label, source in (
            ("touchid", self.touchid), ("components", self.components),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "artifacts"
                root.mkdir(mode=0o700)
                output = root / "old-output"
                output.write_text("recoverable old output\n", encoding="ascii")
                info = root.stat()
                record = json.dumps({
                    "dev": info.st_dev, "gid": info.st_gid,
                    "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                }, separators=(",", ":"), sort_keys=True)
                start = source.index(marker)
                end = source.index(terminator, start)
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", "-c", source[start:end],
                     str(root), record, output.name, "retention_failed"],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertFalse(output.exists())
                retained = list(root.glob(".secure-sandbox-retained-*"))
                self.assertEqual(len(retained), 1)
                self.assertEqual(
                    retained[0].read_text(encoding="ascii"),
                    "recoverable old output\n",
                )

    def test_release_source_snapshots_are_rechecked_after_build_and_publish(self):
        for value in (
            "touchid_source_record",
            "touchid_source_changed_during_snapshot",
            "touchid_source_changed_during_build",
            "touchid_source_changed_before_completion",
        ):
            self.assertIn(value, self.touchid)
        for value in (
            "closed_component_source_record",
            "closed_tree_record",
            "native_component_snapshot_not_source_equivalent",
            "native_component_source_changed_during_build",
            "native_component_source_changed_before_completion",
        ):
            self.assertIn(value, self.components)

    def test_component_snapshot_projection_rejects_malicious_copied_bytes(self):
        marker = (
            "import hashlib,json,os,pathlib,stat,sys\n"
            "root=pathlib.Path(sys.argv[1]); expected_uid=int(sys.argv[2]); "
            "layout=sys.argv[3]\n"
        )
        terminator = "\n' \"$1\" \"$EUID\" \"$2\""
        start = self.components.index(marker)
        end = self.components.index(terminator, start)
        program = self.components[start:end]
        targets = (
            "SecureSandboxNativeAuthCore",
            "SecureSandboxNativeXPCTransport",
            "SecureSandboxNativeCredentialHelper",
            "SecureSandboxNativeCredentialXPCService",
            "SecureSandboxNativeStackBackend",
            "SecureSandboxNativeProjectionConsumer",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            snapshot = root / "snapshot"
            (source / "Sources").mkdir(parents=True)
            (snapshot / "Sources").mkdir(parents=True)
            (source / "NativeHostComponents.Package.swift").write_text(
                "// exact package\n", encoding="utf-8",
            )
            (snapshot / "Package.swift").write_text(
                "// exact package\n", encoding="utf-8",
            )
            for target in targets:
                source_target = source / "Sources" / target
                snapshot_target = snapshot / "Sources" / target
                source_target.mkdir()
                snapshot_target.mkdir()
                (source_target / "Input.swift").write_text(
                    f"// exact {target}\n", encoding="utf-8",
                )
                shutil.copy2(
                    source_target / "Input.swift",
                    snapshot_target / "Input.swift",
                )

            def record(path: Path, layout: str) -> str:
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", "-c", program,
                     str(path), str(path.stat().st_uid), layout],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                return completed.stdout.strip()

            source_record = record(source, "source")
            self.assertEqual(record(snapshot, "snapshot"), source_record)
            (snapshot / "Sources/SecureSandboxNativeAuthCore/Input.swift").write_text(
                "// malicious copied source\n", encoding="utf-8",
            )
            self.assertNotEqual(record(snapshot, "snapshot"), source_record)

    def test_all_components_prove_same_leaf_team_runtime_and_timestamp(self):
        required = (
            f'fixed_team="{FIXED_TEAM}"',
            "SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint",
            'certificate leaf = H\\"$identity\\"',
            "--extract-certificates",
            "SHA1 Fingerprint=",
            '"$fingerprint" == "$identity"',
            '"$observed_team" == "$fixed_team"',
            '"$authority" == "Developer ID Application:"*" ($fixed_team)"',
            '"$details" == *"flags=0x10000(runtime)"*',
            '&& -n "$timestamp"',
            "native_component_unexpected_entitlements",
            "published-helper",
            "published-backend",
            "published-consumer",
        )
        for value in required:
            self.assertIn(value, self.components)

    def test_nonprivileged_shell_invocation_fails_before_build_tools(self):
        for script, message in (
            (TOUCHID, "touchid_builder_requires_direct_privileged_bash_execution"),
            (
                COMPONENTS,
                "native_component_builder_requires_direct_privileged_bash_execution",
            ),
        ):
            completed = subprocess.run(
                ["/bin/bash", str(script)],
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(message, completed.stderr)

    def test_release_and_named_identity_reject_before_signing(self):
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY": "1",
        }
        touchid = subprocess.run(
            [str(TOUCHID)], env=environment, check=False,
            capture_output=True, text=True,
        )
        self.assertEqual(touchid.returncode, 2)
        self.assertIn(
            "SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint",
            touchid.stderr,
        )

        named = dict(environment)
        named["SECURE_SANDBOX_DEVELOPER_ID"] = (
            f"Developer ID Application: Example ({FIXED_TEAM})"
        )
        components = subprocess.run(
            [str(COMPONENTS)], env=named, check=False,
            capture_output=True, text=True,
        )
        self.assertEqual(components.returncode, 2)
        self.assertIn(
            "SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint",
            components.stderr,
        )

    def test_release_config_must_be_exact_read_only_before_identity_lookup(self):
        raw = b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "macos/TouchIDAuthorization"
            for relative in (
                "Package.swift", "AuthorizationUI.entitlements", "Info.plist",
                "Artwork/AppIcon.icon/icon.json",
                "Artwork/AppIcon.icon/Assets/AuthorizationLock.svg",
                "Artwork/AppIcon.icon/Assets/ControlStack.svg",
                "Artwork/AppIcon.icon/Assets/DiagonalAccent.svg",
                "SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj",
                "Sources/AuthorizationCore/AuthorizationRequest.swift",
                "Sources/AuthorizationCore/ExecutionApprovalCrypto.swift",
                "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift",
                "Sources/SecureSandboxAuthorizationUI/main.swift",
            ):
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(
                    REPO / "macos/TouchIDAuthorization" / relative,
                    destination,
                )
            output = root / "output"
            output.mkdir(mode=0o700)
            config = root / "Signing.local.xcconfig"
            config.write_bytes(raw)
            config.chmod(0o644)
            environment = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY": "1",
                "SECURE_SANDBOX_RELEASE_OUTPUT_ROOT": str(output),
                "SECURE_SANDBOX_RELEASE_COMMIT": "b" * 40,
                "SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256": "c" * 64,
                "SECURE_SANDBOX_EXPECTED_TEAM_ID": FIXED_TEAM,
                "SECURE_SANDBOX_SIGNING_CONFIG": str(config),
                "SECURE_SANDBOX_SIGNING_CONFIG_SHA256": hashlib.sha256(raw).hexdigest(),
                "SECURE_SANDBOX_DEVELOPER_ID": "a" * 40,
                "SECURE_SANDBOX_RELEASE_SOURCE_ROOT": str(root.resolve()),
            }
            completed = subprocess.run(
                [str(TOUCHID)], env=environment, check=False,
                capture_output=True, text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("touchid_signing_config_untrusted", completed.stderr)

            config.chmod(0o444)
            completed = subprocess.run(
                [str(TOUCHID)], env=environment, check=False,
                capture_output=True, text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "touchid_requested_developer_id_unavailable", completed.stderr,
            )


if __name__ == "__main__":
    unittest.main()
