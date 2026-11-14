#!/usr/bin/env python3

import importlib.util
import ast
import contextlib
import fcntl
import hashlib
import json
import os
import plistlib
import py_compile
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
import uuid
import zipfile
import io
from pathlib import Path
from typing import Mapping
from unittest import mock

from scripts import native_deployment_payload as NATIVE_DEPLOYMENT_PAYLOAD
from shared.harness_runtime_binding import make_binding as make_harness_binding
from shared.model_stack_runtime_binding import make_binding as make_model_stack_binding, make_brokered_binding
from shared.runtime_authority import make_binding as make_runtime_authority
from shared.session_context_binding import make_binding as make_session_context_binding

SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent
MANAGER_PATH = SCRIPT_DIR / "host-controller-release.py"
SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MANAGER)
LAUNCHER_PATH = SCRIPT_DIR / "secure-sandbox-claude-launcher.py"
LAUNCHER_SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher_test", LAUNCHER_PATH)
LAUNCHER = importlib.util.module_from_spec(LAUNCHER_SPEC)
assert LAUNCHER_SPEC.loader is not None
LAUNCHER_SPEC.loader.exec_module(LAUNCHER)
AUTHORIZATION_PATH = SCRIPT_DIR / "operator-authorization.py"
AUTHORIZATION_SPEC = importlib.util.spec_from_file_location(
    "operator_authorization_inventory_test", AUTHORIZATION_PATH,
)
AUTHORIZATION = importlib.util.module_from_spec(AUTHORIZATION_SPEC)
assert AUTHORIZATION_SPEC.loader is not None
AUTHORIZATION_SPEC.loader.exec_module(AUTHORIZATION)
AUDIT_PATH = SCRIPT_DIR / "external-containment-audit.py"
AUDIT_SPEC = importlib.util.spec_from_file_location(
    "external_containment_inventory_test", AUDIT_PATH,
)
AUDIT = importlib.util.module_from_spec(AUDIT_SPEC)
assert AUDIT_SPEC.loader is not None
AUDIT_SPEC.loader.exec_module(AUDIT)


def inactive_launchd_snapshot(
    *, domain: str, label: str, plist: Path, program: str,
    runs: int | None = 0,
) -> str:
    lines = [
        f"{domain}/{label} = {{",
        "\tactive count = 0",
        f"\tpath = {plist}",
        "\ttype = LaunchAgent",
        "\tstate = not running",
        "",
        f"\tprogram = {program}",
        "\targuments = {",
        f"\t\t{program}",
        "\t}",
        "",
        f"\tdomain = {domain} [100002]",
        "\tasid = 100002",
    ]
    if runs is not None:
        lines.append(f"\truns = {runs}")
    lines.extend([
        "",
        "\tendpoints = {",
        f'\t\t"{label}" = {{',
        "\t\t\tport = 0x0",
        "\t\t\tactive = 0",
        "\t\t\tmanaged = 1",
        "\t\t\treset = 0",
        "\t\t}",
        "\t}",
        "",
        "\tspawn type = interactive (4)",
        "\tjob state = uninitialized",
        "}",
        "",
    ])
    return "\n".join(lines)


class NativeCredentialPackagingContractTests(unittest.TestCase):
    def test_gpgv_runtime_dependency_closure_is_exact(self):
        libraries = {
            name: (name + "\n").encode("ascii")
            for name in MANAGER.GPGV_RUNTIME_LIBRARY_NAMES
        }

        def inspected(argv, **_kwargs):
            path = Path(argv[2])
            dependencies = ["/usr/lib/libSystem.B.dylib"]
            if path.name == "gpgv":
                dependencies.extend(
                    "/opt/homebrew/opt/example/lib/" + name
                    for name in sorted(MANAGER.GPGV_RUNTIME_LIBRARY_NAMES)
                )
            else:
                dependencies.append(
                    "/opt/homebrew/opt/example/lib/" + path.name
                )
            stdout = str(path) + ":\n" + "".join(
                "\t" + dependency
                + " (compatibility version 1.0.0, current version 1.0.0)\n"
                for dependency in dependencies
            )
            return subprocess.CompletedProcess(argv, 0, stdout=stdout)

        with mock.patch.object(
            MANAGER.subprocess, "run", side_effect=inspected,
        ):
            MANAGER.validate_gpgv_runtime_dependency_closure(
                b"gpgv", libraries,
            )

        def unbound(argv, **kwargs):
            result = inspected(argv, **kwargs)
            if Path(argv[2]).name == "libassuan.9.dylib":
                result.stdout += (
                    "\t/opt/homebrew/opt/newlib/lib/libnew.1.dylib "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                )
            return result

        with mock.patch.object(
            MANAGER.subprocess, "run", side_effect=unbound,
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "gpgv_dependency_unbound"
        ):
            MANAGER.validate_gpgv_runtime_dependency_closure(
                b"gpgv", libraries,
            )

        def traversal(argv, **kwargs):
            result = inspected(argv, **kwargs)
            if Path(argv[2]).name == "gpgv":
                result.stdout += (
                    "\t/usr/lib/../../../opt/homebrew/evil/libevil.dylib "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                )
            return result

        with mock.patch.object(
            MANAGER.subprocess, "run", side_effect=traversal,
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "gpgv_dependency_path_invalid"
        ):
            MANAGER.validate_gpgv_runtime_dependency_closure(
                b"gpgv", libraries,
            )

    def test_gpgv_runtime_capsule_is_deterministic_and_closed(self):
        executable = b"\xcf\xfa\xed\xfe" + b"test-gpgv-mach-o"
        libraries = {
            name: (name + "\n").encode("ascii")
            for name in MANAGER.GPGV_RUNTIME_LIBRARY_NAMES
        }
        first = MANAGER.encode_gpgv_runtime_capsule(executable, libraries)
        second = MANAGER.encode_gpgv_runtime_capsule(executable, libraries)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(executable))
        self.assertEqual(MANAGER.gpgv_runtime_files(first), libraries)
        self.assertEqual(MANAGER.gpgv_runtime_files(b"legacy-gpgv"), {})
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            MANAGER.materialize_gpgv_runtime(release, first)
            MANAGER.verify_gpgv_runtime(release, first, os.geteuid())
            runtime = (
                release / MANAGER.GPGV_RUNTIME_DIRECTORY_NAME
                / sorted(libraries)[0]
            )
            runtime.chmod(0o644)
            runtime.write_bytes(b"substituted")
            runtime.chmod(0o444)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "gpgv_runtime_mismatch"
            ):
                MANAGER.verify_gpgv_runtime(
                    release, first, os.geteuid()
                )

    @staticmethod
    def _install_transition(
        *, terminal: dict[str, object] | None = None,
    ) -> dict[str, object]:
        old_services = {
            "authorization": {
                "pid": 71, "euid": 0,
                "start_generation": [1_800_000_000, 123_456],
                "executable": "/usr/bin/python3",
                "arguments": ["/usr/bin/python3", "-I", "/broker", "serve-touchid"],
            },
            "native_credential": {
                "pid": 72, "euid": 501,
                "start_generation": [1_800_000_001, 123_457],
                "executable": "/helper", "arguments": ["/helper"],
            },
        }
        value: dict[str, object] = {
            "schema": MANAGER.INSTALL_TRANSITION_SCHEMA,
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "created_at": 2_000_000_000,
            "expires_at": 2_000_000_000
                + MANAGER.INSTALL_TRANSITION_TTL_SECONDS,
            "authorization_request_id":
                "22222222-2222-4222-8222-222222222222",
            "authorization_request_sha256": "1" * 64,
            "authorization_pending_receipt_sha256": "2" * 64,
            "candidate_release_id": "3" * 64,
            "candidate_manifest_sha256": "4" * 64,
            "candidate_authorization_manifest_sha256": "5" * 64,
            "developer_id_team_id": "ABCDE12345",
            "developer_id_team_floor_sha256": "6" * 64,
            "fallback_release_id": "7" * 64,
            "old_current_target": "releases/" + "7" * 64,
            "old_previous_target": "releases/" + "8" * 64,
            "native_uid": 501,
            "old_services": old_services,
            "old_services_sha256": MANAGER.sha256_bytes(
                MANAGER.canonical_state_record(old_services)
            ),
            "terminal": terminal,
        }
        value["transition_sha256"] = MANAGER.install_transition_digest(value)
        return MANAGER.validate_install_transition(value)

    @staticmethod
    def _custody_status_reply(
        operation_id: str,
        *,
        count: object = 0,
        custody_state: str = "ambiguous",
        schema: str = MANAGER.NATIVE_CREDENTIAL_REPLY_SCHEMA,
    ) -> dict[str, object]:
        status = {
            "provider": "openAIChatGPT", "state": "loggedOut",
            "client_id_sha256": None, "account_subject_sha256": None,
            "workspace_sha256": None, "scope_sha256": None,
            "access_expires_at_ms": None, "earliest_refresh_at_ms": None,
            "refresh_expires_at_ms": None,
            "custody_state": custody_state,
            "custody_tombstone_sha256": (
                "a" * 64 if custody_state == "absent" else None
            ),
            "custody_projection_count": count,
        }
        body = {
            "operation_id": operation_id, "verified": True,
            "status": status, "projection": None, "error_code": None,
            "response_sha256": "b" * 64,
        }
        return {
            "schema": schema, **body,
            "reply_sha256": MANAGER.sha256_bytes(
                MANAGER.canonical_state_record(body)
            ),
        }

    @staticmethod
    def _terminal_record(
        transition_id: str = "11111111-1111-4111-8111-111111111111",
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": MANAGER.INSTALL_TERMINAL_SCHEMA,
            "status": "deployed_verified",
            "transition_id": transition_id,
            "transition_sha256": "1" * 64,
            "authorization_request_id":
                "22222222-2222-4222-8222-222222222222",
            "authorization_request_sha256": "2" * 64,
            "candidate_release_id": "3" * 64,
            "candidate_manifest_sha256": "4" * 64,
            "candidate_authorization_manifest_sha256": "5" * 64,
            "developer_id_team_id": "ABCDE12345",
            "developer_id_team_floor_sha256": "6" * 64,
            "old_authorization_pid": 71,
            "old_authorization_start_generation": [1_800_000_000, 123_456],
            "authorization_pid": 81,
            "authorization_start_generation": [1_800_000_010, 123_466],
            "native_credential_pid": 82,
            "native_credential_start_generation": [1_800_000_011, 123_467],
            "service_evidence_sha256": "7" * 64,
            "authorization_receipt_sha256": "8" * 64,
            "completed_at": 2_000_000_010,
            "error": None,
        }
        value["terminal_sha256"] = MANAGER.terminal_transition_digest(value)
        return MANAGER.validate_terminal_transition(value)

    @staticmethod
    def _completed_install_receipt(
        transition: dict[str, object],
        finalization: dict[str, object],
    ) -> dict[str, object]:
        succeeded = finalization["status"] == "deployed_verified"
        return {
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "request_id": transition["authorization_request_id"],
            "request_sha256": transition["authorization_request_sha256"],
            "operation": "host-controller-install",
            "status": "succeeded" if succeeded else "failed",
            "started_at": transition["created_at"],
            "completed_at": finalization["completed_at"],
            "exit_status": 0 if succeeded else 1,
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "candidate_release_id": transition["candidate_release_id"],
            "authorization_pending_receipt_sha256": transition[
                "authorization_pending_receipt_sha256"
            ],
            "host_install_terminal_status": finalization["status"],
            "host_install_service_evidence_sha256": finalization[
                "service_evidence_sha256"
            ],
            "host_install_finalization_sha256": finalization[
                "finalization_sha256"
            ],
            "stdout_sha256": MANAGER.sha256_bytes(b""),
            "stderr_sha256": MANAGER.sha256_bytes(
                b"" if succeeded else b"host_install_activation_failed\n"
            ),
        }

    def _publish_install_commit_fixture(
        self,
        install_root: Path,
        receipt_root: Path,
        *,
        status: str = "deployed_verified",
    ) -> tuple[
        dict[str, object], dict[str, object],
        dict[str, object], dict[str, object],
    ]:
        transition = self._install_transition()
        finalization = MANAGER.make_install_finalization(
            transition,
            status=status,
            error=None if status == "deployed_verified"
            else "activation_rolled_back",
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"generation": status},
            completed_at=2_000_000_010,
        )
        staged = dict(transition)
        staged["terminal"] = finalization
        staged = MANAGER.validate_install_transition(staged)
        receipt = self._completed_install_receipt(staged, finalization)
        receipt_raw = MANAGER.canonical_state_record(receipt)
        terminal = MANAGER.make_install_terminal(
            staged, finalization, MANAGER.sha256_bytes(receipt_raw),
        )

        install_root.mkdir(mode=0o755)
        pending = install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
        pending.write_bytes(MANAGER.canonical_state_record(staged))
        pending.chmod(0o600)
        receipt_root.mkdir(mode=0o700)
        receipt_path = receipt_root / (
            f"{staged['authorization_request_id']}.json"
        )
        receipt_path.write_bytes(receipt_raw)
        receipt_path.chmod(0o600)
        descriptor = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            MANAGER.publish_terminal_state_record(
                descriptor, terminal, os.geteuid(),
            )
        finally:
            os.close(descriptor)
        return staged, finalization, receipt, terminal

    @staticmethod
    def _open_test_directory(
        path: Path, _expected_uid: int, *, final_mode: int = 0o755,
    ) -> int:
        if stat.S_IMODE(path.stat().st_mode) != final_mode:
            raise MANAGER.ReleaseFailure("test_directory_mode_invalid")
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

    @staticmethod
    def _developer_id_floor_record(
        team: str = "ABCDE" + "12345",
    ) -> dict[str, object]:
        return MANAGER.developer_id_floor_record(
            release_id="a" * 64,
            authorization_manifest=b"{}\n",
            policy={
                "team_id": team,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
            },
            established_at=1,
        )

    @staticmethod
    def _bootstrap_signing_floor(
        _repo, install_root, expected_uid, values, release_id,
        _generation, _candidate, expected_team, _manifest_sha256,
    ):
        record = MANAGER.developer_id_floor_record(
            release_id=release_id,
            authorization_manifest=values["authorization_ui_bundle"],
            policy={
                "team_id": expected_team,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
            },
            established_at=1,
        )
        return MANAGER.create_developer_id_team_floor(
            install_root, expected_uid, record,
        )

    @staticmethod
    def _native_host_product_values() -> dict[str, bytes]:
        team = "ABCDE" + "12345"
        authorization_files = {
            "Contents/Info.plist": {
                "mode": 0o444, "sha256": "1" * 64, "size": 10,
            },
            MANAGER.AUTHORIZATION_UI_EXECUTABLE.as_posix(): {
                "mode": 0o555, "sha256": "2" * 64, "size": 20,
            },
            "Contents/embedded.provisionprofile": {
                "mode": 0o444, "sha256": "3" * 64, "size": 30,
            },
            "Contents/Resources/AppIcon.icns": {
                "mode": 0o444, "sha256": "4" * 64, "size": 40,
            },
        }
        authorization = {
            "bundle": MANAGER.AUTHORIZATION_UI_APP_NAME,
            "files": authorization_files,
            "schema": "secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy": {
                "access_group": team + ".org.zebeth.SecureSandbox.AuthorizationUI",
                "application_identifier": (
                    team + ".org.zebeth.SecureSandbox.AuthorizationUI"
                ),
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": team,
            },
        }
        native = {
            "backend": {
                "identifier": MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
                "mode": 0o555, "sha256": "5" * 64, "size": 3,
            },
            "consumer": {
                "identifier": MANAGER.NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
                "mode": 0o555, "sha256": "6" * 64, "size": 4,
            },
            "helper": {
                "bundle": MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
                "identifier": MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                "files": {
                    "Contents/Info.plist": {
                        "mode": 0o444, "sha256": "7" * 64, "size": 50,
                    },
                    MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix(): {
                        "mode": 0o555, "sha256": "8" * 64, "size": 60,
                    },
                },
            },
            "schema": "secure-sandbox-native-components-bundle-v1",
            "signing_policy": {"team_id": team},
        }
        encode = lambda value: (
            json.dumps(value, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        return {
            "authorization_ui_bundle": encode(authorization),
            "native_credential_helper_bundle": encode(native),
            "native_stack_credential_client": b"abc",
            "native_projection_consumer": b"wxyz",
        }

    def test_developer_id_team_floor_is_canonical_write_once_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "install"
            root.mkdir(mode=0o755)
            record = self._developer_id_floor_record()
            first = MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), record,
            )
            second = MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), record,
            )
            self.assertEqual(first, second)
            path = root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                path.read_bytes(), MANAGER._developer_id_floor_bytes(record)
            )
            conflicting = self._developer_id_floor_record(
                "ZYXWV" + "98765"
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "developer_id_team_floor_conflict"
            ):
                MANAGER.create_developer_id_team_floor(
                    root, os.geteuid(), conflicting,
                )

    def test_touchid_developer_id_build_uses_distribution_export(self):
        script = (REPO / "scripts/build-touchid-authorization-ui.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("-archivePath \"$archive\"", script)
        self.assertIn("-exportArchive", script)
        self.assertIn("-insert method -string developer-id", script)
        self.assertIn("-insert signingStyle -string automatic", script)
        self.assertNotIn(
            'signing_arguments+=("CODE_SIGN_IDENTITY=$developer_id")', script
        )

    def test_native_host_products_use_one_stapled_notarized_container(self):
        script = (REPO / "scripts/build-native-host-products.sh").read_text(
            encoding="utf-8"
        )
        required = (
            "SecureSandboxAuthorizationUI.app",
            "SecureSandboxNativeCredentialHelper.app",
            "SecureSandboxNativeStackBackend",
            "SecureSandboxNativeProjectionConsumer",
            "hdiutil create",
            "notarytool submit",
            "notarytool log",
            'value.get("statusCode")',
            '"issues" not in value',
            'notary_keychain_input="${SECURE_SANDBOX_NOTARY_KEYCHAIN:-}"',
            "notary_keychain_args=(",
            '--keychain-profile "$notary_profile_input"',
            '--keychain "$notary_keychain_input"',
            '"${notary_keychain_args[@]}"',
            "stapler staple",
            "stapler validate",
            "spctl --assess --type open",
            "hdiutil verify",
            "secure-sandbox-native-host-products-manifest-v1",
            "secure-sandbox-native-host-products-notarization-v3",
            '"stapler_validated":True',
            '"gatekeeper_assessed":True',
            '"notary_log_sha256"',
            'value.get("jobId","")',
            'value.get("sha256","")',
            '"developer_id_certificate_sha1"',
            '"source_archive_sha256"',
            '"source_tree_sha256"',
            '"host_release_preimage_sha256"',
            '"build_custody":"trusted-login-principal-v1"',
            '"signing_config_sha256"',
            '"container_cdhash"',
            '"products"',
        )
        for value in required:
            self.assertIn(value, script)
        self.assertLess(
            script.index("SecureSandboxNativeHostProducts.manifest.json"),
            script.index("hdiutil create"),
        )
        stage_copy = script.index(
            '"$generation/SecureSandboxNativeProjectionConsumer" \\\n'
            '    "$stage/"'
        )
        manifest = script.index(
            'root=pathlib.Path(sys.argv[1]); '
            'output=root/"SecureSandboxNativeHostProducts.manifest.json"'
        )
        for normalization in (
            '"$stage/SecureSandboxAuthorizationUI.bundle.json"',
            '"$stage/SecureSandboxNativeComponents.bundle.json"',
            '"$stage/SecureSandboxNativeStackBackend"',
            '"$stage/SecureSandboxNativeProjectionConsumer"',
        ):
            normalized_at = script.index(normalization, stage_copy)
            self.assertLess(stage_copy, normalized_at)
            self.assertLess(normalized_at, manifest)
        self.assertIn("if mode not in {0o444,0o555}:", script)
        self.assertIn("native_host_container_entry_mode_invalid", script)
        self.assertNotIn("source=Notarized Developer ID", script)
        self.assertIn("require_acl_free_paths", script)
        self.assertIn("native_host_candidate_acl_boundary_untrusted", script)
        self.assertNotIn("/bin/chmod -N", script)

    def test_native_host_notary_log_accepts_apples_clean_null_issues(self):
        script = (REPO / "scripts/build-native-host-products.sh").read_text(
            encoding="utf-8"
        )
        log_command = script.index("/usr/bin/xcrun notarytool log")
        code_marker = "/usr/bin/python3 -I -c '\n"
        code_start = script.index(code_marker, log_command) + len(code_marker)
        code_end = script.index(
            "\n' \"$notary_log\" \"$submission_id\" "
            "\"$notary_submission_sha256\"",
            code_start,
        )
        validator = script[code_start:code_end]
        submission_id = "12345678-1234-4123-8123-123456789abc"
        submission_sha256 = "a" * 64

        accepted = (
            {"status": "Accepted", "statusCode": 0, "issues": None,
             "jobId": submission_id, "sha256": submission_sha256},
            {"status": "Accepted", "statusCode": 0, "issues": [],
             "jobId": submission_id.upper(),
             "sha256": submission_sha256.upper()},
        )
        rejected = (
            {"status": "Accepted", "statusCode": 0},
            {"status": "Accepted", "statusCode": 0, "issues": [{}]},
            {"status": "Invalid", "statusCode": 0, "issues": None},
            {"status": "Accepted", "issues": None},
            {"status": "Accepted", "statusCode": False, "issues": None},
            {"status": "Accepted", "statusCode": 1, "issues": None},
            {"status": "Accepted", "statusCode": 0, "issues": None,
             "jobId": "00000000-0000-4000-8000-000000000001",
             "sha256": submission_sha256},
            {"status": "Accepted", "statusCode": 0, "issues": None,
             "jobId": submission_id, "sha256": "b" * 64},
        )
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "notary-log.json"
            for value in accepted:
                record.write_text(json.dumps(value), encoding="utf-8")
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", "-c", validator, str(record),
                     submission_id, submission_sha256],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            for value in rejected:
                record.write_text(json.dumps(value), encoding="utf-8")
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", "-c", validator, str(record),
                     submission_id, submission_sha256],
                    check=False, capture_output=True, text=True,
                )
                self.assertNotEqual(completed.returncode, 0, value)
                self.assertIn(
                    "native_host_container_notary_log_not_clean",
                    completed.stderr,
                )

    def test_native_host_manifest_builder_rejects_unnormalized_modes(self):
        script = (REPO / "scripts/build-native-host-products.sh").read_text(
            encoding="utf-8"
        )
        root_line = (
            'root=pathlib.Path(sys.argv[1]); '
            'output=root/"SecureSandboxNativeHostProducts.manifest.json"'
        )
        root_at = script.index(root_line)
        marker = "/usr/bin/python3 -I -c '\n"
        code_start = script.rfind(marker, 0, root_at) + len(marker)
        code_end = script.index("\n' \"$stage\"", root_at)
        program = script[code_start:code_end]
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            payload = stage / "payload"
            payload.write_bytes(b"signed payload")
            payload.chmod(0o400)
            rejected = subprocess.run(
                ["/usr/bin/python3", "-I", "-c", program, str(stage)],
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "native_host_container_entry_mode_invalid:payload",
                rejected.stderr,
            )
            payload.chmod(0o444)
            accepted = subprocess.run(
                ["/usr/bin/python3", "-I", "-c", program, str(stage)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            manifest = json.loads(
                (stage / "SecureSandboxNativeHostProducts.manifest.json")
                .read_text(encoding="ascii")
            )
            self.assertEqual(manifest["entries"]["payload"]["mode"], 0o444)

    def test_native_component_builder_retires_stage_without_destructive_cleanup(self):
        script = (
            REPO / "scripts/build-native-credential-components.sh"
        ).read_text(encoding="utf-8")
        validation = 'identity(opened)!=expected'
        rename = 'libc.renameatx_np'
        retained = '".secure-sandbox-retained-"'
        self.assertIn(validation, script)
        self.assertIn(rename, script)
        self.assertIn(retained, script)
        self.assertIn('"$build_root" "$build_root_record"', script)
        self.assertNotIn('os.unlink(', script)
        self.assertNotIn('os.rmdir(', script)
        self.assertNotIn('shutil.rmtree(', script)
        self.assertNotIn('/bin/chmod -R u+w "$build_root"', script)
        self.assertNotIn('/bin/rm -rf -- "$build_root"', script)
        self.assertLess(
            script.index(validation),
            script.index(rename, script.index(validation)),
        )

    def test_native_host_builder_retires_scratch_through_held_descriptors(self):
        script = (
            REPO / "scripts/build-native-host-products.sh"
        ).read_text(encoding="utf-8")
        for required in (
            'exec 20<"$release_build_parent"',
            'exec 21<"$build_root"',
            'exec 22<"$source_helper"',
            "create-build-directory-at",
            "verify-build-directory-at",
            "retire-build-directory-at",
            "--parent-fd 20 --root-fd 21",
            '--identity "$build_root_identity"',
        ):
            self.assertIn(required, script)
        self.assertNotIn('-d "$requested_output/.build.XXXXXX"', script)
        self.assertNotIn('-d "$release_build_parent/.build.XXXXXX"', script)
        self.assertNotIn('/bin/chmod -R u+w "$build_root"', script)
        self.assertNotIn('/bin/rm -rf -- "$build_root"', script)
        self.assertLess(
            script.index("create-build-directory-at"),
            script.index("retire-build-directory-at"),
        )

    def test_developer_id_team_floor_recovers_only_pending_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "install"
            root.mkdir(mode=0o755)
            record = self._developer_id_floor_record()
            pending = root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
            MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), record,
            )
            final = root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
            self.assertFalse(pending.exists())
            self.assertEqual(final.stat().st_nlink, 1)

            final.unlink()
            pending.write_bytes(MANAGER._developer_id_floor_bytes(record))
            pending.chmod(0o600)
            os.link(pending, final)
            self.assertEqual(final.stat().st_nlink, 2)
            observed = MANAGER.reconcile_developer_id_team_floor_publication(
                root, os.geteuid(),
            )
            self.assertEqual(observed[0], record)
            self.assertFalse(pending.exists())
            self.assertEqual(final.stat().st_nlink, 1)

    def test_developer_id_floor_adopts_complete_premetadata_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "install"
            root.mkdir(mode=0o755)
            original = self._developer_id_floor_record()
            requested = dict(original)
            requested["established_at"] = original["established_at"] + 99
            pending = root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
            pending.write_bytes(MANAGER._developer_id_floor_bytes(original))
            pending.chmod(0o400)
            observed = MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), requested,
            )
            self.assertEqual(observed[0], original)
            self.assertEqual(
                stat.S_IMODE((
                    root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
                ).stat().st_mode),
                0o600,
            )

    def test_developer_id_floor_retains_partial_pending_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "install"
            root.mkdir(mode=0o755)
            record = self._developer_id_floor_record()
            pending = root / MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
            pending.write_bytes(b"{\"partial\":")
            pending.chmod(0o400)
            MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), record,
            )
            retained = list(root.glob(
                MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
                + ".retained-*"
            ))
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"{\"partial\":")
            self.assertEqual(stat.S_IMODE(retained[0].stat().st_mode), 0o600)

    def test_developer_id_migration_predecessor_bypass_is_exact_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "install"
            release_id = "a" * 64
            release = install_root / "releases" / release_id
            release.mkdir(parents=True)
            predecessor = (
                install_root
                / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
            )
            predecessor.symlink_to(f"releases/{release_id}")
            manifest = {"release_id": release_id, "payloads": {}}

            with mock.patch.object(
                MANAGER, "verified_release",
                return_value=(release, manifest),
            ) as verified:
                observed = (
                    MANAGER.verified_developer_id_migration_predecessor(
                        install_root, os.geteuid(), release_id,
                    )
                )
            self.assertEqual(observed, (release, manifest))
            verified.assert_called_once_with(
                install_root, predecessor, os.geteuid(), allow_legacy=True,
                _bootstrap_without_developer_id_floor=True,
                _bootstrap_without_native_coordination_floor=True,
            )

            with (
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(
                        install_root / "releases" / ("b" * 64), manifest,
                    ),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "developer_id_migration_predecessor_changed",
                ),
            ):
                MANAGER.verified_developer_id_migration_predecessor(
                    install_root, os.geteuid(), release_id,
                )

            predecessor.unlink()
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "developer_id_migration_predecessor_missing",
            ):
                MANAGER.verified_developer_id_migration_predecessor(
                    install_root, os.geteuid(), release_id,
                )

    def test_developer_id_migration_predecessor_floor_is_self_contained(self):
        manifest = b"legacy-authorization-manifest\n"
        predecessor = Path("/trusted/releases") / ("a" * 64)
        policy = {
            "team_id": "ABCDE12345",
            "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
        }
        floor = {
            "team_id": policy["team_id"],
            "authorization_ui_bundle_id": policy["bundle_id"],
            "established_from_release_id": predecessor.name,
            "established_from_authorization_manifest_sha256": (
                MANAGER.sha256_bytes(manifest)
            ),
        }
        MANAGER.enforce_developer_id_migration_predecessor_floor(
            floor, predecessor, manifest, policy,
        )
        for field, changed in (
            ("established_from_release_id", "b" * 64),
            ("established_from_authorization_manifest_sha256", "c" * 64),
            ("team_id", "ZYXWV98765"),
            ("authorization_ui_bundle_id", "org.example.Other"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "developer_id_migration_floor_mismatch",
            ):
                MANAGER.enforce_developer_id_migration_predecessor_floor(
                    {**floor, field: changed},
                    predecessor, manifest, policy,
                )

    def test_developer_id_migration_holds_controller_admission_fence(self):
        source = MANAGER_PATH.read_text(encoding="utf-8")
        declaration = (
            "@host_release_mutation(controller_fence=True)\n"
            "def bootstrap_native_vendor_developer_id_schema("
        )
        self.assertIn(declaration, source)

    def test_developer_id_migration_crash_retry_publishes_coordination_floor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            install_root = root / "install"
            releases = install_root / "releases"
            legacy_id = "a" * 64
            source_id = "b" * 64
            legacy = releases / legacy_id
            source = releases / source_id
            legacy.mkdir(parents=True)
            (legacy / MANAGER.AUTHORIZATION_UI_APP_NAME).mkdir()
            current_manifest_raw = b"legacy-authorization-manifest\n"
            (legacy / "authorization_ui_bundle").write_bytes(
                current_manifest_raw)
            predecessor = (
                install_root
                / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
            )
            predecessor.symlink_to(f"releases/{legacy_id}")
            state_root = root / "state"
            state_root.mkdir()
            launcher_raw = b"#!/usr/bin/env python3\n"
            launcher = root / "launcher"
            launcher.write_bytes(launcher_raw)
            launcher.chmod(0o755)
            replacement = repo / MANAGER.LAUNCHER_SOURCE
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(launcher_raw)

            team_id = "ABCDE12345"
            candidate_manifest = b"candidate-authorization-manifest\n"
            contract_raw = b"candidate-coordination-contract\n"
            values = {
                "authorization_ui_bundle": candidate_manifest,
                "native_stack_coordination_contract": contract_raw,
            }
            legacy_manifest = {
                "release_id": legacy_id,
                "payloads": {
                    name: "c" * 64
                    for name in MANAGER.PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES
                },
            }
            policy = {
                "team_id": team_id,
                "bundle_id": (
                    "org.zebeth.SecureSandbox.AuthorizationUI"
                ),
            }
            floor = {
                "team_id": team_id,
                "established_from_release_id": legacy_id,
                "established_from_authorization_manifest_sha256": (
                    MANAGER.sha256_bytes(current_manifest_raw)
                ),
            }
            replacement_sha256 = MANAGER.sha256_bytes(launcher_raw)
            events: list[str] = []
            crashed = False

            def checkpoint(name: str) -> None:
                nonlocal crashed
                events.append(name)
                if (not crashed
                        and name == "developer-id-floor-published"):
                    crashed = True
                    raise MANAGER.ReleaseFailure(
                        "simulated:developer-id-floor-published")

            def establish(*_args, **kwargs):
                self.assertEqual(kwargs["release_id"], source_id)
                self.assertEqual(kwargs["contract_raw"], contract_raw)
                events.append("establish")
                return ({"minimum_epoch": 1}, "d" * 64)

            def install(*_args, **kwargs):
                self.assertEqual(events[-1], "developer-id-floor-published")
                self.assertEqual(
                    kwargs["_developer_id_migration_current_release_id"],
                    legacy_id,
                )
                source.mkdir(exist_ok=True)
                (install_root / "current").symlink_to(
                    f"releases/{source_id}")
                events.append("install")
                return {"schema": MANAGER.SCHEMA, "release_id": source_id}

            def invoke():
                return MANAGER.bootstrap_native_vendor_developer_id_schema.__wrapped__(
                    repo, install_root, launcher, state_root, os.geteuid(),
                    source_id, legacy_id, "e" * 64,
                    replacement_sha256, team_id,
                    MANAGER.sha256_bytes(current_manifest_raw),
                    MANAGER.sha256_bytes(candidate_manifest),
                )

            with (
                mock.patch.object(MANAGER, "active_markers", return_value=[]),
                mock.patch.object(
                    MANAGER, "source_payload",
                    return_value=(values, {}, source_id),
                ),
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(legacy, legacy_manifest),
                ),
                mock.patch.object(
                    MANAGER, "verified_authorization_ui_signing_policy",
                    return_value=policy,
                ),
                mock.patch.object(
                    MANAGER,
                    "verified_existing_authorization_ui_anchor_policy",
                    return_value=policy,
                ),
                mock.patch.object(
                    MANAGER,
                    "reconcile_developer_id_team_floor_publication",
                    return_value=(floor, "f" * 64),
                ),
                mock.patch.object(
                    MANAGER, "manages_live_touchid_service",
                    return_value=False,
                ),
                mock.patch.object(
                    MANAGER, "native_coordination_bootstrap_checkpoint",
                    side_effect=checkpoint,
                ),
                mock.patch.object(
                    MANAGER, "establish_native_stack_coordination_floor",
                    side_effect=establish,
                ) as establish_floor,
                mock.patch.object(
                    MANAGER, "install", side_effect=install,
                ) as install_release,
            ):
                with self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "simulated:developer-id-floor-published",
                ):
                    invoke()
                self.assertFalse(os.path.lexists(install_root / "current"))
                self.assertTrue(predecessor.is_symlink())
                result = invoke()

            self.assertEqual(result["release_id"], source_id)
            self.assertTrue(result["coordination_floor_established"])
            self.assertEqual(establish_floor.call_count, 2)
            install_release.assert_called_once()
            self.assertFalse(os.path.lexists(predecessor))
            self.assertTrue(os.path.samefile(install_root / "current", source))

    def test_developer_id_migration_coordination_floor_enforces_complete_floor(self):
        contract = b"candidate-contract\n"
        observed = ({"minimum_epoch": 1}, "a" * 64)
        with (
            mock.patch.object(
                MANAGER, "native_stack_coordination_floor",
                return_value=observed,
            ),
            mock.patch.object(
                MANAGER, "enforce_native_stack_coordination_floor",
            ) as enforce,
            mock.patch.object(
                MANAGER, "establish_native_stack_coordination_floor",
            ) as establish,
        ):
            result = (
                MANAGER.ensure_developer_id_migration_coordination_floor(
                    Path("/trusted/install"), 0,
                    release_id="b" * 64, contract_raw=contract,
                )
            )
        self.assertEqual(result, (observed, False))
        enforce.assert_called_once_with(
            contract, Path("/trusted/install"), 0,
        )
        establish.assert_not_called()

    def test_developer_id_migration_coordination_floor_reconciles_exact_hardlink_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "install"
            install_root.mkdir(mode=0o755)
            contract = (
                REPO / MANAGER.PAYLOAD_SOURCES[
                    "native_stack_coordination_contract"
                ]
            ).read_bytes()
            release_id = "a" * 64
            MANAGER.establish_native_stack_coordination_floor(
                install_root, os.geteuid(), release_id=release_id,
                contract_raw=contract,
            )
            final = (
                install_root / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME
            )
            pending = (
                install_root
                / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_PENDING_NAME
            )
            os.link(final, pending)
            self.assertEqual(final.stat().st_nlink, 2)

            _observed, published = (
                MANAGER.ensure_developer_id_migration_coordination_floor(
                    install_root, os.geteuid(), release_id=release_id,
                    contract_raw=contract,
                )
            )
            self.assertTrue(published)
            self.assertFalse(pending.exists())
            self.assertEqual(final.stat().st_nlink, 1)

    def test_developer_id_migration_partial_coordination_floor_rejects_changed_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "install"
            install_root.mkdir(mode=0o755)
            contract = (
                REPO / MANAGER.PAYLOAD_SOURCES[
                    "native_stack_coordination_contract"
                ]
            ).read_bytes()

            def crash(name: str) -> None:
                if name == "coordination-enforcement-published":
                    raise MANAGER.ReleaseFailure("simulated-publication-crash")

            with (
                mock.patch.object(
                    MANAGER, "native_coordination_bootstrap_checkpoint",
                    side_effect=crash,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "simulated-publication-crash",
                ),
            ):
                MANAGER.establish_native_stack_coordination_floor(
                    install_root, os.geteuid(), release_id="a" * 64,
                    contract_raw=contract,
                )

            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_stack_coordination_floor_conflict",
            ):
                MANAGER.ensure_developer_id_migration_coordination_floor(
                    install_root, os.geteuid(), release_id="b" * 64,
                    contract_raw=contract,
                )

    def test_developer_id_migration_current_source_recovers_services_before_unlink(self):
        for scenario in ("predecessor", "service-failure", "completed"):
            service_failure = scenario == "service-failure"
            predecessor_present = scenario != "completed"
            with self.subTest(scenario=scenario), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo = root / "repo"
                install_root = root / "install"
                releases = install_root / "releases"
                legacy_id, source_id = "a" * 64, "b" * 64
                legacy = releases / legacy_id
                source = releases / source_id
                legacy.mkdir(parents=True)
                source.mkdir()
                (legacy / MANAGER.AUTHORIZATION_UI_APP_NAME).mkdir()
                legacy_authorization = b"legacy-authorization\n"
                candidate_authorization = b"candidate-authorization\n"
                (legacy / "authorization_ui_bundle").write_bytes(
                    legacy_authorization)
                (install_root / "current").symlink_to(
                    f"releases/{source_id}")
                predecessor = (
                    install_root
                    / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
                )
                if predecessor_present:
                    predecessor.symlink_to(f"releases/{legacy_id}")
                state_root = root / "state"
                state_root.mkdir()
                launcher = root / "launcher"
                launcher.write_bytes(b"launcher\n")
                replacement = repo / MANAGER.LAUNCHER_SOURCE
                replacement.parent.mkdir(parents=True)
                replacement.write_bytes(b"launcher\n")
                team_id = "ABCDE12345"
                values = {
                    "authorization_ui_bundle": candidate_authorization,
                    "native_stack_coordination_contract": b"contract\n",
                }
                source_manifest = {
                    "release_id": source_id,
                    "payloads": {
                        name: "c" * 64 for name in MANAGER.PAYLOAD_NAMES
                    },
                }
                legacy_manifest = {
                    "release_id": legacy_id,
                    "payloads": {
                        name: "d" * 64 for name in (
                            MANAGER.PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES
                        )
                    },
                }
                policy = {
                    "team_id": team_id,
                    "bundle_id": (
                        "org.zebeth.SecureSandbox.AuthorizationUI"
                    ),
                }
                floor = {
                    "team_id": team_id,
                    "established_from_release_id": legacy_id,
                    "established_from_authorization_manifest_sha256": (
                        MANAGER.sha256_bytes(legacy_authorization)
                    ),
                }

                def verified(_root, link, *_args, **_kwargs):
                    return ((source, source_manifest) if link.name == "current"
                            else (legacy, legacy_manifest))

                def verify_services(*_args, **_kwargs):
                    self.assertEqual(
                        predecessor.is_symlink(), predecessor_present)
                    if service_failure:
                        raise MANAGER.ReleaseFailure(
                            "simulated-service-verification-failure")
                    return {}

                with (
                    mock.patch.object(
                        MANAGER, "active_markers", return_value=[]),
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=(values, {}, source_id),
                    ),
                    mock.patch.object(
                        MANAGER, "verified_release", side_effect=verified),
                    mock.patch.object(
                        MANAGER, "verified_authorization_ui_signing_policy",
                        return_value=policy),
                    mock.patch.object(
                        MANAGER,
                        "verified_existing_authorization_ui_anchor_policy",
                        return_value=policy),
                    mock.patch.object(
                        MANAGER,
                        "reconcile_developer_id_team_floor_publication",
                        return_value=(floor, "e" * 64)),
                    mock.patch.object(
                        MANAGER, "native_stack_coordination_floor",
                        return_value=({"minimum_epoch": 1}, "f" * 64)),
                    mock.patch.object(
                        MANAGER, "enforce_native_stack_coordination_floor"),
                    mock.patch.object(
                        MANAGER, "verify",
                        return_value={
                            "schema": MANAGER.SCHEMA,
                            "release_id": source_id,
                        }),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=True),
                    mock.patch.object(
                        MANAGER, "console_user_uid",
                        return_value=os.geteuid()),
                    mock.patch.object(
                        MANAGER, "install_release_host_services",
                    ) as install_services,
                    mock.patch.object(
                        MANAGER, "verify_release_host_services",
                        side_effect=verify_services,
                    ) as verify_installed_services,
                    mock.patch.object(
                        MANAGER, "stop_touchid_service") as stop_touchid,
                    mock.patch.object(
                        MANAGER, "stop_native_credential_service",
                    ) as stop_native,
                ):
                    def invoke():
                        return MANAGER.bootstrap_native_vendor_developer_id_schema.__wrapped__(
                            repo, install_root, launcher, state_root,
                            os.geteuid(), source_id,
                            source_id if scenario == "completed" else legacy_id,
                            "1" * 64,
                            "2" * 64, team_id,
                            MANAGER.sha256_bytes(
                                candidate_authorization
                                if scenario == "completed"
                                else legacy_authorization
                            ),
                            MANAGER.sha256_bytes(candidate_authorization),
                        )

                    if service_failure:
                        with self.assertRaisesRegex(
                            MANAGER.ReleaseFailure,
                            "simulated-service-verification-failure",
                        ):
                            invoke()
                    else:
                        result = invoke()

                install_services.assert_called_once_with(
                    source, source_manifest, os.geteuid())
                verify_installed_services.assert_called_once_with(
                    source, source_manifest, os.geteuid())
                if service_failure:
                    self.assertTrue(predecessor.is_symlink())
                    stop_touchid.assert_called_once_with()
                    stop_native.assert_called_once_with(uid=os.geteuid())
                else:
                    self.assertFalse(os.path.lexists(predecessor))
                    self.assertEqual(
                        result["recovered_migration_predecessor"],
                        predecessor_present,
                    )
                    stop_touchid.assert_not_called()
                    stop_native.assert_not_called()

    def test_developer_id_team_floor_rejects_tofu_and_release_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "install"
            root.mkdir(mode=0o755)
            candidate = root / "candidate.app"
            candidate.mkdir()
            values = {"authorization_ui_bundle": b"{}\n"}
            policy = {
                "team_id": "ABCDE" + "12345",
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
            }
            with mock.patch.object(
                MANAGER, "verified_authorization_ui_signing_policy",
                return_value=policy,
            ), self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "developer_id_team_floor_bootstrap_required",
            ):
                MANAGER.prepare_developer_id_team_floor(
                    root, root, os.geteuid(), values, "b" * 64, now=1,
                )

            record = self._developer_id_floor_record()
            MANAGER.create_developer_id_team_floor(
                root, os.geteuid(), record,
            )
            release = root / "release"
            release.mkdir()
            (release / "authorization_ui_bundle").write_bytes(b"{}\n")
            with mock.patch.object(
                MANAGER, "verified_authorization_ui_signing_policy",
                return_value={
                    "team_id": "ZYXWV" + "98765",
                    "bundle_id": (
                        "org.zebeth.SecureSandbox.AuthorizationUI"
                    ),
                },
            ), self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_developer_id_team_mismatch"
            ):
                MANAGER.enforce_release_developer_id_team_floor(
                    root,
                    release,
                    {
                        "authorization_ui_bundle": "c" * 64,
                        **{
                            name: "d" * 64
                            for name in MANAGER.NATIVE_HOST_PRODUCT_CONTAINER_PAYLOAD_NAMES
                        },
                    },
                    os.geteuid(),
                )

    def test_native_components_must_share_authorization_ui_signer(self):
        team = "ABCDE" + "12345"
        other_team = "ZYXWV" + "98765"
        native = {"signing_policy": {"team_id": team}}
        authorization = {
            "signing_policy": {
                "access_group": team + ".org.zebeth.SecureSandbox.AuthorizationUI",
                "application_identifier": (
                    team + ".org.zebeth.SecureSandbox.AuthorizationUI"
                ),
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": team,
            }
        }
        MANAGER.enforce_native_component_signer_alignment(
            native, authorization
        )
        native["signing_policy"]["team_id"] = other_team
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_component_signer_mismatch"
        ):
            MANAGER.enforce_native_component_signer_alignment(
                native, authorization
            )

    def test_native_host_products_manifest_is_exactly_inventory_bound(self):
        values = self._native_host_product_values()
        entries = MANAGER.expected_native_host_product_entries(values)
        manifest = {
            "entries": entries,
            "schema": "secure-sandbox-native-host-products-manifest-v1",
        }
        encoded = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        self.assertEqual(MANAGER.native_host_products_manifest(encoded), manifest)
        self.assertEqual(
            entries["SecureSandboxNativeStackBackend"],
            {
                "mode": 0o555,
                "sha256": hashlib.sha256(b"abc").hexdigest(),
                "size": 3,
            },
        )
        manifest["entries"]["unexpected"] = {
            "mode": 0o444, "sha256": "9" * 64, "size": 1,
        }
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_products_inventory_mismatch",
        ):
            with mock.patch.object(
                MANAGER,
                "native_host_products_manifest",
                return_value=manifest,
            ), mock.patch.object(
                MANAGER,
                "native_host_products_notarization",
                return_value={
                    "container_sha256": hashlib.sha256(b"dmg").hexdigest(),
                    "container_size": 3,
                    "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V1_SCHEMA,
                    "team_id": "ABCDE" + "12345",
                },
            ):
                MANAGER.verify_native_host_products_container({
                    **values,
                    "native_host_products_container": b"dmg",
                    "native_host_products_manifest": encoded,
                    "native_host_products_notarization": b"receipt",
                })

    def test_native_host_v2_receipt_binds_exact_outer_manifest(self):
        values = self._native_host_product_values()
        manifest_data = (
            json.dumps({
                "entries": MANAGER.expected_native_host_product_entries(values),
                "schema": "secure-sandbox-native-host-products-manifest-v1",
            }, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        container = b"dmg"
        with mock.patch.object(
            MANAGER, "native_host_products_notarization", return_value={
                "container_manifest_sha256": "0" * 64,
                "container_sha256": hashlib.sha256(container).hexdigest(),
                "container_size": len(container),
                "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
                "team_id": "ABCDE12345",
            },
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_products_notarization_mismatch",
        ):
            MANAGER.verify_native_host_products_container({
                **values,
                "native_host_products_container": container,
                "native_host_products_manifest": manifest_data,
                "native_host_products_notarization": b"receipt",
            })

    def test_native_host_mount_identity_accepts_only_canonical_same_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_root = root / "private"
            real_root.mkdir()
            mount = real_root / "mount"
            mount.mkdir()
            alias_root = root / "alias"
            alias_root.symlink_to(real_root, target_is_directory=True)
            expected = alias_root / "mount"

            self.assertTrue(
                MANAGER.same_native_host_mount_identity(str(mount), expected)
            )
            other = real_root / "other"
            other.mkdir()
            self.assertFalse(
                MANAGER.same_native_host_mount_identity(str(other), expected)
            )
            final_symlink = real_root / "mount-link"
            final_symlink.symlink_to(mount, target_is_directory=True)
            self.assertFalse(
                MANAGER.same_native_host_mount_identity(
                    str(final_symlink), expected,
                )
            )
            self.assertFalse(
                MANAGER.same_native_host_mount_identity(
                    str(mount / ".." / "mount"), expected,
                )
            )
            self.assertFalse(
                MANAGER.same_native_host_mount_identity("relative/mount", expected)
            )
            self.assertFalse(
                MANAGER.same_native_host_mount_identity(None, expected)
            )

    def test_native_host_products_notary_receipt_is_closed_audit_metadata(self):
        receipt = {
            "container_sha256": "a" * 64,
            "container_size": 123,
            "gatekeeper_assessed": True,
            "notary_log_sha256": "b" * 64,
            "notary_status": "accepted",
            "notary_submission_id": (
                "12345678" + "-1234-4abc-8def-123456789abc"
            ),
            "schema": "secure-sandbox-native-host-products-notarization-v1",
            "stapler_validated": True,
            "team_id": "ABCDE" + "12345",
        }
        encoded = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        self.assertEqual(
            MANAGER.native_host_products_notarization(encoded), receipt
        )
        receipt["bypass"] = True
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_products_notarization_invalid",
        ):
            MANAGER.native_host_products_notarization(
                (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(
                    "ascii"
                )
            )

    def test_native_host_products_v2_receipt_is_closed_and_exact(self):
        products = {
            name: {"identifier": identifier, "cdhash": character * 40}
            for (name, identifier), character in zip(
                sorted(MANAGER.NATIVE_HOST_PRODUCTS_V2_PRODUCT_IDENTIFIERS.items()),
                "1234",
            )
        }
        receipt = {
            "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
            "container_cdhash": "5" * 40,
            "container_identifier": MANAGER.NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER,
            "container_manifest_sha256": "6" * 64,
            "container_sha256": "7" * 64,
            "container_size": 123,
            "developer_id_certificate_sha1": "8" * 40,
            "gatekeeper_assessed": True,
            "notary_log_sha256": "9" * 64,
            "notary_status": "accepted",
            "notary_submission_id":
                "12345678-1234-4123-8123-123456789abc",
            "notary_submission_sha256": "a" * 64,
            "products": products,
            "release_commit": "b" * 40,
            "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
            "signing_config_sha256": "c" * 64,
            "source_archive_sha256": "d" * 64,
            "source_tree_sha256": "e" * 64,
            "stapler_validated": True,
            "team_id": MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
        }

        def encode(value):
            return (
                json.dumps(value, indent=2, sort_keys=True) + "\n"
            ).encode("ascii")

        self.assertEqual(
            MANAGER.native_host_products_notarization(encode(receipt)), receipt
        )
        mutations = []
        wrong_team = dict(receipt)
        wrong_team["team_id"] = "ABCDE12345"
        mutations.append(wrong_team)
        uppercase_leaf = dict(receipt)
        uppercase_leaf["developer_id_certificate_sha1"] = "A" * 40
        mutations.append(uppercase_leaf)
        missing_product = {**receipt, "products": dict(products)}
        missing_product["products"].pop("authorization_ui")
        mutations.append(missing_product)
        wrong_identifier = {**receipt, "products": {
            name: dict(value) for name, value in products.items()
        }}
        wrong_identifier["products"]["credential_helper"]["identifier"] = (
            "org.example.Substitute"
        )
        mutations.append(wrong_identifier)
        extra = dict(receipt)
        extra["bypass"] = True
        mutations.append(extra)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_products_notarization_invalid",
            ):
                MANAGER.native_host_products_notarization(encode(mutation))

    def test_new_carrier_admission_rejects_legacy_receipt(self):
        values = self._native_host_product_values()
        manifest = {
            "entries": MANAGER.expected_native_host_product_entries(values),
            "schema": "secure-sandbox-native-host-products-manifest-v1",
        }
        manifest_data = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        container = b"legacy carrier"
        receipt = {
            "container_sha256": hashlib.sha256(container).hexdigest(),
            "container_size": len(container),
            "gatekeeper_assessed": True,
            "notary_log_sha256": "b" * 64,
            "notary_status": "accepted",
            "notary_submission_id":
                "12345678-1234-4123-8123-123456789abc",
            "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V1_SCHEMA,
            "stapler_validated": True,
            "team_id": "ABCDE12345",
        }
        receipt_data = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        self.assertEqual(
            MANAGER.native_host_products_notarization(receipt_data), receipt
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_products_notarization_below_v2",
        ):
            MANAGER.verify_native_host_products_container(
                {
                    **values,
                    "native_host_products_container": container,
                    "native_host_products_manifest": manifest_data,
                    "native_host_products_notarization": receipt_data,
                },
                require_v2=True,
            )

    def test_developer_id_leaf_and_cdhash_are_exact_signature_requirements(self):
        certificate = "a" * 40
        cdhash = "b" * 40
        commands = []

        def run(command, **_kwargs):
            commands.append(command)
            if command[1:3] == ["-d", "--verbose=4"]:
                return subprocess.CompletedProcess(
                    command, 0, stdout="", stderr=(
                        f"Identifier={MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER}\n"
                        f"TeamIdentifier={MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID}\n"
                        f"CDHash={cdhash}\n"
                        "flags=0x10000(runtime)\n"
                    ),
                )
            return subprocess.CompletedProcess(
                command, 0, stdout="", stderr="",
            )

        with mock.patch.object(MANAGER.subprocess, "run", side_effect=run):
            MANAGER.verify_native_component_signature(
                Path("/tmp/test-native-backend"),
                MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
                MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                expected_cdhash=cdhash,
                developer_id_certificate_sha1=certificate,
            )
        requirements = [
            argument
            for command in commands for argument in command
            if isinstance(argument, str) and argument.startswith("-R=")
        ]
        self.assertEqual(len(requirements), 1)
        self.assertIn(f'certificate leaf = H"{certificate}"', requirements[0])
        with mock.patch.object(MANAGER.subprocess, "run", side_effect=run), \
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "native_component_signature_invalid",
                ):
            MANAGER.verify_native_component_signature(
                Path("/tmp/test-native-backend"),
                MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
                MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                expected_cdhash="c" * 40,
                developer_id_certificate_sha1=certificate,
            )

    def test_native_host_receipt_detached_signature_is_exactly_leaf_bound(self):
        certificate = "a" * 40
        receipt = {
            "developer_id_certificate_sha1": certificate,
            "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
            "team_id": MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
        }
        receipt_data = b'{"signed":"receipt"}\n'
        signature_data = b"S" * 512
        commands = []

        def run(command, **_kwargs):
            commands.append(command)
            if "-d" in command:
                return subprocess.CompletedProcess(
                    command, 0, stdout="", stderr=(
                        "Identifier="
                        + MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_IDENTIFIER
                        + "\nTeamIdentifier="
                        + MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
                        + "\nCDHash=" + "b" * 40
                        + "\nAuthority=Developer ID Application: Test ("
                        + MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
                        + ")\nAuthority=Developer ID Certification Authority\n"
                        + "Authority=Apple Root CA\nTimestamp=Nov 5, 2026\n"
                    ),
                )
            return subprocess.CompletedProcess(
                command, 0, stdout="", stderr="",
            )

        with mock.patch.object(MANAGER.subprocess, "run", side_effect=run):
            MANAGER.verify_native_host_products_notarization_signature(
                receipt_data, signature_data, receipt,
                expected_certificate_sha1=certificate,
            )
        requirements = [
            argument for command in commands for argument in command
            if isinstance(argument, str) and argument.startswith("-R=")
        ]
        self.assertEqual(len(requirements), 1)
        self.assertIn(
            f'identifier "{MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_IDENTIFIER}"',
            requirements[0],
        )
        self.assertIn(
            f'certificate leaf = H"{certificate}"', requirements[0],
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_products_receipt_signature_invalid",
        ):
            MANAGER.verify_native_host_products_notarization_signature(
                receipt_data, signature_data, receipt,
                expected_certificate_sha1="c" * 40,
            )

    def test_terminal_bridge_is_current_only_and_does_not_rewrite_legacy_inventories(self):
        self.assertIn("native_stack_terminal_bridge", MANAGER.PAYLOAD_NAMES)
        self.assertEqual(
            MANAGER.EXPECTED_MODES["native_stack_terminal_bridge"], 0o755
        )
        self.assertNotIn(
            "native_stack_terminal_bridge",
            MANAGER.PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES,
        )
        for inventory in (
            MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES,
            MANAGER.PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES,
            MANAGER.PRE_MODEL_PROFILE_PAYLOAD_NAMES,
        ):
            if inventory != MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES:
                self.assertNotIn("native_stack_terminal_bridge", inventory)

    def test_native_deployment_payloads_are_current_only(self):
        signature = "native_host_products_notarization_signature"
        self.assertEqual(
            MANAGER.NATIVE_DEPLOYMENT_PAYLOAD_NAMES,
            {"native_stack_deployer", "native_deployment_payloads"},
        )
        self.assertEqual(
            set(MANAGER.PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES),
            set(MANAGER.PAYLOAD_NAMES) - {signature},
        )
        self.assertEqual(
            set(LAUNCHER.PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES),
            set(MANAGER.PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES),
        )
        self.assertEqual(
            set(AUTHORIZATION.PRE_NATIVE_HOST_RECEIPT_SIGNATURE_RELEASE_MODES),
            set(MANAGER.PRE_NATIVE_HOST_RECEIPT_SIGNATURE_PAYLOAD_NAMES),
        )
        self.assertEqual(
            set(MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES),
            set(MANAGER.PAYLOAD_NAMES)
            - {signature}
            - MANAGER.NATIVE_DEPLOYMENT_PAYLOAD_NAMES
            - MANAGER.NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
        )
        self.assertEqual(
            set(MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES),
            set(MANAGER.PAYLOAD_NAMES)
            - {signature}
            - MANAGER.NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
        )
        self.assertEqual(
            set(LAUNCHER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES),
            set(MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES),
        )
        self.assertNotIn(
            signature, MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
        )
        for inventory in (
            MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES,
        ):
            self.assertNotIn(signature, inventory)
            self.assertTrue(
                MANAGER.NATIVE_DEPLOYMENT_PAYLOAD_NAMES.isdisjoint(inventory)
            )
        self.assertEqual(MANAGER.EXPECTED_MODES["native_stack_deployer"], 0o755)
        self.assertEqual(
            MANAGER.EXPECTED_MODES["native_deployment_payloads"], 0o444,
        )

    def test_current_payload_inventory_is_identical_at_every_trust_boundary(self):
        current = set(MANAGER.PAYLOAD_NAMES)
        self.assertEqual(
            current,
            set(MANAGER.EXPECTED_MODES)
            - {"authorization_ui", "manifest.json", "op_agents"},
        )
        self.assertEqual(current, set(AUTHORIZATION.EXPECTED_RELEASE_MODES))
        self.assertEqual(current, set(LAUNCHER.CURRENT_PAYLOAD_NAMES))
        self.assertEqual(current, set(AUDIT.CONTROLLER_PAYLOAD_NAMES))
        self.assertIn("native_stack_session_manager", current)
        self.assertIn("native_host_products_notarization", current)
        self.assertIn("native_host_products_notarization_signature", current)

    def test_nested_install_root_capability_cannot_unlock_outer_mutation(self):
        contender = (
            "import fcntl,os,sys; "
            "fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); "
            "\ntry:\n fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            "except BlockingIOError:\n raise SystemExit(1)\n"
            "finally:\n os.close(fd)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary).resolve() / "installed"
            install_root.mkdir(mode=0o755)
            outer = MANAGER.open_locked_install_root(install_root, os.geteuid())
            token = MANAGER._HOST_MUTATION_LOCK.set(
                (install_root, os.geteuid(), outer)
            )
            try:
                borrowed = MANAGER.open_locked_install_root(
                    install_root, os.geteuid(),
                )
                fcntl.flock(borrowed, fcntl.LOCK_UN)
                os.close(borrowed)
                blocked = subprocess.run(
                    [sys.executable, "-c", contender, str(install_root)],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(blocked.returncode, 1, blocked.stderr)
            finally:
                MANAGER._HOST_MUTATION_LOCK.reset(token)
                fcntl.flock(outer, fcntl.LOCK_UN)
                os.close(outer)
            admitted = subprocess.run(
                [sys.executable, "-c", contender, str(install_root)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)

    def test_staging_cleanup_waits_for_host_mutation_lock(self):
        worker = """
import importlib.util
import os
import pathlib
import sys

specification = importlib.util.spec_from_file_location("manager", sys.argv[1])
manager = importlib.util.module_from_spec(specification)
specification.loader.exec_module(manager)

@manager.host_release_mutation(initialize=True)
def mutate(install_root, expected_uid):
    manager.prepare_release_root(install_root, expected_uid)
    pathlib.Path(sys.argv[4]).write_text("done", encoding="ascii")

pathlib.Path(sys.argv[3]).write_text("ready", encoding="ascii")
mutate(pathlib.Path(sys.argv[2]), os.geteuid())
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            install_root = root / "installed"
            releases = install_root / "releases"
            staging = releases / ".staging-hostile"
            staging.mkdir(parents=True, mode=0o755)
            ready = root / "ready"
            done = root / "done"
            outer = MANAGER.open_locked_install_root(
                install_root, os.geteuid(),
            )
            process = subprocess.Popen(
                [
                    sys.executable, "-c", worker, str(MANAGER_PATH),
                    str(install_root), str(ready), str(done),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                time.sleep(0.1)
                self.assertTrue(staging.exists())
                self.assertFalse(done.exists())
            finally:
                fcntl.flock(outer, fcntl.LOCK_UN)
                os.close(outer)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr or stdout)
            self.assertFalse(staging.exists())
            self.assertEqual(done.read_text(encoding="ascii"), "done")

    def test_native_deployment_gate_rejects_active_invalid_and_tampered_state(self):
        def response(state, active=None, *, gate_sha256=None):
            body = {"state": state, "active_journal_sha256": active}
            value = {
                "schema": MANAGER.NATIVE_DEPLOYMENT_GATE_SCHEMA, **body,
                "gate_sha256": gate_sha256 or MANAGER.sha256_bytes(
                    MANAGER.canonical_state_record(body)
                ),
            }
            return subprocess.CompletedProcess(
                [], 0, stdout=MANAGER.canonical_state_record(value), stderr=b"",
            )

        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "installed"
            (install_root / "releases").mkdir(parents=True)
            (install_root / "current").symlink_to("releases/" + "a" * 64)
            release = install_root / "releases" / ("a" * 64)
            release.mkdir()
            deployment_state = MANAGER.native_deployment_state_root(
                install_root
            )
            deployment_state.mkdir(mode=0o700)
            (deployment_state / "state.lock").touch(mode=0o600)
            (install_root / "current").unlink()
            descriptor = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
            manifest = {
                "payloads": {
                    name: "b" * 64 for name in MANAGER.PAYLOAD_NAMES
                }
            }
            try:
                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(release, manifest),
                    ),
                    mock.patch.object(
                        MANAGER.subprocess, "run",
                        return_value=response("ready"),
                    ),
                ):
                    self.assertEqual(
                        MANAGER.ensure_native_deployment_inactive_locked(
                            descriptor, install_root, os.geteuid(),
                            selector_release_id="a" * 64,
                        )["state"],
                        "ready",
                    )
                for completed, error in (
                    (response("active", "c" * 64), "native_deployment_active"),
                    (response("invalid"), "native_deployment_state_invalid"),
                    (response("ready", gate_sha256="d" * 64),
                     "native_deployment_state_invalid"),
                ):
                    with (
                        mock.patch.object(
                            MANAGER, "verified_release",
                            return_value=(release, manifest),
                        ),
                        mock.patch.object(
                            MANAGER.subprocess, "run",
                            return_value=completed,
                        ),
                        self.assertRaisesRegex(MANAGER.ReleaseFailure, error),
                    ):
                        MANAGER.ensure_native_deployment_inactive_locked(
                            descriptor, install_root, os.geteuid(),
                            selector_release_id="a" * 64,
                        )
            finally:
                os.close(descriptor)

    def test_legacy_release_cannot_mutate_after_native_state_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "installed"
            (install_root / "releases").mkdir(parents=True)
            (install_root / "current").symlink_to("releases/" + "a" * 64)
            release = install_root / "releases" / ("a" * 64)
            release.mkdir()
            state_root = MANAGER.native_deployment_state_root(install_root)
            state_root.mkdir(mode=0o700)
            descriptor = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(release, {
                            "payloads": {
                                name: "b" * 64 for name
                                in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
                            }
                        }),
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "native_deployment_state_invalid",
                    ),
                ):
                    MANAGER.ensure_native_deployment_inactive_locked(
                        descriptor, install_root, os.geteuid(),
                    )
            finally:
                os.close(descriptor)

    def test_native_deployment_gate_reader_ignores_planted_unchecked_pyc(self):
        self.assertNotIn(
            "importlib", MANAGER._NATIVE_DEPLOYMENT_GATE_READER,
        )
        source = b'''import hashlib\nimport json\n\ndef deployment_gate_state(*args, **kwargs):\n    body = {"state": "ready", "active_journal_sha256": None}\n    raw = (json.dumps(body, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\\n").encode("ascii")\n    return {"schema": "secure-sandbox-native-deployment-gate-state-v1", **body, "gate_sha256": hashlib.sha256(raw).hexdigest()}\n'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            deployer = root / "native_stack_deployer"
            deployer.write_bytes(source)
            deployer.chmod(0o755)
            marker = root / "planted-pyc-executed"
            poison_source = root / "poison.py"
            poison_source.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='ascii')\n",
                encoding="ascii",
            )
            cache = Path(importlib.util.cache_from_source(str(deployer)))
            cache.parent.mkdir(mode=0o755, parents=True)
            py_compile.compile(
                str(poison_source), cfile=str(cache), doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            self.assertTrue(cache.is_file())
            install_root = root / "installed"
            install_root.mkdir(mode=0o755)
            state_root = root / "state"
            descriptor = os.open(
                install_root, os.O_RDONLY | os.O_DIRECTORY,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                completed = subprocess.run(
                    [
                        sys.executable, "-I", "-B", "-c",
                        MANAGER._NATIVE_DEPLOYMENT_GATE_READER,
                        str(deployer), str(state_root), str(install_root),
                        str(descriptor), str(os.geteuid()),
                        str(os.getegid()), hashlib.sha256(source).hexdigest(),
                        "-",
                    ],
                    check=False, capture_output=True, text=True,
                    pass_fds=(descriptor,),
                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(
                json.loads(completed.stdout)["state"], "ready",
            )
            rejected_descriptor = os.open(
                install_root, os.O_RDONLY | os.O_DIRECTORY,
            )
            fcntl.flock(rejected_descriptor, fcntl.LOCK_EX)
            try:
                rejected = subprocess.run(
                    [
                        sys.executable, "-I", "-B", "-c",
                        MANAGER._NATIVE_DEPLOYMENT_GATE_READER,
                        str(deployer), str(state_root), str(install_root),
                        str(rejected_descriptor), str(os.geteuid()),
                        str(os.getegid()), "0" * 64,
                        "-",
                    ],
                    check=False, capture_output=True, text=True,
                    pass_fds=(rejected_descriptor,),
                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                )
            finally:
                fcntl.flock(rejected_descriptor, fcntl.LOCK_UN)
                os.close(rejected_descriptor)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, "")
            self.assertFalse(marker.exists())

    def test_install_and_rollback_stop_before_body_when_gate_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            install_root = root / "installed"
            launcher = root / "launcher"
            state_root = root / "controller-state"
            with (
                mock.patch.object(
                    MANAGER, "ensure_native_deployment_inactive_locked",
                    side_effect=MANAGER.ReleaseFailure(
                        "native_deployment_active"
                    ),
                ),
                mock.patch.object(MANAGER, "source_payload") as source,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "native_deployment_active",
                ),
            ):
                MANAGER.install(
                    root, install_root, launcher, state_root, os.geteuid(),
                )
            source.assert_not_called()
            with (
                mock.patch.object(
                    MANAGER, "ensure_native_deployment_inactive_locked",
                    side_effect=MANAGER.ReleaseFailure(
                        "native_deployment_state_invalid"
                    ),
                ),
                mock.patch.object(
                    MANAGER, "developer_id_team_floor",
                ) as floor,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_deployment_state_invalid",
                ),
            ):
                MANAGER.rollback(
                    root, install_root, state_root, None, os.geteuid(),
                )
            floor.assert_not_called()

    def test_legacy_rollback_target_is_rejected_after_native_state_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "installed"
            install_root.mkdir()
            MANAGER.native_deployment_state_root(install_root).mkdir(
                mode=0o700
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_legacy_state_untrusted",
            ):
                MANAGER.ensure_release_native_deployment_compatible(
                    {"payloads": {
                        name: "a" * 64 for name
                        in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
                    }},
                    install_root,
                )
            MANAGER.ensure_release_native_deployment_compatible(
                {"payloads": {
                    name: "a" * 64 for name in MANAGER.PAYLOAD_NAMES
                }},
                install_root,
            )

    def test_read_only_gate_preserves_pre_deployer_rollback_and_reupgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "installed"
            releases = install_root / "releases"
            predecessor = releases / ("a" * 64)
            candidate = releases / ("b" * 64)
            predecessor.mkdir(parents=True)
            candidate.mkdir()
            current = install_root / "current"
            current.symlink_to(f"releases/{candidate.name}")
            predecessor_manifest = {
                "payloads": {
                    name: "c" * 64 for name
                    in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
                }
            }
            candidate_manifest = {
                "payloads": {
                    name: "d" * 64 for name in MANAGER.PAYLOAD_NAMES
                }
            }
            descriptor = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(candidate, candidate_manifest),
                ):
                    self.assertEqual(
                        MANAGER.ensure_native_deployment_inactive_locked(
                            descriptor, install_root, os.geteuid(),
                        )["state"],
                        "ready",
                    )
                state_root = MANAGER.native_deployment_state_root(install_root)
                self.assertFalse(os.path.lexists(state_root))
                MANAGER.ensure_release_native_deployment_compatible(
                    predecessor_manifest, install_root,
                )
                current.unlink()
                current.symlink_to(f"releases/{predecessor.name}")
                with mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(predecessor, predecessor_manifest),
                ):
                    self.assertEqual(
                        MANAGER.ensure_native_deployment_inactive_locked(
                            descriptor, install_root, os.geteuid(),
                        )["state"],
                        "ready",
                    )
                current.unlink()
                current.symlink_to(f"releases/{candidate.name}")
                with mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(candidate, candidate_manifest),
                ):
                    self.assertEqual(
                        MANAGER.ensure_native_deployment_inactive_locked(
                            descriptor, install_root, os.geteuid(),
                        )["state"],
                        "ready",
                    )
                self.assertFalse(os.path.lexists(state_root))
            finally:
                os.close(descriptor)

    def test_native_deployment_schema_bootstrap_binds_exact_predecessor(self):
        source_id = "b" * 64
        predecessor_id = "a" * 64
        predecessor = Path("/protected/releases") / predecessor_id
        manifest = {
            "payloads": {
                name: "c" * 64 for name
                in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
            }
        }
        operation = MANAGER.bootstrap_native_deployment_schema.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, manifest),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "native_stack_coordination_contract": (
                        REPO / "config/native-stack-coordination-contract.json"
                    ).read_bytes(),
                }, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value=None,
            ),
            mock.patch.object(
                MANAGER, "read_regular", return_value=b"launcher",
            ),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=b"launcher",
            ),
            mock.patch.object(
                MANAGER, "install",
                return_value={"schema": MANAGER.SCHEMA},
            ) as install,
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=False,
            ),
            mock.patch.object(MANAGER, "atomic_symlink"),
            mock.patch.object(MANAGER, "fsync_directory"),
            mock.patch.object(
                MANAGER, "establish_native_stack_coordination_floor",
            ),
        ):
            result = operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                MANAGER.sha256_bytes(b"launcher"),
                MANAGER.sha256_bytes(b"launcher"),
            )
        self.assertEqual(
            result["status"], "native_deployment_schema_bootstrapped",
        )
        self.assertEqual(result["previous_release_id"], predecessor_id)
        install.assert_called_once()

    def test_native_deployment_schema_bootstrap_rejects_wrong_bindings(self):
        source_id = "b" * 64
        predecessor_id = "a" * 64
        predecessor = Path("/protected/releases") / predecessor_id
        operation = MANAGER.bootstrap_native_deployment_schema.__wrapped__
        exact = {
            "payloads": {
                name: "c" * 64 for name
                in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
            }
        }
        with mock.patch.object(
            MANAGER, "verified_release", return_value=(predecessor, exact),
        ):
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "current_release_id_unexpected",
            ):
                operation(
                    Path("/repo"), Path("/protected"), Path("/launcher"),
                    Path("/state"), os.geteuid(), source_id, "0" * 64,
                    "d" * 64, "d" * 64,
                )
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, exact),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({}, {}, "e" * 64),
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "source_release_id_unexpected",
            ),
        ):
            operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                "d" * 64, "d" * 64,
            )

        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, exact),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "native_stack_coordination_contract": (
                        REPO / "config/native-stack-coordination-contract.json"
                    ).read_bytes(),
                }, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value=None,
            ),
            mock.patch.object(Path, "is_symlink", return_value=True),
            mock.patch.object(MANAGER, "read_regular", return_value=b"launcher"),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=b"launcher",
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "installed_launcher_hash_unexpected",
            ),
        ):
            operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                "d" * 64, MANAGER.sha256_bytes(b"launcher"),
            )
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, exact),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "native_stack_coordination_contract": (
                        REPO / "config/native-stack-coordination-contract.json"
                    ).read_bytes(),
                }, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value=None,
            ),
            mock.patch.object(MANAGER, "read_regular", return_value=b"launcher"),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=b"launcher",
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "replacement_launcher_hash_unexpected",
            ),
        ):
            operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                MANAGER.sha256_bytes(b"launcher"), "d" * 64,
            )
        wrong_inventory = {
            "payloads": dict(exact["payloads"]),
        }
        wrong_inventory["payloads"].pop("native_stack_session_manager")
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, wrong_inventory),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({}, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value=None,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_schema_predecessor_invalid",
            ),
        ):
            operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                "d" * 64, "d" * 64,
            )

    def test_native_deployment_bootstrap_accepts_exact_coordination_predecessor(self):
        source_id = "b" * 64
        predecessor_id = "a" * 64
        predecessor = Path("/protected/releases") / predecessor_id
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        operation = MANAGER.bootstrap_native_deployment_schema.__wrapped__
        manifest = {
            "payloads": {
                name: "c" * 64
                for name in MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
            }
        }
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, manifest),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "native_stack_coordination_contract": contract,
                }, {}, source_id),
            ),
            mock.patch.object(MANAGER, "read_regular", return_value=b"launcher"),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=b"launcher",
            ),
            mock.patch.object(MANAGER, "manages_live_touchid_service", return_value=False),
            mock.patch.object(MANAGER, "atomic_symlink"),
            mock.patch.object(MANAGER, "fsync_directory"),
            mock.patch.object(MANAGER, "establish_native_stack_coordination_floor"),
            mock.patch.object(
                MANAGER, "install",
                return_value={"schema": MANAGER.SCHEMA},
            ) as install,
        ):
            result = operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, predecessor_id,
                MANAGER.sha256_bytes(b"launcher"),
                MANAGER.sha256_bytes(b"launcher"),
            )
        self.assertEqual(
            result["status"], "native_deployment_schema_bootstrapped")
        install.assert_called_once()

    def test_native_deployment_schema_replay_recovers_interrupted_transition(self):
        source_id = "b" * 64
        selected = Path("/protected/releases") / source_id
        operation = MANAGER.bootstrap_native_deployment_schema.__wrapped__
        recovered = {
            "schema": MANAGER.SCHEMA,
            "status": "verified",
            "recovered_existing_release": True,
        }
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(selected, {
                    "payloads": {
                        name: "c" * 64 for name in MANAGER.PAYLOAD_NAMES
                    }
                }),
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "native_stack_coordination_contract": (
                        REPO / "config/native-stack-coordination-contract.json"
                    ).read_bytes(),
                }, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value=dict(recovered),
            ) as recover,
            mock.patch.object(MANAGER, "install") as install,
            mock.patch.object(
                MANAGER, "establish_native_stack_coordination_floor",
            ),
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=False,
            ),
        ):
            result = operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id, source_id,
                "d" * 64, "d" * 64,
            )
        self.assertEqual(
            result["status"], "native_deployment_schema_bootstrapped",
        )
        self.assertTrue(result["recovered_existing_release"])
        recover.assert_called_once()
        install.assert_not_called()

    def test_coordination_floor_bootstrap_never_reactivates_predecessor(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        predecessor_id = "a" * 64
        manifest = {
            "payloads": {
                name: "c" * 64
                for name in MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
            }
        }
        operation = MANAGER.bootstrap_native_deployment_schema.__wrapped__
        for failure in (
            "before-floor-publication",
            "before-coordination-enforcement-publication",
            "coordination-enforcement-published",
            "coordination-private-floor-published",
            "install-failure",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                predecessor = install_root / "releases" / predecessor_id
                predecessor.mkdir(parents=True, mode=0o555)
                install_root.chmod(0o755)
                (install_root / "releases").chmod(0o755)
                (install_root / "current").symlink_to(
                    f"releases/{predecessor_id}")
                launcher = root / "launcher"
                launcher.write_bytes(b"launcher")
                launcher.chmod(0o755)
                (root / "scripts").mkdir()
                (root / MANAGER.LAUNCHER_SOURCE).write_bytes(b"launcher")

                def checkpoint(phase: str) -> None:
                    if phase == failure:
                        raise MANAGER.ReleaseFailure("crash:" + phase)

                def install_effect(*_args, **_kwargs):
                    if failure == "install-failure":
                        raise MANAGER.ReleaseFailure(
                            "crash:install-failure")
                    return {"schema": MANAGER.SCHEMA}
                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(predecessor, manifest),
                    ),
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=({
                            "native_stack_coordination_contract": contract,
                        }, {}, source_id),
                    ),
                    mock.patch.object(
                        MANAGER, "native_host_candidate_tracked_source",
                        return_value=b"launcher",
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=True,
                    ),
                    mock.patch.object(
                        MANAGER, "console_user_uid", return_value=501,
                    ),
                    mock.patch.object(
                        MANAGER, "stop_and_fence_host_services",
                    ) as stop_services,
                    mock.patch.object(
                        MANAGER, "native_coordination_bootstrap_checkpoint",
                        side_effect=checkpoint,
                    ),
                    mock.patch.object(
                        MANAGER, "install", side_effect=install_effect,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "crash:" + failure,
                    ),
                ):
                    operation(
                        root, install_root, launcher, root / "state",
                        os.geteuid(), source_id, predecessor_id,
                        MANAGER.sha256_bytes(b"launcher"),
                        MANAGER.sha256_bytes(b"launcher"),
                    )
                stop_services.assert_called_once_with(501)
                self.assertFalse(os.path.lexists(install_root / "current"))
                floor_exists = os.path.lexists(
                    install_root / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME)
                enforcement_exists = os.path.lexists(
                    install_root
                    / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME)
                self.assertEqual(
                    floor_exists,
                    failure in {
                        "coordination-private-floor-published",
                        "install-failure",
                    },
                )
                self.assertEqual(
                    enforcement_exists,
                    failure in {
                        "coordination-enforcement-published",
                        "coordination-private-floor-published",
                        "install-failure",
                    },
                )
                with self.assertRaisesRegex(
                    LAUNCHER.LaunchFailure, "controller_current_missing",
                ):
                    LAUNCHER.load_release(install_root, os.geteuid())

    def test_coordination_floor_recovers_every_publication_prefix(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        for failure in (
            "before-coordination-enforcement-publication",
            "coordination-enforcement-published",
            "coordination-private-floor-published",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                install_root = Path(temporary) / "host"
                install_root.mkdir(mode=0o755)

                def checkpoint(phase: str) -> None:
                    if phase == failure:
                        raise MANAGER.ReleaseFailure("crash:" + phase)

                with (
                    mock.patch.object(
                        MANAGER, "native_coordination_bootstrap_checkpoint",
                        side_effect=checkpoint,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "crash:" + failure,
                    ),
                ):
                    MANAGER.establish_native_stack_coordination_floor(
                        install_root, os.geteuid(), release_id=source_id,
                        contract_raw=contract,
                    )
                MANAGER.establish_native_stack_coordination_floor(
                    install_root, os.geteuid(), release_id=source_id,
                    contract_raw=contract,
                )
                floor = MANAGER.native_stack_coordination_floor(
                    install_root, os.geteuid())
                enforcement = MANAGER.native_stack_coordination_enforcement(
                    install_root, os.geteuid())
                self.assertIsNotNone(floor)
                self.assertIsNotNone(enforcement)
                assert floor is not None and enforcement is not None
                self.assertEqual(
                    enforcement[0]["authoritative_floor_sha256"], floor[1])
                for name, mode in (
                    (MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME, 0o600),
                    (
                        MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME,
                        0o444,
                    ),
                ):
                    info = (install_root / name).stat()
                    self.assertEqual(info.st_nlink, 1)
                    self.assertEqual(stat.S_IMODE(info.st_mode), mode)

    def test_authorization_bootstrap_fences_before_floor_and_active_marker(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        predecessor_id = "a" * 64
        authorization_manifest = b"candidate-authorization-manifest\n"
        manifest = {
            "payloads": {
                name: "c" * 64
                for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
            }
        }
        operation = MANAGER.bootstrap_authorization.__wrapped__
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            predecessor = install_root / "releases" / predecessor_id
            predecessor.mkdir(parents=True, mode=0o555)
            install_root.chmod(0o755)
            (install_root / "releases").chmod(0o755)
            (install_root / "current").symlink_to(
                f"releases/{predecessor_id}")
            launcher = root / "launcher"
            launcher.write_bytes(b"launcher")
            launcher.chmod(0o755)
            (root / "scripts").mkdir()
            (root / MANAGER.LAUNCHER_SOURCE).write_bytes(b"launcher")
            with (
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(predecessor, manifest),
                ),
                mock.patch.object(
                    MANAGER, "source_payload",
                    return_value=({
                        "native_stack_coordination_contract": contract,
                        "authorization_ui_bundle": authorization_manifest,
                    }, {}, source_id),
                ),
                mock.patch.object(
                    MANAGER, "active_markers", return_value=["live"],
                ),
                mock.patch.object(MANAGER, "install") as install,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "active_controller_invocations",
                ),
            ):
                operation(
                    root, install_root, launcher, root / "state",
                    os.geteuid(), source_id,
                    MANAGER.sha256_bytes(b"launcher"),
                    MANAGER.sha256_bytes(b"launcher"),
                    {"generation_path": "/retained/generation"},
                    MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                    MANAGER.sha256_bytes(authorization_manifest),
                )
            install.assert_not_called()
            self.assertTrue((install_root / "current").is_symlink())
            self.assertFalse(os.path.lexists(
                install_root
                / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME))
        for failure in (
            "coordination-enforcement-published", "install-failure",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                predecessor = install_root / "releases" / predecessor_id
                predecessor.mkdir(parents=True, mode=0o555)
                install_root.chmod(0o755)
                (install_root / "releases").chmod(0o755)
                (install_root / "current").symlink_to(
                    f"releases/{predecessor_id}")
                launcher = root / "launcher"
                launcher.write_bytes(b"launcher")
                launcher.chmod(0o755)
                (root / "scripts").mkdir()
                (root / MANAGER.LAUNCHER_SOURCE).write_bytes(b"launcher")

                def checkpoint(phase: str) -> None:
                    if phase == failure:
                        raise MANAGER.ReleaseFailure("crash:" + phase)

                def install_effect(*_args, **_kwargs):
                    if failure == "install-failure":
                        raise MANAGER.ReleaseFailure("crash:install-failure")
                    return {"schema": MANAGER.SCHEMA}

                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(predecessor, manifest),
                    ),
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=({
                            "native_stack_coordination_contract": contract,
                            "authorization_ui_bundle": authorization_manifest,
                        }, {}, source_id),
                    ),
                    mock.patch.object(
                        MANAGER, "native_host_candidate_tracked_source",
                        return_value=b"launcher",
                    ),
                    mock.patch.object(
                        MANAGER,
                        "bootstrap_developer_id_team_floor_from_candidate",
                        side_effect=self._bootstrap_signing_floor,
                    ),
                    mock.patch.object(
                        MANAGER, "active_markers", return_value=[],
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MANAGER, "native_coordination_bootstrap_checkpoint",
                        side_effect=checkpoint,
                    ),
                    mock.patch.object(
                        MANAGER, "install", side_effect=install_effect,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "crash:" + failure,
                    ),
                ):
                    operation(
                        root, install_root, launcher, root / "state",
                        os.geteuid(), source_id,
                        MANAGER.sha256_bytes(b"launcher"),
                        MANAGER.sha256_bytes(b"launcher"),
                        {"generation_path": "/retained/generation"},
                        MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                        MANAGER.sha256_bytes(authorization_manifest),
                    )
                self.assertFalse(os.path.lexists(install_root / "current"))
                self.assertEqual(
                    (
                        install_root
                        / MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME
                    ).resolve().name,
                    predecessor_id,
                )
                self.assertTrue(os.path.lexists(
                    install_root
                    / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME))
                self.assertEqual(
                    os.path.lexists(
                        install_root
                        / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME),
                    failure == "install-failure",
                )

    def test_authorization_bootstrap_excludes_post_load_pre_marker_race(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        predecessor_id = "a" * 64
        manifest = {
            "payloads": {
                name: "c" * 64
                for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            predecessor = install_root / "releases" / predecessor_id
            predecessor.mkdir(parents=True, mode=0o555)
            install_root.chmod(0o755)
            (install_root / "releases").chmod(0o755)
            (install_root / "current").symlink_to(
                f"releases/{predecessor_id}")
            launcher = root / "launcher"
            launcher.write_bytes(b"launcher")
            (root / "scripts").mkdir()
            (root / MANAGER.LAUNCHER_SOURCE).write_bytes(b"launcher")
            state_root = root / "state"
            launcher_lock = LAUNCHER.acquire_lock(state_root)
            failures: list[BaseException] = []

            def bootstrap() -> None:
                try:
                    authorization_manifest = (
                        b"candidate-authorization-manifest\n"
                    )
                    MANAGER.bootstrap_authorization(
                        root, install_root, launcher, state_root,
                        os.geteuid(), source_id,
                        MANAGER.sha256_bytes(b"launcher"),
                        MANAGER.sha256_bytes(b"launcher"),
                        {"generation_path": "/retained/generation"},
                        MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                        MANAGER.sha256_bytes(authorization_manifest),
                    )
                except BaseException as error:
                    failures.append(error)

            with (
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(predecessor, manifest),
                ),
                mock.patch.object(
                    MANAGER, "source_payload",
                    return_value=({
                        "native_stack_coordination_contract": contract,
                        "authorization_ui_bundle":
                            b"candidate-authorization-manifest\n",
                    }, {}, source_id),
                ),
                mock.patch.object(
                    MANAGER, "console_user_uid", return_value=os.geteuid(),
                ),
                mock.patch.object(MANAGER, "install") as install,
            ):
                thread = threading.Thread(target=bootstrap, daemon=True)
                thread.start()
                contender = os.open(
                    install_root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    for _attempt in range(200):
                        try:
                            fcntl.flock(
                                contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            break
                        else:
                            fcntl.flock(contender, fcntl.LOCK_UN)
                            time.sleep(0.005)
                    else:
                        self.fail("bootstrap did not acquire Host lock")
                finally:
                    os.close(contender)
                active = state_root / "active"
                active.mkdir(mode=0o700)
                marker = active / "post-load-pre-marker.json"
                marker.write_text(json.dumps({
                    "pid": os.getpid(), "release_id": predecessor_id,
                }), encoding="ascii")
                marker.chmod(0o600)
                LAUNCHER.release_lock(launcher_lock)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], MANAGER.ReleaseFailure)
            self.assertIn("active_controller_invocations", str(failures[0]))
            install.assert_not_called()
            self.assertTrue((install_root / "current").is_symlink())
            self.assertFalse(os.path.lexists(
                install_root
                / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME))
            with (
                mock.patch.object(
                    MANAGER, "console_user_uid", return_value=os.geteuid(),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "active_controller_invocations",
                ),
            ):
                MANAGER.bootstrap_native_deployment_schema(
                    root, install_root, launcher, state_root,
                    os.geteuid(), "b" * 64, predecessor_id,
                    MANAGER.sha256_bytes(b"launcher"),
                    MANAGER.sha256_bytes(b"launcher"),
                )

    def test_controller_admission_fence_is_inode_bound_and_host_serialized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            real_open = os.open
            swapped = False

            def substitute_on_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if (
                    not swapped and path == "state"
                    and kwargs.get("dir_fd") == parent_fd
                ):
                    os.rename(
                        "state", "state-held",
                        src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    )
                    os.mkdir("state", 0o700, dir_fd=parent_fd)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        MANAGER.os, "open", side_effect=substitute_on_open,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "controller_state_directory_changed",
                    ),
                ):
                    MANAGER._open_controller_directory_at(
                        parent_fd, "state", "controller_state_directory")
            finally:
                os.close(parent_fd)
            self.assertTrue((root / "state").is_dir())
            self.assertTrue((root / "state-held").is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            launcher_lock = LAUNCHER.acquire_lock(state)

            def substitute_while_waiting(_seconds: float) -> None:
                os.rename(
                    state / "coordination.lock",
                    state / "coordination.lock-held",
                )
                (state / "coordination.lock").mkdir(mode=0o700)
                raise RuntimeError("waiting-substitution")

            with (
                mock.patch.object(
                    MANAGER.time, "sleep",
                    side_effect=substitute_while_waiting,
                ),
                self.assertRaisesRegex(RuntimeError, "waiting-substitution"),
            ):
                with MANAGER.controller_admission_fence(
                    state, os.geteuid(), timeout=1,
                ):
                    self.fail("live launcher lock must block admission")
            self.assertTrue((state / "coordination.lock").is_dir())
            self.assertTrue((state / "coordination.lock-held").is_dir())
            del launcher_lock

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            real_remove = MANAGER._remove_controller_lock_at
            replacements: list[str] = []

            def substitute_tombstone(
                state_fd: int, name: str,
                expected_identity: tuple[int, int], controller_uid: int,
            ) -> None:
                saved = name + ".held"
                os.rename(
                    name, saved,
                    src_dir_fd=state_fd, dst_dir_fd=state_fd,
                )
                os.mkdir(name, 0o700, dir_fd=state_fd)
                replacements.append(name)
                real_remove(
                    state_fd, name, expected_identity, controller_uid)

            with (
                mock.patch.object(
                    MANAGER, "_remove_controller_lock_at",
                    side_effect=substitute_tombstone,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "controller_coordination_tombstone_changed",
                ),
            ):
                with MANAGER.controller_admission_fence(
                    state, os.geteuid(),
                ):
                    pass
            self.assertEqual(len(replacements), 1)
            self.assertTrue((state / replacements[0]).is_dir())
            self.assertTrue((state / (replacements[0] + ".held")).is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / "host"
            state = root / "state"
            host.mkdir(mode=0o755)
            state.mkdir(mode=0o700)
            host_fd = os.open(host, os.O_RDONLY | os.O_DIRECTORY)
            acquired = threading.Event()

            def launcher_shared_lock() -> None:
                descriptor = os.open(host, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_SH)
                    acquired.set()
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

            thread: threading.Thread | None = None
            try:
                fcntl.flock(host_fd, fcntl.LOCK_EX)
                with MANAGER.controller_admission_fence(
                    state, os.geteuid(),
                ):
                    state.rename(root / "state-displaced")
                    state.mkdir(mode=0o700)
                    thread = threading.Thread(
                        target=launcher_shared_lock, daemon=True)
                    thread.start()
                    self.assertFalse(acquired.wait(0.1))
                fcntl.flock(host_fd, fcntl.LOCK_UN)
                self.assertTrue(acquired.wait(2))
            finally:
                fcntl.flock(host_fd, fcntl.LOCK_UN)
                os.close(host_fd)
                if thread is not None:
                    thread.join(timeout=2)
            launcher_source = (
                REPO / "scripts/secure-sandbox-claude-launcher.py"
            ).read_text(encoding="utf-8")
            main_source = launcher_source[
                launcher_source.index("def main() -> int:"):
            ]
            self.assertLess(
                main_source.index(
                    "fcntl.flock(host_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)"
                ),
                main_source.index("lock = acquire_lock(STATE_ROOT)"),
            )
            self.assertLess(
                main_source.index("lock = acquire_lock(STATE_ROOT)"),
                main_source.index(
                    "release, release_id, controller = load_release_snapshot"
                ),
            )

    def test_bootstraps_unlink_predecessor_before_launcher_replacement(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        predecessor_id = "a" * 64
        authorization_manifest = b"candidate-authorization-manifest\n"
        cases = (
            (
                "authorization",
                MANAGER.bootstrap_authorization,
                MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES,
                MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME,
            ),
            (
                "native-deployment",
                MANAGER.bootstrap_native_deployment_schema,
                MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
                MANAGER.NATIVE_STACK_COORDINATION_PREDECESSOR_NAME,
            ),
        )
        for label, operation, predecessor_names, predecessor_link_name in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                predecessor = install_root / "releases" / predecessor_id
                predecessor.mkdir(parents=True, mode=0o555)
                install_root.chmod(0o755)
                (install_root / "releases").chmod(0o755)
                (install_root / "current").symlink_to(
                    f"releases/{predecessor_id}")
                launcher = root / "launcher"
                launcher.write_bytes(b"old-launcher")
                launcher.chmod(0o755)
                (root / "scripts").mkdir()
                (root / MANAGER.LAUNCHER_SOURCE).write_bytes(
                    b"new-launcher")
                state_root = root / "state"
                state_root.mkdir(mode=0o700)
                manifest = {
                    "payloads": {
                        name: "c" * 64 for name in predecessor_names
                    }
                }
                migration_observed: list[bool] = []

                def migrate_effect(*_args, **kwargs):
                    migration_observed.append(True)
                    self.assertFalse(os.path.lexists(
                        install_root / "current"))
                    self.assertEqual(
                        kwargs.get("_selector"),
                        install_root / predecessor_link_name,
                    )
                    state_root.rename(root / "state-displaced")
                    state_root.mkdir(mode=0o700)
                    with self.assertRaisesRegex(
                        LAUNCHER.LaunchFailure, "controller_current_missing",
                    ):
                        LAUNCHER.load_release(install_root, os.geteuid())
                    return {"status": "launcher_migrated"}

                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(predecessor, manifest),
                    ),
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=({
                            "native_stack_coordination_contract": contract,
                            "authorization_ui_bundle": authorization_manifest,
                        }, {}, source_id),
                    ),
                    mock.patch.object(
                        MANAGER, "native_host_candidate_tracked_source",
                        return_value=b"new-launcher",
                    ),
                    mock.patch.object(
                        MANAGER,
                        "bootstrap_developer_id_team_floor_from_candidate",
                        side_effect=self._bootstrap_signing_floor,
                    ),
                    mock.patch.object(
                        MANAGER, "console_user_uid",
                        return_value=os.geteuid(),
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MANAGER, "migrate_launcher",
                        side_effect=migrate_effect,
                    ),
                    mock.patch.object(
                        MANAGER, "install",
                        side_effect=MANAGER.ReleaseFailure(
                            "simulated-install-failure"),
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "simulated-install-failure",
                    ),
                ):
                    arguments = [
                        root, install_root, launcher, state_root,
                        os.geteuid(), source_id,
                    ]
                    if label == "native-deployment":
                        arguments.append(predecessor_id)
                    arguments.extend([
                        MANAGER.sha256_bytes(b"old-launcher"),
                        MANAGER.sha256_bytes(b"new-launcher"),
                    ])
                    if label == "authorization":
                        arguments.extend([{
                            "generation_path": "/retained/generation",
                        }, MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                            MANAGER.sha256_bytes(authorization_manifest)])
                    operation(*arguments)
                self.assertEqual(migration_observed, [True])
                self.assertFalse(os.path.lexists(
                    install_root / "current"))

    def test_launcher_migration_crash_retries_from_retained_predecessor(self):
        contract = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        source_id = "b" * 64
        predecessor_id = "a" * 64
        authorization_manifest = b"candidate-authorization-manifest\n"
        cases = (
            (
                "authorization", MANAGER.bootstrap_authorization,
                MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES,
                MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME,
            ),
            (
                "native-deployment",
                MANAGER.bootstrap_native_deployment_schema,
                MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
                MANAGER.NATIVE_STACK_COORDINATION_PREDECESSOR_NAME,
            ),
        )
        for label, operation, predecessor_names, predecessor_link_name in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                predecessor = install_root / "releases" / predecessor_id
                predecessor.mkdir(parents=True, mode=0o555)
                install_root.chmod(0o755)
                (install_root / "releases").chmod(0o755)
                (install_root / "current").symlink_to(
                    f"releases/{predecessor_id}")
                launcher = root / "launcher"
                launcher.write_bytes(b"old-launcher")
                launcher.chmod(0o755)
                (root / "scripts").mkdir()
                (root / MANAGER.LAUNCHER_SOURCE).write_bytes(
                    b"new-launcher")
                state_root = root / "state"
                state_root.mkdir(mode=0o700)
                manifest = {
                    "payloads": {
                        name: "c" * 64 for name in predecessor_names
                    }
                }
                attempts = 0
                old_hash = MANAGER.sha256_bytes(b"old-launcher")
                new_hash = MANAGER.sha256_bytes(b"new-launcher")

                def migrate_effect(*_args, **kwargs):
                    nonlocal attempts
                    attempts += 1
                    self.assertFalse(os.path.lexists(
                        install_root / "current"))
                    self.assertEqual(
                        kwargs.get("_selector"),
                        install_root / predecessor_link_name,
                    )
                    backup_root = install_root / "launcher-backups"
                    backup_root.mkdir(mode=0o555, exist_ok=True)
                    backup_root.chmod(0o755)
                    backup = backup_root / old_hash
                    backup.write_bytes(b"old-launcher")
                    backup.chmod(0o555)
                    backup_root.chmod(0o555)
                    launcher.write_bytes(b"new-launcher")
                    launcher.chmod(0o755)
                    if attempts == 1:
                        raise MANAGER.ReleaseFailure(
                            "simulated-launcher-crash")
                    return {"status": "launcher_migrated"}

                def invoke():
                    arguments = [
                        root, install_root, launcher, state_root,
                        os.geteuid(), source_id,
                    ]
                    if label == "native-deployment":
                        arguments.append(predecessor_id)
                    arguments.extend([old_hash, new_hash])
                    if label == "authorization":
                        arguments.extend([{
                            "generation_path": "/retained/generation",
                        }, MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                            MANAGER.sha256_bytes(authorization_manifest)])
                    return operation(*arguments)

                with (
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(predecessor, manifest),
                    ),
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=({
                            "native_stack_coordination_contract": contract,
                            "authorization_ui_bundle": authorization_manifest,
                        }, {}, source_id),
                    ),
                    mock.patch.object(
                        MANAGER, "native_host_candidate_tracked_source",
                        return_value=b"new-launcher",
                    ),
                    mock.patch.object(
                        MANAGER,
                        "bootstrap_developer_id_team_floor_from_candidate",
                        side_effect=self._bootstrap_signing_floor,
                    ),
                    mock.patch.object(
                        MANAGER, "console_user_uid",
                        return_value=os.geteuid(),
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MANAGER, "migrate_launcher",
                        side_effect=migrate_effect,
                    ),
                    mock.patch.object(
                        MANAGER, "install",
                        return_value={"schema": MANAGER.SCHEMA},
                    ) as install,
                ):
                    with self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "simulated-launcher-crash",
                    ):
                        invoke()
                    self.assertFalse(os.path.lexists(
                        install_root / "current"))
                    self.assertEqual(
                        (install_root / predecessor_link_name).resolve().name,
                        predecessor_id,
                    )
                    self.assertFalse(os.path.lexists(
                        install_root
                        / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME))
                    result = invoke()
                self.assertEqual(attempts, 1)
                install.assert_called_once()
                self.assertTrue(result["launcher_migrated"])
                self.assertTrue(result["launcher_migration_recovered"])

    def test_session_manager_is_current_only_and_preserves_predecessor_inventories(self):
        self.assertIn("native_stack_session_manager", MANAGER.PAYLOAD_NAMES)
        self.assertEqual(
            MANAGER.EXPECTED_MODES["native_stack_session_manager"], 0o755,
        )
        self.assertEqual(
            set(MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES),
            set(MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES)
            - {"native_stack_session_manager"},
        )
        self.assertEqual(
            set(LAUNCHER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES),
            set(MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES),
        )
        for inventory in (
            MANAGER.PRE_NATIVE_TERMINAL_BRIDGE_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_CREDENTIAL_PAYLOAD_NAMES,
            MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES,
            MANAGER.PRE_HARNESS_LIFECYCLE_PAYLOAD_NAMES,
            MANAGER.PRE_MODEL_PROFILE_PAYLOAD_NAMES,
        ):
            self.assertNotIn("native_stack_session_manager", inventory)

    def test_session_manager_imports_from_clean_installed_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            (release / "native_stack_manager").write_bytes(
                (REPO / "scripts/native_stack_manager.py").read_bytes()
            )
            (release / "native_stack_session_manager").write_bytes(
                (REPO / "scripts/native_stack_session_manager.py").read_bytes()
            )
            (release / "native_stack_support").write_bytes(
                MANAGER.native_stack_support_archive(REPO)
            )
            completed = subprocess.run(
                [
                    sys.executable, "-I", "-c",
                    (
                        "import importlib.machinery, importlib.util, pathlib; "
                        "p=pathlib.Path(r'" + str(
                            release / "native_stack_session_manager"
                        ) + "'); "
                        "l=importlib.machinery.SourceFileLoader('installed_session',str(p)); "
                        "s=importlib.util.spec_from_loader(l.name,l); "
                        "m=importlib.util.module_from_spec(s); l.exec_module(m); "
                        "from shared import native_projection_identity_recovery; "
                        "assert m.stack_manager.__name__ == "
                        "'native_stack_session_manager_stack_manager'"
                    ),
                ],
                cwd=release, capture_output=True, text=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_component_manifest_is_closed_and_name_bound(self):
        executable = MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix()
        value = {
            "backend": {
                "identifier": MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
                "mode": 0o555, "sha256": "a" * 64, "size": 123,
            },
            "consumer": {
                "identifier": MANAGER.NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
                "mode": 0o555, "sha256": "b" * 64, "size": 456,
            },
            "helper": {
                "bundle": MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
                "identifier": MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                "files": {
                    "Contents/Info.plist": {
                        "mode": 0o444, "sha256": "c" * 64, "size": 64,
                    },
                    executable: {
                        "mode": 0o555, "sha256": "d" * 64, "size": 789,
                    },
                },
            },
            "schema": "secure-sandbox-native-components-bundle-v1",
            "signing_policy": {"team_id": "ABCDE" + "12345"},
        }
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        self.assertEqual(MANAGER.native_components_manifest(encoded), value)
        value["fallback"] = True
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_components_manifest_invalid"
        ):
            MANAGER.native_components_manifest(
                (json.dumps(value, sort_keys=True) + "\n").encode()
            )

    def test_launch_agent_install_is_atomic_exact_and_read_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release"
            release.mkdir()
            service = {
                "Label": MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                "ProgramArguments": [
                    MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH
                ],
                "MachServices": {
                    MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL: True
                },
                "LimitLoadToSessionType": ["Aqua"],
                "ProcessType": "Interactive",
                "RunAtLoad": False,
            }
            data = plistlib.dumps(service, sort_keys=True)
            (release / "native_credential_helper_service").write_bytes(data)
            plist_path = root / "LaunchAgents" / "native.plist"
            plist_path.parent.mkdir()
            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(
                MANAGER, "native_credential_service_is_loaded",
                return_value=True,
            ), mock.patch.object(
                MANAGER, "stop_launchd_service_exact",
            ), mock.patch.object(
                MANAGER.subprocess, "run", return_value=completed,
            ) as launched:
                MANAGER.install_native_credential_service(
                    release, uid=501, plist_path=plist_path
                )
            self.assertEqual(plist_path.read_bytes(), data)
            self.assertEqual(plist_path.stat().st_mode & 0o777, 0o444)
            self.assertEqual(
                launched.call_args.args[0],
                ["/bin/launchctl", "bootstrap", "gui/501", str(plist_path)],
            )

    def test_launchd_identity_rejects_same_second_pid_generation_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "helper"
            executable.write_bytes(b"helper\n")
            executable.chmod(0o555)
            first = {
                "pid": 71,
                "euid": 501,
                "start_generation": [1_800_000_000, 111_111],
                "executable": str(executable),
                "arguments": [str(executable)],
            }
            reused = {
                **first,
                "start_generation": [1_800_000_000, 222_222],
            }
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_pid", side_effect=[71, 71]
                ),
                mock.patch.object(
                    MANAGER, "process_live_identity",
                    side_effect=[first, reused, reused],
                ),
                mock.patch.object(
                    MANAGER, "verify_live_native_code"
                ) as live_code,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_process_changed",
                ),
            ):
                MANAGER.launchd_live_identity(
                    "gui/501", MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                    [str(executable)], executable, 501,
                    native_code_identity=(
                        MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                        "ABCDE" + "12345",
                    ),
                )
            live_code.assert_called_once_with(
                71, MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                "ABCDE" + "12345",
            )

    def test_process_identity_brackets_path_and_argv_with_microseconds(self):
        with (
            mock.patch.object(
                MANAGER, "process_generation",
                side_effect=[(501, 1234, 10), (501, 1234, 11)],
            ),
            mock.patch.object(
                MANAGER, "process_executable_path", return_value="/bin/helper"
            ),
            mock.patch.object(
                MANAGER, "process_arguments", return_value=["/bin/helper"]
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_process_changed"
            ),
        ):
            MANAGER.process_live_identity(71, "helper")

    def test_launchd_state_classifies_exact_inactive_job_without_weakening_pid_api(self):
        target = "gui/501/test.service"
        inactive = subprocess.CompletedProcess(
            [], 0,
            "\n".join([
                f"{target} = {{",
                "\tactive count = 0",
                "\tstate = not running",
                "\tjob state = uninitialized",
                "}",
                "",
            ]),
            "",
        )
        with mock.patch.object(
            MANAGER.subprocess, "run", return_value=inactive,
        ):
            self.assertEqual(
                MANAGER.launchd_service_state("gui/501", "test.service"),
                ("inactive", None),
            )
        with (
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=inactive,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_pid_unproven",
            ),
        ):
            MANAGER.launchd_service_pid_or_absent(
                "gui/501", "test.service",
            )

    def test_launchd_state_classifies_exact_scheduled_job_for_stop_only(self):
        target = "system/test.service"
        scheduled = subprocess.CompletedProcess(
            [], 0,
            "\n".join([
                f"{target} = {{",
                "\tactive count = 0",
                "\tstate = spawn scheduled",
                "\tjob state = exited",
                "}",
                "",
            ]),
            "",
        )
        with mock.patch.object(
            MANAGER.subprocess, "run", return_value=scheduled,
        ):
            self.assertEqual(
                MANAGER.launchd_service_state("system", "test.service"),
                ("scheduled", None),
            )
        with (
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=scheduled,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_pid_unproven",
            ),
        ):
            MANAGER.launchd_service_pid_or_absent(
                "system", "test.service",
            )

    def test_inactive_launchd_definition_accepts_only_exact_nested_inventory(self):
        domain = "gui/501"
        label = MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL
        plist = Path("/Library/LaunchAgents") / f"{label}.plist"
        program = "/trusted/current/helper"
        snapshot = inactive_launchd_snapshot(
            domain=domain, label=label, plist=plist, program=program,
            runs=None,
        )
        observed = MANAGER.inactive_launchd_service_definition(
            snapshot, domain, label,
            expected_plist=plist, expected_program=program,
        )
        self.assertIsNone(observed["runs"])
        self.assertEqual(observed["arguments"], [program])
        self.assertEqual(observed["endpoint"], {
            "active": 0, "managed": 1, "name": label,
        })
        self.assertEqual(observed["job_state"], "uninitialized")
        self.assertIsNone(observed["last_exit_code"])

        mutations = {
            "missing-path": snapshot.replace(f"\tpath = {plist}\n", "", 1),
            "duplicate-path": snapshot.replace(
                f"\tpath = {plist}\n",
                f"\tpath = {plist}\n\tpath = {plist}\n", 1,
            ),
            "wrong-type": snapshot.replace(
                "\ttype = LaunchAgent", "\ttype = LaunchDaemon", 1,
            ),
            "wrong-program": snapshot.replace(
                f"\tprogram = {program}", "\tprogram = /other/helper", 1,
            ),
            "wrong-domain": snapshot.replace(
                f"\tdomain = {domain} [100002]",
                "\tdomain = gui/502 [100002]", 1,
            ),
            "wrong-asid": snapshot.replace(
                "\tasid = 100002", "\tasid = 100003", 1,
            ),
            "extra-argument": snapshot.replace(
                f"\t\t{program}\n\t}}",
                f"\t\t{program}\n\t\t--unsafe\n\t}}", 1,
            ),
            "wrong-spawn-type": snapshot.replace(
                "\tspawn type = interactive (4)",
                "\tspawn type = daemon (3)", 1,
            ),
            "unmanaged-endpoint": snapshot.replace(
                "\t\t\tmanaged = 1", "\t\t\tmanaged = 0", 1,
            ),
            "wrong-endpoint": snapshot.replace(
                f'\t\t"{label}" = {{',
                '\t\t"org.example.Other" = {', 1,
            ),
            "extra-endpoint": snapshot.replace(
                "\t\t}\n\t}\n\n\tspawn type",
                "\t\t}\n\t\t\"org.example.Other\" = {\n"
                "\t\t\tactive = 0\n\t\t\tmanaged = 1\n\t\t}\n"
                "\t}\n\n\tspawn type", 1,
            ),
            "duplicate-runs": snapshot.replace(
                "\tasid = 100002\n",
                "\tasid = 100002\n\truns = 0\n\truns = 0\n", 1,
            ),
            "malformed-runs": snapshot.replace(
                "\tasid = 100002\n",
                "\tasid = 100002\n\truns = unknown\n", 1,
            ),
            "duplicate-job-state": snapshot.replace(
                "\tjob state = uninitialized",
                "\tjob state = uninitialized\n\tjob state = uninitialized",
                1,
            ),
            "empty-last-exit": snapshot.replace(
                "\tjob state = uninitialized",
                "\tlast exit code =\n\tjob state = uninitialized", 1,
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "host_service_definition_unproven",
            ):
                MANAGER.inactive_launchd_service_definition(
                    mutated, domain, label,
                    expected_plist=plist, expected_program=program,
                )

    def test_inactive_native_identity_brackets_static_and_launchd_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root / "releases"
            release = releases / ("a" * 64)
            executable = (
                release / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE
            )
            executable.parent.mkdir(parents=True)
            executable_data = b"signed helper\n"
            executable.write_bytes(executable_data)
            service_data = b"exact service plist\n"
            (release / "native_credential_helper_service").write_bytes(
                service_data
            )
            current = root / "current"
            current.symlink_to(Path("releases") / release.name)
            program = str(
                current / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE
            )
            plist = root / "native.plist"
            plist.write_bytes(service_data)
            manifest = {
                "helper": {"files": {
                    MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix(): {
                        "mode": 0o555,
                        "sha256": hashlib.sha256(executable_data).hexdigest(),
                        "size": len(executable_data),
                    },
                }},
                "signing_policy": {"team_id": "ABCDE12345"},
            }
            first = inactive_launchd_snapshot(
                domain="gui/501", label=MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                plist=plist, program=program, runs=None,
            )

            def read_acl(path, *_args, **_kwargs):
                return Path(path).read_bytes()

            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular", side_effect=read_acl,
                ) as trusted_read,
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                ) as signature,
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, first),
                ),
            ):
                evidence = MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, first,
                )
            self.assertEqual(evidence["attestation_mode"], "inactive-static")
            self.assertEqual(evidence["state"], "inactive")
            self.assertEqual(evidence["launchd_uid"], 501)
            self.assertNotIn("pid", evidence)
            self.assertEqual(trusted_read.call_count, 4)
            self.assertEqual(
                trusted_read.call_args_list[0].args[:3],
                (plist, 0, 0o444),
            )
            self.assertEqual(
                trusted_read.call_args_list[1].args[:3],
                (executable, 0, 0o555),
            )
            signature.assert_called_once_with(
                release / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
                MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                "ABCDE12345",
            )

            changed_runs = inactive_launchd_snapshot(
                domain="gui/501", label=MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                plist=plist, program=program, runs=1,
            )
            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular", side_effect=read_acl,
                ),
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                ),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, changed_runs),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_definition_changed",
                ),
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, first,
                )

            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular", side_effect=read_acl,
                ),
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                ),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("running", 72, "running"),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_state_changed",
                ),
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, first,
                )

    def test_inactive_native_identity_rejects_static_evidence_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "releases" / ("b" * 64)
            executable = (
                release / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE
            )
            executable.parent.mkdir(parents=True)
            executable_data = b"signed helper\n"
            executable.write_bytes(executable_data)
            service_data = b"service\n"
            (release / "native_credential_helper_service").write_bytes(
                service_data
            )
            current = root / "current"
            current.symlink_to(Path("releases") / release.name)
            program = str(
                current / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE
            )
            plist = root / "native.plist"
            plist.write_bytes(service_data)
            manifest = {
                "helper": {"files": {
                    MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix(): {
                        "mode": 0o555,
                        "sha256": hashlib.sha256(executable_data).hexdigest(),
                        "size": len(executable_data),
                    },
                }},
                "signing_policy": {"team_id": "ABCDE12345"},
            }
            snapshot = inactive_launchd_snapshot(
                domain="gui/501", label=MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                plist=plist, program=program,
            )
            common = (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, snapshot),
                ),
            )
            reads = [service_data, executable_data, b"tampered", executable_data]
            with common[0], common[1], common[2], mock.patch.object(
                MANAGER, "read_acl_free_regular", side_effect=reads,
            ), mock.patch.object(
                MANAGER, "verify_native_component_signature",
            ), self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_definition_changed",
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, snapshot,
                )

            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular",
                    side_effect=lambda path, *_args, **_kwargs:
                        Path(path).read_bytes(),
                ),
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                    side_effect=MANAGER.ReleaseFailure(
                        "native_component_signature_invalid"
                    ),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_component_signature_invalid",
                ),
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, snapshot,
                )

            executable_reads = [
                service_data, executable_data, service_data, b"tampered",
            ]
            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular",
                    side_effect=executable_reads,
                ),
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                ),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, snapshot),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_definition_changed",
                ),
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, snapshot,
                )

            other = root / "releases" / ("c" * 64)
            other_executable = (
                other / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE
            )
            other_executable.parent.mkdir(parents=True)
            other_executable.write_bytes(executable_data)

            def swap_selector(*_args):
                current.unlink()
                current.symlink_to(Path("releases") / other.name)

            with (
                mock.patch.object(
                    MANAGER, "NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH",
                    program,
                ),
                mock.patch.object(
                    MANAGER, "DEFAULT_NATIVE_CREDENTIAL_PLIST", plist,
                ),
                mock.patch.object(
                    MANAGER, "read_acl_free_regular",
                    side_effect=lambda path, *_args, **_kwargs:
                        Path(path).read_bytes(),
                ),
                mock.patch.object(
                    MANAGER, "verify_native_component_signature",
                    side_effect=swap_selector,
                ),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, snapshot),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_definition_changed",
                ),
            ):
                MANAGER.inactive_native_credential_identity(
                    release, 501, manifest, snapshot,
                )

    def test_host_pair_only_opts_into_inactive_native_attestation(self):
        source = MANAGER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "DEFAULT_AUTHORIZATION_PLIST, 0, 0o644,\n"
            "        \"authorization_service_install_untrusted\"",
            source,
        )
        tree = ast.parse(source)
        opted_in = set()
        for function in tree.body:
            if not isinstance(function, ast.FunctionDef):
                continue
            for node in ast.walk(function):
                if (not isinstance(node, ast.Call)
                        or not isinstance(node.func, ast.Name)
                        or node.func.id != "verify_release_host_services"):
                    continue
                for keyword in node.keywords:
                    if (keyword.arg == "allow_inactive_native"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True):
                        opted_in.add(function.name)
        self.assertEqual(opted_in, {
            "_select_host_pair_physical_state",
            "_verify_committed_host_pair_physical_state",
            "execute_host_pair_transition",
            "install",
            "rollback",
        })

        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            (release / "authorization_service").write_bytes(b"service")
            manifest = {
                "payloads": {
                    name: "a" * 64
                    for name in MANAGER.LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES
                },
            }
            native_manifest = {
                "signing_policy": {"team_id": "ABCDE12345"},
            }
            with (
                mock.patch.object(
                    MANAGER, "verify_release_authorization_service",
                    return_value={"pid": 71},
                ),
                mock.patch.object(
                    MANAGER, "native_components_manifest",
                    return_value=native_manifest,
                ),
                mock.patch.object(MANAGER, "read_regular", return_value=b"x"),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, "snapshot"),
                ) as snapshot,
                mock.patch.object(
                    MANAGER, "launchd_live_identity",
                    side_effect=MANAGER.ReleaseFailure(
                        "host_service_pid_unproven"
                    ),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "host_service_pid_unproven",
                ),
            ):
                MANAGER.verify_release_host_services(
                    release, manifest, 501,
                )
            snapshot.assert_not_called()

            inactive_evidence = {
                "attestation_mode": "inactive-static", "state": "inactive",
            }
            with (
                mock.patch.object(
                    MANAGER, "verify_release_authorization_service",
                    return_value={"pid": 71},
                ),
                mock.patch.object(
                    MANAGER, "native_components_manifest",
                    return_value=native_manifest,
                ),
                mock.patch.object(MANAGER, "read_regular", return_value=b"x"),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("inactive", None, "snapshot"),
                ),
                mock.patch.object(
                    MANAGER, "inactive_native_credential_identity",
                    return_value=inactive_evidence,
                ) as inactive_identity,
                mock.patch.object(MANAGER, "launchd_live_identity") as live,
            ):
                result = MANAGER.verify_release_host_services(
                    release, manifest, 501, allow_inactive_native=True,
                )
            self.assertEqual(result["native_credential"], inactive_evidence)
            inactive_identity.assert_called_once()
            live.assert_not_called()

            running_evidence = {"pid": 72, "start_generation": [1, 2]}
            with (
                mock.patch.object(
                    MANAGER, "verify_release_authorization_service",
                    return_value={"pid": 71},
                ),
                mock.patch.object(
                    MANAGER, "native_components_manifest",
                    return_value=native_manifest,
                ),
                mock.patch.object(MANAGER, "read_regular", return_value=b"x"),
                mock.patch.object(
                    MANAGER, "launchd_service_snapshot",
                    return_value=("running", 72, "snapshot"),
                ),
                mock.patch.object(
                    MANAGER, "inactive_native_credential_identity",
                ) as inactive_identity,
                mock.patch.object(
                    MANAGER, "launchd_live_identity",
                    return_value=running_evidence,
                ) as live,
            ):
                result = MANAGER.verify_release_host_services(
                    release, manifest, 501, allow_inactive_native=True,
                )
            self.assertEqual(result["native_credential"], running_evidence)
            live.assert_called_once()
            inactive_identity.assert_not_called()

    def test_launchd_state_accepts_only_exact_absent_and_running_records(self):
        target = "system/test.service"
        absent = subprocess.CompletedProcess([], 113, "", "not found")
        running = subprocess.CompletedProcess(
            [], 0,
            "\n".join([
                f"{target} = {{",
                "\tactive count = 1",
                "\tstate = running",
                "\tresource coalition = {",
                "\t\tstate = active",
                "\t\tactive count = 1",
                "\t}",
                "\tjetsam coalition = {",
                "\t\tstate = active",
                "\t\tactive count = 1",
                "\t}",
                "\tpid = 71",
                "}",
                "",
            ]),
            "",
        )
        with mock.patch.object(
            MANAGER.subprocess, "run", return_value=absent,
        ):
            self.assertEqual(
                MANAGER.launchd_service_state("system", "test.service"),
                ("absent", None),
            )
        with mock.patch.object(
            MANAGER.subprocess, "run", return_value=running,
        ):
            self.assertEqual(
                MANAGER.launchd_service_state("system", "test.service"),
                ("running", 71),
            )

    def test_launchd_state_rejects_contradictory_or_duplicate_records(self):
        target = "gui/501/test.service"
        bodies = {
            "wrong-header": [
                "gui/501/other.service = {",
                "\tactive count = 0", "\tstate = not running", "}",
            ],
            "duplicate-active": [
                f"{target} = {{", "\tactive count = 0",
                "\tactive count = 0", "\tstate = not running", "}",
            ],
            "malformed-duplicate-active": [
                f"{target} = {{", "\tactive count = 0",
                "\tactive count = nonsense", "\tstate = not running", "}",
            ],
            "duplicate-state": [
                f"{target} = {{", "\tactive count = 0",
                "\tstate = not running", "\tstate = not running", "}",
            ],
            "inactive-with-pid": [
                f"{target} = {{", "\tactive count = 0",
                "\tstate = not running", "\tpid = 71", "}",
            ],
            "inactive-with-zero-pid": [
                f"{target} = {{", "\tactive count = 0",
                "\tstate = not running", "\tpid = 0", "}",
            ],
            "inactive-with-malformed-pid": [
                f"{target} = {{", "\tactive count = 0",
                "\tstate = not running", "\tpid = nonsense", "}",
            ],
            "scheduled-with-active-count": [
                f"{target} = {{", "\tactive count = 1",
                "\tstate = spawn scheduled", "}",
            ],
            "scheduled-with-pid": [
                f"{target} = {{", "\tactive count = 0",
                "\tstate = spawn scheduled", "\tpid = 71", "}",
            ],
            "running-without-pid": [
                f"{target} = {{", "\tactive count = 1",
                "\tstate = running", "}",
            ],
            "multiple-pids": [
                f"{target} = {{", "\tactive count = 2",
                "\tstate = running", "\tpid = 71", "\tpid = 72", "}",
            ],
        }
        for label, lines in bodies.items():
            with self.subTest(label=label), mock.patch.object(
                MANAGER.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    [], 0, "\n".join(lines) + "\n", "",
                ),
            ), self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_state_unproven",
            ):
                MANAGER.launchd_service_state("gui/501", "test.service")

    def test_launchd_state_rejects_oversized_output_before_classification(self):
        oversized = subprocess.CompletedProcess(
            [], 113, "x" * (512 * 1024 + 1), "",
        )
        with (
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=oversized,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "host_service_state_unproven",
            ),
        ):
            MANAGER.launchd_service_state("system", "test.service")

    def test_exact_service_stop_boots_out_inactive_job_then_fences_before_unlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            inactive = ("inactive", None)
            absent = ("absent", None)
            completed = subprocess.CompletedProcess([], 0, "", "")
            events = []

            def fence():
                self.assertTrue(plist.is_file())
                events.append("fenced")

            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[inactive, absent, absent],
                ),
                mock.patch.object(
                    MANAGER.subprocess, "run", return_value=completed,
                ) as run,
            ):
                MANAGER.stop_launchd_service_exact(
                    "gui/501", "test.service", plist,
                    post_bootout_fence=fence,
                )
            self.assertEqual(events, ["fenced"])
            self.assertFalse(plist.exists())
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/bin/launchctl", "bootout",
                    "gui/501/test.service",
                ],
            )

    def test_exact_service_stop_boots_out_scheduled_job_and_proves_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[
                        ("scheduled", None),
                        ("absent", None),
                        ("absent", None),
                    ],
                ),
                mock.patch.object(
                    MANAGER.subprocess, "run", return_value=completed,
                ) as run,
            ):
                MANAGER.stop_launchd_service_exact(
                    "system", "test.service", plist,
                )
            self.assertFalse(plist.exists())
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/bin/launchctl", "bootout",
                    "system/test.service",
                ],
            )

    def test_exact_service_stop_preserves_plist_when_inactive_fence_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[
                        ("inactive", None),
                        ("absent", None),
                        ("absent", None),
                    ],
                ),
                mock.patch.object(
                    MANAGER.subprocess, "run", return_value=completed,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_coordination_legacy_operation_active",
                ),
            ):
                MANAGER.stop_launchd_service_exact(
                    "gui/501", "test.service", plist,
                    post_bootout_fence=lambda: (_ for _ in ()).throw(
                        MANAGER.ReleaseFailure(
                            "native_coordination_legacy_operation_active"
                        )
                    ),
                )
            self.assertTrue(plist.is_file())

    def test_exact_service_stop_rejects_inactive_job_reappearing_after_bootout(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[
                        ("inactive", None),
                        ("absent", None),
                        ("running", 72),
                    ],
                ),
                mock.patch.object(
                    MANAGER.subprocess, "run", return_value=completed,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "host_service_state_changed",
                ),
            ):
                MANAGER.stop_launchd_service_exact(
                    "gui/501", "test.service", plist,
                )
            self.assertTrue(plist.is_file())

    def test_native_credential_stop_forwards_post_bootout_fence(self):
        fence = mock.Mock()
        plist = Path("/tmp/native-credential-test.plist")
        with mock.patch.object(
            MANAGER, "stop_launchd_service_exact",
        ) as stopped:
            MANAGER.stop_native_credential_service(
                uid=501, plist_path=plist, post_bootout_fence=fence,
            )
        stopped.assert_called_once_with(
            "gui/501", MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL, plist,
            post_bootout_fence=fence,
        )

    def test_legacy_service_fence_repeats_release_census_after_helper_bootout(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "host"
            release = install_root / "releases" / ("f" * 64)
            release.mkdir(parents=True)
            manifest = {
                "release_id": release.name,
                "payloads": {"authorization_broker": "a" * 64},
            }

            def stop_native(*, uid, post_bootout_fence):
                self.assertEqual(uid, 501)
                post_bootout_fence()

            with (
                mock.patch.object(
                    MANAGER, "launchd_service_pid_or_absent",
                    side_effect=[None, None, None],
                ),
                mock.patch.object(MANAGER, "stop_touchid_service"),
                mock.patch.object(
                    MANAGER, "stop_native_credential_service",
                    side_effect=stop_native,
                ),
                mock.patch.object(
                    MANAGER, "ensure_no_d8653cb_release_processes",
                ) as census,
            ):
                MANAGER.stop_and_fence_d8653cb_host_services(
                    501, release, manifest,
                    expected_release_id=release.name,
                    expected_broker_sha256="a" * 64,
                )
            self.assertEqual(
                census.call_args_list,
                [
                    mock.call(release, install_root, 0),
                    mock.call(release, install_root, 501),
                    mock.call(release, install_root, 501),
                ],
            )

    def test_legacy_service_fence_censuses_helper_when_job_was_already_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "host"
            release = install_root / "releases" / ("f" * 64)
            release.mkdir(parents=True)
            manifest = {
                "release_id": release.name,
                "payloads": {"authorization_broker": "a" * 64},
            }
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_pid_or_absent",
                    side_effect=[None, None, None],
                ),
                mock.patch.object(MANAGER, "stop_touchid_service"),
                mock.patch.object(
                    MANAGER, "stop_native_credential_service",
                ) as stop_native,
                mock.patch.object(
                    MANAGER, "ensure_no_d8653cb_release_processes",
                ) as census,
            ):
                MANAGER.stop_and_fence_d8653cb_host_services(
                    501, release, manifest,
                    expected_release_id=release.name,
                    expected_broker_sha256="a" * 64,
                )
            stop_native.assert_called_once()
            self.assertEqual(
                census.call_args_list,
                [
                    mock.call(release, install_root, 0),
                    mock.call(release, install_root, 501),
                ],
            )

    def test_exact_service_stop_rejects_bootout_failure_before_plist_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            failed = subprocess.CompletedProcess([], 5, "", "denied")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[("running", 71), ("running", 71)],
                ),
                mock.patch.object(
                    MANAGER, "process_generation", return_value=(0, 1234, 5),
                ),
                mock.patch.object(MANAGER.subprocess, "run", return_value=failed),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "host_service_bootout_failed",
                ),
            ):
                MANAGER.stop_launchd_service_exact(
                    "system", "test.service", plist,
                )
            self.assertTrue(plist.is_file())

    def test_exact_service_stop_waits_for_captured_generation_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[
                        ("running", 71), ("running", 71),
                        ("running", 71), ("absent", None),
                        ("absent", None),
                    ],
                ),
                mock.patch.object(
                    MANAGER, "process_generation", return_value=(0, 1234, 5),
                ),
                mock.patch.object(
                    MANAGER, "process_generation_or_absent",
                    side_effect=[(0, 1234, 5), (501, 1234, 6)],
                ),
                mock.patch.object(MANAGER.subprocess, "run", return_value=completed),
                mock.patch.object(MANAGER.time, "sleep"),
            ):
                MANAGER.stop_launchd_service_exact(
                    "system", "test.service", plist,
                )
            self.assertFalse(plist.exists())

    def test_exact_service_stop_accepts_only_stable_launchd_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_state",
                    side_effect=[("absent", None), ("running", 72)],
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "host_service_state_changed",
                ),
            ):
                MANAGER.stop_launchd_service_exact(
                    "system", "test.service", plist,
                )
            self.assertTrue(plist.is_file())

    def test_terminal_record_publication_is_idempotent_and_recovers_link_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            terminal = self._terminal_record()
            try:
                first = MANAGER.publish_terminal_state_record(
                    descriptor, terminal, os.geteuid(),
                )
                second = MANAGER.publish_terminal_state_record(
                    descriptor, terminal, os.geteuid(),
                )
                self.assertEqual(first, second)
                directory = root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                final = directory / f"{terminal['transition_id']}.json"
                pending = directory / f".{terminal['transition_id']}.pending"
                os.link(final, pending)
                self.assertEqual(final.stat().st_nlink, 2)
                MANAGER.publish_terminal_state_record(
                    descriptor, terminal, os.geteuid(),
                )
                self.assertFalse(pending.exists())
                self.assertEqual(final.stat().st_nlink, 1)
                self.assertEqual(final.stat().st_mode & 0o777, 0o444)
            finally:
                os.close(descriptor)

    def test_install_transition_authority_rejects_allow_and_deny_acls(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            root_descriptor = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                directory = MANAGER.open_install_transition_directory(
                    root_descriptor, os.geteuid(),
                )
                try:
                    MANAGER.write_new_state_record_at(
                        directory, "fixture.json", {"value": "bound"},
                        os.geteuid(), 0o600,
                    )
                finally:
                    os.close(directory)
                transition_root = (
                    root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                )
                record = transition_root / "fixture.json"
                subprocess.run(
                    [
                        "/usr/bin/xattr", "-w",
                        "com.zebeth.securesandbox.test", "xattr",
                        str(record),
                    ],
                    check=True, capture_output=True, text=True,
                )
                directory = MANAGER.open_install_transition_directory(
                    root_descriptor, os.geteuid(),
                )
                try:
                    observed, _raw, _info = MANAGER.read_state_record_at(
                        directory, "fixture.json", os.geteuid(), 0o600,
                    )
                    self.assertEqual(observed, {"value": "bound"})
                finally:
                    os.close(directory)

                for target, rule, operation in (
                    (
                        transition_root, "everyone allow write",
                        lambda: MANAGER.open_install_transition_directory(
                            root_descriptor, os.geteuid(),
                        ),
                    ),
                    (
                        record, "everyone deny read",
                        lambda: self._read_transition_fixture(
                            root_descriptor,
                        ),
                    ),
                ):
                    added = subprocess.run(
                        ["/bin/chmod", "+a", rule, str(target)],
                        check=False, capture_output=True, text=True,
                    )
                    if added.returncode != 0:
                        self.skipTest("extended ACL fixture unavailable")
                    try:
                        with self.assertRaises(MANAGER.ReleaseFailure):
                            operation()
                    finally:
                        subprocess.run(
                            ["/bin/chmod", "-N", str(target)], check=False,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
            finally:
                os.close(root_descriptor)

    @staticmethod
    def _read_transition_fixture(root_descriptor: int) -> None:
        directory = MANAGER.open_install_transition_directory(
            root_descriptor, os.geteuid(),
        )
        try:
            MANAGER.read_state_record_at(
                directory, "fixture.json", os.geteuid(), 0o600,
            )
        finally:
            os.close(directory)

    def test_terminal_record_discards_only_non_authoritative_partial_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            terminal = self._terminal_record(
                "33333333-3333-4333-8333-333333333333"
            )
            try:
                directory_descriptor = MANAGER.open_install_transition_directory(
                    descriptor, os.geteuid(),
                )
                try:
                    staging = f".{terminal['transition_id']}.staging"
                    partial = os.open(
                        staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600, dir_fd=directory_descriptor,
                    )
                    os.write(partial, b"partial")
                    os.close(partial)
                finally:
                    os.close(directory_descriptor)
                MANAGER.publish_terminal_state_record(
                    descriptor, terminal, os.geteuid(),
                )
                final = (
                    root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                    / f"{terminal['transition_id']}.json"
                )
                self.assertEqual(
                    final.read_bytes(), MANAGER.canonical_state_record(terminal)
                )
            finally:
                os.close(descriptor)

    def test_successor_consumes_published_commit_before_pid_revalidation(self):
        for status in ("deployed_verified", "failed_rolled_back"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                install_root = base / "host"
                receipt_root = base / "receipts"
                transition, _finalization, _receipt, terminal = (
                    self._publish_install_commit_fixture(
                        install_root, receipt_root, status=status,
                    )
                )
                expected_release = (
                    transition["candidate_release_id"]
                    if status == "deployed_verified"
                    else transition["fallback_release_id"]
                )
                listener, listener_peer = os.pipe()
                readiness, readiness_peer = os.pipe()
                try:
                    with (
                        mock.patch.object(
                            MANAGER, "open_trusted_absolute_directory",
                            side_effect=self._open_test_directory,
                        ),
                        mock.patch.object(
                            MANAGER, "DEFAULT_AUTHORIZATION_RECEIPT_ROOT",
                            receipt_root,
                        ),
                        mock.patch.object(
                            MANAGER, "successful_install_finalization",
                        ) as dynamic_success,
                        mock.patch.object(
                            MANAGER, "rolled_back_install_finalization",
                        ) as dynamic_rollback,
                    ):
                        observed = MANAGER.finalize_install_transition(
                            install_root, expected_release, 91,
                            os.geteuid(), listener, readiness, "ab" * 32,
                            now=2_000_000_020,
                        )
                finally:
                    os.close(listener_peer)
                    os.close(readiness_peer)
                self.assertEqual(observed, terminal)
                self.assertFalse(
                    (install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME)
                    .exists()
                )
                public = (
                    install_root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                    / f"{transition['transition_id']}.json"
                )
                self.assertEqual(
                    public.read_bytes(), MANAGER.canonical_state_record(terminal)
                )
                self.assertEqual(public.stat().st_nlink, 1)
                dynamic_success.assert_not_called()
                dynamic_rollback.assert_not_called()

    def test_successor_rejects_stale_receipt_for_published_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            install_root = base / "host"
            receipt_root = base / "receipts"
            transition, _finalization, receipt, _terminal = (
                self._publish_install_commit_fixture(
                    install_root, receipt_root,
                )
            )
            receipt["host_install_service_evidence_sha256"] = "f" * 64
            receipt_path = receipt_root / (
                f"{transition['authorization_request_id']}.json"
            )
            receipt_path.chmod(0o600)
            receipt_path.write_bytes(MANAGER.canonical_state_record(receipt))
            listener, listener_peer = os.pipe()
            readiness, readiness_peer = os.pipe()
            try:
                with (
                    mock.patch.object(
                        MANAGER, "open_trusted_absolute_directory",
                        side_effect=self._open_test_directory,
                    ),
                    mock.patch.object(
                        MANAGER, "DEFAULT_AUTHORIZATION_RECEIPT_ROOT",
                        receipt_root,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "install_transition_receipt_not_committed",
                    ),
                ):
                    MANAGER.finalize_install_transition(
                        install_root, transition["candidate_release_id"], 91,
                        os.geteuid(), listener, readiness, "ab" * 32,
                        now=2_000_000_020,
                    )
            finally:
                os.close(listener_peer)
                os.close(readiness_peer)
            self.assertTrue(
                (install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME).exists()
            )

    def test_successor_rejects_mismatched_public_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            install_root = base / "host"
            receipt_root = base / "receipts"
            transition, _finalization, _receipt, terminal = (
                self._publish_install_commit_fixture(
                    install_root, receipt_root,
                )
            )
            public = (
                install_root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
                / f"{transition['transition_id']}.json"
            )
            public.chmod(0o600)
            public.unlink()
            mismatched = dict(terminal)
            mismatched["authorization_receipt_sha256"] = "f" * 64
            mismatched["terminal_sha256"] = MANAGER.terminal_transition_digest(
                mismatched
            )
            descriptor = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                MANAGER.publish_terminal_state_record(
                    descriptor, mismatched, os.geteuid(),
                )
            finally:
                os.close(descriptor)
            listener, listener_peer = os.pipe()
            readiness, readiness_peer = os.pipe()
            try:
                with (
                    mock.patch.object(
                        MANAGER, "open_trusted_absolute_directory",
                        side_effect=self._open_test_directory,
                    ),
                    mock.patch.object(
                        MANAGER, "DEFAULT_AUTHORIZATION_RECEIPT_ROOT",
                        receipt_root,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "install_transition_terminal_conflict",
                    ),
                ):
                    MANAGER.finalize_install_transition(
                        install_root, transition["candidate_release_id"], 91,
                        os.geteuid(), listener, readiness, "ab" * 32,
                        now=2_000_000_020,
                    )
            finally:
                os.close(listener_peer)
                os.close(readiness_peer)
            self.assertTrue(
                (install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME).exists()
            )

    def test_state_record_helpers_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "record_name_invalid",
                ):
                    MANAGER.write_new_state_record_at(
                        descriptor, "../escape", {"value": 1}, os.geteuid(), 0o600,
                    )
            finally:
                os.close(descriptor)

    def test_install_root_lock_serializes_pending_record_retirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)

            def opened(*_args, **_kwargs):
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)

            acquired = threading.Event()
            release = threading.Event()
            descriptors: list[int] = []
            with mock.patch.object(
                MANAGER, "open_trusted_absolute_directory",
                side_effect=opened,
            ):
                first = MANAGER.open_locked_install_root(
                    root, os.geteuid(),
                )

                def contender() -> None:
                    descriptor = MANAGER.open_locked_install_root(
                        root, os.geteuid(),
                    )
                    descriptors.append(descriptor)
                    acquired.set()
                    release.wait(timeout=1.0)
                    os.close(descriptor)

                thread = threading.Thread(target=contender)
                thread.start()
                self.assertFalse(acquired.wait(timeout=0.05))
                os.close(first)
                self.assertTrue(acquired.wait(timeout=1.0))
                release.set()
                thread.join(timeout=1.0)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(descriptors), 1)

    def test_activation_listener_evidence_requires_bound_listening_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorization.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            nonce = "ab" * 32
            try:
                listener.bind(str(path))
                with self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "install_transition_listener_unready",
                ):
                    MANAGER.authorization_listener_evidence(
                        listener.fileno(), -1, nonce, 81, path,
                        expected_uid=os.geteuid(),
                    )
                path.chmod(0o666)
                listener.listen(1)
                responder, finalizer = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_STREAM,
                )
                errors = []

                def respond() -> None:
                    try:
                        challenge = responder.recv(4096)
                        expected_challenge = {
                            "schema":
                                "secure-sandbox-install-readiness-challenge-v1",
                            "nonce_sha256": MANAGER.sha256_bytes(
                                bytes.fromhex(nonce)
                            ),
                        }
                        self.assertEqual(
                            challenge,
                            MANAGER.canonical_state_record(expected_challenge),
                        )
                        info = path.lstat()
                        responder.sendall(MANAGER.canonical_state_record({
                            "schema":
                                "secure-sandbox-install-readiness-response-v1",
                            "nonce_sha256": expected_challenge["nonce_sha256"],
                            "broker_pid": 81,
                            "path": str(path),
                            "device": info.st_dev,
                            "inode": info.st_ino,
                            "mode": stat.S_IMODE(info.st_mode),
                            "uid": info.st_uid,
                        }))
                    except BaseException as error:
                        errors.append(error)

                thread = threading.Thread(target=respond)
                thread.start()
                try:
                    evidence = MANAGER.authorization_listener_evidence(
                        listener.fileno(), finalizer.fileno(), nonce, 81, path,
                        expected_uid=os.geteuid(),
                    )
                finally:
                    thread.join(timeout=1.0)
                    finalizer.close()
                    responder.close()
                if errors:
                    raise errors[0]
                self.assertTrue(evidence["private_readiness_challenge"])
                self.assertEqual(evidence["path"], str(path))
                self.assertEqual(evidence["inode"], path.stat().st_ino)
            finally:
                listener.close()

    def test_activation_custody_status_uses_unlinked_mode_0400_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / ("a" * 64)
            release.mkdir()
            client = release / "native_stack_credential_client"
            client.write_bytes(b"signed-client\n")
            client.chmod(0o555)
            observed: dict[str, object] = {}

            def runner(command, **kwargs):
                descriptor = kwargs["pass_fds"][0]
                info = os.fstat(descriptor)
                observed.update({
                    "command": command,
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "nlink": info.st_nlink,
                })
                handoff = json.loads(os.read(descriptor, info.st_size + 1))
                observed["handoff"] = handoff
                reply = self._custody_status_reply(handoff["operation_id"])
                return subprocess.CompletedProcess(
                    command, 0, MANAGER.canonical_state_record(reply), b"",
                )

            evidence = MANAGER.zero_projection_custody_evidence(
                root, release, 501, os.geteuid(),
                operation_id="11111111-1111-4111-8111-111111111111",
                runner=runner,
            )
        self.assertEqual(observed["mode"], 0o400)
        self.assertEqual(observed["uid"], os.geteuid())
        self.assertEqual(observed["nlink"], 0)
        self.assertEqual(
            observed["command"][:-1], [
                "/bin/launchctl", "asuser", "501", str(client),
                "--request-fd",
            ],
        )
        self.assertTrue(str(observed["command"][-1]).isdecimal())
        handoff = observed["handoff"]
        self.assertEqual(handoff["operation"], "status")
        self.assertEqual(
            handoff["operation_id"],
            "11111111-1111-4111-8111-111111111111",
        )
        self.assertTrue(all(
            handoff[name] is None
            for name in MANAGER.NATIVE_PROJECTION_AUTHORITY_FIELDS
        ))
        self.assertEqual(evidence["custody_state"], "ambiguous")
        self.assertEqual(evidence["custody_projection_count"], 0)

    def test_activation_custody_status_rejects_v1_nonzero_and_unavailable(self):
        operation_id = "11111111-1111-4111-8111-111111111111"
        valid = self._custody_status_reply(operation_id)
        v1 = json.loads(json.dumps(valid))
        del v1["status"]["custody_projection_count"]
        body = {
            key: value for key, value in v1.items()
            if key not in {"schema", "reply_sha256"}
        }
        v1["reply_sha256"] = MANAGER.sha256_bytes(
            MANAGER.canonical_state_record(body)
        )
        nonzero = self._custody_status_reply(
            operation_id, count=1, custody_state="retained",
        )
        null_count = self._custody_status_reply(operation_id, count=None)
        wrong_schema = json.loads(json.dumps(valid))
        wrong_schema["schema"] = "secure-sandbox-native-credential-client-reply-v0"
        wrong_digest = json.loads(json.dumps(valid))
        wrong_digest["reply_sha256"] = "0" * 64
        extra_field = json.loads(json.dumps(valid))
        extra_field["bypass"] = True
        for value in (
            v1, nonzero, null_count, wrong_schema, wrong_digest, extra_field,
        ):
            with self.subTest(value=value["status"]):
                with self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_credential_custody_reply_invalid",
                ):
                    MANAGER.validate_zero_projection_custody_reply(
                        value, operation_id=operation_id,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / ("a" * 64)
            release.mkdir()

            def unavailable(command, **_kwargs):
                return subprocess.CompletedProcess(command, 1, b"", b"down")

            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_credential_custody_status_unavailable",
            ):
                MANAGER.zero_projection_custody_evidence(
                    root, release, 501, os.geteuid(), runner=unavailable,
                )

    def test_successor_exactly_consumes_crash_stranded_executing_receipt(self):
        transition = self._install_transition()
        receipt = {
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "request_id": transition["authorization_request_id"],
            "request_sha256": transition["authorization_request_sha256"],
            "operation": "host-controller-install",
            "status": "executing", "started_at": 2_000_000_000,
            "completed_at": None, "exit_status": None,
        }
        raw = MANAGER.canonical_state_record(receipt)
        transition = dict(transition)
        transition["authorization_pending_receipt_sha256"] = (
            MANAGER.sha256_bytes(raw)
        )
        transition["transition_sha256"] = MANAGER.install_transition_digest(
            transition
        )
        transition = MANAGER.validate_install_transition(transition)
        finalization = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"ready": True}, completed_at=2_000_000_010,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / f"{transition['authorization_request_id']}.json"
            path.write_bytes(raw)
            path.chmod(0o600)

            def open_root(*_args, **_kwargs):
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)

            with mock.patch.object(
                MANAGER, "open_trusted_absolute_directory",
                side_effect=open_root,
            ):
                completed, _completed_raw = (
                    MANAGER.complete_install_authorization_receipt(
                        transition, finalization, os.geteuid(),
                    )
                )
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(
            completed["authorization_pending_receipt_sha256"],
            MANAGER.sha256_bytes(raw),
        )
        self.assertEqual(
            completed["transition_sha256"], transition["transition_sha256"],
        )

    def test_initial_candidate_failure_requests_exact_rollback_without_fencing(self):
        transition = self._install_transition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "current").symlink_to(
                Path("releases") / transition["candidate_release_id"]
            )
            (root / MANAGER.INSTALL_TRANSITION_PENDING_NAME).write_text(
                "pending\n", encoding="ascii",
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "ensure_native_deployment_inactive_locked",
                ),
                mock.patch.object(
                    MANAGER, "successful_install_finalization",
                    side_effect=MANAGER.ReleaseFailure("injected"),
                ),
                mock.patch.object(MANAGER, "failed_install_finalization") as failed,
                mock.patch.object(MANAGER, "stage_install_finalization") as stage,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "install_transition_rollback_required",
                ),
            ):
                MANAGER.finalize_install_transition(
                    root, transition["candidate_release_id"], 81,
                    os.geteuid(), 40, 41, "ab" * 32,
                    now=2_000_000_010,
                )
        failed.assert_not_called()
        stage.assert_not_called()

    def test_same_release_activation_failure_publishes_recovery_fence(self):
        transition = dict(self._install_transition())
        transition["fallback_release_id"] = transition["candidate_release_id"]
        transition["old_current_target"] = (
            f"releases/{transition['candidate_release_id']}"
        )
        transition["transition_sha256"] = MANAGER.install_transition_digest(
            transition
        )
        transition = MANAGER.validate_install_transition(transition)
        failure = MANAGER.make_install_finalization(
            transition, status="failed_fenced",
            error="activation_verification_failed",
            authorization=None, native_credential=None,
            service_evidence={"same_release": True},
            completed_at=2_000_000_010,
        )
        staged = dict(transition)
        staged["terminal"] = failure
        staged = MANAGER.validate_install_transition(staged)
        terminal = MANAGER.make_install_terminal(staged, failure, "9" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            pending.write_text("pending\n", encoding="ascii")
            (root / "current").symlink_to(transition["old_current_target"])
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            listener, listener_peer = os.pipe()
            readiness, readiness_peer = os.pipe()
            try:
                with (
                    mock.patch.object(
                        MANAGER, "read_pending_install_transition",
                        return_value=(transition, descriptor),
                    ),
                    mock.patch.object(
                        MANAGER, "ensure_native_deployment_inactive_locked",
                    ),
                    mock.patch.object(
                        MANAGER, "successful_install_finalization",
                        side_effect=MANAGER.ReleaseFailure("injected"),
                    ),
                    mock.patch.object(
                        MANAGER, "failed_install_finalization",
                        return_value=failure,
                    ) as failed,
                    mock.patch.object(
                        MANAGER, "stage_install_finalization",
                        return_value=staged,
                    ) as stage,
                    mock.patch.object(
                        MANAGER, "ensure_install_failure_selector",
                    ) as selector,
                    mock.patch.object(
                        MANAGER, "complete_install_authorization_receipt",
                        return_value=({}, b"receipt\n"),
                    ),
                    mock.patch.object(
                        MANAGER, "make_install_terminal", return_value=terminal,
                    ),
                    mock.patch.object(
                        MANAGER, "publish_terminal_state_record",
                    ) as publish,
                ):
                    result = MANAGER.finalize_install_transition(
                        root, transition["candidate_release_id"], 81,
                        os.geteuid(), listener, readiness, "ab" * 32,
                        now=2_000_000_010,
                    )
            finally:
                os.close(listener_peer)
                os.close(readiness_peer)
            self.assertTrue(pending.exists())
        self.assertEqual(result["status"], "failed_fenced")
        failed.assert_called_once()
        stage.assert_called_once()
        selector.assert_called_once()
        publish.assert_called_once()

    def test_staged_candidate_success_for_dead_broker_requests_rollback(self):
        transition = self._install_transition()
        success = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"generation": "old"},
            completed_at=2_000_000_010,
        )
        transition = dict(transition)
        transition["terminal"] = success
        transition = MANAGER.validate_install_transition(transition)
        refreshed = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 91, "start_generation": [12, 22]},
            native_credential={"pid": 92, "start_generation": [13, 23]},
            service_evidence={"generation": "new"},
            completed_at=2_000_000_020,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / MANAGER.INSTALL_TRANSITION_PENDING_NAME).write_text(
                "pending\n", encoding="ascii",
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "successful_install_finalization",
                    return_value=refreshed,
                ),
                mock.patch.object(
                    MANAGER, "failed_install_finalization",
                ) as failed,
                mock.patch.object(MANAGER, "stage_install_finalization") as stage,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "install_transition_rollback_required",
                ),
            ):
                MANAGER.finalize_install_transition(
                    root, transition["candidate_release_id"], 91,
                    os.geteuid(), 40, 41, "ab" * 32,
                    now=2_000_000_020,
                )
        failed.assert_not_called()
        stage.assert_not_called()

    def test_selected_fallback_supersedes_staged_success_and_clears_pending(self):
        transition = self._install_transition()
        success = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"generation": "candidate"},
            completed_at=2_000_000_010,
        )
        transition = dict(transition)
        transition["terminal"] = success
        transition = MANAGER.validate_install_transition(transition)
        rollback = MANAGER.make_install_finalization(
            transition, status="failed_rolled_back",
            error="activation_rolled_back",
            authorization={"pid": 91, "start_generation": [12, 22]},
            native_credential={"pid": 92, "start_generation": [13, 23]},
            service_evidence={"generation": "fallback"},
            completed_at=2_000_000_020,
            superseded_finalization_sha256=success["finalization_sha256"],
        )
        staged = dict(transition)
        staged["terminal"] = rollback
        terminal = MANAGER.make_install_terminal(staged, rollback, "9" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            pending.write_text("pending\n", encoding="ascii")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            listener, listener_peer = os.pipe()
            readiness, readiness_peer = os.pipe()
            try:
                with (
                    mock.patch.object(
                        MANAGER, "read_pending_install_transition",
                        return_value=(transition, descriptor),
                    ),
                    mock.patch.object(
                        MANAGER, "rolled_back_install_finalization",
                        return_value=rollback,
                    ) as rolled_back,
                    mock.patch.object(
                        MANAGER, "stage_install_finalization",
                        return_value=staged,
                    ) as stage,
                    mock.patch.object(
                        MANAGER, "verify_finalized_services_still_live",
                    ),
                    mock.patch.object(
                        MANAGER, "complete_install_authorization_receipt",
                        return_value=({}, b"receipt\n"),
                    ),
                    mock.patch.object(
                        MANAGER, "make_install_terminal", return_value=terminal,
                    ),
                    mock.patch.object(
                        MANAGER, "publish_terminal_state_record",
                    ) as publish,
                ):
                    result = MANAGER.finalize_install_transition(
                        root, transition["fallback_release_id"], 91,
                        os.geteuid(), listener, readiness, "ab" * 32,
                        now=2_000_000_020,
                    )
            finally:
                os.close(listener_peer)
                os.close(readiness_peer)
            self.assertFalse(pending.exists())
        self.assertEqual(result["status"], "failed_rolled_back")
        self.assertEqual(
            rolled_back.call_args.kwargs["superseded_finalization_sha256"],
            success["finalization_sha256"],
        )
        stage.assert_called_once_with(
            descriptor, transition, rollback, os.geteuid(),
        )
        publish.assert_called_once()

    def test_candidate_startup_failure_prepares_exact_fallback_selector(self):
        transition = self._install_transition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            release = root / "candidate"
            release.mkdir()
            manifest = {"payloads": {"authorization_broker": "1" * 64}}
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "selector_target",
                    side_effect=[
                        f"releases/{transition['candidate_release_id']}",
                        transition["old_current_target"],
                    ],
                ),
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(release, manifest),
                ),
                mock.patch.object(
                    MANAGER, "verify_release_authorization_service",
                    return_value={"pid": 81},
                ),
                mock.patch.object(MANAGER, "atomic_symlink") as current,
            ):
                result = MANAGER.prepare_install_transition_rollback(
                    root, transition["candidate_release_id"], 81,
                    os.geteuid(),
                )
        self.assertEqual(result["status"], "rollback_prepared")
        current.assert_called_once_with(
            transition["old_current_target"], root / "current",
        )

    def test_failure_fence_preserves_selected_immutable_broker(self):
        transition = self._install_transition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "releases").mkdir()
            (root / "current").symlink_to(
                Path("releases") / transition["fallback_release_id"]
            )
            with (
                mock.patch.object(MANAGER, "stop_native_credential_service"),
                mock.patch.object(
                    MANAGER, "launchd_service_pid_or_absent", return_value=None,
                ),
                mock.patch.object(
                    MANAGER, "process_live_identity",
                    return_value={"pid": 81, "start_generation": [10, 20]},
                ),
            ):
                failure = MANAGER.failed_install_finalization(
                    root, transition, 81, os.geteuid(), 2_000_000_010,
                )
            self.assertEqual(failure["status"], "failed_fenced")
            self.assertEqual(
                os.readlink(root / "current"),
                transition["old_current_target"],
            )

    def test_failure_selector_repairs_absent_or_candidate_to_bound_fallback(self):
        transition = self._install_transition()
        candidate_target = f"releases/{transition['candidate_release_id']}"
        for starting_target in (None, candidate_target):
            with self.subTest(starting_target=starting_target):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    fallback = (
                        root / "releases" / transition["fallback_release_id"]
                    )
                    fallback.mkdir(parents=True)
                    if starting_target is not None:
                        (root / "current").symlink_to(starting_target)
                    with mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(fallback, {"payloads": {}}),
                    ) as verified:
                        MANAGER.ensure_install_failure_selector(
                            root, transition, os.geteuid(),
                        )
                    self.assertEqual(
                        os.readlink(root / "current"),
                        transition["old_current_target"],
                    )
                    self.assertEqual(
                        (root / "current").resolve(strict=True),
                        fallback.resolve(strict=True),
                    )
                    self.assertTrue(verified.call_args.kwargs["allow_legacy"])

    def test_failed_install_recovery_selects_fallback_before_each_later_step(self):
        transition = self._install_transition()
        checkpoints = (
            "install-recovery-helper-fenced",
            "install-recovery-current-selected",
            "install-recovery-previous-restored",
            "install-recovery-authorization-restored",
            "install-recovery-credential-restored",
            "install-recovery-services-verified",
        )
        for failed_checkpoint in checkpoints:
            with self.subTest(checkpoint=failed_checkpoint), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o755)
                releases = root / "releases"
                releases.mkdir()
                candidate = releases / transition["candidate_release_id"]
                fallback = releases / transition["fallback_release_id"]
                candidate.mkdir()
                fallback.mkdir()
                current = root / "current"
                current.symlink_to(
                    f"releases/{transition['candidate_release_id']}"
                )
                pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
                pending.write_text("pending\n", encoding="ascii")
                observed: list[str] = []

                def checkpoint(name: str) -> None:
                    observed.append(name)
                    if name == failed_checkpoint:
                        raise MANAGER.ReleaseFailure("injected")

                with (
                    mock.patch.object(
                        MANAGER, "rollback_transition_checkpoint",
                        side_effect=checkpoint,
                    ),
                    mock.patch.object(
                        MANAGER, "stop_native_credential_service",
                    ),
                    mock.patch.object(
                        MANAGER, "verified_release",
                        return_value=(fallback, {"payloads": {}}),
                    ),
                    mock.patch.object(MANAGER, "restore_selector"),
                    mock.patch.object(MANAGER, "install_touchid_service"),
                    mock.patch.object(
                        MANAGER, "install_native_credential_service",
                    ),
                    mock.patch.object(MANAGER, "verify_release_host_services"),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "host_service_rollback_unproven",
                    ),
                ):
                    MANAGER.restore_failed_install_transition(
                        root, transition, fallback, {"payloads": {}},
                        transition["old_previous_target"], 501, os.geteuid(),
                    )
                self.assertEqual(
                    os.readlink(current), transition["old_current_target"],
                )
                self.assertTrue(pending.exists())
                self.assertIn(failed_checkpoint, observed)

    def test_failed_install_recovery_never_unlinks_unproven_current(self):
        transition = self._install_transition()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            (root / "releases").mkdir()
            fallback = root / "releases" / transition["fallback_release_id"]
            fallback.mkdir()
            current = root / "current"
            candidate_target = f"releases/{transition['candidate_release_id']}"
            current.symlink_to(candidate_target)
            pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            pending.write_text("pending\n", encoding="ascii")
            with (
                mock.patch.object(
                    MANAGER, "stop_native_credential_service",
                ),
                mock.patch.object(
                    MANAGER, "verified_release",
                    side_effect=MANAGER.ReleaseFailure("unproven"),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_service_rollback_selector_unproven",
                ),
            ):
                MANAGER.restore_failed_install_transition(
                    root, transition, fallback, {"payloads": {}},
                    transition["old_previous_target"], 501, os.geteuid(),
                )
            self.assertTrue(os.path.lexists(current))
            self.assertEqual(os.readlink(current), candidate_target)
            self.assertTrue(pending.exists())

    def test_current_absent_recovery_publishes_only_failure_and_retains_fence(self):
        transition = self._install_transition()
        failure = MANAGER.make_install_finalization(
            transition, status="failed_fenced",
            error="activation_verification_failed",
            authorization=None, native_credential=None,
            service_evidence={"current_absent": True},
            completed_at=2_000_000_010,
        )
        staged = dict(transition)
        staged["terminal"] = failure
        terminal = MANAGER.make_install_terminal(staged, failure, "9" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            pending.write_text("pending\n", encoding="ascii")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "failed_install_finalization",
                    return_value=failure,
                ) as failed,
                mock.patch.object(
                    MANAGER, "ensure_install_failure_selector",
                ) as selector,
                mock.patch.object(
                    MANAGER, "stage_install_finalization", return_value=staged,
                ) as stage,
                mock.patch.object(
                    MANAGER, "complete_install_authorization_receipt",
                    return_value=({}, b"receipt\n"),
                ),
                mock.patch.object(
                    MANAGER, "make_install_terminal", return_value=terminal,
                ),
                mock.patch.object(
                    MANAGER, "publish_terminal_state_record",
                ) as publish,
            ):
                result = MANAGER.finalize_install_transition(
                    root, transition["candidate_release_id"], 81,
                    os.geteuid(), 40, 41, "ab" * 32,
                    now=2_000_000_010,
                )
            self.assertTrue(pending.exists())
        self.assertEqual(result["status"], "failed_fenced")
        failed.assert_called_once()
        selector.assert_called_once_with(root, transition, os.geteuid())
        stage.assert_called_once()
        publish.assert_called_once()

    def test_staged_failure_reselects_fallback_before_publication(self):
        transition = self._install_transition()
        failure = MANAGER.make_install_finalization(
            transition, status="failure_fence_unproven",
            error="activation_failure_fence_unproven",
            authorization=None, native_credential=None,
            service_evidence={"current_absent": True, "fence": "unproven"},
            completed_at=2_000_000_010,
        )
        transition = dict(transition)
        transition["terminal"] = failure
        transition = MANAGER.validate_install_transition(transition)
        terminal = MANAGER.make_install_terminal(
            transition, failure, "9" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pending = root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            pending.write_text("pending\n", encoding="ascii")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(MANAGER, "failed_install_finalization") as failed,
                mock.patch.object(
                    MANAGER, "ensure_install_failure_selector",
                ) as selector,
                mock.patch.object(MANAGER, "stage_install_finalization") as stage,
                mock.patch.object(
                    MANAGER, "complete_install_authorization_receipt",
                    return_value=({}, b"receipt\n"),
                ),
                mock.patch.object(
                    MANAGER, "make_install_terminal", return_value=terminal,
                ),
                mock.patch.object(
                    MANAGER, "publish_terminal_state_record",
                ) as publish,
            ):
                result = MANAGER.finalize_install_transition(
                    root, transition["candidate_release_id"], 81,
                    os.geteuid(), 40, 41, "ab" * 32,
                    now=2_000_000_020,
                )
            self.assertTrue(pending.exists())
        self.assertEqual(result["status"], "failure_fence_unproven")
        failed.assert_not_called()
        selector.assert_called_once_with(root, transition, os.geteuid())
        stage.assert_not_called()
        publish.assert_called_once()

    def test_rollback_prepare_accepts_staged_success_and_never_mutates_previous(self):
        transition = self._install_transition()
        success = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"ready": True}, completed_at=2_000_000_010,
        )
        transition = dict(transition)
        transition["terminal"] = success
        transition = MANAGER.validate_install_transition(transition)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            release = root / "candidate"
            release.mkdir()
            with (
                mock.patch.object(
                    MANAGER, "read_pending_install_transition",
                    return_value=(transition, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "selector_target",
                    side_effect=[
                        f"releases/{transition['candidate_release_id']}",
                        transition["old_current_target"],
                    ],
                ),
                mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(release, {"payloads": {}}),
                ),
                mock.patch.object(
                    MANAGER, "verify_release_authorization_service",
                    return_value={"pid": 81},
                ),
                mock.patch.object(MANAGER, "restore_selector") as previous,
                mock.patch.object(MANAGER, "atomic_symlink") as current,
            ):
                result = MANAGER.prepare_install_transition_rollback(
                    root, transition["candidate_release_id"], 81,
                    os.geteuid(),
                )
        self.assertEqual(result["status"], "rollback_prepared")
        previous.assert_not_called()
        current.assert_called_once_with(
            transition["old_current_target"], root / "current",
        )

    def test_self_restart_rejects_changed_authorization_job_definition(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / ("a" * 64)
            predecessor = root / ("b" * 64)
            candidate.mkdir()
            predecessor.mkdir()
            (candidate / "authorization_service").write_bytes(b"candidate\n")
            (predecessor / "authorization_service").write_bytes(b"predecessor\n")
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_service_change_requires_explicit_migration",
            ):
                MANAGER.begin_install_transition(
                    root, os.geteuid(), candidate,
                    {"payloads": {"authorization_ui_bundle": "1" * 64}},
                    predecessor, {"payloads": {}},
                    f"releases/{predecessor.name}", None, 501,
                    {"team_id": "ABCDE12345"}, "2" * 64,
                    "11111111-1111-4111-8111-111111111111", "3" * 64,
                )

    def test_succeeded_receipt_can_only_be_superseded_by_bound_failure_fence(self):
        transition = self._install_transition()
        success = MANAGER.make_install_finalization(
            transition, status="deployed_verified", error=None,
            authorization={"pid": 81, "start_generation": [10, 20]},
            native_credential={"pid": 82, "start_generation": [11, 21]},
            service_evidence={"generation": "old"},
            completed_at=2_000_000_010,
        )
        failure = MANAGER.make_install_finalization(
            transition, status="failed_fenced",
            error="activation_verification_failed",
            authorization={"pid": 91, "start_generation": [12, 22]},
            native_credential=None,
            service_evidence={"fenced": True},
            completed_at=2_000_000_020,
            superseded_finalization_sha256=success["finalization_sha256"],
        )
        receipt = {
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "request_id": transition["authorization_request_id"],
            "request_sha256": transition["authorization_request_sha256"],
            "operation": "host-controller-install",
            "status": "activation_pending", "completed_at": None,
            "exit_status": None,
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "candidate_release_id": transition["candidate_release_id"],
            "authorization_pending_receipt_sha256": transition[
                "authorization_pending_receipt_sha256"
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / f"{transition['authorization_request_id']}.json"
            path.write_bytes(MANAGER.canonical_state_record(receipt))
            path.chmod(0o600)

            def open_root(*_args, **_kwargs):
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)

            with mock.patch.object(
                MANAGER, "open_trusted_absolute_directory",
                side_effect=open_root,
            ):
                succeeded, succeeded_raw = (
                    MANAGER.complete_install_authorization_receipt(
                        transition, success, os.geteuid(),
                    )
                )
                failed, _failed_raw = (
                    MANAGER.complete_install_authorization_receipt(
                        transition, failure, os.geteuid(),
                    )
                )
        self.assertEqual(succeeded["status"], "succeeded")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(
            failed["host_install_superseded_receipt_sha256"],
            hashlib.sha256(succeeded_raw).hexdigest(),
        )
        self.assertEqual(
            failed["host_install_finalization_sha256"],
            failure["finalization_sha256"],
        )


class RollbackTransactionContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.install_root = self.root / "installed"
        releases = self.install_root / "releases"
        releases.mkdir(parents=True)
        self.current_id = "b" * 64
        self.target_id = "a" * 64
        self.current_release = releases / self.current_id
        self.target_release = releases / self.target_id
        self.current_release.mkdir()
        self.target_release.mkdir()
        (self.target_release / "authorization_service").write_bytes(b"plist")
        self.current = self.install_root / "current"
        self.previous = self.install_root / "previous"
        self.current.symlink_to(f"releases/{self.current_id}")
        self.previous.symlink_to(f"releases/{self.target_id}")
        payloads = {
            name: "1" * 64 for name in MANAGER.NATIVE_CREDENTIAL_PAYLOAD_NAMES
        }
        self.manifests = {
            self.current_id: {
                "schema": MANAGER.SCHEMA,
                "release_id": self.current_id,
                "payloads": dict(payloads),
            },
            self.target_id: {
                "schema": MANAGER.SCHEMA,
                "release_id": self.target_id,
                "payloads": dict(payloads),
            },
        }
        self.floor = {
            "team_id": "ABCDE" + "12345",
            "established_from_release_id": self.current_id,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def _verified_release(self, _root, link, _uid, **_kwargs):
        path = link.resolve(strict=True)
        return path, self.manifests[path.name]

    def _enter_common_patches(self, stack):
        stack.enter_context(mock.patch.object(
            MANAGER, "active_markers", return_value=[]
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "developer_id_team_floor",
            return_value=(self.floor, "f" * 64),
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "verified_release", side_effect=self._verified_release,
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "source_payload", return_value=({}, {}, self.target_id),
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "unchanged_developer_id_floor"
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "enforce_release_developer_id_team_floor"
        ))
        stack.enter_context(mock.patch.object(
            MANAGER,
            "enforce_release_native_stack_coordination_compatible",
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "manages_live_touchid_service", return_value=True,
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "console_user_uid", return_value=501,
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "install_touchid_service"
        ))
        stack.enter_context(mock.patch.object(
            MANAGER, "install_native_credential_service"
        ))

    def _rollback(self):
        return MANAGER.rollback(
            self.root / "repo", self.install_root, self.root / "state",
            self.target_id, os.geteuid(), self.root / "op", self.root / "gpgv",
        )

    def test_every_transition_failure_restores_exact_prior_state(self):
        transitions = (
            "services-fenced",
            "previous-selected",
            "current-selected",
            "authorization-service-selected",
            "native-service-selected",
            "service-identity-readback",
            "transaction-verified",
        )
        for transition in transitions:
            with self.subTest(transition=transition), contextlib.ExitStack() as stack:
                self._enter_common_patches(stack)
                fenced = stack.enter_context(mock.patch.object(
                    MANAGER, "stop_and_fence_host_services"
                ))
                restored = stack.enter_context(mock.patch.object(
                    MANAGER, "install_release_host_services"
                ))
                stack.enter_context(mock.patch.object(
                    MANAGER, "verify_release_host_services",
                    return_value={"verified": True},
                ))

                def fail_at(name):
                    if name == transition:
                        raise MANAGER.ReleaseFailure("injected:" + transition)

                stack.enter_context(mock.patch.object(
                    MANAGER, "rollback_transition_checkpoint",
                    side_effect=fail_at,
                ))
                with self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "injected:" + transition,
                ):
                    self._rollback()
                self.assertEqual(
                    os.readlink(self.current), f"releases/{self.current_id}"
                )
                self.assertEqual(
                    os.readlink(self.previous), f"releases/{self.target_id}"
                )
                self.assertGreaterEqual(fenced.call_count, 2)
                restored.assert_called_once()

    def test_failed_recovery_leaves_current_absent_and_both_services_fenced(self):
        with contextlib.ExitStack() as stack:
            self._enter_common_patches(stack)
            fenced = stack.enter_context(mock.patch.object(
                MANAGER, "stop_and_fence_host_services"
            ))

            def fail_after_selector(name):
                if name == "current-selected":
                    raise MANAGER.ReleaseFailure("injected-current-selection")

            stack.enter_context(mock.patch.object(
                MANAGER, "rollback_transition_checkpoint",
                side_effect=fail_after_selector,
            ))
            stack.enter_context(mock.patch.object(
                MANAGER, "install_release_host_services",
                side_effect=MANAGER.ReleaseFailure("restore-failed"),
            ))
            stack.enter_context(mock.patch.object(
                MANAGER, "verify_release_host_services",
                return_value={"verified": True},
            ))
            stop_auth = stack.enter_context(mock.patch.object(
                MANAGER, "stop_touchid_service"
            ))
            stop_native = stack.enter_context(mock.patch.object(
                MANAGER, "stop_native_credential_service"
            ))
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "rollback_transaction_recovery_unproven",
            ):
                self._rollback()
        self.assertFalse(os.path.lexists(self.current))
        self.assertEqual(
            os.readlink(self.previous), f"releases/{self.target_id}"
        )
        self.assertGreaterEqual(fenced.call_count, 2)
        stop_auth.assert_called_once()
        stop_native.assert_called_once_with(uid=501)


class NativeDeploymentReleasePayloadTests(unittest.TestCase):
    def copy_payload_repository(self, destination: Path) -> None:
        paths = {
            Path("scripts/native_deployment_payload.py"),
            Path("shared/__init__.py"),
            Path("shared/native_deployment.py"),
        }
        paths.update(MANAGER.NATIVE_STACK_SUPPORT_SOURCES.values())
        paths.update(
            Path(relative)
            for role in NATIVE_DEPLOYMENT_PAYLOAD.CONTAINER_MEMBERS.values()
            for _name, relative, _mode
            in NATIVE_DEPLOYMENT_PAYLOAD.inventory(role)
        )
        for relative in sorted(paths):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, target)

    def make_minimal_driver_release(
        self, install_root: Path,
    ) -> tuple[Path, dict[str, object]]:
        releases = install_root / "releases"
        staging = releases / "staging"
        staging.mkdir(parents=True, mode=0o755)
        release_manager = b'''import json\nEXPECTED_MODES = {}\ndef verified_release(install_root, link, expected_uid, *args, **kwargs):\n    selected = link.resolve(strict=True)\n    return selected, json.loads((selected / "manifest.json").read_text(encoding="utf-8"))\n'''
        coordination_contract = json.loads((
            REPO / "config/native-stack-coordination-contract.json"
        ).read_text(encoding="ascii"))
        coordination_contract["features"].remove(
            MANAGER.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
        )
        coordination_contract["features"].remove(
            MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
        )
        payloads = {
            "authorization_broker": b"broker",
            "control_client": b"control-client",
            "native_deployment_payloads": (
                MANAGER.native_deployment_payload_container(REPO)
            ),
            "native_stack_deployer": (
                REPO / "scripts/native-stack-deploy.py"
            ).read_bytes(),
            "native_stack_catalog_promoter": (
                REPO / "scripts/native-stack-catalog-promote.py"
            ).read_bytes(),
            "native_stack_coordination_contract": (
                MANAGER.canonical_state_record(coordination_contract)
            ),
            "native_stack_support": MANAGER.native_stack_support_archive(REPO),
            "release_manager": release_manager,
            "ssh_config": b"ssh-config",
        }
        modes = {
            "authorization_broker": 0o755,
            "control_client": 0o755,
            "native_deployment_payloads": 0o444,
            "native_stack_deployer": 0o755,
            "native_stack_catalog_promoter": 0o755,
            "native_stack_coordination_contract": 0o444,
            "native_stack_support": 0o444,
            "release_manager": 0o755,
            "ssh_config": 0o444,
        }
        hashes = {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in payloads.items()
        }
        release_id = MANAGER.release_identity(hashes)
        manifest: dict[str, object] = {
            "schema": MANAGER.SCHEMA,
            "release_id": release_id,
            "payloads": hashes,
        }
        for name, raw in payloads.items():
            candidate = staging / name
            candidate.write_bytes(raw)
            candidate.chmod(modes[name])
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                manifest, ensure_ascii=True, separators=(",", ":"),
                sort_keys=True,
            ) + "\n",
            encoding="ascii",
        )
        manifest_path.chmod(0o444)
        release = releases / release_id
        staging.rename(release)
        release.chmod(0o555)
        (install_root / "current").symlink_to(f"releases/{release_id}")
        MANAGER.establish_native_stack_coordination_floor(
            install_root, os.geteuid(), release_id=release_id,
            contract_raw=payloads["native_stack_coordination_contract"],
        )
        return release, manifest

    def write_gate_release(
        self, install_root: Path, values: dict[str, bytes],
    ) -> tuple[Path, dict[str, object], dict[str, str]]:
        hashes = {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in values.items()
        }
        release_id = MANAGER.release_identity(hashes)
        releases = install_root / "releases"
        releases.mkdir(parents=True, mode=0o755, exist_ok=True)
        releases.chmod(0o755)
        release = releases / release_id
        release.mkdir(mode=0o755)
        for name, raw in values.items():
            path = release / name
            path.write_bytes(raw)
            path.chmod(MANAGER.EXPECTED_MODES[name])
        manifest: dict[str, object] = {
            "schema": MANAGER.SCHEMA,
            "release_id": release_id,
            "payloads": hashes,
        }
        manifest_path = release / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o444)
        release.chmod(0o555)
        return release, manifest, hashes

    def d8653cb_payloads(
        self, destination: Path,
    ) -> tuple[dict[str, bytes], object]:
        archived = subprocess.run(
            ["git", "archive", "--format=tar", "d8653cb"],
            cwd=REPO, check=True, stdout=subprocess.PIPE,
        ).stdout
        historical = destination / "d8653cb"
        historical.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archived), mode="r:") as bundle:
            bundle.extractall(historical, filter="data")
        for candidate in historical.rglob("*"):
            if candidate.is_file() and not candidate.is_symlink():
                candidate.chmod(stat.S_IMODE(candidate.stat().st_mode) & ~0o022)
        manager_path = historical / "scripts/host-controller-release.py"
        specification = importlib.util.spec_from_file_location(
            "historical_d8653cb_release_manager", manager_path)
        assert specification is not None and specification.loader is not None
        historical_manager = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(historical_manager)
        self.assertEqual(
            set(historical_manager.PAYLOAD_NAMES),
            MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES,
        )
        values = {
            name: ("d8653cb:" + name + "\n").encode("ascii")
            for name in MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
        }
        values.update({
            "authorization_broker": (
                historical / "scripts/operator-authorization.py"
            ).read_bytes(),
            "authorization_service": (
                historical
                / "config/org.zebeth.securesandbox.authorization.plist"
            ).read_bytes(),
            "release_manager": (
                historical / "scripts/host-controller-release.py"
            ).read_bytes(),
            "native_stack_catalog_promoter": (
                historical / "scripts/native-stack-catalog-promote.py"
            ).read_bytes(),
            "native_stack_deployer": (
                historical / "scripts/native-stack-deploy.py"
            ).read_bytes(),
            "native_stack_support": (
                historical_manager.native_stack_support_archive(historical)
            ),
            "native_deployment_payloads": (
                historical_manager.native_deployment_payload_container(
                    historical)
            ),
        })
        self.assertEqual(
            {
                name: hashlib.sha256(values[name]).hexdigest()
                for name in MANAGER.D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256
            },
            MANAGER.D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256,
        )
        return values, historical_manager

    def current_gate_candidate_payloads(self) -> dict[str, bytes]:
        # The gate subprocess validates every release payload before importing
        # this manager.  Keep the fixture manager narrowly limited to the two
        # interfaces ReleaseAuthority needs so the test does not depend on the
        # unavailable signed/notarized product carrier ignored by the checkout.
        expected_modes = {
            name: MANAGER.EXPECTED_MODES[name]
            for name in MANAGER.PAYLOAD_NAMES
        }
        test_release_manager = (
            "import json\n"
            "from pathlib import Path\n"
            f"EXPECTED_MODES = {expected_modes!r}\n"
            "def verified_release(install_root, link, expected_uid, "
            "*args, **kwargs):\n"
            "    selected = Path(link).resolve(strict=True)\n"
            "    manifest = json.loads((selected / 'manifest.json').read_bytes())\n"
            "    return selected, manifest\n"
        ).encode("ascii")
        coordination_contract = json.loads((
            REPO / "config/native-stack-coordination-contract.json"
        ).read_text(encoding="ascii"))
        coordination_contract["features"].remove(
            MANAGER.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
        )
        coordination_contract["features"].remove(
            MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
        )
        values = {
            name: ("candidate:" + name + "\n").encode("ascii")
            for name in MANAGER.PAYLOAD_NAMES
        }
        values.update({
            "native_stack_catalog_promoter": (
                REPO / "scripts/native-stack-catalog-promote.py"
            ).read_bytes(),
            "native_stack_deployer": (
                REPO / "scripts/native-stack-deploy.py"
            ).read_bytes(),
            "native_stack_support": MANAGER.native_stack_support_archive(REPO),
            "native_deployment_payloads": (
                MANAGER.native_deployment_payload_container(REPO)
            ),
            "native_stack_coordination_contract": (
                MANAGER.canonical_state_record(coordination_contract)
            ),
            "release_manager": test_release_manager,
        })
        return values

    def write_d8653cb_terminal_native_state(
        self, install_root: Path, release: Path,
        manifest: dict[str, object],
    ) -> None:
        saved_path = list(sys.path)
        saved_modules = {
            name: module for name, module in sys.modules.items()
            if name == "shared" or name.startswith("shared.")
            or name == "native_deployment_payload"
        }
        try:
            promoter = types.ModuleType("historical_d8653cb_promoter")
            promoter.__file__ = str(release / "native_stack_catalog_promoter")
            promoter.__package__ = None
            exec(compile(
                (release / "native_stack_catalog_promoter").read_bytes(),
                promoter.__file__, "exec",
            ), promoter.__dict__)

            catalog_root, transactions, public_status = (
                MANAGER.native_catalog_gate_paths(install_root))
            catalog_root.mkdir(mode=0o700)
            transactions.mkdir(mode=0o700)
            for directory in (
                catalog_root / "promotion-receipts",
                catalog_root / "promotion-staging",
                catalog_root / "promotion-journals",
            ):
                directory.mkdir(mode=0o700)
            (catalog_root / ".promotion.lock").touch(mode=0o600)
            (transactions / ".lock").touch(mode=0o600)
            catalog = dict(promoter.EMPTY_CATALOG)
            catalog_raw = promoter.native_vendor_stack.canonical_bytes(catalog)
            catalog_sha256 = hashlib.sha256(catalog_raw).hexdigest()
            catalog_path = catalog_root / "catalog.json"
            catalog_path.write_bytes(catalog_raw)
            catalog_path.chmod(0o600)
            promotion_id = "11111111-1111-4111-8111-111111111111"
            plan = {
                "promotion_id": promotion_id,
                "plan_sha256": "1" * 64,
                "source_sha256": catalog_sha256,
                "previous_catalog_sha256": None,
                "catalog_sha256": catalog_sha256,
                "host_release_id": release.name,
            }
            authorization = {
                "authorization_sha256": "2" * 64,
                "pending_receipt_sha256": "3" * 64,
            }
            receipt = promoter._promotion_receipt(
                plan, authorization, promoted_at=1000)
            receipt_path = (
                catalog_root / "promotion-receipts" / f"{promotion_id}.json")
            receipt_path.write_bytes(promoter.canonical(receipt))
            receipt_path.chmod(0o600)
            journal = promoter._new_promotion_journal(
                plan, authorization, receipt, updated_at=1000)
            journal.update({
                "phase": "committed",
                "research_observed_catalog_sha256": catalog_sha256,
                "research_fence_sha256": "4" * 64,
                "research_idle_evidence_sha256": "5" * 64,
                "research_publication_evidence_sha256": "6" * 64,
                "host_observed_catalog_sha256": catalog_sha256,
                "research_readback_evidence_sha256": "7" * 64,
                "research_release_evidence_sha256": "8" * 64,
                "research_terminal_evidence_sha256": "9" * 64,
                "updated_at": 1009,
            })
            journal_body = {
                key: item for key, item in journal.items()
                if key not in {"schema", "journal_sha256"}
            }
            journal["journal_sha256"] = promoter.digest(journal_body)
            promoter._validate_promotion_journal(
                journal, plan, authorization, receipt)
            journal_path = (
                catalog_root / "promotion-journals" / f"{promotion_id}.json")
            journal_path.write_bytes(promoter.canonical(journal))
            journal_path.chmod(0o600)
            promoter.publish_public_status(
                catalog=catalog, catalog_sha256=catalog_sha256,
                host_release_id=release.name, receipt=receipt,
                published_at=1010, path=public_status,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )

            deployer = types.ModuleType("historical_d8653cb_deployer")
            deployer.__file__ = str(release / "native_stack_deployer")
            deployer.__package__ = None
            exec(compile(
                (release / "native_stack_deployer").read_bytes(),
                deployer.__file__, "exec",
            ), deployer.__dict__)
            payloads = manifest["payloads"]
            assert isinstance(payloads, dict)
            deployer._activate_support(
                release / "native_stack_support",
                payloads["native_stack_support"],
                expected_uid=os.geteuid(),
            )
            native = deployer.native_deployment
            gateway_prior = native.make_status(
                role="gateway", state="absent", generation_kind="absent",
                package_sha256=None, release_id=None, catalog_sha256=None,
                closed_evidence_sha256=None, observed_at=1000)
            research_prior = native.make_status(
                role="research", state="absent", generation_kind="absent",
                package_sha256=None, release_id=None, catalog_sha256=None,
                closed_evidence_sha256=None, observed_at=1000)
            deployment_plan = native.make_plan(
                deployment_id="22222222-2222-4222-8222-222222222222",
                host_release_id=release.name, catalog_sha256=catalog_sha256,
                gateway_package_sha256="a" * 64,
                research_package_sha256="b" * 64,
                previous_gateway_package_sha256=None,
                previous_research_package_sha256=None,
                previous_gateway_status_sha256=(
                    native.stable_status_sha256(gateway_prior)),
                previous_research_status_sha256=(
                    native.stable_status_sha256(research_prior)),
                created_at=1000, expires_at=4600,
            )
            gateway = native.make_status(
                role="gateway", state="verified",
                generation_kind="protected", package_sha256="a" * 64,
                release_id="c" * 64, catalog_sha256=None,
                closed_evidence_sha256="d" * 64, observed_at=1001)
            research = native.make_status(
                role="research", state="verified",
                generation_kind="protected", package_sha256="b" * 64,
                release_id="e" * 64, catalog_sha256=catalog_sha256,
                closed_evidence_sha256="f" * 64, observed_at=1002)
            state = MANAGER.native_deployment_state_root(install_root)
            host_fd = os.open(
                install_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            fcntl.flock(host_fd, fcntl.LOCK_EX)
            journal_driver = deployer.Journal(
                state, trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                host_install_fd=host_fd, host_install_root=install_root)
            journal_driver.lock(create=True)
            try:
                sequence = 0

                def transport(kind: str) -> dict[str, str]:
                    nonlocal sequence
                    sequence += 1
                    return {
                        "kind": kind,
                        "request_id": (
                            f"33333333-3333-4333-8333-{sequence:012d}"),
                        "semantic_sha256": "1" * 64,
                        "payload_sha256": "2" * 64,
                    }

                def append(
                    phase: str, phase_evidence: dict[str, object], now: int,
                    phase_transport: dict[str, str] | None = None,
                ) -> dict[str, object]:
                    return journal_driver.append(
                        plan=deployment_plan,
                        apply_authorization_sha256="3" * 64,
                        authorization_sha256="3" * 64,
                        payload_container_sha256=(
                            payloads["native_deployment_payloads"]),
                        prior_gateway=gateway_prior,
                        prior_research=research_prior,
                        phase=phase, event=phase, evidence=phase_evidence,
                        transport=phase_transport, now=now,
                    )

                append("authorized", deployer.evidence(
                    outcome="authorized"), 1000)
                append("fence-requested", deployer.evidence(
                    outcome="requested"), 1001, transport("fence"))
                append("fenced", deployer.evidence(
                    outcome="fenced", fence_evidence_sha256="4" * 64), 1002)
                append("gateway-requested", deployer.evidence(
                    outcome="requested"), 1003, transport("gateway"))
                append("gateway-observed", deployer.evidence(
                    outcome="candidate-prior", gateway_status=gateway,
                    research_status=research_prior), 1004)
                append("research-requested", deployer.evidence(
                    outcome="requested"), 1005, transport("research"))
                append("research-observed", deployer.evidence(
                    outcome="candidate-candidate", gateway_status=gateway,
                    research_status=research), 1006)
                append("release-requested", deployer.evidence(
                    outcome="requested"), 1007, transport("release"))
                append("release-observed", deployer.evidence(
                    outcome="candidate-candidate", gateway_status=gateway,
                    research_status=research,
                    fence_evidence_sha256="4" * 64,
                    terminal_sha256="5" * 64,
                    result_sha256="6" * 64), 1008)
                terminal = append("committed", deployer.evidence(
                    outcome="committed", gateway_status=gateway,
                    research_status=research,
                    terminal_sha256="5" * 64), 1009)
                journal_driver.complete(terminal)
                self.assertIsNone(journal_driver.load())
            finally:
                journal_driver.unlock()
                fcntl.flock(host_fd, fcntl.LOCK_UN)
                os.close(host_fd)
        finally:
            sys.path[:] = saved_path
            for name in list(sys.modules):
                if (name == "shared" or name.startswith("shared.")
                        or name == "native_deployment_payload"):
                    sys.modules.pop(name, None)
            sys.modules.update(saved_modules)

    def spawn_d8653cb_blocked_promoter(
        self, promoter_path: Path, lock_path: Path,
    ) -> tuple[subprocess.Popen[str], int]:
        child_code = """
import fcntl
import os
import pathlib
import sys
import types
promoter_path = pathlib.Path(sys.argv[1])
module = types.ModuleType("historical_d8653cb_blocked_promoter")
module.__file__ = str(promoter_path)
module.__package__ = None
exec(compile(promoter_path.read_bytes(), str(promoter_path), "exec"), module.__dict__)
descriptor = module._open_trusted_lock(
    pathlib.Path(sys.argv[2]), trusted_uid=os.geteuid(), trusted_gid=os.getegid())
print("ready", flush=True)
fcntl.flock(descriptor, fcntl.LOCK_EX)
fcntl.flock(descriptor, fcntl.LOCK_UN)
os.close(descriptor)
"""
        broker_code = """
import subprocess
import sys
child = subprocess.Popen(
    [sys.executable, "-I", "-c", sys.argv[1], sys.argv[2], sys.argv[3]],
    stdout=subprocess.PIPE, text=True, start_new_session=True)
ready = child.stdout.readline().strip()
print(f"{child.pid}:{ready}", flush=True)
raise SystemExit(child.wait())
"""
        broker = subprocess.Popen(
            [
                sys.executable, "-I", "-c", broker_code, child_code,
                str(promoter_path), str(lock_path),
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        assert broker.stdout is not None
        readable, _writable, _exceptional = select.select(
            [broker.stdout], [], [], 10)
        self.assertTrue(readable, "historical promoter did not start")
        child_value, ready = broker.stdout.readline().strip().split(":", 1)
        self.assertEqual(ready, "ready")
        return broker, int(child_value)

    def test_d8653cb_compatibility_requires_exact_payload_digests(self):
        payloads = {
            name: "a" * 64
            for name in MANAGER.PRE_NATIVE_STACK_COORDINATION_PAYLOAD_NAMES
        }
        payloads.update(MANAGER.D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256)
        manifest = {"payloads": payloads}
        self.assertTrue(
            MANAGER.is_d8653cb_native_coordination_predecessor(manifest))
        for name in MANAGER.D8653CB_NATIVE_COORDINATION_PAYLOAD_SHA256:
            with self.subTest(name=name):
                changed = {"payloads": dict(payloads)}
                changed["payloads"][name] = "f" * 64
                self.assertFalse(
                    MANAGER.is_d8653cb_native_coordination_predecessor(
                        changed))
        changed_inventory = {"payloads": dict(payloads)}
        changed_inventory["payloads"]["unexpected"] = "f" * 64
        self.assertFalse(
            MANAGER.is_d8653cb_native_coordination_predecessor(
                changed_inventory))

    def test_d8653cb_gate_reply_rejects_active_and_malformed_state(self):
        catalog_body = {
            "state": "ready",
            "active_promotion_id": None,
            "active_state_sha256": None,
        }
        deployment_body = {
            "state": "ready",
            "active_journal_sha256": None,
        }
        ready = {
            "schema": (
                "secure-sandbox-d8653cb-native-coordination-admission-v1"
            ),
            "catalog_gate": {
                "schema": MANAGER.NATIVE_CATALOG_PROMOTION_GATE_SCHEMA,
                **catalog_body,
                "gate_sha256": MANAGER.sha256_bytes(
                    MANAGER.canonical_state_record(catalog_body)),
            },
            "deployment_gate": {
                "schema": MANAGER.NATIVE_DEPLOYMENT_GATE_SCHEMA,
                **deployment_body,
                "gate_sha256": MANAGER.sha256_bytes(
                    MANAGER.canonical_state_record(deployment_body)),
            },
        }
        self.assertEqual(
            MANAGER._validate_d8653cb_coordination_gate_reply(ready), ready)

        active_catalog = json.loads(json.dumps(ready))
        active_catalog["catalog_gate"].update({
            "state": "active",
            "active_promotion_id": "11111111-1111-4111-8111-111111111111",
            "active_state_sha256": "a" * 64,
        })
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_catalog_promotion_active",
        ):
            MANAGER._validate_d8653cb_coordination_gate_reply(active_catalog)

        active_deployment = json.loads(json.dumps(ready))
        active_deployment["deployment_gate"].update({
            "state": "active", "active_journal_sha256": "b" * 64,
        })
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_deployment_active",
        ):
            MANAGER._validate_d8653cb_coordination_gate_reply(
                active_deployment)

        malformed = json.loads(json.dumps(ready))
        malformed["catalog_gate"]["gate_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_catalog_promotion_state_invalid",
        ):
            MANAGER._validate_d8653cb_coordination_gate_reply(malformed)

    def test_d8653cb_service_fence_precedes_legacy_lock_drain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            install_root.mkdir(mode=0o755)
            legacy_values, _legacy_manager = self.d8653cb_payloads(root)
            legacy, _manifest, _hashes = self.write_gate_release(
                install_root, legacy_values)
            (install_root / "current").symlink_to(
                f"releases/{legacy.name}")

            candidate_values = self.current_gate_candidate_payloads()
            candidate_hashes = {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in candidate_values.items()
            }
            candidate_release_id = MANAGER.release_identity(
                candidate_hashes)
            catalog_root, transactions, _public_status = (
                MANAGER.native_catalog_gate_paths(install_root))
            catalog_root.mkdir(mode=0o700)
            transactions.mkdir(mode=0o700)
            manager_lock_path = transactions / ".lock"
            promotion_lock_path = catalog_root / ".promotion.lock"
            manager_lock_path.touch(mode=0o600)
            promotion_lock_path.touch(mode=0o600)
            manager_lock_path.chmod(0o600)
            promotion_lock_path.chmod(0o600)

            # Model an already admitted d8653cb promoter.  Bootstrap must
            # fence the old broker before waiting for this transaction to
            # finish; the inverse ordering deadlocks this test.
            old_manager = os.open(
                manager_lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            old_promotion = os.open(
                promotion_lock_path,
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            fcntl.flock(old_manager, fcntl.LOCK_EX)
            fcntl.flock(old_promotion, fcntl.LOCK_EX)
            host_fd = MANAGER.open_locked_install_root(
                install_root, os.geteuid())
            fenced = threading.Event()
            admitted = threading.Event()
            release_admission = threading.Event()
            failures: list[BaseException] = []

            def stop_services(
                uid: int, selected: Path, manifest: dict[str, object],
            ) -> None:
                self.assertEqual(uid, os.geteuid())
                self.assertEqual(selected, legacy.resolve())
                self.assertEqual(manifest["release_id"], legacy.name)
                fenced.set()

            def bootstrap_admission() -> None:
                try:
                    with MANAGER.d8653cb_native_coordination_admission(
                        host_fd, REPO, install_root, os.geteuid(),
                        legacy.name, candidate_release_id,
                    ) as value:
                        self.assertIsNotNone(value)
                        admitted.set()
                        self.assertTrue(release_admission.wait(10))
                except BaseException as error:
                    failures.append(error)
                    admitted.set()

            try:
                with (
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=(
                            candidate_values, candidate_hashes,
                            candidate_release_id,
                        ),
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=True,
                    ),
                    mock.patch.object(
                        MANAGER, "console_user_uid",
                        return_value=os.geteuid(),
                    ),
                    mock.patch.object(
                        MANAGER, "stop_and_fence_d8653cb_host_services",
                        side_effect=stop_services,
                    ),
                    mock.patch.object(
                        MANAGER, "LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES",
                        {"__unavailable_test_product_carrier__"},
                    ),
                    mock.patch.object(
                        MANAGER, "execution_approval_floor",
                        return_value=(1, 0),
                    ),
                ):
                    worker = threading.Thread(
                        target=bootstrap_admission, daemon=True)
                    worker.start()
                    self.assertTrue(
                        fenced.wait(5),
                        "service fence must run before legacy lock drain",
                    )
                    self.assertFalse(admitted.wait(0.05))
                    fcntl.flock(old_promotion, fcntl.LOCK_UN)
                    fcntl.flock(old_manager, fcntl.LOCK_UN)
                    self.assertTrue(admitted.wait(10))
                    self.assertEqual(failures, [])

                    for lock_path in (manager_lock_path, promotion_lock_path):
                        contender = os.open(
                            lock_path,
                            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                        )
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(
                                    contender,
                                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                                )
                        finally:
                            os.close(contender)
                    release_admission.set()
                    worker.join(10)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(failures, [])
            finally:
                release_admission.set()
                fcntl.flock(old_promotion, fcntl.LOCK_UN)
                fcntl.flock(old_manager, fcntl.LOCK_UN)
                os.close(old_promotion)
                os.close(old_manager)
                fcntl.flock(host_fd, fcntl.LOCK_UN)
                os.close(host_fd)

    def test_d8653cb_broker_fence_rejects_real_blocked_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            install_root.mkdir(mode=0o755)
            legacy_values, _legacy_manager = self.d8653cb_payloads(root)
            legacy, manifest, _hashes = self.write_gate_release(
                install_root, legacy_values)
            _catalog_root, transactions, _public_status = (
                MANAGER.native_catalog_gate_paths(install_root))
            transactions.mkdir(mode=0o700)
            lock_path = transactions / ".lock"
            lock_path.touch(mode=0o600)
            lock_path.chmod(0o600)
            held_lock = os.open(
                lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            fcntl.flock(held_lock, fcntl.LOCK_EX)
            broker, child_pid = self.spawn_d8653cb_blocked_promoter(
                legacy / "native_stack_catalog_promoter", lock_path)
            actual_status = MANAGER.process_status_generation_or_absent
            actual_generation = MANAGER.process_generation_or_absent
            try:
                observed = actual_status(
                    broker.pid, MANAGER.AUTHORIZATION_LABEL)
                self.assertIsNotNone(observed)
                assert observed is not None
                generation = (0, observed[1], observed[2])
                live = {
                    "pid": broker.pid, "euid": 0,
                    "start_generation": [observed[1], observed[2]],
                }

                def root_status(pid: int, label: str):
                    value = actual_status(pid, label)
                    return None if value is None else (
                        0, value[1], value[2], value[3])

                def root_generation(pid: int, label: str):
                    value = actual_generation(pid, label)
                    return None if value is None else (
                        0, value[1], value[2])

                def launchctl_signal(command, **_kwargs):
                    self.assertEqual(command[:2], ["/bin/launchctl", "kill"])
                    os.kill(
                        broker.pid,
                        signal.SIGSTOP
                        if command[2] == "SIGSTOP" else signal.SIGCONT,
                    )
                    return subprocess.CompletedProcess(command, 0, "", "")

                with (
                    mock.patch.object(
                        MANAGER, "launchd_service_pid_or_absent",
                        return_value=broker.pid,
                    ),
                    mock.patch.object(
                        MANAGER, "verify_release_authorization_service",
                        return_value=live,
                    ),
                    mock.patch.object(
                        MANAGER, "process_status_generation_or_absent",
                        side_effect=root_status,
                    ),
                    mock.patch.object(
                        MANAGER, "process_generation_or_absent",
                        side_effect=root_generation,
                    ),
                    mock.patch.object(
                        MANAGER.subprocess, "run",
                        side_effect=launchctl_signal,
                    ),
                    mock.patch.object(
                        MANAGER, "stop_touchid_service",
                    ) as stop_touchid,
                    mock.patch.object(
                        MANAGER, "stop_native_credential_service",
                    ) as stop_native,
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "native_coordination_legacy_operation_active",
                    ),
                ):
                    MANAGER.stop_and_fence_d8653cb_host_services(
                        os.geteuid(), legacy, manifest)
                stop_touchid.assert_not_called()
                stop_native.assert_not_called()
                self.assertIsNone(broker.poll())
                self.assertEqual(
                    root_generation(broker.pid, MANAGER.AUTHORIZATION_LABEL),
                    generation,
                )
                fcntl.flock(held_lock, fcntl.LOCK_UN)
                broker.wait(timeout=10)
                self.assertEqual(broker.returncode, 0)
            finally:
                fcntl.flock(held_lock, fcntl.LOCK_UN)
                os.close(held_lock)
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if broker.poll() is None:
                    broker.kill()
                broker.communicate(timeout=10)

    def test_d8653cb_process_inventory_rejects_orphaned_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            install_root.mkdir(mode=0o755)
            legacy_values, _legacy_manager = self.d8653cb_payloads(root)
            legacy, _manifest, _hashes = self.write_gate_release(
                install_root, legacy_values)
            (install_root / "current").symlink_to(
                f"releases/{legacy.name}")
            _catalog_root, transactions, _public_status = (
                MANAGER.native_catalog_gate_paths(install_root))
            transactions.mkdir(mode=0o700)
            lock_path = transactions / ".lock"
            lock_path.touch(mode=0o600)
            lock_path.chmod(0o600)
            held_lock = os.open(
                lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            fcntl.flock(held_lock, fcntl.LOCK_EX)
            broker, child_pid = self.spawn_d8653cb_blocked_promoter(
                legacy / "native_stack_catalog_promoter", lock_path)
            unrelated = subprocess.Popen(
                [
                    sys.executable, "-I", "-c",
                    "import time\nprint('ready', flush=True)\ntime.sleep(30)\n",
                ],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            try:
                assert unrelated.stdout is not None
                self.assertEqual(unrelated.stdout.readline().strip(), "ready")
                broker.terminate()
                broker.wait(timeout=10)
                self.assertIsNotNone(
                    MANAGER.process_generation_or_absent(
                        child_pid, "d8653cb-orphan"))
                arguments = MANAGER.process_arguments_inventory(
                    child_pid, "d8653cb-orphan")
                self.assertTrue(any("\n" in argument for argument in arguments))
                self.assertIn(
                    str(legacy / "native_stack_catalog_promoter"),
                    arguments,
                )
                with (
                    mock.patch.object(
                        MANAGER, "process_ids",
                        return_value=(child_pid, unrelated.pid),
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure,
                        "native_coordination_legacy_operation_active",
                    ),
                ):
                    MANAGER.ensure_no_d8653cb_release_processes(
                        legacy, install_root, os.geteuid())

                fcntl.flock(held_lock, fcntl.LOCK_UN)
                deadline = time.monotonic() + 10
                while MANAGER.process_generation_or_absent(
                    child_pid, "d8653cb-orphan"
                ) is not None:
                    if time.monotonic() >= deadline:
                        self.fail("orphaned historical promoter did not exit")
                    time.sleep(0.02)
                with (
                    mock.patch.object(
                        MANAGER, "process_ids",
                        return_value=(child_pid, unrelated.pid),
                    ),
                ):
                    MANAGER.ensure_no_d8653cb_release_processes(
                        legacy, install_root, os.geteuid())
            finally:
                fcntl.flock(held_lock, fcntl.LOCK_UN)
                os.close(held_lock)
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if broker.poll() is None:
                    broker.kill()
                broker.communicate(timeout=10)
                if unrelated.poll() is None:
                    unrelated.terminate()
                unrelated.communicate(timeout=10)

    def test_d8653cb_inventory_recognizes_relative_stable_launcher_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            release = install_root / "releases" / ("a" * 64)
            release.mkdir(parents=True)
            launcher = root / "bin" / "secure-sandbox-claude"
            generation = (os.geteuid(), 1_900_000_000, 123_456, 2)
            for argument in (
                "secure-sandbox-claude",
                "./secure-sandbox-claude",
                "bin/../secure-sandbox-claude",
                "component\n/secure-sandbox-claude",
            ):
                with (
                    self.subTest(argument=argument),
                    mock.patch.object(
                        MANAGER, "process_ids", return_value=(4242,),
                    ),
                    mock.patch.object(
                        MANAGER, "process_status_generation_or_absent",
                        return_value=generation,
                    ),
                    mock.patch.object(
                        MANAGER, "process_executable_path",
                        return_value="/usr/bin/python3",
                    ),
                    mock.patch.object(
                        MANAGER, "process_arguments_inventory",
                        return_value=("-I", argument),
                    ),
                ):
                    self.assertEqual(
                        MANAGER.d8653cb_release_processes(
                            release, install_root, os.geteuid(),
                            extra_aliases=(launcher,),
                        ),
                        ((4242, generation[1], generation[2]),),
                    )

            with (
                mock.patch.object(
                    MANAGER, "process_ids", return_value=(4242,),
                ),
                mock.patch.object(
                    MANAGER, "process_status_generation_or_absent",
                    return_value=generation,
                ),
                mock.patch.object(
                    MANAGER, "process_executable_path",
                    return_value="/usr/bin/python3",
                ),
                mock.patch.object(
                    MANAGER, "process_arguments_inventory",
                    return_value=("-I", "unrelated-tool"),
                ),
            ):
                self.assertEqual(
                    MANAGER.d8653cb_release_processes(
                        release, install_root, os.geteuid(),
                        extra_aliases=(launcher,),
                    ),
                    (),
                )

    def test_d8653cb_second_census_catches_relative_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            release = install_root / "releases" / ("a" * 64)
            release.mkdir(parents=True)
            launcher = root / "bin" / "secure-sandbox-claude"
            generation = (os.geteuid(), 1_900_000_000, 123_456, 2)
            with (
                mock.patch.object(
                    MANAGER, "process_ids",
                    side_effect=((), (4242,)),
                ) as process_ids,
                mock.patch.object(
                    MANAGER, "process_status_generation_or_absent",
                    return_value=generation,
                ),
                mock.patch.object(
                    MANAGER, "process_executable_path",
                    return_value="/usr/bin/python3",
                ),
                mock.patch.object(
                    MANAGER, "process_arguments_inventory",
                    return_value=("-I", "./secure-sandbox-claude"),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_coordination_legacy_operation_active",
                ),
            ):
                MANAGER.ensure_no_d8653cb_release_processes(
                    release, install_root, os.geteuid(),
                    extra_aliases=(launcher,),
                )
            self.assertEqual(process_ids.call_count, 2)

    def test_d8653cb_inventory_allows_only_terminal_exit_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            release = install_root / "releases" / ("a" * 64)
            release.mkdir(parents=True)
            live = (os.geteuid(), 1_900_000_000, 123_456, 2)
            zombie = (*live[:3], 5)

            with (
                mock.patch.object(
                    MANAGER, "process_ids", return_value=(4242,),
                ),
                mock.patch.object(
                    MANAGER, "process_status_generation_or_absent",
                    side_effect=(live, zombie),
                ),
                mock.patch.object(
                    MANAGER, "process_executable_path",
                    side_effect=MANAGER.ReleaseFailure(
                        "host_service_executable_unproven:d8653cb"
                    ),
                ),
            ):
                self.assertEqual(
                    MANAGER.d8653cb_release_processes(
                        release, install_root, os.geteuid(),
                    ),
                    (),
                )

            with (
                mock.patch.object(
                    MANAGER, "process_ids", return_value=(4242,),
                ),
                mock.patch.object(
                    MANAGER, "process_status_generation_or_absent",
                    return_value=live,
                ),
                mock.patch.object(
                    MANAGER, "process_executable_path",
                    side_effect=MANAGER.ReleaseFailure(
                        "host_service_executable_unproven:d8653cb"
                    ),
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "native_coordination_legacy_process_inventory_unproven",
                ),
            ):
                MANAGER.d8653cb_release_processes(
                    release, install_root, os.geteuid(),
                )

    def test_actual_d8653cb_terminal_state_bootstrap_crash_retry(self):
        for crash_phase in ("current-unlinked", "floor-published"):
            with self.subTest(crash_phase=crash_phase), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                install_root.mkdir(mode=0o755)
                legacy_values, _legacy_manager = self.d8653cb_payloads(root)
                legacy, legacy_manifest, _legacy_hashes = (
                    self.write_gate_release(install_root, legacy_values))
                candidate_values = self.current_gate_candidate_payloads()
                candidate, _candidate_manifest, candidate_hashes = (
                    self.write_gate_release(install_root, candidate_values))
                current = install_root / "current"
                current.symlink_to(f"releases/{legacy.name}")
                self.write_d8653cb_terminal_native_state(
                    install_root, legacy, legacy_manifest)

                launcher = root / "launcher"
                launcher_raw = (
                    REPO / MANAGER.LAUNCHER_SOURCE).read_bytes()
                launcher.write_bytes(launcher_raw)
                launcher.chmod(0o755)
                launcher_sha256 = hashlib.sha256(launcher_raw).hexdigest()
                state_root = root / "controller-state"
                state_root.mkdir(mode=0o700)
                crashed = False

                def checkpoint(phase: str) -> None:
                    nonlocal crashed
                    if not crashed and phase == crash_phase:
                        crashed = True
                        raise MANAGER.ReleaseFailure("simulated:" + phase)

                def install_candidate(*_args, **_kwargs):
                    self.assertFalse(os.path.lexists(current))
                    current.symlink_to(f"releases/{candidate.name}")
                    return {
                        "schema": MANAGER.SCHEMA,
                        "release_id": candidate.name,
                    }

                def invoke():
                    return MANAGER.bootstrap_native_deployment_schema(
                        REPO, install_root, launcher, state_root,
                        os.geteuid(), candidate.name, legacy.name,
                        launcher_sha256, launcher_sha256,
                    )

                with (
                    mock.patch.object(
                        MANAGER, "source_payload",
                        return_value=(
                            candidate_values, candidate_hashes, candidate.name),
                    ),
                    mock.patch.object(
                        MANAGER, "console_user_uid",
                        return_value=os.geteuid(),
                    ),
                    mock.patch.object(
                        MANAGER, "manages_live_touchid_service",
                        return_value=False,
                    ),
                    mock.patch.object(
                        MANAGER, "native_coordination_bootstrap_checkpoint",
                        side_effect=checkpoint,
                    ),
                    mock.patch.object(
                        MANAGER, "install", side_effect=install_candidate,
                    ) as install,
                    # Preserve verified_release's inventory, mode, ownership,
                    # and digest checks while excluding only the signed native
                    # product semantic verifier from this gate-focused fixture.
                    mock.patch.object(
                        MANAGER, "LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES",
                        {"__unavailable_test_product_carrier__"},
                    ),
                    mock.patch.object(
                        MANAGER, "execution_approval_floor",
                        return_value=(1, 0),
                    ),
                ):
                    with self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "simulated:" + crash_phase,
                    ):
                        invoke()
                    self.assertFalse(os.path.lexists(current))
                    predecessor = (
                        install_root
                        / MANAGER.NATIVE_STACK_COORDINATION_PREDECESSOR_NAME)
                    self.assertEqual(predecessor.resolve(), legacy.resolve())
                    result = invoke()
                self.assertEqual(result["release_id"], candidate.name)
                self.assertTrue(result["coordination_floor_established"])
                install.assert_called_once()
                self.assertEqual(current.resolve(), candidate.resolve())

                with (
                    mock.patch.object(
                        MANAGER, "LEGACY_NATIVE_CREDENTIAL_PAYLOAD_NAMES",
                        {"__unavailable_test_product_carrier__"},
                    ),
                    mock.patch.object(
                        MANAGER, "execution_approval_floor",
                        return_value=(1, 0),
                    ),
                ):
                    descriptor = MANAGER.open_locked_install_root(
                        install_root, os.geteuid())
                    try:
                        self.assertEqual(
                            MANAGER.ensure_native_catalog_promotion_inactive_locked(
                                descriptor, install_root, os.geteuid())["state"],
                            "ready",
                        )
                        self.assertEqual(
                            MANAGER.ensure_native_deployment_inactive_locked(
                                descriptor, install_root, os.geteuid())["state"],
                            "ready",
                        )
                    finally:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                        os.close(descriptor)

    def test_launcher_uses_readable_enforcement_not_private_floor(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_root = Path(temporary) / "host"
            release, manifest = self.make_minimal_driver_release(install_root)
            private_floor = (
                install_root / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME)
            private_floor.chmod(0o000)
            if os.geteuid() != 0:
                with self.assertRaises(PermissionError):
                    private_floor.read_bytes()
            with mock.patch.object(
                LAUNCHER, "CURRENT_PAYLOAD_NAMES",
                frozenset(manifest["payloads"]),
            ):
                selected, release_id = LAUNCHER.load_release(
                    install_root, os.geteuid())
            self.assertEqual(selected, release.resolve())
            self.assertEqual(release_id, release.name)
            enforcement_path = (
                install_root
                / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME)
            enforcement = json.loads(enforcement_path.read_bytes())
            enforcement["minimum_features"] = sorted([
                *enforcement["minimum_features"], "future-fence-v2",
            ])
            enforcement_path.chmod(0o644)
            enforcement_path.write_bytes(
                MANAGER.canonical_state_record(enforcement))
            enforcement_path.chmod(0o444)
            with (
                mock.patch.object(
                    LAUNCHER, "CURRENT_PAYLOAD_NAMES",
                    frozenset(manifest["payloads"]),
                ),
                self.assertRaisesRegex(
                    LAUNCHER.LaunchFailure,
                    "controller_coordination_contract_invalid",
                ),
            ):
                LAUNCHER.load_release(install_root, os.geteuid())

    def test_payload_container_is_deterministic_exact_and_closed(self):
        first = MANAGER.native_deployment_payload_container(REPO)
        second = MANAGER.native_deployment_payload_container(REPO)
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            NATIVE_DEPLOYMENT_PAYLOAD.build_payload_container(REPO),
        )
        with zipfile.ZipFile(io.BytesIO(first), "r") as archive:
            self.assertEqual(
                archive.namelist(),
                sorted(MANAGER.NATIVE_DEPLOYMENT_CONTAINER_MEMBERS),
            )
            self.assertEqual(len(archive.namelist()), 5)
            self.assertIn(
                "research-fence-recovery-acquire.zip",
                archive.namelist(),
            )
            for item in archive.infolist():
                self.assertEqual(item.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(item.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(
                    (item.external_attr >> 16) & 0o7777, 0o444,
                )
                role = NATIVE_DEPLOYMENT_PAYLOAD.CONTAINER_MEMBERS[
                    item.filename
                ]
                NATIVE_DEPLOYMENT_PAYLOAD.read_base_archive(
                    archive.read(item), role,
                )

    def test_payload_container_rejects_symlink_and_writable_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            self.copy_payload_repository(repository)
            source = repository / "scripts/install-native-egress-gateway.sh"
            source.unlink()
            source.symlink_to(REPO / "scripts/install-native-egress-gateway.sh")
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_payload_build_failed",
            ):
                MANAGER.native_deployment_payload_container(repository)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            self.copy_payload_repository(repository)
            source = repository / "scripts/install-native-egress-gateway.sh"
            source.chmod(0o664)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_payload_build_failed",
            ):
                MANAGER.native_deployment_payload_container(repository)

    def test_payload_builder_never_executes_candidate_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            self.copy_payload_repository(repository)
            module = repository / "scripts/native_deployment_payload.py"
            module.write_bytes(
                module.read_bytes()
                + b"\nraise RuntimeError('candidate module executed')\n"
            )
            self.assertEqual(
                MANAGER.native_deployment_payload_container(repository),
                MANAGER.native_deployment_payload_container(REPO),
            )

    def test_payload_container_inventory_is_bound_to_support_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            self.copy_payload_repository(repository)
            support = MANAGER.native_stack_support_archive(repository)
            expected = MANAGER.native_deployment_payload_container(
                repository, support_archive=support,
            )
            module = repository / "scripts/native_deployment_payload.py"
            module.write_bytes(
                module.read_bytes() + b"\nCONTAINER_MEMBERS = dict()\n"
            )
            self.assertEqual(
                MANAGER.native_deployment_payload_container(
                    repository, support_archive=support,
                ),
                expected,
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_payload_inventory_invalid",
            ):
                MANAGER.native_deployment_payload_container(repository)
            overlapping = repository / "shared/native_deployment.py"
            overlapping.write_bytes(
                overlapping.read_bytes() + b"\n# changed after support snapshot\n"
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_payload_source_changed",
            ):
                MANAGER.native_deployment_payload_container(
                    repository, support_archive=support,
                )

    def test_payload_builder_rejects_dynamic_inventory_rebinding(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            self.copy_payload_repository(repository)
            module = repository / "scripts/native_deployment_payload.py"
            module.write_bytes(
                module.read_bytes() + b"\nCONTAINER_MEMBERS = dict()\n"
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_deployment_payload_inventory_invalid",
            ):
                MANAGER.native_deployment_payload_container(repository)

    def test_payload_builder_rejects_missing_recovery_fence_member(self):
        source = (
            REPO / "scripts/native_deployment_payload.py"
        ).read_bytes()
        recovery_member = (
            b'    "research-fence-recovery-acquire.zip": (\n'
            b'        "research-fence-recovery-acquire"),\n'
        )
        self.assertEqual(source.count(recovery_member), 1)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_deployment_payload_inventory_invalid",
        ):
            MANAGER.native_deployment_payload_inventories(
                REPO, source=source.replace(recovery_member, b""),
            )

    def test_installed_deployer_imports_only_immutable_support(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            deployer = release / "native_stack_deployer"
            deployer.write_bytes(
                (REPO / "scripts/native-stack-deploy.py").read_bytes()
            )
            (release / "native_stack_support").write_bytes(
                MANAGER.native_stack_support_archive(REPO)
            )
            (release / "native_stack_support").chmod(0o444)
            (release / "native_deployment_payloads").write_bytes(
                MANAGER.native_deployment_payload_container(REPO)
            )
            support_sha256 = hashlib.sha256(
                (release / "native_stack_support").read_bytes()
            ).hexdigest()
            loaded = subprocess.run(
                [
                    sys.executable, "-I", "-c",
                    (
                        "import os, pathlib, types, sys; "
                        "p=pathlib.Path(sys.argv[1]); "
                        "m=types.ModuleType('deployer'); m.__file__=str(p); "
                        "exec(compile(p.read_bytes(),str(p),'exec'),m.__dict__); "
                        "assert callable(m.deployment_gate_state); "
                        "assert m.native_deployment_payload is None; "
                        "m._activate_support(p.parent/'native_stack_support',"
                        "sys.argv[2],expected_uid=os.geteuid()); "
                        "assert m.native_deployment_payload.__file__.startswith("
                        "str(p.parent/'native_stack_support')+'/')"
                    ),
                    str(deployer), support_sha256,
                ],
                check=False, capture_output=True, text=True, cwd=release,
            )
        self.assertEqual(loaded.returncode, 0, loaded.stderr)

    def test_installed_deployer_gate_runs_under_host_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            install_root = root / "installed"
            release, manifest = self.make_minimal_driver_release(install_root)
            deployment_state = MANAGER.native_deployment_state_root(
                install_root
            )
            deployment_state.mkdir(mode=0o700)
            (deployment_state / "state.lock").touch(mode=0o600)
            release_id = release.name
            (install_root / "current").unlink()
            descriptor = MANAGER.open_locked_install_root(
                install_root, os.geteuid(),
            )
            try:
                with mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(release, manifest),
                ):
                    result = MANAGER.ensure_native_deployment_inactive_locked(
                        descriptor, install_root, os.geteuid(),
                        selector_release_id=release_id,
                    )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual(result["state"], "ready")
            state_root = MANAGER.native_deployment_state_root(install_root)
            self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((state_root / "state.lock").stat().st_mode),
                0o600,
            )

    def test_host_gate_rejects_active_and_invalid_catalog_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            install_root = root / "installed"
            release, manifest = self.make_minimal_driver_release(install_root)
            catalog_root, _transactions, _status = (
                MANAGER.native_catalog_gate_paths(install_root))
            catalog_root.mkdir(mode=0o700)
            (catalog_root / ".promotion.lock").touch(mode=0o600)
            release_id = release.name
            (install_root / "current").unlink()
            descriptor = MANAGER.open_locked_install_root(
                install_root, os.geteuid())
            try:
                for state in ("active", "invalid"):
                    with self.subTest(state=state):
                        body = {
                            "state": state,
                            "active_promotion_id": (
                                "11111111-1111-4111-8111-111111111111"
                                if state == "active" else None),
                            "active_state_sha256": (
                                "a" * 64 if state == "active" else None),
                        }
                        value = {
                            "schema": MANAGER.NATIVE_CATALOG_PROMOTION_GATE_SCHEMA,
                            **body,
                            "gate_sha256": hashlib.sha256(
                                MANAGER.canonical_state_record(body)
                            ).hexdigest(),
                        }
                        completed = subprocess.CompletedProcess(
                            [], 0, MANAGER.canonical_state_record(value), b"")
                        expected = (
                            "native_catalog_promotion_active"
                            if state == "active"
                            else "native_catalog_promotion_state_invalid"
                        )
                        with mock.patch.object(
                            MANAGER, "verified_release",
                            return_value=(release, manifest),
                        ), mock.patch.object(
                            MANAGER.subprocess, "run", return_value=completed,
                        ), self.assertRaisesRegex(
                            MANAGER.ReleaseFailure, expected,
                        ):
                            MANAGER.ensure_native_catalog_promotion_inactive_locked(
                                descriptor, install_root, os.geteuid(),
                                selector_release_id=release_id)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def test_installed_promoter_gate_runs_under_host_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            install_root = root / "installed"
            release, manifest = self.make_minimal_driver_release(install_root)
            catalog_root, transactions, _status = (
                MANAGER.native_catalog_gate_paths(install_root))
            catalog_root.mkdir(mode=0o700)
            transactions.mkdir(mode=0o700)
            (catalog_root / ".promotion.lock").touch(mode=0o600)
            (transactions / ".lock").touch(mode=0o600)
            for name in (
                "promotion-replay-authorities", "promotion-receipts",
                "promotion-staging", "promotion-journals",
            ):
                (catalog_root / name).mkdir(mode=0o700)
            release_id = release.name
            (install_root / "current").unlink()
            descriptor = MANAGER.open_locked_install_root(
                install_root, os.geteuid())
            try:
                with mock.patch.object(
                    MANAGER, "verified_release",
                    return_value=(release, manifest),
                ):
                    value = MANAGER.ensure_native_catalog_promotion_inactive_locked(
                        descriptor, install_root, os.geteuid(),
                        selector_release_id=release_id)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual(value["state"], "ready")


class NativeHostSourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        (self.repo / "macos/TouchIDAuthorization").mkdir(parents=True)
        (self.repo / ".gitignore").write_text(
            "macos/TouchIDAuthorization/Signing.local.xcconfig\n",
            encoding="ascii",
        )
        (self.repo / "macos/TouchIDAuthorization/Signing.local.xcconfig").write_text(
            "SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n",
            encoding="ascii",
        )
        (self.repo / "source.txt").write_text("first\n", encoding="ascii")
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "init", "-q", "-b",
             "public-release"], check=True,
        )
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "add", ".gitignore",
             "source.txt"], check=True,
        )
        self._commit("initial")

    def tearDown(self):
        self.temporary.cleanup()

    def _commit(self, message):
        subprocess.run(
            [
                "/usr/bin/git", "-c", "user.name=SecureSandbox Test",
                "-c", "user.email=test@example.invalid", "-C",
                str(self.repo), "commit", "-q", "-m", message,
            ],
            check=True,
        )

    def test_clean_public_release_provenance_is_independently_derived(self):
        value = MANAGER.current_native_host_source_provenance(self.repo)
        self.assertEqual(
            value["release_commit"],
            subprocess.run(
                ["/usr/bin/git", "-C", str(self.repo), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip(),
        )
        self.assertRegex(value["source_archive_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(value["source_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            value["signing_config_sha256"],
            hashlib.sha256(
                b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
            ).hexdigest(),
        )

    def test_root_reverification_accepts_exact_nonroot_owned_repository(self):
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            value = MANAGER.current_native_host_source_provenance(self.repo)
        self.assertRegex(value["release_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(value["source_tree_sha256"], r"^[0-9a-f]{64}$")

    def test_candidate_source_provenance_needs_no_local_signing_config(self):
        expected = MANAGER.current_native_host_source_provenance(self.repo)
        (
            self.repo
            / "macos/TouchIDAuthorization/Signing.local.xcconfig"
        ).unlink()
        observed = MANAGER.current_native_host_candidate_source_provenance(
            self.repo,
            expected_signing_config_sha256=(
                expected["signing_config_sha256"]
            ),
        )
        self.assertEqual(observed, expected)

    def test_generation_archive_replaces_mutable_git_at_admission(self):
        provenance, expected_files = MANAGER.current_native_host_source_snapshot(
            self.repo
        )
        source_archive = MANAGER._native_host_git(
            self.repo, "archive", "--format=tar", provenance["release_commit"],
        )
        receipt = {
            "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
            "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
            **provenance,
        }
        with mock.patch.object(
            MANAGER, "_native_host_git",
            side_effect=AssertionError("admission must not consult Git"),
        ):
            observed, files = (
                MANAGER.native_host_source_snapshot_from_generation(
                    source_archive, receipt,
                )
            )
        self.assertEqual(observed, provenance)
        self.assertEqual(files, expected_files)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_generation_source_invalid",
        ):
            MANAGER.native_host_source_snapshot_from_generation(
                source_archive + b"tamper", receipt,
            )

    def test_dirty_source_and_git_archive_overrides_fail_closed(self):
        (self.repo / "source.txt").write_text("dirty\n", encoding="ascii")
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_source_worktree_not_clean",
        ):
            MANAGER.current_native_host_source_provenance(self.repo)
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "restore", "source.txt"],
            check=True,
        )
        attributes = self.repo / ".git/info/attributes"
        attributes.write_text("source.txt export-ignore\n", encoding="ascii")
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_source_git_override_present",
        ):
            MANAGER.current_native_host_source_provenance(self.repo)
        attributes.unlink()
        (self.repo / "source.txt").write_text("second\n", encoding="ascii")
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "add", "source.txt"],
            check=True,
        )
        predecessor = subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self._commit("second")
        current = subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), "replace", current,
             predecessor],
            check=True,
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_source_git_replace_present",
        ):
            MANAGER.current_native_host_source_provenance(self.repo)


class HostControllerReleaseTests(unittest.TestCase):
    @staticmethod
    def _developer_id_floor_record(
        team: str = "ABCDE" + "12345",
    ) -> dict[str, object]:
        return MANAGER.developer_id_floor_record(
            release_id="a" * 64,
            authorization_manifest=b"{}\n",
            policy={
                "team_id": team,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
            },
            established_at=1,
        )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "config").mkdir()
        (self.repo / "seeds").mkdir()
        (self.repo / ".private").mkdir()
        (self.repo / ".private").chmod(0o700)
        (self.repo / ".private/secure-enclave-ddd.json").write_text(json.dumps({
            "schema":"secure-sandbox-secure-enclave-ddd-local-config-v1",
            "acceptance_source_id":"11111111-1111-4111-8111-111111111111",
            "legacy_launchservices_ui_bundle_sha256":"f" * 64,
        }) + "\n", encoding="ascii")
        (self.repo / ".private/secure-enclave-ddd.json").chmod(0o600)
        touchid_sources = [
            Path("macos/TouchIDAuthorization/Package.swift"),
            Path("macos/TouchIDAuthorization/AuthorizationUI.entitlements"),
            Path("macos/TouchIDAuthorization/Info.plist"),
            Path("macos/TouchIDAuthorization/Artwork/AppIcon.icon/icon.json"),
            Path("macos/TouchIDAuthorization/Artwork/AppIcon.icon/Assets/AuthorizationLock.svg"),
            Path("macos/TouchIDAuthorization/Artwork/AppIcon.icon/Assets/ControlStack.svg"),
            Path("macos/TouchIDAuthorization/Artwork/AppIcon.icon/Assets/DiagonalAccent.svg"),
            Path("macos/TouchIDAuthorization/Signing.example.xcconfig"),
            Path("macos/TouchIDAuthorization/SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj"),
            Path("macos/TouchIDAuthorization/Sources/AuthorizationCore/AuthorizationRequest.swift"),
            Path("macos/TouchIDAuthorization/Sources/AuthorizationCore/ExecutionApprovalCrypto.swift"),
            Path("macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift"),
            Path("macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/main.swift"),
        ]
        deployment_sources = sorted({
            Path(relative)
            for role in NATIVE_DEPLOYMENT_PAYLOAD.CONTAINER_MEMBERS.values()
            for _name, relative, _mode
            in NATIVE_DEPLOYMENT_PAYLOAD.inventory(role)
        })
        generated_host_payloads = {
            MANAGER.PAYLOAD_SOURCES[name]
            for name in (
                "authorization_ui_bundle",
                "authorization_ui_sources",
                "native_stack_credential_client",
                "native_projection_consumer",
                "native_credential_helper_bundle",
                "native_host_products_container",
                "native_host_products_manifest",
                "native_host_products_notarization",
                "native_host_products_notarization_signature",
            )
        }
        for relative in [*MANAGER.PAYLOAD_SOURCES.values(),
                         *MANAGER.NATIVE_STACK_SUPPORT_SOURCES.values(),
                         MANAGER.LAUNCHER_SOURCE, *touchid_sources,
                         *deployment_sources]:
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            if relative not in generated_host_payloads:
                if relative in {
                    MANAGER.PAYLOAD_SOURCES[name]
                    for name in ("seed_gateway", "seed_research", "seed_target")
                }:
                    (self.repo / relative).write_bytes(
                        b"SecureSandbox test-only seed placeholder\n"
                    )
                elif relative == MANAGER.PAYLOAD_SOURCES["ssh_config"]:
                    (self.repo / relative).write_text(
                        (REPO / "config/ssh_config.example").read_text()
                        .replace("REPLACE_WITH_ABSOLUTE_REPOSITORY_PATH", str(self.repo)),
                        encoding="utf-8",
                    )
                else:
                    shutil.copyfile(REPO / relative, self.repo / relative)

        def write_test_bundle(root, files):
            root.mkdir(parents=True)
            for relative, (data, mode) in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(mode)
            for directory in sorted(
                (item for item in root.rglob("*") if item.is_dir()),
                key=lambda item: len(item.parts), reverse=True,
            ):
                directory.chmod(0o555)
            root.chmod(0o555)

        authorization_files = {
            MANAGER.AUTHORIZATION_UI_EXECUTABLE.as_posix(): (
                b"SecureSandbox test-only Authorization UI executable\n",
                0o555,
            ),
            "Contents/Info.plist": (
                plistlib.dumps({
                    "CFBundleExecutable":
                        MANAGER.AUTHORIZATION_UI_EXECUTABLE.name,
                    "CFBundleIdentifier":
                        "org.zebeth.SecureSandbox.AuthorizationUI",
                    "CFBundlePackageType": "APPL",
                }),
                0o444,
            ),
            "Contents/Resources/AppIcon.icns": (
                b"SecureSandbox test-only icon\n", 0o444,
            ),
            "Contents/embedded.provisionprofile": (
                b"SecureSandbox test-only provisioning profile\n", 0o444,
            ),
        }
        write_test_bundle(
            self.repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            authorization_files,
        )
        team_id = MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
        bundle_id = "org.zebeth.SecureSandbox.AuthorizationUI"
        authorization_manifest = {
            "bundle": MANAGER.AUTHORIZATION_UI_APP_NAME,
            "files": {
                relative: {
                    "mode": mode,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for relative, (data, mode) in authorization_files.items()
            },
            "schema": "secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy": {
                "access_group": f"{team_id}.{bundle_id}",
                "application_identifier": f"{team_id}.{bundle_id}",
                "bundle_id": bundle_id,
                "team_id": team_id,
            },
        }
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "authorization_ui_bundle"
        ]).write_text(
            json.dumps(authorization_manifest, indent=2, sort_keys=True)
            + "\n",
            encoding="ascii",
        )
        source_hashes = {
            relative.relative_to(
                Path("macos/TouchIDAuthorization")
            ).as_posix(): hashlib.sha256(
                (self.repo / relative).read_bytes()
            ).hexdigest()
            for relative in touchid_sources
            if relative.relative_to(
                Path("macos/TouchIDAuthorization")
            ).as_posix()
            in MANAGER.AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES
        }
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "authorization_ui_sources"
        ]).write_text(
            json.dumps({
                "schema": "secure-sandbox-touchid-ui-source-v1",
                "sources": source_hashes,
            }, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

        backend = b"SecureSandbox test-only native credential backend\n"
        consumer = b"SecureSandbox test-only native projection consumer\n"
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_stack_credential_client"
        ]).write_bytes(backend)
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_projection_consumer"
        ]).write_bytes(consumer)
        helper_files = {
            "Contents/Info.plist": (
                plistlib.dumps({
                    "CFBundleDevelopmentRegion": "en",
                    "CFBundleDisplayName": "SecureSandbox Native Credential Helper",
                    "CFBundleExecutable":
                        MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.name,
                    "CFBundleIdentifier":
                        MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
                    "CFBundleInfoDictionaryVersion": "6.0",
                    "CFBundleName": "SecureSandboxNativeCredentialHelper",
                    "CFBundlePackageType": "APPL",
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "1",
                    "LSBackgroundOnly": True,
                    "LSUIElement": True,
                }),
                0o444,
            ),
            MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE.as_posix(): (
                b"SecureSandbox test-only native credential helper\n",
                0o555,
            ),
        }
        write_test_bundle(
            self.repo / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_SOURCE,
            helper_files,
        )
        native_manifest = {
            "backend": {
                "identifier": MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER,
                "mode": 0o555,
                "sha256": hashlib.sha256(backend).hexdigest(),
                "size": len(backend),
            },
            "consumer": {
                "identifier": MANAGER.NATIVE_PROJECTION_CONSUMER_IDENTIFIER,
                "mode": 0o555,
                "sha256": hashlib.sha256(consumer).hexdigest(),
                "size": len(consumer),
            },
            "helper": {
                "bundle": MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
                "files": {
                    relative: {
                        "mode": mode,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size": len(data),
                    }
                    for relative, (data, mode) in helper_files.items()
                },
                "identifier": MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL,
            },
            "schema": "secure-sandbox-native-components-bundle-v1",
            "signing_policy": {"team_id": team_id},
        }
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_credential_helper_bundle"
        ]).write_text(
            json.dumps(native_manifest, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        container = b"SecureSandbox test-only native Host product carrier\n"
        product_values = {
            name: (
                self.repo / MANAGER.PAYLOAD_SOURCES[name]
            ).read_bytes()
            for name in (
                "authorization_ui_bundle",
                "native_credential_helper_bundle",
                "native_stack_credential_client",
                "native_projection_consumer",
            )
        }
        manifest = (
            json.dumps({
                "entries": MANAGER.expected_native_host_product_entries(
                    product_values
                ),
                "schema": "secure-sandbox-native-host-products-manifest-v1",
            }, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        source_archive_output = io.BytesIO()
        with tarfile.open(
            fileobj=source_archive_output, mode="w", format=tarfile.USTAR_FORMAT,
        ) as archive:
            source_value = b"fixture source archive\n"
            item = tarfile.TarInfo("source.txt")
            item.mode = 0o644
            item.size = len(source_value)
            item.mtime = 0
            archive.addfile(item, io.BytesIO(source_value))
        source_archive = source_archive_output.getvalue()
        source_archive_sha256 = hashlib.sha256(source_archive).hexdigest()
        (self.repo / "artifacts/host" /
         MANAGER.NATIVE_HOST_SOURCE_ARCHIVE_NAME).write_bytes(source_archive)
        self.gpgv_binary = self.root / "gpgv"
        self.gpgv_binary.write_bytes(b"test-gpgv-binary\n")
        self.gpgv_binary.chmod(0o755)
        fixture_source_files = {
            path.relative_to(self.repo).as_posix(): path.read_bytes()
            for path in self.repo.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        self.native_host_release_preimage = (
            MANAGER.native_host_release_preimage_archive(
                self.repo, source_archive, self.gpgv_binary,
                _source_files=fixture_source_files,
            )
        )
        native_host_release_preimage_sha256 = hashlib.sha256(
            self.native_host_release_preimage
        ).hexdigest()
        fixture_submission_id = "00000000-0000-4000-8000-000000000001"
        self.native_host_notary_result = (json.dumps({
            "id": fixture_submission_id, "status": "Accepted",
        }, sort_keys=True) + "\n").encode("ascii")
        self.native_host_notary_log = (json.dumps({
            "issues": [], "jobId": fixture_submission_id,
            "sha256": "3" * 64, "status": "Accepted", "statusCode": 0,
        }, sort_keys=True) + "\n").encode("ascii")
        notarization = (
            json.dumps({
                "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
                "container_cdhash": "1" * 40,
                "container_identifier":
                    MANAGER.NATIVE_HOST_PRODUCTS_CONTAINER_IDENTIFIER,
                "container_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "container_sha256": hashlib.sha256(container).hexdigest(),
                "container_size": len(container),
                "developer_id_certificate_sha1": "2" * 40,
                "gatekeeper_assessed": True,
                "host_release_preimage_sha256":
                    native_host_release_preimage_sha256,
                "notary_log_sha256": hashlib.sha256(
                    self.native_host_notary_log
                ).hexdigest(),
                "notary_status": "accepted",
                "notary_submission_id": fixture_submission_id,
                "notary_submission_sha256": "3" * 64,
                "products": {
                    name: {"identifier": identifier, "cdhash": character * 40}
                    for (name, identifier), character in zip(
                        sorted(
                            MANAGER.NATIVE_HOST_PRODUCTS_V2_PRODUCT_IDENTIFIERS.items()
                        ),
                        "4567",
                    )
                },
                "release_commit": "8" * 40,
                "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
                "signing_config_sha256": "9" * 64,
                "source_archive_sha256": source_archive_sha256,
                "source_tree_sha256": "b" * 64,
                "stapler_validated": True,
                "team_id": team_id,
            }, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        generated_native_host_delivery_values = {
            "native_host_products_container": container,
            "native_host_products_manifest": manifest,
            "native_host_products_notarization": notarization,
            "native_host_products_notarization_signature": b"S" * 512,
        }
        self.generated_native_host_product_values = {
            **product_values,
            **generated_native_host_delivery_values,
        }
        self.generated_native_host_product_value_sets = [
            dict(self.generated_native_host_product_values)
        ]
        self.alternate_candidate_sequence = 0
        for name, data in generated_native_host_delivery_values.items():
            (self.repo / MANAGER.PAYLOAD_SOURCES[name]).write_bytes(data)

        source_provenance = {
            "release_commit": "8" * 40,
            "signing_config_sha256": "9" * 64,
            "source_archive_sha256": source_archive_sha256,
            "source_tree_sha256": "b" * 64,
        }
        def test_source_snapshot(_source_archive, _receipt):
            # Production derives these bytes from the exact Git archive.  This
            # fixture has no release commit containing its generated test
            # payloads, so retain the exact setup-time source snapshot.  Later
            # mutable-checkout edits must not alter candidate authority.
            return source_provenance, dict(fixture_source_files)

        def verify_generated_native_host_products(
            values, *, require_v2=False, expected_source_provenance=None,
            expected_certificate_sha1=None,
        ):
            required = set(self.generated_native_host_product_values)
            if not required <= set(values):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_inventory_mismatch"
                )
            observed_manifest = MANAGER.native_host_products_manifest(
                values["native_host_products_manifest"]
            )
            observed_receipt = MANAGER.native_host_products_notarization(
                values["native_host_products_notarization"]
            )
            if (require_v2
                    and observed_receipt["schema"] not in {
                        MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA,
                        MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA,
                    }):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_notarization_below_v2"
                )
            if (expected_source_provenance is not None
                    and expected_source_provenance != source_provenance):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_source_provenance_mismatch"
                )
            if (expected_certificate_sha1 is not None
                    and expected_certificate_sha1 != "2" * 40):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_receipt_signature_invalid"
                )
            expected_entries = MANAGER.expected_native_host_product_entries(
                values
            )
            if observed_manifest["entries"] != expected_entries:
                raise MANAGER.ReleaseFailure(
                    "native_host_products_inventory_mismatch"
                )
            authorization = MANAGER.authorization_ui_bundle_manifest(
                values["authorization_ui_bundle"]
            )
            native = MANAGER.native_components_manifest(
                values["native_credential_helper_bundle"]
            )
            MANAGER.enforce_native_component_signer_alignment(
                native, authorization
            )
            container_bytes = values["native_host_products_container"]
            if (
                observed_receipt["container_sha256"]
                    != hashlib.sha256(container_bytes).hexdigest()
                or observed_receipt["container_size"]
                    != len(container_bytes)
                or observed_receipt["team_id"]
                    != native["signing_policy"]["team_id"]
                or observed_receipt["container_manifest_sha256"]
                    != hashlib.sha256(
                        values["native_host_products_manifest"]
                    ).hexdigest()
            ):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_notarization_mismatch"
                )
            if not any(
                all(values[name] == expected[name] for name in expected)
                for expected in self.generated_native_host_product_value_sets
            ):
                raise MANAGER.ReleaseFailure(
                    "native_host_products_test_signature_mismatch"
                )

        def verify_test_authorization_payload(
            repo, values, *, source_files=None,
            native_host_generation=None,
        ):
            source_manifest = json.loads(values["authorization_ui_sources"])
            if (source_manifest.get("schema")
                    != "secure-sandbox-touchid-ui-source-v1"
                    or set(source_manifest.get("sources", {}))
                    != MANAGER.AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES):
                raise MANAGER.ReleaseFailure(
                    "authorization_ui_source_manifest_invalid"
                )
            package = repo / "macos/TouchIDAuthorization"
            for name, expected in source_manifest["sources"].items():
                if hashlib.sha256(
                    MANAGER.read_regular(package / name)
                ).hexdigest() != expected:
                    raise MANAGER.ReleaseFailure(
                        f"authorization_ui_source_mismatch:{name}"
                    )
            try:
                service = plistlib.loads(values["authorization_service"])
            except plistlib.InvalidFileException as error:
                raise MANAGER.ReleaseFailure(
                    "authorization_service_plist_invalid"
                ) from error
            expected_service = {
                "KeepAlive": True,
                "Label": MANAGER.AUTHORIZATION_LABEL,
                "ProcessType": "Interactive",
                "ProgramArguments": [
                    "/usr/bin/python3",
                    "-I",
                    "/usr/local/libexec/secure-sandbox-host/current/"
                    "authorization_broker",
                    "serve-touchid",
                ],
                "RunAtLoad": True,
                "StandardErrorPath":
                    "/var/log/secure-sandbox-touchid-authorization.log",
                "StandardOutPath":
                    "/var/log/secure-sandbox-touchid-authorization.log",
                "Umask": 0o077,
            }
            if service != expected_service:
                raise MANAGER.ReleaseFailure(
                    "authorization_service_plist_invalid"
                )
            MANAGER.verify_authorization_ui_bundle(
                repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
                values["authorization_ui_bundle"],
            )

        native_helper_entitlements = {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.network.client": True,
            "com.apple.security.network.server": True,
            "com.apple.security.temporary-exception.files.absolute-path.read-only": [
                "/usr/local/libexec/secure-sandbox-host/",
                "/usr/local/var/lib/secure-sandbox/native-credential-tickets/",
            ],
        }
        real_subprocess_run = MANAGER.subprocess.run

        def run_test_signature_command(command, *arguments, **keywords):
            if (
                isinstance(command, list)
                and command[:4]
                    == ["/usr/bin/codesign", "-d", "--entitlements", ":-"]
                and len(command) == 5
            ):
                helper = Path(command[4]).resolve()
                self.assertTrue(helper.is_relative_to(self.root.resolve()))
                self.assertEqual(
                    helper.name, MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                )
                return subprocess.CompletedProcess(
                    command, 0,
                    stdout=plistlib.dumps(native_helper_entitlements),
                    stderr=b"",
                )
            return real_subprocess_run(command, *arguments, **keywords)

        def verify_test_native_signature(path, identifier, observed_team):
            resolved = Path(path).resolve()
            self.assertTrue(resolved.is_relative_to(self.root.resolve()))
            self.assertEqual(observed_team, team_id)
            expected_names = {
                MANAGER.NATIVE_CREDENTIAL_BACKEND_IDENTIFIER: {
                    MANAGER.PAYLOAD_SOURCES[
                        "native_stack_credential_client"
                    ].name,
                    "native_stack_credential_client",
                },
                MANAGER.NATIVE_PROJECTION_CONSUMER_IDENTIFIER: {
                    MANAGER.PAYLOAD_SOURCES[
                        "native_projection_consumer"
                    ].name,
                    "native_projection_consumer",
                },
                MANAGER.NATIVE_CREDENTIAL_HELPER_LABEL: {
                    MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
                },
            }
            self.assertIn(identifier, expected_names)
            self.assertIn(resolved.name, expected_names[identifier])

        def verify_test_authorization_policy(
            root, manifest_data, expected_uid=None, *,
            expected_cdhash=None, developer_id_certificate_sha1=None,
        ):
            manifest = MANAGER.authorization_ui_bundle_manifest(
                manifest_data
            )
            policy = MANAGER.authorization_ui_signing_policy(manifest)
            if policy is None:
                raise MANAGER.ReleaseFailure(
                    "authorization_ui_signing_policy_below_floor"
                )
            MANAGER.verify_authorization_ui_bundle(
                root, manifest_data, expected_uid
            )
            return policy

        # Live Developer ID, stapling, Gatekeeper, and mounted-DMG verification
        # have dedicated contract tests.  Release-manager behavior tests use
        # deterministic carrier metadata so a clean checkout never depends on
        # ignored, machine-specific notarization output.
        self.real_release_process_census = (
            MANAGER.ensure_no_d8653cb_release_processes
        )
        self.generated_host_verifiers = [
            mock.patch.object(
                MANAGER, "validate_touchid_payload",
                side_effect=verify_test_authorization_payload,
            ),
            mock.patch.object(
                MANAGER, "verify_native_component_signature",
                side_effect=verify_test_native_signature,
            ),
            mock.patch.object(
                MANAGER.subprocess, "run",
                side_effect=run_test_signature_command,
            ),
            mock.patch.object(
                MANAGER, "verified_authorization_ui_signing_policy",
                side_effect=verify_test_authorization_policy,
            ),
            mock.patch.object(
                MANAGER, "verified_existing_authorization_ui_anchor_policy",
                side_effect=verify_test_authorization_policy,
            ),
            mock.patch.object(
                MANAGER, "verify_native_host_products_container",
                side_effect=verify_generated_native_host_products,
            ),
            mock.patch.object(
                MANAGER,
                "verify_native_host_products_notarization_signature",
                return_value=None,
            ),
            mock.patch.object(
                MANAGER, "native_host_source_snapshot_from_generation",
                side_effect=test_source_snapshot,
            ),
            mock.patch.object(
                MANAGER, "ensure_no_d8653cb_release_processes",
                return_value=None,
            ),
        ]
        for verifier in self.generated_host_verifiers:
            verifier.start()
        self.install_root = self.root / "installed"
        self.launcher = self.root / "bin/secure-sandbox-claude"
        self.state = self.root / "state"
        self.uid = os.geteuid()
        self.authorization_receipts = self.root / "authorization-receipts"
        self.authorization_receipts.mkdir(mode=0o700)
        self.authorization_receipt_root = mock.patch.object(
            MANAGER, "DEFAULT_AUTHORIZATION_RECEIPT_ROOT",
            self.authorization_receipts,
        )
        self.authorization_receipt_root.start()
        self.op_binary = self.root / "op"
        self.op_binary.write_bytes(b"test-op-binary\n")
        self.op_binary.chmod(0o755)
        # A live protocol-v2 installation deliberately makes the host floor
        # root-only. Unit tests must never inherit that machine-global state.
        self.execution_approval_floor = mock.patch.object(
            MANAGER, "EXECUTION_APPROVAL_FLOOR", self.root / "minimum-floor.json"
        )
        self.execution_approval_floor.start()

    def tearDown(self):
        for verifier in reversed(self.generated_host_verifiers):
            verifier.stop()
        self.execution_approval_floor.stop()
        self.authorization_receipt_root.stop()
        self.temporary.cleanup()

    def native_host_candidate_binding(self):
        receipt = json.loads((
            self.repo / MANAGER.PAYLOAD_SOURCES[
                "native_host_products_notarization"
            ]
        ).read_text(encoding="ascii"))
        candidate = (
            self.repo / ".private/native-host-product-candidates" /
            (receipt["release_commit"] + "-" + receipt["notary_submission_id"])
        )
        candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        generation = candidate / "generation"
        if not candidate.exists():
            shutil.copytree(self.repo / "artifacts/host", generation)
            evidence = candidate / "evidence"
            evidence.mkdir(mode=0o700)
            preimage = (
                evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
            )
            preimage.write_bytes(self.native_host_release_preimage)
            preimage.chmod(0o400)
            (evidence / "notary-result.json").write_bytes(
                self.native_host_notary_result
            )
            (evidence / "notary-log.json").write_bytes(
                self.native_host_notary_log
            )
            (evidence / "notary-result.json").chmod(0o600)
            (evidence / "notary-log.json").chmod(0o600)
            candidate.chmod(0o700)
        generation = generation.resolve()
        return generation, MANAGER.native_host_candidate_record(
            self.repo, generation,
        )

    def alternate_native_host_candidate(
        self, overrides: Mapping[str, bytes],
    ):
        generation, _candidate = self.native_host_candidate_binding()
        base_root = generation.parent
        base_preimage = (
            base_root / "evidence"
            / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
        ).read_bytes()
        payloads, metadata = MANAGER.native_host_release_preimage_snapshot(
            base_preimage,
        )
        payloads.update(overrides)
        metadata_raw = (json.dumps(
            metadata, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
        preimage = MANAGER._encode_native_host_release_preimage(
            payloads, metadata_raw,
        )
        self.alternate_candidate_sequence += 1
        submission_id = (
            "12345678-1234-4123-8123-"
            f"{self.alternate_candidate_sequence:012d}"
        )
        receipt_path = generation / MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ].name
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt["notary_submission_id"] = submission_id
        receipt["host_release_preimage_sha256"] = MANAGER.sha256_bytes(
            preimage
        )
        log = json.loads(self.native_host_notary_log)
        log["jobId"] = submission_id
        log_raw = json.dumps(log, sort_keys=True).encode("ascii")
        receipt["notary_log_sha256"] = MANAGER.sha256_bytes(log_raw)
        result = json.loads(self.native_host_notary_result)
        result["id"] = submission_id
        result_raw = json.dumps(result, sort_keys=True).encode("ascii")
        candidate_root = (
            self.repo / ".private/native-host-product-candidates"
            / (receipt["release_commit"] + "-" + submission_id)
        )
        shutil.copytree(base_root, candidate_root)
        alternate_generation = candidate_root / "generation"
        alternate_receipt = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        (alternate_generation / receipt_path.name).write_bytes(
            alternate_receipt
        )
        evidence = candidate_root / "evidence"
        (evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME).chmod(
            0o600
        )
        (evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME).write_bytes(
            preimage
        )
        (evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME).chmod(
            0o400
        )
        (evidence / "notary-log.json").write_bytes(log_raw)
        (evidence / "notary-result.json").write_bytes(result_raw)
        (evidence / "notary-log.json").chmod(0o600)
        (evidence / "notary-result.json").chmod(0o600)
        allowed = dict(self.generated_native_host_product_values)
        allowed["native_host_products_notarization"] = alternate_receipt
        self.generated_native_host_product_value_sets.append(allowed)
        alternate_generation = alternate_generation.resolve()
        return (
            alternate_generation,
            MANAGER.native_host_candidate_record(
                self.repo, alternate_generation,
            ),
        )

    def install(self, candidate_binding=None):
        generation, candidate = (
            self.native_host_candidate_binding()
            if candidate_binding is None else candidate_binding
        )
        values, hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        MANAGER.prepare_install_root_for_lock(self.install_root, self.uid)
        if MANAGER.developer_id_team_floor(
            self.install_root, self.uid, allow_absent=True
        ) is None:
            policy = MANAGER.authorization_ui_signing_policy(
                MANAGER.authorization_ui_bundle_manifest(
                    values["authorization_ui_bundle"]
                )
            )
            if policy is None:
                raise MANAGER.ReleaseFailure(
                    "developer_id_team_floor_bootstrap_requires_v2"
                )
            MANAGER.create_developer_id_team_floor(
                self.install_root,
                self.uid,
                MANAGER.developer_id_floor_record(
                    release_id=release_id,
                    authorization_manifest=values[
                        "authorization_ui_bundle"
                    ],
                    policy=policy,
                    established_at=2_000_000_000,
                ),
            )
        if MANAGER.native_stack_coordination_floor(
            self.install_root, self.uid, allow_absent=True
        ) is None:
            MANAGER.establish_native_stack_coordination_floor(
                self.install_root, self.uid, release_id=release_id,
                contract_raw=values["native_stack_coordination_contract"],
            )
        if MANAGER.native_host_candidate_floor(
            self.install_root, self.uid, allow_absent=True,
        ) is None:
            # The pair bootstrap now re-proves and process-censuses the exact
            # predecessor named by the candidate floor on every replay.  Keep
            # a real pre-authorization predecessor in this synthetic layout;
            # a floor that merely names the historical production c5 release
            # would no longer be an honest fixture.
            predecessor_values = {
                name: values[name]
                for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
            }
            predecessor_hashes = {
                name: hashlib.sha256(value).hexdigest()
                for name, value in predecessor_values.items()
            }
            predecessor_id = MANAGER.release_identity(predecessor_hashes)
            releases = self.install_root / "releases"
            releases.mkdir(mode=0o755, exist_ok=True)
            predecessor = releases / predecessor_id
            predecessor.mkdir(mode=0o755)
            for name, value in predecessor_values.items():
                member = predecessor / name
                member.write_bytes(value)
                member.chmod(MANAGER.EXPECTED_MODES[name])
            manifest = {
                "payloads": predecessor_hashes,
                "release_id": predecessor_id,
                "schema": MANAGER.SCHEMA,
            }
            manifest_path = predecessor / "manifest.json"
            manifest_path.write_bytes(MANAGER.canonical_state_record(manifest))
            manifest_path.chmod(MANAGER.EXPECTED_MODES["manifest.json"])
            predecessor.chmod(0o555)
            predecessor_selector = (
                self.install_root
                / MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME
            )
            predecessor_selector.symlink_to(
                f"releases/{predecessor_id}"
            )
            MANAGER.establish_native_host_candidate_floor(
                self.install_root, self.uid, release_id=release_id,
                candidate_record=candidate,
                establishment_mode=(
                    MANAGER.NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
                ),
                predecessor_release_id=predecessor_id,
            )
        authorization_request_id = None
        authorization_request_sha256 = None
        authorized_target_plan_sha256 = None
        pair = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid, allow_absent=True,
        )
        if pair is not None:
            launcher = MANAGER.native_host_candidate_tracked_source(
                self.repo, generation, candidate, MANAGER.LAUNCHER_SOURCE,
            )
            _plan, authorized_target_plan_sha256 = (
                MANAGER.authorized_host_release_target_plan(
                    release_id=release_id, payloads=hashes,
                    candidate_record=candidate,
                    target_launcher_sha256=hashlib.sha256(
                        launcher
                    ).hexdigest(),
                    source_stable_sha256=pair[1],
                )
            )
            if (pair[0]["pair"]["release_id"] != release_id
                    or pair[0]["pair"]["launcher_sha256"]
                        != hashlib.sha256(launcher).hexdigest()):
                (
                    authorization_request_id,
                    authorization_request_sha256,
                ) = self.authorize_host_pair(
                    "host-controller-install",
                    authorized_target_plan_sha256,
                )
            else:
                authorized_target_plan_sha256 = None
        return MANAGER.install(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            self.op_binary, self.gpgv_binary,
            release_id,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
            authorization_request_id=authorization_request_id,
            authorization_request_sha256=authorization_request_sha256,
            authorized_target_plan_sha256=authorized_target_plan_sha256,
            _host_pair_bootstrap_mode=(
                MANAGER.native_host_candidate_floor(
                    self.install_root, self.uid,
                )[0]["establishment_mode"]
                if pair is None else None
            ),
        )

    def authorize_host_pair(
        self, operation: str, authorized_target_plan_sha256: str,
    ) -> tuple[str, str]:
        request_id = str(uuid.uuid4())
        request_sha256 = hashlib.sha256(
            f"{operation}:{request_id}:{authorized_target_plan_sha256}".encode(
                "ascii"
            )
        ).hexdigest()
        receipt = {
            "host_pair_authorized_target_plan_sha256":
                authorized_target_plan_sha256,
            "operation": operation,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "status": "executing",
        }
        path = self.authorization_receipts / f"{request_id}.json"
        path.write_bytes(MANAGER.canonical_state_record(receipt))
        path.chmod(0o600)
        return request_id, request_sha256

    def test_runtime_metadata_receipt_recovery_is_exact_and_idempotent(self):
        request_id = str(uuid.uuid4())
        request_sha256 = "1" * 64
        plan_sha256 = "2" * 64
        failed = {
            "authorization_method": "touch-id",
            "ceremony": "approve",
            "completed_at": 1001,
            "declared_agent": "Codex",
            "declared_session": "test-session",
            "exit_status": 1,
            "host_pair_authorized_target_plan_sha256": plan_sha256,
            "identity_evidence": "operator-declared",
            "operation": "host-controller-install",
            "purpose": "test",
            "request_id": request_id,
            "request_sha256": request_sha256,
            "resource": str(self.install_root),
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "started_at": 1000,
            "status": "failed",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_sha256": hashlib.sha256((json.dumps({
                    "error": "host_release_launcher_pair_tree_mismatch",
                    "schema": MANAGER.SCHEMA,
                    "status": "rejected",
                }, sort_keys=True) + "\n").encode("ascii")
            ).hexdigest(),
        }
        receipt_path = self.authorization_receipts / f"{request_id}.json"
        receipt_path.write_bytes(MANAGER.canonical_state_record(failed))
        receipt_path.chmod(0o600)
        self.assertEqual(
            failed["stdout_sha256"],
            "5c68a4264f43a39d4bad819b645ec8e068d2d55b60be56e2b7ed3c60fbfe2a3d",
        )
        recovery_root = self.root / "authorization-receipt-recoveries"
        pending, pending_sha256 = (
            MANAGER.reopen_runtime_metadata_failed_host_pair_receipt(
                request_id, request_sha256, plan_sha256, self.uid,
                receipt_root=self.authorization_receipts,
                recovery_root=recovery_root,
                install_root=self.install_root,
            )
        )
        self.assertEqual(pending["status"], "executing")
        self.assertIsNone(pending["completed_at"])
        self.assertEqual(
            pending_sha256,
            hashlib.sha256(
                MANAGER.canonical_state_record(pending)
            ).hexdigest(),
        )
        archives = list(recovery_root.iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual(stat.S_IMODE(archives[0].stat().st_mode), 0o400)
        self.assertEqual(
            json.loads(archives[0].read_text(encoding="ascii")), failed,
        )
        repeated, repeated_sha256 = (
            MANAGER.reopen_runtime_metadata_failed_host_pair_receipt(
                request_id, request_sha256, plan_sha256, self.uid,
                receipt_root=self.authorization_receipts,
                recovery_root=recovery_root,
                install_root=self.install_root,
            )
        )
        self.assertEqual(repeated, pending)
        self.assertEqual(repeated_sha256, pending_sha256)

    def test_runtime_metadata_receipt_recovery_accepts_exact_inventory_failure(
        self,
    ):
        request_id = str(uuid.uuid4())
        request_sha256 = "a" * 64
        plan_sha256 = "b" * 64
        failed = {
            "authorization_method": "touch-id",
            "ceremony": "approve",
            "completed_at": 1001,
            "declared_agent": "Codex",
            "declared_session": "test-session",
            "exit_status": 1,
            "host_pair_authorized_target_plan_sha256": plan_sha256,
            "identity_evidence": "operator-declared",
            "operation": "host-controller-install",
            "purpose": "test",
            "request_id": request_id,
            "request_sha256": request_sha256,
            "resource": str(self.install_root),
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "started_at": 1000,
            "status": "failed",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_sha256": hashlib.sha256((json.dumps({
                    "error": (
                        "native_host_release_tree_identity_inventory_invalid"
                    ),
                    "schema": MANAGER.SCHEMA,
                    "status": "rejected",
                }, sort_keys=True) + "\n").encode("ascii")
            ).hexdigest(),
        }
        self.assertEqual(
            failed["stdout_sha256"],
            "b7a9f9e4ad011bce303478c2898c2b2dc1fa55c9aad6f0e360e5b020ff0d978c",
        )
        receipt_path = self.authorization_receipts / f"{request_id}.json"
        receipt_path.write_bytes(MANAGER.canonical_state_record(failed))
        receipt_path.chmod(0o600)
        recovery_root = self.root / "authorization-receipt-recoveries"

        pending, _pending_sha256 = (
            MANAGER.reopen_runtime_metadata_failed_host_pair_receipt(
                request_id, request_sha256, plan_sha256, self.uid,
                receipt_root=self.authorization_receipts,
                recovery_root=recovery_root,
                install_root=self.install_root,
            )
        )

        self.assertEqual(pending["status"], "executing")
        archives = list(recovery_root.iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual(
            json.loads(archives[0].read_text(encoding="ascii")), failed,
        )

    def test_runtime_metadata_receipt_recovery_rejects_active_transition(self):
        request_id = str(uuid.uuid4())
        request_sha256 = "c" * 64
        plan_sha256 = "d" * 64
        failed = {
            "authorization_method": "touch-id",
            "ceremony": "approve",
            "completed_at": 1001,
            "declared_agent": "Codex",
            "declared_session": "test-session",
            "exit_status": 1,
            "host_pair_authorized_target_plan_sha256": plan_sha256,
            "identity_evidence": "operator-declared",
            "operation": "host-controller-install",
            "purpose": "test",
            "request_id": request_id,
            "request_sha256": request_sha256,
            "resource": str(self.install_root),
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "started_at": 1000,
            "status": "failed",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_sha256": hashlib.sha256((json.dumps({
                    "error": (
                        "native_host_release_tree_identity_inventory_invalid"
                    ),
                    "schema": MANAGER.SCHEMA,
                    "status": "rejected",
                }, sort_keys=True) + "\n").encode("ascii")
            ).hexdigest(),
        }
        receipt_path = self.authorization_receipts / f"{request_id}.json"
        receipt_path.write_bytes(MANAGER.canonical_state_record(failed))
        receipt_path.chmod(0o600)
        pending_transition = (
            self.install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
        )
        self.install_root.mkdir()
        pending_transition.write_text("retained transition evidence\n")

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "runtime_metadata_receipt_recovery_transition_active",
        ):
            MANAGER.reopen_runtime_metadata_failed_host_pair_receipt(
                request_id, request_sha256, plan_sha256, self.uid,
                receipt_root=self.authorization_receipts,
                recovery_root=(
                    self.root / "authorization-receipt-recoveries"
                ),
                install_root=self.install_root,
            )

        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="ascii")), failed,
        )
        self.assertFalse(
            (self.root / "authorization-receipt-recoveries").exists()
        )

    def test_runtime_metadata_receipt_recovery_rejects_other_failure(self):
        request_id = str(uuid.uuid4())
        request_sha256 = "3" * 64
        plan_sha256 = "4" * 64
        failed = {
            "authorization_method": "touch-id",
            "ceremony": "approve",
            "completed_at": 1001,
            "declared_agent": "Codex",
            "declared_session": "test-session",
            "exit_status": 1,
            "host_pair_authorized_target_plan_sha256": plan_sha256,
            "identity_evidence": "operator-declared",
            "operation": "host-controller-install",
            "purpose": "test",
            "request_id": request_id,
            "request_sha256": request_sha256,
            "resource": str(self.install_root),
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "started_at": 1000,
            "status": "failed",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_sha256": "5" * 64,
        }
        path = self.authorization_receipts / f"{request_id}.json"
        path.write_bytes(MANAGER.canonical_state_record(failed))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "runtime_metadata_receipt_recovery_error_mismatch",
        ):
            MANAGER.reopen_runtime_metadata_failed_host_pair_receipt(
                request_id, request_sha256, plan_sha256, self.uid,
                receipt_root=self.authorization_receipts,
                recovery_root=(
                    self.root / "authorization-receipt-recoveries"
                ),
                install_root=self.install_root,
            )

    def authorized_rollback(self, target_id: str | None = None):
        pair = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        target = (
            (self.install_root / "previous").resolve()
            if target_id is None
            else self.install_root / "releases" / target_id
        )
        authority = MANAGER.native_host_candidate_authority(
            self.install_root, target.name, self.uid,
        )
        _plan, plan_sha256 = MANAGER.authorized_host_release_rollback_plan(
            source_stable_sha256=pair[1], target_authority=authority,
        )
        request_id, request_sha256 = self.authorize_host_pair(
            "host-controller-rollback", plan_sha256,
        )
        return MANAGER.rollback(
            self.repo, self.install_root, self.state, target_id, self.uid,
            self.op_binary, self.gpgv_binary,
            launcher_path=self.launcher,
            authorization_request_id=request_id,
            authorization_request_sha256=request_sha256,
            authorized_target_plan_sha256=plan_sha256,
        )

    def test_install_and_verify_are_content_bound(self):
        deployed = self.install()
        verified = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        loaded_path, loaded_id = LAUNCHER.load_release(
            self.install_root, self.uid, launcher_path=self.launcher,
        )
        self.assertEqual(deployed["release_id"], verified["release_id"])
        self.assertEqual((loaded_path.name, loaded_id), (verified["release_id"], verified["release_id"]))
        self.assertEqual(os.readlink(self.install_root / "current"), f"releases/{verified['release_id']}")
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed\n")
        verified_after_checkout_change = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(
            verified_after_checkout_change["release_id"],
            deployed["release_id"],
        )

    def test_coordination_floor_blocks_pre_marker_selector_everywhere(self):
        deployed = self.install()
        current_release = (
            self.install_root / "releases" / deployed["release_id"])
        manifest = json.loads((current_release / "manifest.json").read_text())
        legacy_payloads = dict(manifest["payloads"])
        legacy_payloads.pop("native_stack_coordination_contract")
        legacy_payloads.pop("native_host_products_notarization_signature")
        legacy_id = MANAGER.release_identity(legacy_payloads)
        legacy = self.install_root / "releases" / legacy_id
        legacy.mkdir(mode=0o755)
        for name in legacy_payloads:
            shutil.copyfile(current_release / name, legacy / name)
            (legacy / name).chmod(MANAGER.EXPECTED_MODES[name])
        (legacy / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA,
            "release_id": legacy_id,
            "payloads": legacy_payloads,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (legacy / "manifest.json").chmod(0o444)
        legacy.chmod(0o555)
        current = self.install_root / "current"
        current.unlink()
        current.symlink_to(f"releases/{legacy_id}")
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_release_below_coordination_floor",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.verified_release(
                self.install_root, current, self.uid, allow_legacy=True)

    def test_candidate_floor_publication_replays_every_crash_prefix(self):
        _generation, candidate = self.native_host_candidate_binding()
        release_id = "d" * 64
        checkpoints = (
            "candidate-enforcement-pending-created",
            "candidate-private-floor-pending-created",
            "before-candidate-enforcement-publication",
            "candidate-enforcement-published",
            "candidate-private-floor-published",
        )
        for index, checkpoint in enumerate(checkpoints):
            with self.subTest(checkpoint=checkpoint):
                install_root = self.root / f"candidate-floor-{index}"
                install_root.mkdir(mode=0o755)
                MANAGER.create_developer_id_team_floor(
                    install_root, self.uid,
                    self._developer_id_floor_record(),
                )

                def interrupt(observed):
                    if observed == checkpoint:
                        raise RuntimeError("simulated-power-loss")

                with (
                    mock.patch.object(
                        MANAGER,
                        "native_host_candidate_bootstrap_checkpoint",
                        side_effect=interrupt,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError, "simulated-power-loss",
                    ),
                ):
                    MANAGER.establish_native_host_candidate_floor(
                        install_root, self.uid, release_id=release_id,
                        candidate_record=candidate,
                        establishment_mode=(
                            MANAGER.
                            NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                        ),
                        predecessor_release_id=(
                            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                        ),
                    )
                replay_projection = (
                    MANAGER.native_host_candidate_replay_enforcement(
                        install_root, self.uid,
                    )
                )
                self.assertIsNotNone(replay_projection)
                self.assertIsNotNone(
                    LAUNCHER._native_host_candidate_enforcement(
                        install_root, self.uid,
                    )
                )
                with self.assertRaises(MANAGER.ReleaseFailure):
                    MANAGER.native_host_candidate_floor(
                        install_root, self.uid, allow_absent=True,
                    )
                if checkpoint == checkpoints[0]:
                    self.assertFalse((
                        install_root
                        / MANAGER.NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME
                    ).exists())
                observed = MANAGER.establish_native_host_candidate_floor(
                    install_root, self.uid, release_id=release_id,
                    candidate_record=candidate,
                    establishment_mode=(
                        MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                    ),
                    predecessor_release_id=(
                        MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                    ),
                )
                self.assertEqual(
                    observed[0]["established_from_release_id"], release_id,
                )
                public = MANAGER.native_host_candidate_enforcement(
                    install_root, self.uid,
                )
                self.assertIsNotNone(public)
                assert public is not None
                derived = MANAGER.native_host_candidate_floor_records(
                    release_id=release_id, candidate_record=candidate,
                    establishment_mode=(
                        MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                    ),
                    predecessor_release_id=(
                        MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                    ),
                )
                self.assertEqual(derived[0], observed[0])
                self.assertEqual(derived[2], public[0])
                self.assertEqual(
                    derived[2]["authoritative_floor_sha256"], observed[1],
                )
                self.assertFalse((
                    install_root
                    / MANAGER.NATIVE_HOST_CANDIDATE_FLOOR_PENDING_NAME
                ).exists())
                self.assertFalse((
                    install_root
                    / MANAGER.NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME
                ).exists())

    def test_candidate_floor_partial_publication_rejects_changed_record(self):
        _generation, candidate = self.native_host_candidate_binding()
        install_root = self.root / "candidate-floor-conflict"
        install_root.mkdir(mode=0o755)
        MANAGER.create_developer_id_team_floor(
            install_root, self.uid, self._developer_id_floor_record(),
        )

        def interrupt(observed):
            if observed == "candidate-enforcement-published":
                raise RuntimeError("simulated-power-loss")

        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_bootstrap_checkpoint",
                side_effect=interrupt,
            ),
            self.assertRaisesRegex(RuntimeError, "simulated-power-loss"),
        ):
            MANAGER.establish_native_host_candidate_floor(
                install_root, self.uid, release_id="d" * 64,
                candidate_record=candidate,
                establishment_mode=(
                    MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )
        changed = dict(candidate)
        changed["generation_tree_sha256"] = "e" * 64
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_candidate_floor_conflict",
        ):
            MANAGER.establish_native_host_candidate_floor(
                install_root, self.uid, release_id="d" * 64,
                candidate_record=changed,
                establishment_mode=(
                    MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )

    def test_candidate_floor_blocks_featureless_rollback_and_launcher(self):
        # Model the production migration: its existing coordination floor was
        # established before candidate admission became a contract feature.
        MANAGER.prepare_install_root_for_lock(self.install_root, self.uid)
        pre_candidate_contract = json.loads((
            self.repo / MANAGER.PAYLOAD_SOURCES[
                "native_stack_coordination_contract"
            ]
        ).read_text(encoding="ascii"))
        pre_candidate_contract["features"].remove(
            MANAGER.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
        )
        MANAGER.establish_native_stack_coordination_floor(
            self.install_root, self.uid, release_id="c" * 64,
            contract_raw=(json.dumps(
                pre_candidate_contract, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n").encode("ascii"),
        )
        deployed = self.install()
        current_path = (
            self.install_root / "releases" / deployed["release_id"]
        )
        manifest = json.loads(
            (current_path / "manifest.json").read_text(encoding="utf-8")
        )
        contract = json.loads(
            (current_path / "native_stack_coordination_contract").read_text(
                encoding="ascii"
            )
        )
        contract["features"].remove(
            MANAGER.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
        )
        contract_raw = (json.dumps(
            contract, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
        old_payloads = dict(manifest["payloads"])
        old_payloads["native_stack_coordination_contract"] = (
            hashlib.sha256(contract_raw).hexdigest()
        )
        old_release_id = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release_id
        shutil.copytree(current_path, old_path)
        old_path.chmod(0o755)
        contract_path = old_path / "native_stack_coordination_contract"
        contract_path.chmod(0o644)
        contract_path.write_bytes(contract_raw)
        contract_path.chmod(0o444)
        manifest_path = old_path / "manifest.json"
        manifest_path.chmod(0o644)
        manifest_path.write_text(json.dumps({
            "schema": MANAGER.SCHEMA,
            "release_id": old_release_id,
            "payloads": old_payloads,
        }, indent=2, sort_keys=True) + "\n", encoding="ascii")
        manifest_path.chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "previous").symlink_to(
            f"releases/{old_release_id}"
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_host_candidate_floor",
        ):
            MANAGER.rollback(
                self.repo, self.install_root, self.state, None, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(
            (self.install_root / "current").resolve().name,
            deployed["release_id"],
        )
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(
            f"releases/{old_release_id}"
        )
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_release_below_native_host_candidate_floor",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )

    def test_candidate_feature_and_private_floor_fail_closed_without_projection(self):
        self.install()
        (
            self.install_root
            / MANAGER.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
        ).unlink()
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_native_host_candidate_enforcement_missing",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_candidate_enforcement_missing",
        ):
            MANAGER.verified_release(
                self.install_root, self.install_root / "current", self.uid,
            )

    def test_candidate_schema_bootstrap_rejects_near_match_predecessor(self):
        source_id = "d" * 64
        predecessor_id = (
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        near_match = dict(
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS
        )
        changed_name = sorted(near_match)[0]
        near_match[changed_name] = "e" * 64
        candidate = {
            "generation_path": "/retained/generation",
            "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
        }
        source_values = {name: b"fixture" for name in MANAGER.PAYLOAD_NAMES}
        source_values["native_stack_coordination_contract"] = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        operation = MANAGER.bootstrap_native_host_candidate_schema.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_record",
                return_value=candidate,
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=(source_values, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(
                    Path("/protected/releases") / predecessor_id,
                    {"payloads": near_match},
                ),
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_candidate_schema_predecessor_invalid",
            ),
        ):
            operation(
                Path("/repo"), Path("/protected"), Path("/launcher"),
                Path("/state"), self.uid, source_id, "absent",
                "a" * 64, "b" * 64, candidate,
            )

    def test_candidate_schema_bootstrap_publishes_floor_before_install(self):
        source_id = "d" * 64
        predecessor_id = (
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        candidate = {
            "generation_path": "/retained/generation",
            "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
        }
        source_values = {name: b"fixture" for name in MANAGER.PAYLOAD_NAMES}
        source_values["native_stack_coordination_contract"] = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        launcher = b"stable-launcher"
        launcher_sha256 = MANAGER.sha256_bytes(launcher)
        events = []
        self.install_root.mkdir(parents=True, exist_ok=True)
        (self.install_root / "current").symlink_to(
            f"releases/{predecessor_id}"
        )

        def candidate_floor(*_arguments, **keywords):
            events.append("candidate-floor")
            self.assertEqual(
                keywords["establishment_mode"],
                MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
            )
            self.assertEqual(
                keywords["predecessor_release_id"], predecessor_id,
            )

        def install(*_arguments, **_keywords):
            events.append("install")
            self.assertEqual(
                _keywords["_host_pair_bootstrap_mode"],
                MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE,
            )
            return {"schema": MANAGER.SCHEMA, "release_id": source_id}

        operation = MANAGER.bootstrap_native_host_candidate_schema.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_record",
                return_value=candidate,
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=(source_values, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(
                    Path("/protected/releases") / predecessor_id,
                    {"payloads": dict(
                        MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_PAYLOADS
                    )},
                ),
            ) as verified,
            mock.patch.object(
                MANAGER, "read_regular", return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=False,
            ),
            mock.patch.object(
                MANAGER, "ensure_no_d8653cb_release_processes",
            ),
            mock.patch.object(
                MANAGER, "establish_native_host_candidate_floor",
                side_effect=candidate_floor,
            ),
            mock.patch.object(MANAGER, "install", side_effect=install),
        ):
            result = operation(
                Path("/repo"), self.install_root, Path("/launcher"),
                Path("/state"), self.uid, source_id, predecessor_id,
                launcher_sha256, launcher_sha256, candidate,
            )
        self.assertEqual(events, ["candidate-floor", "install"])
        self.assertEqual(
            result["status"], "native_host_candidate_schema_bootstrapped",
        )
        self.assertTrue(verified.call_args_list[0].kwargs.get(
            "_bootstrap_without_candidate_admission_floor"
        ))

    def test_candidate_schema_bootstrap_replays_candidate_selector(self):
        source_id = "d" * 64
        candidate = {
            "generation_path": "/retained/generation",
            "build_custody": MANAGER.NATIVE_HOST_BUILD_CUSTODY,
        }
        source_values = {name: b"fixture" for name in MANAGER.PAYLOAD_NAMES}
        source_values["native_stack_coordination_contract"] = (
            REPO / "config/native-stack-coordination-contract.json"
        ).read_bytes()
        launcher = b"stable-launcher"
        launcher_sha256 = MANAGER.sha256_bytes(launcher)
        self.install_root.mkdir(parents=True, exist_ok=True)
        (self.install_root / "current").symlink_to(
            f"releases/{source_id}"
        )
        operation = MANAGER.bootstrap_native_host_candidate_schema.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_record",
                return_value=candidate,
            ),
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=(source_values, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(
                    Path("/protected/releases") / source_id,
                    {"payloads": {name: "e" * 64
                                  for name in MANAGER.PAYLOAD_NAMES}},
                ),
            ),
            mock.patch.object(
                MANAGER, "read_regular", return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "read_trusted_stable_launcher",
                return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                return_value=launcher,
            ),
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=False,
            ),
            mock.patch.object(
                MANAGER, "recover_terminal_schema_service",
                return_value={
                    "schema": MANAGER.SCHEMA, "release_id": source_id,
                },
            ),
            mock.patch.object(
                MANAGER, "establish_native_host_candidate_floor",
            ) as floor,
            mock.patch.object(MANAGER, "install") as install,
        ):
            result = operation(
                Path("/repo"), self.install_root, Path("/launcher"),
                Path("/state"), self.uid, source_id, source_id,
                launcher_sha256, launcher_sha256, candidate,
            )
        install.assert_not_called()
        self.assertTrue(result["recovered_existing_release"])
        self.assertEqual(
            result["previous_release_id"],
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
        )
        self.assertEqual(
            floor.call_args.kwargs["predecessor_release_id"],
            MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID,
        )

    def test_authorization_bootstrap_publishes_candidate_floor_before_install(self):
        generation, candidate = self.native_host_candidate_binding()
        _values, _hashes, source_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        predecessor_id = "a" * 64
        predecessor = self.install_root / "releases" / predecessor_id
        predecessor.mkdir(parents=True, mode=0o555)
        self.install_root.chmod(0o755)
        (self.install_root / "releases").chmod(0o755)
        (self.install_root / "current").symlink_to(
            f"releases/{predecessor_id}"
        )
        self.launcher.parent.mkdir(parents=True)
        launcher_bytes = (self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes()
        self.launcher.write_bytes(launcher_bytes)
        self.launcher.chmod(0o755)
        launcher_sha256 = MANAGER.sha256_bytes(launcher_bytes)
        events = []

        def candidate_floor(*_arguments, **keywords):
            events.append("candidate-floor")
            self.assertEqual(
                keywords["establishment_mode"],
                MANAGER.NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
            )
            self.assertEqual(
                keywords["predecessor_release_id"], predecessor_id,
            )

        def install(*_arguments, **_keywords):
            events.append("install")
            self.assertEqual(
                _keywords["_host_pair_bootstrap_mode"],
                MANAGER.NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE,
            )
            return {"schema": MANAGER.SCHEMA, "release_id": source_id}

        operation = MANAGER.bootstrap_authorization.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "verified_release",
                return_value=(predecessor, {
                    "payloads": {
                        name: "c" * 64
                        for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
                    },
                }),
            ) as verified,
            mock.patch.object(
                MANAGER, "establish_native_stack_coordination_floor",
            ),
            mock.patch.object(
                MANAGER, "establish_native_host_candidate_floor",
                side_effect=candidate_floor,
            ),
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=False,
            ),
            mock.patch.object(MANAGER, "install", side_effect=install),
        ):
            result = operation(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_id, launcher_sha256, launcher_sha256,
                candidate, MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                MANAGER.sha256_bytes(_values["authorization_ui_bundle"]),
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(
            events, ["candidate-floor", "candidate-floor", "install"],
        )
        self.assertEqual(result["status"], "authorization_bootstrapped")
        self.assertGreaterEqual(verified.call_count, 2)
        self.assertTrue(all(
            call.kwargs.get(
                "_bootstrap_without_candidate_admission_floor"
            ) is True
            for call in verified.call_args_list
        ))

    def test_native_stack_support_archive_is_deterministic_exact_and_syntax_checked(self):
        first = MANAGER.native_stack_support_archive(self.repo)
        second = MANAGER.native_stack_support_archive(self.repo)
        self.assertEqual(first, second)
        with zipfile.ZipFile(io.BytesIO(first), "r") as archive:
            self.assertEqual(archive.namelist(), sorted(MANAGER.NATIVE_STACK_SUPPORT_SOURCES))
            self.assertIn("shared/native_stack_session.py", archive.namelist())
            self.assertIn("shared/native_program_attestation.py", archive.namelist())
            self.assertIn(
                "shared/native_projection_identity_recovery.py",
                archive.namelist(),
            )
            for name in archive.namelist():
                self.assertEqual((archive.getinfo(name).external_attr >> 16) & 0o777, 0o444)
                self.assertEqual(
                    archive.read(name),
                    (self.repo / MANAGER.NATIVE_STACK_SUPPORT_SOURCES[name]).read_bytes(),
                )

        support_path = self.root / "native_stack_support.zip"
        support_path.write_bytes(first)
        imported = subprocess.run(
            [
                sys.executable, "-I", "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "import shared.native_projection_identity_recovery",
                str(support_path),
            ],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)

        operation_source = self.repo / MANAGER.NATIVE_STACK_SUPPORT_SOURCES[
            "shared/native_stack_operations.py"
        ]
        operation_source.write_bytes(operation_source.read_bytes() + b"# reviewed-change\n")
        self.assertNotEqual(first, MANAGER.native_stack_support_archive(self.repo))
        operation_source.write_bytes(b"def invalid(:\n")
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_stack_support_syntax_invalid"
        ):
            MANAGER.native_stack_support_archive(self.repo)

    def test_native_stack_payloads_are_installed_and_independently_read_back(self):
        with mock.patch.object(MANAGER, "validate_touchid_payload"):
            deployed = self.install()
            verified = MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        release = self.install_root / "releases" / deployed["release_id"]
        manifest = json.loads((release / "manifest.json").read_text())
        self.assertEqual(verified["release_id"], deployed["release_id"])
        for name, mode in {
            "native_stack_manager":0o755,
            "native_stack_session_manager":0o755,
            "native_stack_catalog_promoter":0o755,
            "native_stack_terminal_bridge":0o755,
            "native_stack_deployer":0o755,
            "native_stack_support":0o444,
            "native_deployment_payloads":0o444,
        }.items():
            path = release / name
            self.assertEqual(path.stat().st_mode & 0o777, mode)
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), manifest["payloads"][name]
            )
        release.chmod(0o755)
        support = release / "native_stack_support"
        with zipfile.ZipFile(support, "r") as archive:
            self.assertIn(
                "shared/native_projection_identity_recovery.py",
                archive.namelist(),
            )
        imported = subprocess.run(
            [
                sys.executable, "-I", "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "import shared.native_projection_identity_recovery",
                str(support),
            ],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        installed_loader = (
            "import importlib.machinery, importlib.util, sys; "
            "path=sys.argv[1]; name=sys.argv[2]; "
            "loader=importlib.machinery.SourceFileLoader(name,path); "
            "spec=importlib.util.spec_from_loader(name,loader); "
            "module=importlib.util.module_from_spec(spec); "
            "loader.exec_module(module); "
            "assert module"
        )
        for name in (
            "native_stack_session_manager", "native_stack_catalog_promoter",
            "native_stack_deployer",
        ):
            loaded = subprocess.run(
                [
                    sys.executable, "-I", "-c", installed_loader,
                    str(release / name), "installed_" + name,
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
        support.chmod(0o644)
        support.write_bytes(support.read_bytes() + b"tamper")
        support.chmod(0o444)
        release.chmod(0o555)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "payload_hash_mismatch"):
            MANAGER.verified_release(self.install_root, self.install_root / "current", self.uid)

    def test_native_credential_components_are_signed_content_bound_release_members(self):
        deployed = self.install()
        release = self.install_root / "releases" / deployed["release_id"]
        manifest = MANAGER.native_components_manifest(
            (release / "native_credential_helper_bundle").read_bytes()
        )
        self.assertEqual(
            (release / "native_stack_credential_client").stat().st_mode & 0o777,
            0o555,
        )
        self.assertEqual(
            (release / "native_projection_consumer").stat().st_mode & 0o777,
            0o555,
        )
        self.assertEqual(
            manifest["helper"]["bundle"],
            MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
        )
        MANAGER.verify_native_credential_helper_bundle(
            release / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
            (release / "native_credential_helper_bundle").read_bytes(),
            self.uid,
        )
        service = plistlib.loads(
            (release / "native_credential_helper_service").read_bytes()
        )
        self.assertEqual(
            service["ProgramArguments"],
            [MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE_PATH],
        )

    def test_native_credential_binary_drift_is_rejected_before_release_creation(self):
        backend = self.repo / MANAGER.PAYLOAD_SOURCES["native_stack_credential_client"]
        backend.chmod(0o755)
        backend.write_bytes(backend.read_bytes() + b"tamper")
        backend.chmod(0o555)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_component_payload_mismatch"
        ):
            MANAGER.source_payload(self.repo, self.op_binary, self.gpgv_binary)

    def test_source_payload_requires_v2_carrier_receipt(self):
        container_path = self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_host_products_container"
        ]
        receipt_path = self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ]
        container = container_path.read_bytes()
        receipt_path.write_text(
            json.dumps({
                "container_sha256": hashlib.sha256(container).hexdigest(),
                "container_size": len(container),
                "gatekeeper_assessed": True,
                "notary_log_sha256": "b" * 64,
                "notary_status": "accepted",
                "notary_submission_id":
                    "00000000-0000-4000-8000-000000000001",
                "schema": MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V1_SCHEMA,
                "stapler_validated": True,
                "team_id": MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
            }, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_products_notarization_below_v2",
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )

    def test_source_payload_rejects_split_artifact_directory_generation(self):
        artifact_root = self.repo / "artifacts/host"
        displaced = self.repo / "artifacts/host-displaced"
        original_snapshot = MANAGER._native_host_generation_snapshot
        switched = False

        def swap_after_first_generation_read(repo, generation):
            nonlocal switched
            result = original_snapshot(repo, generation)
            if not switched and generation == artifact_root:
                artifact_root.rename(displaced)
                shutil.copytree(displaced, artifact_root, copy_function=shutil.copy2)
                switched = True
            return result

        with mock.patch.object(
            MANAGER, "_native_host_generation_snapshot",
            side_effect=swap_after_first_generation_read,
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_generation_changed",
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )
        self.assertTrue(switched)

    def test_candidate_source_payload_binds_its_middle_snapshot_to_record(self):
        generation, candidate = self.native_host_candidate_binding()
        original = MANAGER._native_host_generation_snapshot
        calls = 0

        def transient(repo, observed_generation):
            nonlocal calls
            calls += 1
            identity, tree_sha256, captured = original(
                repo, observed_generation,
            )
            if calls == 2:
                tree_sha256 = "0" * 64
            return identity, tree_sha256, captured

        with (
            mock.patch.object(
                MANAGER, "_native_host_generation_snapshot",
                side_effect=transient,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_candidate_record_mismatch",
            ),
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
            )

    def test_mutable_source_read_rejects_transient_path_substitution(self):
        relative = MANAGER.PAYLOAD_SOURCES["seed_gateway"]
        source = self.repo / relative
        displaced = source.with_name(source.name + ".displaced")
        identity = MANAGER.mutable_source_input_identity(self.repo, relative)
        source.rename(displaced)
        source.write_bytes(b"transient substituted seed\n")
        source.chmod(0o600)
        try:
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "mutable_source_input_changed",
            ):
                MANAGER.read_mutable_source_input(
                    self.repo, relative, identity,
                )
        finally:
            source.unlink()
            displaced.rename(source)

    def test_build_inputs_and_root_trust_surfaces_reject_extended_acl(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        floor = self.root / "acl-execution-floor.json"
        floor.write_text(json.dumps({
            "schema": "secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol": 2,
            "minimum_epoch": 4,
            "updated_at": 2_000_000_000,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        floor.chmod(0o600)
        install_root = self.root / "acl-install-root"
        install_root.mkdir(mode=0o755)
        targets = (
            (
                self.repo / MANAGER.PAYLOAD_SOURCES["seed_gateway"],
                lambda: MANAGER.mutable_source_input_identity(
                    self.repo, MANAGER.PAYLOAD_SOURCES["seed_gateway"],
                ),
            ),
            (
                floor,
                lambda: MANAGER.execution_approval_floor(
                    self.uid, floor,
                ),
            ),
            (
                install_root,
                lambda: MANAGER.prepare_release_root(
                    install_root, self.uid,
                ),
            ),
        )
        for target, operation in targets:
            with self.subTest(target=target.name):
                added = subprocess.run(
                    ["/bin/chmod", "+a", "everyone allow write", str(target)],
                    check=False, capture_output=True, text=True,
                )
                if added.returncode != 0:
                    self.skipTest("extended ACL fixture unavailable")
                try:
                    with self.assertRaises(MANAGER.ReleaseFailure):
                        operation()
                finally:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(target)], check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

    def test_source_payload_never_reads_tracked_payload_from_mutable_checkout(self):
        tracked = self.repo / MANAGER.PAYLOAD_SOURCES["control_client"]
        expected = tracked.read_bytes()
        original_read = MANAGER.read_regular
        substituted = False

        def transient_substitute(path):
            nonlocal substituted
            if path == tracked:
                substituted = True
                return b"#!/usr/bin/python3\nraise SystemExit('substituted')\n"
            return original_read(path)

        with mock.patch.object(
            MANAGER, "read_regular", side_effect=transient_substitute,
        ):
            values, _hashes, _release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )
        self.assertFalse(substituted)
        self.assertEqual(values["control_client"], expected)

    def test_retained_candidate_record_is_closed_canonical_and_revalidated(self):
        generation, candidate = self.native_host_candidate_binding()
        encoded = json.dumps(
            candidate, sort_keys=True, separators=(",", ":"),
        )
        self.assertEqual(
            MANAGER.parse_native_host_candidate_json(encoded), candidate,
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_candidate_json_invalid",
        ):
            MANAGER.parse_native_host_candidate_json(
                json.dumps(candidate, indent=2, sort_keys=True)
            )
        values, hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        self.assertEqual(set(values), MANAGER.PAYLOAD_NAMES)
        self.assertEqual(release_id, MANAGER.release_identity(hashes))
        changed = dict(candidate)
        changed["generation_tree_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_candidate_record_mismatch",
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=generation,
                expected_native_host_candidate=changed,
            )

    def test_historical_v2_candidate_requires_exact_evidence_container(self):
        generation, _candidate = self.native_host_candidate_binding()
        receipt_path = generation / MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ].name
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt["schema"] = MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA
        receipt.pop("host_release_preimage_sha256")
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        (self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ]).write_bytes(receipt_path.read_bytes())
        self.generated_native_host_product_values[
            "native_host_products_notarization"
        ] = receipt_path.read_bytes()
        evidence = generation.parent / "evidence"
        (evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME).unlink()
        with mock.patch.object(
            MANAGER, "verify_native_host_products_container",
            return_value=None,
        ):
            classified = MANAGER.classify_native_host_retained_candidate(
                self.repo, generation,
            )
        self.assertEqual(
            classified["eligibility"],
            "historical-receipt-v2-ineligible",
        )
        extra = evidence / "unexpected"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        with (
            mock.patch.object(
                MANAGER, "verify_native_host_products_container",
                return_value=None,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_candidate_evidence_untrusted",
            ),
        ):
            MANAGER.classify_native_host_retained_candidate(
                self.repo, generation,
            )

    def test_retained_candidate_rejects_extended_acl(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        generation, _candidate = self.native_host_candidate_binding()
        target = generation / MANAGER.NATIVE_HOST_SOURCE_ARCHIVE_NAME
        added = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow write", str(target)],
            check=False, capture_output=True, text=True,
        )
        if added.returncode != 0:
            self.skipTest("extended ACL fixture unavailable")
        try:
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "extended_acl",
            ):
                MANAGER.native_host_candidate_record(
                    self.repo, generation,
                )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(target)], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    def test_installed_payload_and_public_floor_reject_extended_acl(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        self.install()
        release = (self.install_root / "current").resolve()
        for target in (
            release / "controller",
            self.install_root / MANAGER.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME,
            self.launcher,
        ):
            added = subprocess.run(
                ["/bin/chmod", "+a", "everyone allow write", str(target)],
                check=False, capture_output=True, text=True,
            )
            if added.returncode != 0:
                self.skipTest("extended ACL fixture unavailable")
            try:
                with self.assertRaises((
                    MANAGER.ReleaseFailure, LAUNCHER.LaunchFailure,
                )):
                    if target == self.launcher:
                        MANAGER.verify(
                            self.repo, self.install_root, self.launcher,
                            self.uid, self.op_binary, self.gpgv_binary,
                        )
                    else:
                        LAUNCHER.load_release(
                            self.install_root, self.uid,
                            launcher_path=self.launcher,
                        )
                with self.assertRaises(MANAGER.ReleaseFailure):
                    MANAGER.verify(
                        self.repo, self.install_root, self.launcher,
                        self.uid, self.op_binary, self.gpgv_binary,
                    )
            finally:
                subprocess.run(
                    ["/bin/chmod", "-N", str(target)], check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )

    def test_installed_bundles_and_coordination_records_reject_extended_acl(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        self.install()
        release = (self.install_root / "current").resolve()
        targets = (
            release / MANAGER.AUTHORIZATION_UI_APP_NAME
                / MANAGER.AUTHORIZATION_UI_EXECUTABLE,
            release / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME
                / MANAGER.NATIVE_CREDENTIAL_HELPER_EXECUTABLE,
            self.install_root
                / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME,
            self.install_root / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME,
        )
        for target in targets:
            with self.subTest(target=target.name):
                added = subprocess.run(
                    ["/bin/chmod", "+a", "everyone allow write", str(target)],
                    check=False, capture_output=True, text=True,
                )
                if added.returncode != 0:
                    self.skipTest("extended ACL fixture unavailable")
                try:
                    with self.assertRaises(MANAGER.ReleaseFailure):
                        MANAGER.verify(
                            self.repo, self.install_root, self.launcher,
                            self.uid, self.op_binary, self.gpgv_binary,
                        )
                    if target.name == (
                        MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
                    ):
                        with self.assertRaises(LAUNCHER.LaunchFailure):
                            LAUNCHER.load_release(
                                self.install_root, self.uid,
                            )
                finally:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(target)], check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

    def test_v3_candidate_rejects_extra_evidence_and_preimage_mode(self):
        generation, _candidate = self.native_host_candidate_binding()
        evidence = generation.parent / "evidence"
        extra = evidence / "unexpected"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_release_preimage_untrusted",
        ):
            MANAGER.native_host_candidate_record(self.repo, generation)
        extra.unlink()
        preimage = (
            evidence / MANAGER.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
        )
        preimage.chmod(0o600)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_host_release_preimage_untrusted",
        ):
            MANAGER.native_host_candidate_record(self.repo, generation)

    def test_candidate_tracked_source_rejects_transient_middle_snapshot(self):
        generation, candidate = self.native_host_candidate_binding()
        original = MANAGER._native_host_generation_snapshot
        calls = 0

        def transient(repo, observed_generation):
            nonlocal calls
            calls += 1
            identity, tree_sha256, captured = original(
                repo, observed_generation,
            )
            if calls == 2:
                tree_sha256 = "0" * 64
            return identity, tree_sha256, captured

        with (
            mock.patch.object(
                MANAGER, "_native_host_generation_snapshot",
                side_effect=transient,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_candidate_record_mismatch",
            ),
        ):
            MANAGER.native_host_candidate_tracked_source(
                self.repo, generation, candidate, MANAGER.LAUNCHER_SOURCE,
            )

    def test_native_credential_launch_agent_checkout_change_is_not_authority(self):
        generation, candidate = self.native_host_candidate_binding()
        values_before, _hashes, release_before = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        template = self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_credential_helper_service"
        ]
        template.write_bytes(
            template.read_bytes()
            + b"\n<!-- __SECURE_SANDBOX_NATIVE_CREDENTIAL_HELPER_EXECUTABLE__ -->\n"
        )
        values_after, _hashes, release_after = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        self.assertEqual(release_after, release_before)
        self.assertEqual(
            values_after["native_credential_helper_service"],
            values_before["native_credential_helper_service"],
        )

    def test_malformed_authorization_service_is_rejected(self):
        candidate = self.alternate_native_host_candidate({
            "authorization_service": b"not a property list\n",
        })
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "authorization_service_plist_invalid"
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=candidate[0],
                expected_native_host_candidate=candidate[1],
            )

    def test_native_credential_service_rejects_wrong_mach_service(self):
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        value = plistlib.loads(values["native_credential_helper_service"])
        value["MachServices"] = {"org.example.WrongService": True}
        candidate = self.alternate_native_host_candidate({
            "native_credential_helper_service": plistlib.dumps(value),
        })
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_credential_helper_service_invalid",
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=candidate[0],
                expected_native_host_candidate=candidate[1],
            )

    def test_execution_approval_floor_blocks_v1_release_rollback(self):
        floor = self.root / "minimum-floor.json"
        floor.write_text(json.dumps({
            "schema":"secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol":2, "minimum_epoch":4, "updated_at":100,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        floor.chmod(0o600)
        with mock.patch.object(MANAGER, "EXECUTION_APPROVAL_FLOOR", floor):
            MANAGER.enforce_execution_approval_floor(
                b"contains secure-sandbox-execution-approval-floor-enforcement-v2", self.uid
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_below_execution_approval_floor"
            ):
                MANAGER.enforce_execution_approval_floor(
                    b"has envelopes but not the monotonic floor gate: secure-sandbox-execution-approval-envelope-v2",
                    self.uid,
                )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_below_execution_approval_floor"
            ):
                MANAGER.enforce_execution_approval_floor(b"v1 only", self.uid)

    def test_install_rejects_source_drift_from_authorized_release_identity(self):
        self.install()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, expected = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"]
                + b"\n# changed after authorization\n",
        })
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "source_release_id_unexpected"):
            MANAGER.install(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                self.op_binary, self.gpgv_binary, expected,
                native_host_generation=candidate[0],
                expected_native_host_candidate=candidate[1],
            )

    def test_local_secure_enclave_config_is_bound_to_repo_owner_under_sudo(self):
        generation, candidate = self.native_host_candidate_binding()
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            _values, hashes, release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
            )
        self.assertEqual(release_id, MANAGER.release_identity(hashes))

    def test_capacity_recovery_archives_inactive_releases_without_deleting_history(self):
        # The exact typed first-pair fixture retains its real predecessor as
        # non-selectable evidence, so four on-disk releases represent the same
        # three candidate generations exercised by this capacity boundary.
        with mock.patch.object(MANAGER, "MAX_RELEASES", 4):
            first = self.install()["release_id"]
            generation, record = self.native_host_candidate_binding()
            values, _hashes, _release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=generation,
                expected_native_host_candidate=record,
            )
            for suffix in ("second", "third"):
                candidate = self.alternate_native_host_candidate({
                    "controller": values["controller"]
                        + f"\n# {suffix}\n".encode("ascii"),
                })
                latest = self.install(candidate)["release_id"]
            self.assertNotEqual(first, latest)
            # A power loss in the narrow chmod-before-rename window leaves an
            # inactive source writable only by root; recovery must resume.
            (self.install_root / "releases" / first).chmod(0o755)
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            predecessor_id = MANAGER.native_host_candidate_floor(
                self.install_root, self.uid,
            )[0]["established_from_predecessor_release_id"]
            self.assertEqual(
                plan["archive_release_ids"], sorted([predecessor_id, first])
            )
            with mock.patch.object(
                MANAGER, "enforce_execution_approval_floor",
                wraps=MANAGER.enforce_execution_approval_floor,
            ) as floor:
                result = MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"], plan["previous_release_id"],
                    plan["plan_sha256"],
                )
            # Current, rollback, and the coordination predecessor remain
            # activation-floor checked.  The inactive target is
            # integrity-verified but deliberately exempt because archival
            # makes it non-selectable.
            self.assertEqual(floor.call_count, 3)
            self.assertEqual(result["archived"], 2)
            self.assertFalse((self.install_root / "releases" / first).exists())
            self.assertTrue((self.install_root / "release-archive" / first).is_dir())
            self.assertFalse(
                (self.install_root / "releases" / predecessor_id).exists()
            )
            self.assertTrue(
                (self.install_root / "release-archive" / predecessor_id).is_dir()
            )
            self.assertEqual((self.install_root / "current").resolve().name,
                             plan["current_release_id"])
            self.assertEqual((self.install_root / "previous").resolve().name,
                             plan["previous_release_id"])
            fourth = self.alternate_native_host_candidate({
                "controller": values["controller"] + b"\n# fourth\n",
            })
            self.assertEqual(self.install(fourth)["status"], "deployed")

    def test_capacity_recovery_rejects_changed_plan_before_moving_releases(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 4):
            first = self.install()["release_id"]
            generation, record = self.native_host_candidate_binding()
            values, _hashes, _release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=generation,
                expected_native_host_candidate=record,
            )
            for suffix in ("second", "third"):
                candidate = self.alternate_native_host_candidate({
                    "controller": values["controller"]
                        + f"\n# {suffix}\n".encode("ascii"),
                })
                self.install(candidate)
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            with self.assertRaisesRegex(MANAGER.ReleaseFailure,
                                        "release_archive_plan_changed"):
                MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"], plan["previous_release_id"],
                    "0" * 64,
                )
            self.assertTrue((self.install_root / "releases" / first).is_dir())
            self.assertFalse((self.install_root / "release-archive").exists())

    def test_capacity_recovery_rejects_any_pending_install_transition(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 2):
            self.install()
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            before = sorted(
                path.name for path in (self.install_root / "releases").iterdir()
            )
            pending = (
                self.install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
            )
            pending.write_bytes(b"schema-agnostic pending transition\n")
            pending.chmod(0o600)

            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "release_capacity_recovery_transition_pending",
            ):
                MANAGER.release_archive_plan(self.install_root, self.uid)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "release_capacity_recovery_transition_pending",
            ):
                MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"],
                    plan["previous_release_id"] or "none",
                    plan["plan_sha256"],
                )

            self.assertEqual(
                sorted(
                    path.name
                    for path in (self.install_root / "releases").iterdir()
                ),
                before,
            )
            self.assertFalse((self.install_root / "release-archive").exists())

    def test_capacity_recovery_rejects_tampered_pre_floor_predecessor(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 2):
            self.install()
            floor = MANAGER.native_host_candidate_floor(
                self.install_root, self.uid,
            )[0]
            predecessor_id = floor[
                "established_from_predecessor_release_id"
            ]
            plan = MANAGER.release_archive_plan(
                self.install_root, self.uid,
            )
            self.assertEqual(
                plan["archive_release_ids"], [predecessor_id]
            )
            controller = (
                self.install_root / "releases" / predecessor_id / "controller"
            )
            controller.chmod(0o755)
            with controller.open("ab") as handle:
                handle.write(b"\n# tampered pre-floor evidence\n")
            controller.chmod(MANAGER.EXPECTED_MODES["controller"])
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_payload_hash_mismatch",
            ):
                MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"],
                    plan["previous_release_id"] or "none",
                    plan["plan_sha256"],
                )
            self.assertTrue(
                (self.install_root / "releases" / predecessor_id).is_dir()
            )

    def test_launcher_rejects_payload_tampering(self):
        self.install()
        controller = (self.install_root / "current").resolve() / "controller"
        controller.chmod(0o755)
        with controller.open("a", encoding="utf-8") as handle:
            handle.write("# tampered\n")
        controller.chmod(0o555)
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "payload_hash_mismatch"):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )

    def test_failed_syntax_check_does_not_change_current(self):
        original = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\nif then\n",
        })
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "controller_syntax_invalid"):
            self.install(candidate)
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_service_bootstrap_failure_restores_previous_current_release(self):
        original = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# second release\n",
        })
        service_evidence = {
            "authorization": {"pid": 100, "start_generation": [1, 1]},
            "native_credential": {"pid": 101, "start_generation": [1, 1]},
        }
        with (
            mock.patch.object(
                MANAGER, "manages_live_touchid_service", return_value=True,
            ),
            mock.patch.object(
                MANAGER, "install_touchid_service",
                side_effect=[
                    MANAGER.ReleaseFailure("service failed"), None, None,
                ],
            ) as install_touchid,
            mock.patch.object(
                MANAGER, "install_native_credential_service",
            ) as install_native_credential,
            mock.patch.object(
                MANAGER, "stop_and_fence_host_services",
            ) as stop_and_fence,
            mock.patch.object(
                MANAGER, "verify_release_host_services",
                return_value=service_evidence,
            ),
            mock.patch.object(
                MANAGER, "attest_pending_source_host_services",
                return_value=service_evidence,
            ),
        ):
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "service failed"
            ):
                self.install(candidate)
        self.assertEqual(install_touchid.call_count, 3)
        self.assertEqual(install_native_credential.call_count, 2)
        self.assertEqual(stop_and_fence.call_count, 2)
        self.assertEqual((self.install_root / "current").resolve().name, original)
        pair = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        self.assertEqual(pair[0]["schema"],
                         MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA)

    def test_pair_transition_installs_and_rolls_back_across_launcher_generations(self):
        first = self.install()["release_id"]
        first_launcher = self.launcher.read_bytes()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# pair generation two\n",
        })
        second_launcher = first_launcher + b"\n# pair generation two\n"
        original_tracked_source = MANAGER.native_host_candidate_tracked_source

        def tracked_source(repo, candidate_generation, candidate, relative):
            if (Path(candidate_generation) == second_candidate[0]
                    and Path(relative) == MANAGER.LAUNCHER_SOURCE):
                return second_launcher
            return original_tracked_source(
                repo, candidate_generation, candidate, relative,
            )

        with mock.patch.object(
            MANAGER, "native_host_candidate_tracked_source",
            side_effect=tracked_source,
        ):
            second = self.install(second_candidate)
        self.assertNotEqual(second["release_id"], first)
        self.assertEqual(self.launcher.read_bytes(), second_launcher)
        rolled_back = self.authorized_rollback(first)
        self.assertEqual(rolled_back["status"], "rolled_back")
        self.assertEqual((self.install_root / "current").resolve().name, first)
        self.assertEqual(self.launcher.read_bytes(), first_launcher)
        verified = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(verified["release_id"], first)

    def test_pair_transition_recovers_after_process_death_at_every_checkpoint(self):
        first_candidate = self.native_host_candidate_binding()
        first = self.install(first_candidate)["release_id"]
        first_launcher = self.launcher.read_bytes()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=first_candidate[0],
            expected_native_host_candidate=first_candidate[1],
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# crash matrix target\n",
        })
        second_launcher = first_launcher + b"\n# crash matrix launcher\n"
        original_tracked_source = MANAGER.native_host_candidate_tracked_source

        def tracked_source(repo, candidate_generation, candidate, relative):
            if (Path(candidate_generation) == second_candidate[0]
                    and Path(relative) == MANAGER.LAUNCHER_SOURCE):
                return second_launcher
            return original_tracked_source(
                repo, candidate_generation, candidate, relative,
            )

        checkpoints = (
            "PREPARED", "PUBLIC_PENDING", "SERVICES_FENCED",
            "LAUNCHER_SELECTED", "PREVIOUS_SELECTED", "RELEASE_SELECTED",
            "SERVICES_SELECTED", "FINALIZATION_STAGED",
            "TERMINAL_PUBLISHED", "STABLE_PUBLISHED",
        )
        current_id = first
        for index, checkpoint in enumerate(checkpoints):
            target = second_candidate if current_id == first else first_candidate
            target_id = (
                MANAGER.source_payload(
                    self.repo, self.op_binary, self.gpgv_binary,
                    native_host_generation=target[0],
                    expected_native_host_candidate=target[1],
                )[2]
            )
            with self.subTest(checkpoint=checkpoint):
                pid = os.fork()
                if pid == 0:
                    try:
                        def terminate(phase):
                            if phase == checkpoint:
                                os._exit(73)

                        with (
                            mock.patch.object(
                                MANAGER,
                                "native_host_candidate_tracked_source",
                                side_effect=tracked_source,
                            ),
                            mock.patch.object(
                                MANAGER, "host_pair_transition_checkpoint",
                                side_effect=terminate,
                            ),
                        ):
                            self.install(target)
                    except BaseException:
                        os._exit(74)
                    os._exit(75)
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status), 73)
                recovered = MANAGER.recover_host_pair_transition(
                    self.install_root, self.launcher, self.state, self.uid,
                )
                self.assertEqual(
                    recovered["status"], "host_pair_transition_recovered",
                )
                self.assertEqual(
                    (self.install_root / "current").resolve().name,
                    target_id,
                )
                current_id = target_id

    def test_pair_transition_recovers_process_death_during_source_restoration(self):
        first_candidate = self.native_host_candidate_binding()
        first = self.install(first_candidate)["release_id"]
        first_launcher = self.launcher.read_bytes()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=first_candidate[0],
            expected_native_host_candidate=first_candidate[1],
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"]
                + b"\n# restoration crash target\n",
        })
        second_launcher = first_launcher + b"\n# restoration crash launcher\n"
        original_tracked_source = MANAGER.native_host_candidate_tracked_source

        def tracked_source(repo, candidate_generation, candidate, relative):
            if (Path(candidate_generation) == second_candidate[0]
                    and Path(relative) == MANAGER.LAUNCHER_SOURCE):
                return second_launcher
            return original_tracked_source(
                repo, candidate_generation, candidate, relative,
            )

        current_id = first
        for restore_checkpoint in (
            "LAUNCHER_SELECTED", "PREVIOUS_SELECTED", "RELEASE_SELECTED",
            "SERVICES_SELECTED",
        ):
            target = second_candidate if current_id == first else first_candidate
            target_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
                native_host_generation=target[0],
                expected_native_host_candidate=target[1],
            )[2]
            with self.subTest(checkpoint=restore_checkpoint):
                pid = os.fork()
                if pid == 0:
                    try:
                        restoring = False

                        def fail_then_terminate(phase):
                            nonlocal restoring
                            if not restoring and phase == "SERVICES_SELECTED":
                                restoring = True
                                raise MANAGER.ReleaseFailure(
                                    "synthetic_target_failure"
                                )
                            if restoring and phase == restore_checkpoint:
                                os._exit(73)

                        with (
                            mock.patch.object(
                                MANAGER,
                                "native_host_candidate_tracked_source",
                                side_effect=tracked_source,
                            ),
                            mock.patch.object(
                                MANAGER, "host_pair_transition_checkpoint",
                                side_effect=fail_then_terminate,
                            ),
                        ):
                            self.install(target)
                    except BaseException:
                        os._exit(74)
                    os._exit(75)
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status), 73)
                recovered = MANAGER.recover_host_pair_transition(
                    self.install_root, self.launcher, self.state, self.uid,
                )
                self.assertEqual(recovered["release_id"], target_id)
                self.assertEqual(
                    (self.install_root / "current").resolve().name,
                    target_id,
                )
                current_id = target_id

    def test_pair_initial_journal_and_public_record_writes_are_crash_atomic(self):
        for crash_name in (
            MANAGER.INSTALL_TRANSITION_PENDING_NAME,
            MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME,
        ):
            with self.subTest(record=crash_name):
                # Each branch needs a fresh pair bootstrap.  Recreate the
                # fixture explicitly after the first completed branch.
                if os.path.lexists(self.install_root):
                    self.tearDown()
                    self.setUp()
                original_write = MANAGER.write_new_state_record_at
                pid = os.fork()
                if pid == 0:
                    try:
                        def crash_during_new_record(
                            directory, name, value, expected_uid, mode,
                        ):
                            if name != crash_name:
                                return original_write(
                                    directory, name, value, expected_uid, mode,
                                )
                            raw = MANAGER.canonical_state_record(dict(value))
                            temporary = f".{name}.new-crash-{os.getpid()}"
                            descriptor = os.open(
                                temporary,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | os.O_NOFOLLOW | os.O_CLOEXEC,
                                mode,
                                dir_fd=directory,
                            )
                            try:
                                os.write(descriptor, raw[:max(1, len(raw) // 2)])
                                os.fsync(descriptor)
                            finally:
                                os.close(descriptor)
                            os.fsync(directory)
                            os._exit(73)

                        with mock.patch.object(
                            MANAGER, "write_new_state_record_at",
                            side_effect=crash_during_new_record,
                        ):
                            self.install()
                    except BaseException:
                        os._exit(74)
                    os._exit(75)
                _waited, status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status), 73)
                final = self.install_root / crash_name
                self.assertFalse(final.exists())
                if crash_name == MANAGER.INSTALL_TRANSITION_PENDING_NAME:
                    deployed = self.install()
                    self.assertEqual(deployed["status"], "deployed")
                else:
                    recovered = MANAGER.recover_host_pair_transition(
                        self.install_root, self.launcher, self.state, self.uid,
                    )
                    self.assertEqual(
                        recovered["status"],
                        "host_pair_transition_recovered",
                    )

    def test_pair_public_replace_crash_preserves_source_and_replays(self):
        first = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# public replace crash\n",
        })
        original_replace = MANAGER.replace_state_record_at
        pid = os.fork()
        if pid == 0:
            try:
                def crash_during_replace(
                    directory, name, value, expected_uid, mode,
                ):
                    if name != MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME:
                        return original_replace(
                            directory, name, value, expected_uid, mode,
                        )
                    raw = MANAGER.canonical_state_record(dict(value))
                    temporary = f".{name}.new-crash-{os.getpid()}"
                    descriptor = os.open(
                        temporary,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC,
                        mode, dir_fd=directory,
                    )
                    try:
                        os.write(descriptor, raw)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.fsync(directory)
                    os._exit(73)

                with mock.patch.object(
                    MANAGER, "replace_state_record_at",
                    side_effect=crash_during_replace,
                ):
                    self.install(candidate)
            except BaseException:
                os._exit(74)
            os._exit(75)
        _waited, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 73)
        self.assertEqual((self.install_root / "current").resolve().name, first)
        recovered = MANAGER.recover_host_pair_transition(
            self.install_root, self.launcher, self.state, self.uid,
        )
        self.assertEqual(recovered["status"],
                         "host_pair_transition_recovered")

    def test_pair_recovery_repairs_release_target_launcher_source_prefix(self):
        first = self.install()["release_id"]
        first_launcher = self.launcher.read_bytes()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# forbidden prefix\n",
        })
        target_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=candidate[0],
            expected_native_host_candidate=candidate[1],
        )[2]
        target_launcher = first_launcher + b"\n# mixed prefix target\n"
        original_tracked_source = MANAGER.native_host_candidate_tracked_source
        pid = os.fork()
        if pid == 0:
            try:
                def tracked_source(
                    repo, candidate_generation, candidate_record, relative,
                ):
                    if (Path(candidate_generation) == candidate[0]
                            and Path(relative) == MANAGER.LAUNCHER_SOURCE):
                        return target_launcher
                    return original_tracked_source(
                        repo, candidate_generation, candidate_record, relative,
                    )

                def terminate(phase):
                    if phase == "PUBLIC_PENDING":
                        os._exit(73)

                with (
                    mock.patch.object(
                        MANAGER, "native_host_candidate_tracked_source",
                        side_effect=tracked_source,
                    ),
                    mock.patch.object(
                        MANAGER, "host_pair_transition_checkpoint",
                        side_effect=terminate,
                    ),
                ):
                    self.install(candidate)
            except BaseException:
                os._exit(74)
            os._exit(75)
        _waited, status = os.waitpid(pid, 0)
        self.assertEqual(os.WEXITSTATUS(status), 73)
        self.assertEqual((self.install_root / "current").resolve().name, first)
        MANAGER.atomic_symlink(
            f"releases/{target_id}", self.install_root / "current",
        )
        recovered = MANAGER.recover_host_pair_transition(
            self.install_root, self.launcher, self.state, self.uid,
        )
        self.assertEqual(recovered["release_id"], target_id)
        self.assertEqual(self.launcher.read_bytes(), target_launcher)

    def test_pair_pending_without_private_journal_and_missing_terminal_deny(self):
        first = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# pending mismatch\n",
        })
        second = self.install(second_candidate)["release_id"]
        self.authorized_rollback(first)
        stable, stable_sha256 = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        target_authority = MANAGER.native_host_candidate_authority(
            self.install_root, second, self.uid,
        )
        pending = MANAGER.host_release_launcher_pair_pending_record(
            operation="install", transition_id=str(uuid.uuid4()),
            transition_sha256="a" * 64,
            prior_stable_sha256=stable_sha256,
            source_pair=stable["pair"],
            target_pair=MANAGER.host_release_launcher_pair_generation(
                target_authority
            ),
        )
        MANAGER.publish_host_release_launcher_pair_record(
            self.install_root, self.uid, pending,
            expected_previous_sha256=stable_sha256,
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "host_release_launcher_pair_(pending|transition_active)",
        ):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure, "controller_pair_transition_active",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_pair_transition_missing",
        ):
            MANAGER.recover_host_pair_transition(
                self.install_root, self.launcher, self.state, self.uid,
            )

    def test_missing_pair_floor_blocks_install_rollback_and_migrate(self):
        first_candidate = self.native_host_candidate_binding()
        first = self.install(first_candidate)["release_id"]
        generation, record = first_candidate
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# missing pair floor\n",
        })
        second = self.install(second_candidate)["release_id"]
        self.assertNotEqual(first, second)
        pair_path = (
            self.install_root / MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
        )
        pair_path.unlink()
        MANAGER.fsync_directory(self.install_root)
        current_before = os.readlink(self.install_root / "current")
        previous_before = os.readlink(self.install_root / "previous")
        launcher_before = self.launcher.read_bytes()
        releases_before = sorted(
            path.name for path in (self.install_root / "releases").iterdir()
        )
        receipts_before = sorted(self.authorization_receipts.iterdir())

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_release_launcher_pair_missing",
        ):
            MANAGER.install(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, self.op_binary, self.gpgv_binary, first,
                native_host_generation=generation,
                expected_native_host_candidate=record,
            )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_release_launcher_pair_missing",
        ):
            MANAGER.rollback(
                self.repo, self.install_root, self.state, first, self.uid,
                self.op_binary, self.gpgv_binary,
                launcher_path=self.launcher,
            )
        installed_sha256 = hashlib.sha256(launcher_before).hexdigest()
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_release_launcher_pair_missing",
        ):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, installed_sha256, "f" * 64,
            )

        self.assertEqual(os.readlink(self.install_root / "current"),
                         current_before)
        self.assertEqual(os.readlink(self.install_root / "previous"),
                         previous_before)
        self.assertEqual(self.launcher.read_bytes(), launcher_before)
        self.assertEqual(sorted(
            path.name for path in (self.install_root / "releases").iterdir()
        ), releases_before)
        self.assertEqual(sorted(self.authorization_receipts.iterdir()),
                         receipts_before)
        self.assertFalse(os.path.lexists(
            self.install_root / MANAGER.INSTALL_TRANSITION_PENDING_NAME
        ))

    def test_pair_stable_requires_exact_immutable_terminal(self):
        self.install()
        stable, _sha256 = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        transition_id = stable["committed_transition_id"]
        self.assertIsNotNone(transition_id)
        terminal = (
            self.install_root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
            / f"{transition_id}.json"
        )
        terminal.unlink()
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_pair_terminal_untrusted",
        ):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_(pair_terminal|coordination_record_unavailable)",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )

    def test_pair_terminal_rejects_missing_or_tampered_service_evidence(self):
        self.install()
        stable, _sha256 = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        terminal_path = (
            self.install_root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
            / f"{stable['committed_transition_id']}.json"
        )
        terminal = json.loads(terminal_path.read_text(encoding="ascii"))
        missing = dict(terminal)
        missing.pop("service_evidence")
        missing["terminal_sha256"] = MANAGER.host_pair_terminal_digest(
            missing
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_pair_terminal_invalid",
        ):
            MANAGER.validate_public_host_pair_terminal(missing)
        tampered = json.loads(json.dumps(terminal))
        tampered["service_evidence"]["current_target"] = "releases/" + "f" * 64
        tampered["service_evidence_sha256"] = hashlib.sha256(
            MANAGER.canonical_state_record(tampered["service_evidence"])
        ).hexdigest()
        tampered["terminal_sha256"] = MANAGER.host_pair_terminal_digest(
            tampered
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_pair_service_evidence_invalid",
        ):
            MANAGER.validate_public_host_pair_terminal(tampered)

    def test_completed_pair_receipt_cannot_be_rebound_to_another_plan(self):
        self.install()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        second_candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# receipt binding\n",
        })
        self.install(second_candidate)
        stable, _sha256 = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        terminal_path = (
            self.install_root / MANAGER.INSTALL_TRANSITION_DIRECTORY_NAME
            / f"{stable['committed_transition_id']}.json"
        )
        terminal = json.loads(terminal_path.read_text(encoding="ascii"))
        request_id = terminal["authorization_request_id"]
        receipt_path = self.authorization_receipts / f"{request_id}.json"
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt["host_pair_authorized_target_plan_sha256"] = "f" * 64
        receipt_path.write_bytes(MANAGER.canonical_state_record(receipt))
        transition = {
            "authorization_pending_receipt_sha256": "0" * 64,
            "authorization_request_id": request_id,
            "authorization_request_sha256": terminal[
                "authorization_request_sha256"
            ],
            "authorized_target_plan_sha256": terminal[
                "authorized_target_plan_sha256"
            ],
            "bootstrap": False,
            "operation": terminal["operation"],
            "transition_id": terminal["transition_id"],
            "transition_sha256": terminal["transition_sha256"],
        }
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_pair_transition_receipt_invalid",
        ):
            MANAGER.complete_host_pair_authorization_receipt(
                transition, status=terminal["status"],
                committed_pair=terminal["committed_pair"],
                service_evidence_sha256=terminal[
                    "service_evidence_sha256"
                ],
                finalization_sha256=terminal["finalization_sha256"],
                completed_at=terminal["completed_at"],
                expected_uid=self.uid,
            )

    def test_completed_receipt_crash_replays_durable_target_finalization(self):
        self.install()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# receipt crash\n",
        })
        target_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=candidate[0],
            expected_native_host_candidate=candidate[1],
        )[2]
        original_complete = MANAGER.complete_host_pair_authorization_receipt

        def complete_then_fail(*args, **kwargs):
            original_complete(*args, **kwargs)
            raise MANAGER.ReleaseFailure("synthetic_receipt_readback_failure")

        with (
            mock.patch.object(
                MANAGER, "complete_host_pair_authorization_receipt",
                side_effect=complete_then_fail,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "synthetic_receipt_readback_failure",
            ),
        ):
            self.install(candidate)
        public = MANAGER.host_release_launcher_pair_public(
            self.install_root, self.uid,
        )
        self.assertEqual(
            public[0]["schema"],
            MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
        )
        recovered = MANAGER.recover_host_pair_transition(
            self.install_root, self.launcher, self.state, self.uid,
        )
        self.assertEqual(recovered["release_id"], target_id)

    def test_release_tree_ctime_detects_removed_acl_and_stale_writer(self):
        retained_writer = None
        retained_byte = None
        original_publish = MANAGER.publish_native_host_candidate_authority

        def publish_with_writer(*args, **kwargs):
            nonlocal retained_writer, retained_byte
            release = (
                self.install_root / "releases" / kwargs["release_id"]
                / "controller"
            )
            retained_byte = release.read_bytes()[:1]
            retained_writer = os.open(release, os.O_WRONLY)
            return original_publish(*args, **kwargs)

        with mock.patch.object(
            MANAGER, "publish_native_host_candidate_authority",
            side_effect=publish_with_writer,
        ):
            self.install()
        self.assertIsNotNone(retained_writer)
        controller = (self.install_root / "current").resolve() / "controller"
        try:
            self.assertIsNotNone(retained_byte)
            os.pwrite(retained_writer, retained_byte, 0)
            os.fsync(retained_writer)
        finally:
            os.close(retained_writer)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_candidate_authority_tree_mismatch",
        ):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_pair_tree_identity_mismatch",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )

        if sys.platform != "darwin":
            return
        # Reinstall in a clean fixture is unnecessary for the stale writer
        # assertion above; ctime behavior itself is independently proven on a
        # root-owned release payload and must be irreversible across ACL
        # removal.
        probe = self.root / "acl-ctime-probe"
        probe.write_bytes(b"probe\n")
        before = probe.stat().st_ctime_ns
        subprocess.run(
            ["/bin/chmod", "+a", "everyone allow write", str(probe)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["/bin/chmod", "-N", str(probe)],
            check=True, capture_output=True, text=True,
        )
        self.assertNotEqual(probe.stat().st_ctime_ns, before)

    def test_release_tree_allows_only_exact_runtime_app_directory_ctime_drift(self):
        self.install()
        release = (self.install_root / "current").resolve()
        actual, actual_sha256 = (
            MANAGER.installed_native_host_release_tree_identity(
                release, self.uid,
            )
        )
        for relative in (
            MANAGER.AUTHORIZATION_UI_APP_NAME,
            MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
        ):
            changed = json.loads(json.dumps(actual))
            changed[relative]["ctime_ns"] += 1
            with mock.patch.object(
                MANAGER, "installed_native_host_release_tree_identity",
                return_value=(changed, actual_sha256),
            ):
                MANAGER.verify(
                    self.repo, self.install_root, self.launcher, self.uid,
                    self.op_binary, self.gpgv_binary,
                )
            with mock.patch.object(
                LAUNCHER, "_snapshot_release_tree", return_value=changed,
            ):
                loaded, release_id = LAUNCHER.load_release(
                    self.install_root, self.uid,
                    launcher_path=self.launcher,
                )
            self.assertEqual(loaded, release)
            self.assertEqual(release_id, release.name)

        changed = json.loads(json.dumps(actual))
        changed[
            MANAGER.AUTHORIZATION_UI_APP_NAME + "/Contents"
        ]["ctime_ns"] += 1
        with (
            mock.patch.object(
                MANAGER, "installed_native_host_release_tree_identity",
                return_value=(changed, actual_sha256),
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "native_host_candidate_authority_tree_mismatch",
            ),
        ):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        with (
            mock.patch.object(
                LAUNCHER, "_snapshot_release_tree", return_value=changed,
            ),
            self.assertRaisesRegex(
                LAUNCHER.LaunchFailure,
                "controller_pair_tree_identity_mismatch",
            ),
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid,
                launcher_path=self.launcher,
            )

    def test_release_tree_identity_rejects_acl_add_then_remove(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin ACL ctime contract")
        self.install()
        controller = (self.install_root / "current").resolve() / "controller"
        before = controller.stat().st_ctime_ns
        try:
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow write", str(controller)],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["/bin/chmod", "-N", str(controller)],
                check=True, capture_output=True, text=True,
            )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(controller)],
                check=False, capture_output=True, text=True,
            )
        self.assertNotEqual(controller.stat().st_ctime_ns, before)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_host_candidate_authority_tree_mismatch",
        ):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        with self.assertRaisesRegex(
            LAUNCHER.LaunchFailure,
            "controller_pair_tree_identity_mismatch",
        ):
            LAUNCHER.load_release(
                self.install_root, self.uid, launcher_path=self.launcher,
            )

    def test_loaded_old_launcher_census_failure_restores_exact_source_pair(self):
        original = self.install()["release_id"]
        original_launcher = self.launcher.read_bytes()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# queued old launcher\n",
        })
        next_launcher = original_launcher + b"\n# queued old launcher\n"
        original_tracked_source = MANAGER.native_host_candidate_tracked_source

        def tracked_source(repo, candidate_generation, candidate_record, relative):
            if (Path(candidate_generation) == candidate[0]
                    and Path(relative) == MANAGER.LAUNCHER_SOURCE):
                return next_launcher
            return original_tracked_source(
                repo, candidate_generation, candidate_record, relative,
            )

        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                side_effect=tracked_source,
            ),
            mock.patch.object(
                MANAGER, "ensure_no_d8653cb_release_processes",
                side_effect=[
                    MANAGER.ReleaseFailure("old_launcher_process_present"),
                    None,
                ],
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "old_launcher_process_present",
            ),
        ):
            self.install(candidate)
        self.assertEqual((self.install_root / "current").resolve().name,
                         original)
        self.assertEqual(self.launcher.read_bytes(), original_launcher)
        MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )

    def test_live_loaded_old_launcher_process_keeps_transition_fenced(self):
        self.install()
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# live old process\n",
        })
        process = subprocess.Popen(
            [
                sys.executable, "-c", "import time; time.sleep(60)",
                str(self.launcher),
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with (
                mock.patch.object(
                    MANAGER, "process_ids", return_value=(process.pid,),
                ),
                mock.patch.object(
                    MANAGER, "ensure_no_d8653cb_release_processes",
                    side_effect=self.real_release_process_census,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_pair_transition_recovery_unproven",
                ),
            ):
                self.install(candidate)
            public = MANAGER.host_release_launcher_pair_public(
                self.install_root, self.uid,
            )
            self.assertEqual(
                public[0]["schema"],
                MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
            )
        finally:
            process.terminate()
            process.wait(timeout=10)
        with mock.patch.object(
            MANAGER, "process_ids", return_value=(process.pid,),
        ), mock.patch.object(
            MANAGER, "ensure_no_d8653cb_release_processes",
            side_effect=self.real_release_process_census,
        ):
            recovered = MANAGER.recover_host_pair_transition(
                self.install_root, self.launcher, self.state, self.uid,
            )
        self.assertEqual(recovered["status"],
                         "host_pair_transition_recovered")

    def test_touchid_service_plist_is_atomically_installed_with_root_style_mode(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "authorization_service"
        source.write_bytes((REPO / MANAGER.PAYLOAD_SOURCES["authorization_service"]).read_bytes())
        plist = self.root / "LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
        plist.parent.mkdir()
        absent = subprocess.CompletedProcess([], 113, "", "")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(
                MANAGER.subprocess, "run", side_effect=[absent, completed],
            ) as run,
            mock.patch.object(
                MANAGER, "bootstrap_touchid_service_exact", return_value=71,
            ) as bootstrap,
        ):
            MANAGER.install_touchid_service(release, plist)
        self.assertEqual(plist.read_bytes(), source.read_bytes())
        self.assertEqual(plist.stat().st_mode & 0o777, 0o644)
        self.assertEqual(run.call_args_list[-1].args[0][0:3],
                         ["/bin/launchctl", "bootout",
                          "system/org.zebeth.securesandbox.authorization"])
        bootstrap.assert_called_once_with(plist)

    def test_touchid_bootstrap_retries_only_after_stable_absence(self):
        failed = subprocess.CompletedProcess(
            [], 5, "", "Bootstrap failed: 5: Input/output error",
        )
        completed = subprocess.CompletedProcess([], 0, "", "")
        absent = ("absent", None)
        running = ("running", 71)
        with (
            mock.patch.object(
                MANAGER, "launchd_service_state",
                side_effect=[
                    absent, absent, absent, absent,
                    running, running,
                ],
            ) as state,
            mock.patch.object(
                MANAGER.subprocess, "run",
                side_effect=[failed, completed],
            ) as run,
            mock.patch.object(MANAGER.time, "sleep") as sleep,
        ):
            pid = MANAGER.bootstrap_touchid_service_exact(
                Path("/Library/LaunchDaemons/test.plist"),
            )
        self.assertEqual(pid, 71)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(state.call_count, 6)
        self.assertEqual(sleep.call_count, 2)

    def test_touchid_bootstrap_nonzero_registered_outcome_fails_closed(self):
        failed = subprocess.CompletedProcess(
            [], 5, "", "Bootstrap failed: 5: Input/output error",
        )
        with (
            mock.patch.object(
                MANAGER, "launchd_service_state",
                side_effect=[
                    ("absent", None), ("absent", None),
                    ("scheduled", None),
                ],
            ),
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=failed,
            ) as run,
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_service_bootstrap_outcome_unproven",
            ),
        ):
            MANAGER.bootstrap_touchid_service_exact(
                Path("/Library/LaunchDaemons/test.plist"),
            )
        self.assertEqual(run.call_count, 1)

    def test_touchid_bootstrap_success_requires_registered_job(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(
                MANAGER, "launchd_service_state",
                side_effect=[
                    ("absent", None), ("absent", None),
                    ("absent", None),
                ],
            ),
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=completed,
            ) as run,
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_service_bootstrap_outcome_unproven",
            ),
        ):
            MANAGER.bootstrap_touchid_service_exact(
                Path("/Library/LaunchDaemons/test.plist"),
            )
        self.assertEqual(run.call_count, 1)

    def test_touchid_bootstrap_waits_for_exact_running_generation(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(
                MANAGER, "launchd_service_state",
                side_effect=[
                    ("absent", None), ("absent", None),
                    ("scheduled", None),
                    ("running", 72), ("running", 72),
                ],
            ),
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=completed,
            ) as run,
            mock.patch.object(MANAGER.time, "sleep") as sleep,
        ):
            pid = MANAGER.bootstrap_touchid_service_exact(
                Path("/Library/LaunchDaemons/test.plist"),
            )
        self.assertEqual(pid, 72)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleep.call_count, 2)

    def test_touchid_bootstrap_waits_out_unproven_cleanup_snapshot(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        unproven = MANAGER.ReleaseFailure(
            "host_service_state_unproven:"
            + MANAGER.AUTHORIZATION_LABEL
        )
        with (
            mock.patch.object(
                MANAGER, "launchd_service_state",
                side_effect=[
                    unproven, ("absent", None), ("absent", None),
                    ("running", 73), ("running", 73),
                ],
            ),
            mock.patch.object(
                MANAGER.subprocess, "run", return_value=completed,
            ) as run,
            mock.patch.object(MANAGER.time, "sleep") as sleep,
        ):
            pid = MANAGER.bootstrap_touchid_service_exact(
                Path("/Library/LaunchDaemons/test.plist"),
            )
        self.assertEqual(pid, 73)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleep.call_count, 2)

    def test_touchid_service_update_does_not_kill_authorizing_broker(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "authorization_service"
        source.write_bytes((REPO / MANAGER.PAYLOAD_SOURCES["authorization_service"]).read_bytes())
        plist = self.root / "LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
        plist.parent.mkdir()
        loaded = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(MANAGER.subprocess, "run", return_value=loaded) as run:
            MANAGER.install_touchid_service(release, plist)
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(run.call_args_list[0].args[0][0:3],
                         ["/bin/launchctl", "print", "system/org.zebeth.securesandbox.authorization"])

    def test_terminal_bootstrap_restart_reexecs_loaded_touchid_service(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            MANAGER.subprocess, "run", side_effect=[completed, completed]
        ) as run:
            MANAGER.restart_touchid_service()
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "/bin/launchctl", "kickstart", "-k",
                "system/org.zebeth.securesandbox.authorization",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0][0:3],
            ["/bin/launchctl", "print", "system/org.zebeth.securesandbox.authorization"],
        )

    def test_terminal_bootstrap_restart_fails_closed(self):
        failed = subprocess.CompletedProcess([], 5, "", "kickstart denied")
        with mock.patch.object(MANAGER.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "authorization_service_restart_failed"
            ):
                MANAGER.restart_touchid_service()

    def test_exact_successor_recovery_retries_failed_service_restart(self):
        release_id = "a" * 64
        current = self.root / "releases" / release_id
        verified = {
            "schema":MANAGER.SCHEMA,
            "status":"verified",
            "release_id":release_id,
        }
        with (mock.patch.object(MANAGER, "verify", return_value=verified) as verify,
              mock.patch.object(MANAGER, "manages_live_touchid_service", return_value=True),
              mock.patch.object(
                  MANAGER, "restart_touchid_service",
                  side_effect=[MANAGER.ReleaseFailure("restart failed"), None],
              ) as restart):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "restart failed"):
                MANAGER.recover_terminal_schema_service(
                    self.repo, current, self.install_root, self.launcher, 0,
                    release_id, self.op_binary, self.gpgv_binary,
                )
            recovered = MANAGER.recover_terminal_schema_service(
                self.repo, current, self.install_root, self.launcher, 0,
                release_id, self.op_binary, self.gpgv_binary,
            )
        self.assertTrue(recovered["recovered_existing_release"])
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(verify.call_count, 2)

        with mock.patch.object(MANAGER, "verify") as verify_mismatch:
            self.assertIsNone(MANAGER.recover_terminal_schema_service(
                self.repo, self.root / "releases" / ("b" * 64),
                self.install_root, self.launcher, 0, release_id,
                self.op_binary, self.gpgv_binary,
            ))
        verify_mismatch.assert_not_called()

    def test_touchid_binary_tampering_invalidates_source_release(self):
        binary = (self.repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE
                  / MANAGER.AUTHORIZATION_UI_EXECUTABLE)
        binary.chmod(0o755)
        with binary.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "authorization_ui_bundle_member_invalid"):
            MANAGER.source_payload(self.repo, self.op_binary, self.gpgv_binary)

    def test_deploy_refuses_live_marker_and_prunes_stale_marker(self):
        self.install()
        active = self.state / "active"
        active.mkdir(parents=True)
        active.chmod(0o700)
        live = active / "live.json"
        live.write_text(json.dumps({"pid": os.getpid(), "release_id": "a" * 64}), encoding="ascii")
        live.chmod(0o600)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_controller_invocations"):
            self.install()
        live.write_text(json.dumps({"pid": 2147483647, "release_id": "a" * 64}), encoding="ascii")
        self.install()
        self.assertFalse(live.exists())

    def test_second_release_can_roll_back(self):
        first = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        candidate = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# second release\n",
        })
        second = self.install(candidate)["release_id"]
        self.assertNotEqual(first, second)
        result = self.authorized_rollback()
        self.assertEqual(result["release_id"], first)
        self.assertTrue(result["repo_match"])
        self.assertEqual((self.install_root / "previous").resolve().name, second)

    def test_first_v1_install_is_rejected_below_coordination_floor(self):
        values, hashes, _ = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        legacy_hashes = {
            name: hashes[name]
            for name in MANAGER.PRE_CONTROL_PAYLOAD_NAMES
            if name in hashes
        }
        legacy_hashes["op_agents"] = hashlib.sha256(b"legacy bridge\n").hexdigest()
        legacy_id = MANAGER.release_identity(legacy_hashes)
        release = self.install_root / "releases" / legacy_id
        release.mkdir(parents=True)
        for name, digest in legacy_hashes.items():
            data = b"legacy bridge\n" if name == "op_agents" else values[name]
            path = release / name
            path.write_bytes(data)
            path.chmod(MANAGER.EXPECTED_MODES[name])
        manifest = {"schema": MANAGER.SCHEMA, "release_id": legacy_id, "payloads": legacy_hashes}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")
        loaded_path, loaded_id = LAUNCHER.load_release(
            self.install_root, self.uid, launcher_path=self.launcher,
        )
        self.assertEqual((loaded_path.name, loaded_id), (legacy_id, legacy_id))
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            self.install()
        self.assertEqual((self.install_root / "current").resolve().name,
                         legacy_id)
        self.assertFalse((self.install_root / "previous").exists())

    def test_migration_rejects_unrecognized_near_legacy_payload_set(self):
        values, hashes, _ = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        legacy_hashes = {
            name: hashes[name]
            for name in MANAGER.PRE_CONTROL_PAYLOAD_NAMES
            if name in hashes
        }
        legacy_hashes["op_agents"] = hashlib.sha256(b"legacy bridge\n").hexdigest()
        legacy_hashes["unexpected"] = hashlib.sha256(b"unexpected\n").hexdigest()
        legacy_id = MANAGER.release_identity(legacy_hashes)
        release = self.install_root / "releases" / legacy_id
        release.mkdir(parents=True)
        for name in legacy_hashes:
            data = (
                b"legacy bridge\n" if name == "op_agents"
                else b"unexpected\n" if name == "unexpected"
                else values[name]
            )
            path = release / name
            path.write_bytes(data)
            path.chmod(MANAGER.EXPECTED_MODES.get(name, 0o444))
        manifest = {"schema": MANAGER.SCHEMA, "release_id": legacy_id, "payloads": legacy_hashes}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "release_manifest_payloads_invalid"):
            self.install()

    def test_mutable_checkout_launcher_change_cannot_request_migration(self):
        deployed = self.install()
        installed_launcher = self.launcher.read_bytes()
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# incompatible launcher change\n")
        repeated = self.install()
        self.assertEqual(repeated["release_id"], deployed["release_id"])
        self.assertEqual(self.launcher.read_bytes(), installed_launcher)

    def test_launcher_migration_is_old_hash_gated_and_backed_up(self):
        self.install()
        generation, candidate = self.native_host_candidate_binding()
        _values, _hashes, source_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        old_bytes = self.launcher.read_bytes()
        old_hash = MANAGER.sha256_bytes(old_bytes)
        replacement = old_bytes + b"\n# reviewed retained migration\n"
        replacement_hash = MANAGER.sha256_bytes(replacement)
        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                return_value=replacement,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "stable_launcher_pair_transition_required",
            ),
        ):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, old_hash, replacement_hash,
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
                expected_source_release_id=source_id,
                op_binary=self.op_binary, gpgv_binary=self.gpgv_binary,
            )
        self.assertEqual(self.launcher.read_bytes(), old_bytes)

    def test_authorization_bootstrap_is_blocked_below_candidate_floor(self):
        old_release = self.install()["release_id"]
        generation, candidate = self.native_host_candidate_binding()
        old_launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        _values, _hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        replacement_sha256 = old_launcher_sha256
        current_manifest = json.loads(
            ((self.install_root / "current").resolve() / "manifest.json").read_text()
        )
        current_manifest["payloads"] = {
            name: digest for name, digest in current_manifest["payloads"].items()
            if name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        legacy_id = MANAGER.release_identity(current_manifest["payloads"])
        legacy = self.install_root / "releases" / legacy_id
        if not legacy.exists():
            legacy.mkdir()
            for name in current_manifest["payloads"]:
                shutil.copyfile(
                    self.install_root / "releases" / old_release / name,
                    legacy / name,
                )
                (legacy / name).chmod(MANAGER.EXPECTED_MODES[name])
            current_manifest["release_id"] = legacy_id
            (legacy / "manifest.json").write_text(
                json.dumps(current_manifest), encoding="utf-8",
            )
            (legacy / "manifest.json").chmod(0o444)
            legacy.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")
        (self.install_root / MANAGER.NATIVE_STACK_COORDINATION_FLOOR_NAME).unlink()
        (
            self.install_root
            / MANAGER.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
        ).unlink()

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_host_candidate_floor",
        ):
            MANAGER.bootstrap_authorization(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, release_id, old_launcher_sha256,
                replacement_sha256, candidate,
                MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                MANAGER.sha256_bytes(_values["authorization_ui_bundle"]),
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(
            MANAGER.sha256_bytes(self.launcher.read_bytes()),
            old_launcher_sha256,
        )
        self.assertEqual((self.install_root / "current").resolve().name,
                         legacy_id)

    def test_maintenance_schema_bootstrap_is_blocked_below_floor(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_payloads = {
            name: source_manifest["payloads"][name]
            for name in MANAGER.PRE_MAINTENANCE_PAYLOAD_NAMES
        }
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release, "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.bootstrap_maintenance_schema(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual((self.install_root / "current").resolve().name,
                         old_release)

    def test_touchid_schema_bootstrap_is_blocked_below_floor(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_payloads = {
            name: source_manifest["payloads"][name]
            for name in MANAGER.PRE_TOUCHID_PAYLOAD_NAMES
        }
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release, "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.bootstrap_touchid_schema(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual((self.install_root / "current").resolve().name,
                         old_release)

    @unittest.skip("superseded by the deployed Secure Enclave source-schema bootstrap")
    def test_secure_enclave_schema_bootstrap_is_exactly_current_and_one_time(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        installed_sources = json.loads(
            (source_path / "authorization_ui_sources").read_text(encoding="utf-8")
        )
        old_sources = {
            "schema": installed_sources["schema"],
            "sources": {
                name: digest for name, digest in installed_sources["sources"].items()
                if name in MANAGER.PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES
            },
        }
        old_sources_bytes = json.dumps(
            old_sources, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        old_payloads = dict(source_manifest["payloads"])
        old_payloads["authorization_ui_sources"] = MANAGER.sha256_bytes(old_sources_bytes)
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            if name == "authorization_ui_sources":
                (old_path / name).write_bytes(old_sources_bytes)
            else:
                shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_secure_enclave_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )

    def test_profiled_touchid_schema_bootstrap_is_blocked_below_floor(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        binary = (source_path / MANAGER.AUTHORIZATION_UI_APP_NAME
                  / MANAGER.AUTHORIZATION_UI_EXECUTABLE).read_bytes()
        old_payloads = {
            name:digest for name, digest in source_manifest["payloads"].items()
            if name in MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES
        }
        old_payloads.pop("authorization_ui_bundle")
        old_payloads["authorization_ui"] = MANAGER.sha256_bytes(binary)
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            if name == "authorization_ui":
                (old_path / name).write_bytes(binary)
            else:
                shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.bootstrap_profiled_touchid_schema(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_release, old_release,
                launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual((self.install_root / "current").resolve().name, old_release)

    def test_touchid_bundle_v1_is_rejected_below_native_signing_floor(self):
        bundle_path = self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_bundle"]
        bundle_v2 = json.loads(bundle_path.read_text(encoding="utf-8"))
        self.assertEqual(bundle_v2["schema"], "secure-sandbox-touchid-ui-bundle-v2")
        bundle_v1 = {
            "bundle":bundle_v2["bundle"],
            "files":bundle_v2["files"],
            "schema":"secure-sandbox-touchid-ui-bundle-v1",
        }
        bundle_path.write_text(
            json.dumps(bundle_v1, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "native_component_signer_mismatch"
        ):
            MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )

    def test_model_profile_schema_bootstrap_is_blocked_below_floor(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_payloads = {
            name:digest for name, digest in source_manifest["payloads"].items()
            if name in MANAGER.PRE_MODEL_PROFILE_PAYLOAD_NAMES
        }
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.bootstrap_model_profile_schema(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_release, old_release,
                launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual((self.install_root / "current").resolve().name,
                         old_release)

    def test_native_stack_schema_bootstrap_is_blocked_below_floor(self):
        with mock.patch.object(MANAGER, "validate_touchid_payload"):
            source_release = self.install()["release_id"]
            source_path = self.install_root / "releases" / source_release
            source_manifest = json.loads((source_path / "manifest.json").read_text())
            old_payloads = {
                name:digest for name, digest in source_manifest["payloads"].items()
                if name in MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES
            }
            self.assertEqual(set(old_payloads), MANAGER.PRE_NATIVE_STACK_PAYLOAD_NAMES)
            old_release = MANAGER.release_identity(old_payloads)
            old_path = self.install_root / "releases" / old_release
            old_path.mkdir()
            for name in old_payloads:
                shutil.copyfile(source_path / name, old_path / name)
                (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
            shutil.copytree(
                source_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                old_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                copy_function=shutil.copy2,
            )
            (old_path / "manifest.json").write_text(json.dumps({
                "schema":MANAGER.SCHEMA,
                "release_id":old_release,
                "payloads":old_payloads,
            }), encoding="utf-8")
            (old_path / "manifest.json").chmod(0o444)
            old_path.chmod(0o555)
            (self.install_root / "current").unlink()
            (self.install_root / "current").symlink_to(f"releases/{old_release}")
            with self.assertRaisesRegex(
                LAUNCHER.LaunchFailure,
                "controller_release_below_coordination_floor",
            ):
                LAUNCHER.load_release(
                    self.install_root, self.uid,
                )
            self.assertEqual((self.install_root / "current").resolve().name,
                             old_release)

    def test_native_deployment_schema_bootstrap_is_blocked_below_floor(self):
        with mock.patch.object(MANAGER, "validate_touchid_payload"):
            source_release = self.install()["release_id"]
            source_path = self.install_root / "releases" / source_release
            source_manifest = json.loads(
                (source_path / "manifest.json").read_text()
            )
            old_payloads = {
                name: digest
                for name, digest in source_manifest["payloads"].items()
                if name in MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES
            }
            self.assertEqual(
                set(old_payloads),
                MANAGER.PRE_NATIVE_DEPLOYMENT_PAYLOAD_NAMES,
            )
            old_release = MANAGER.release_identity(old_payloads)
            old_path = self.install_root / "releases" / old_release
            old_path.mkdir()
            for name in old_payloads:
                shutil.copyfile(source_path / name, old_path / name)
                (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
            for bundle_name in (
                MANAGER.AUTHORIZATION_UI_APP_NAME,
                MANAGER.NATIVE_CREDENTIAL_HELPER_APP_NAME,
            ):
                shutil.copytree(
                    source_path / bundle_name, old_path / bundle_name,
                    copy_function=shutil.copy2,
                )
            (old_path / "manifest.json").write_text(json.dumps({
                "schema": MANAGER.SCHEMA,
                "release_id": old_release,
                "payloads": old_payloads,
            }), encoding="utf-8")
            (old_path / "manifest.json").chmod(0o444)
            old_path.chmod(0o555)
            (self.install_root / "current").unlink()
            (self.install_root / "current").symlink_to(
                f"releases/{old_release}"
            )
            with self.assertRaisesRegex(
                LAUNCHER.LaunchFailure,
                "controller_release_below_coordination_floor",
            ):
                LAUNCHER.load_release(
                    self.install_root, self.uid,
                )
            self.assertEqual((self.install_root / "current").resolve().name,
                             old_release)

    def test_authorization_icon_schema_bootstrap_is_blocked_below_floor(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_sources = {
            name: MANAGER.sha256_bytes(
                (self.repo / "macos/TouchIDAuthorization" / name).read_bytes()
            )
            for name in MANAGER.PRE_AUTHORIZATION_ICON_TOUCHID_SOURCE_NAMES
        }
        old_source_bytes = (
            json.dumps({
                "schema":"secure-sandbox-touchid-ui-source-v1",
                "sources":old_sources,
            }, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        old_payloads = dict(source_manifest["payloads"])
        old_payloads["authorization_ui_sources"] = MANAGER.sha256_bytes(old_source_bytes)
        old_payloads.pop("native_stack_coordination_contract")
        old_payloads.pop("native_host_products_notarization_signature")
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            if name == "authorization_ui_sources":
                (old_path / name).write_bytes(old_source_bytes)
            else:
                shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        shutil.copytree(
            source_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
            old_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
            copy_function=shutil.copy2,
        )
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "release_below_native_stack_coordination_floor",
        ):
            MANAGER.bootstrap_authorization_icon_schema(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, source_release, old_release,
                launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual((self.install_root / "current").resolve().name,
                         old_release)

    def test_private_floor_broker_recovery_stages_without_selecting(self):
        installed = self.install()
        current_id = installed["release_id"]
        current_path = self.install_root / "releases" / current_id
        current_broker = (current_path / "authorization_broker").read_bytes()
        fixed_broker = current_broker + b"\n# private-floor path ACL fix\n"
        self.assertIn(b"def reject_path_extended_acl(", fixed_broker)
        self.assertNotIn(b"getattr(os, \"O_EVTONLY\"", fixed_broker)
        generation, candidate = self.alternate_native_host_candidate({
            "authorization_broker": fixed_broker,
        })
        _values, _hashes, target_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        current_target = os.readlink(self.install_root / "current")
        previous_target = (
            os.readlink(self.install_root / "previous")
            if (self.install_root / "previous").is_symlink() else None
        )
        pair_path = (
            self.install_root / MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_NAME
        )
        pair_before = pair_path.read_bytes()
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with mock.patch.object(
            MANAGER, "BROKEN_PRIVATE_FLOOR_BROKER_RELEASE_ID", current_id,
        ), mock.patch.object(
            MANAGER, "BROKEN_PRIVATE_FLOOR_BROKER_SHA256",
            MANAGER.sha256_bytes(current_broker),
        ):
            result = MANAGER.stage_private_floor_broker_recovery(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, target_id, current_id, launcher_sha256,
                launcher_sha256, candidate, self.op_binary,
                self.gpgv_binary,
            )
        self.assertEqual(
            result["status"], "private_floor_broker_recovery_staged",
        )
        self.assertEqual(result["release_id"], target_id)
        self.assertEqual(
            result["authorization_broker_sha256"],
            MANAGER.sha256_bytes(fixed_broker),
        )
        self.assertEqual(
            os.readlink(self.install_root / "current"), current_target,
        )
        self.assertEqual(
            os.readlink(self.install_root / "previous")
            if (self.install_root / "previous").is_symlink() else None,
            previous_target,
        )
        self.assertEqual(pair_path.read_bytes(), pair_before)
        self.assertTrue((self.install_root / "releases" / target_id).is_dir())
        authority = MANAGER.native_host_candidate_authority(
            self.install_root, target_id, self.uid,
        )
        self.assertEqual(authority["release_id"], target_id)

    def test_operator_ceremony_broker_recovery_cannot_bypass_candidate_authority(self):
        predecessor = self.install()["release_id"]
        current = (self.install_root / "current").resolve()
        predecessor_broker = MANAGER.sha256_bytes(
            (current / "authorization_broker").read_bytes()
        )
        original_release = MANAGER.BROKEN_CEREMONY_BROKER_RELEASE_ID
        original_broker = MANAGER.BROKEN_CEREMONY_BROKER_SHA256
        self.addCleanup(
            setattr, MANAGER, "BROKEN_CEREMONY_BROKER_RELEASE_ID", original_release
        )
        self.addCleanup(
            setattr, MANAGER, "BROKEN_CEREMONY_BROKER_SHA256", original_broker
        )
        MANAGER.BROKEN_CEREMONY_BROKER_RELEASE_ID = predecessor
        MANAGER.BROKEN_CEREMONY_BROKER_SHA256 = predecessor_broker
        broker_path = self.repo / MANAGER.PAYLOAD_SOURCES["authorization_broker"]
        broker_path.write_bytes(broker_path.read_bytes() + b"\n# bounded recovery\n")
        successor = "f" * 64
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "operator_ceremony_broker_recovery_predecessor_invalid",
        ):
            MANAGER.recover_operator_ceremony_broker(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                successor, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "operator_ceremony_broker_recovery_source_invalid",
        ):
            MANAGER.recover_operator_ceremony_broker(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                successor, predecessor, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(
            (self.install_root / "current").resolve().name, predecessor,
        )
    @unittest.skip("superseded by the provisioned app-bundle schema bootstrap")
    def test_touchid_ui_recovery_accepts_only_known_vulnerable_source_once(self):
        original_recovery_main_sha256 = MANAGER.RECOVERED_TOUCHID_MAIN_SOURCE_SHA256
        original_recovery_ui_sha256 = MANAGER.RECOVERED_TOUCHID_UI_SHA256
        original_recovery_sources_sha256 = MANAGER.RECOVERED_TOUCHID_SOURCES_SHA256
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_MAIN_SOURCE_SHA256",
            original_recovery_main_sha256,
        )
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_UI_SHA256",
            original_recovery_ui_sha256,
        )
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_SOURCES_SHA256",
            original_recovery_sources_sha256,
        )
        # Standard deployments legitimately rebuild and re-sign the UI. This
        # isolated recovery test pins the exact signed fixture copied into its
        # temporary repository, just as the live one-time recovery pinned its
        # independently reviewed artifact.
        MANAGER.RECOVERED_TOUCHID_UI_SHA256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui"]).read_bytes()
        )
        MANAGER.RECOVERED_TOUCHID_SOURCES_SHA256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_sources"]).read_bytes()
        )
        current_sources = json.loads(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_sources"]).read_text(
                encoding="utf-8"
            )
        )
        MANAGER.RECOVERED_TOUCHID_MAIN_SOURCE_SHA256 = current_sources["sources"][
            "Sources/SecureSandboxAuthorizationUI/main.swift"
        ]
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        manifest_path = source_path / "manifest.json"
        sources_path = source_path / "authorization_ui_sources"
        source_path.chmod(0o755)
        manifest_path.chmod(0o644)
        sources_path.chmod(0o644)
        sources = json.loads(sources_path.read_text(encoding="utf-8"))
        sources["sources"]["Sources/SecureSandboxAuthorizationUI/main.swift"] = next(
            iter(MANAGER.VULNERABLE_TOUCHID_MAIN_SOURCE_SHA256)
        )
        vulnerable_bytes = (json.dumps(sources, indent=2, sort_keys=True) + "\n").encode()
        sources_path.write_bytes(vulnerable_bytes)
        sources_path.chmod(0o444)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["payloads"]["authorization_ui_sources"] = hashlib.sha256(
            vulnerable_bytes
        ).hexdigest()
        vulnerable_release = MANAGER.release_identity(manifest["payloads"])
        manifest["release_id"] = vulnerable_release
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        manifest_path.chmod(0o444)
        vulnerable_path = source_path.with_name(vulnerable_release)
        source_path.rename(vulnerable_path)
        vulnerable_path.chmod(0o555)
        current = self.install_root / "current"
        current.unlink()
        current.symlink_to(f"releases/{vulnerable_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        recovery_values, recovery_hashes, recovery_release = (
            MANAGER.touchid_ui_recovery_payload(
                self.repo, self.install_root, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        )

        result = MANAGER.recover_touchid_ui(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            recovery_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_ui_recovered")
        self.assertEqual(result["previous_release_id"], vulnerable_release)
        recovered_manifest = json.loads(
            ((self.install_root / "current").resolve() / "manifest.json").read_text()
        )
        self.assertEqual(recovered_manifest["payloads"], recovery_hashes)
        self.assertEqual(
            {name: digest for name, digest in recovered_manifest["payloads"].items()
             if name not in {"authorization_ui", "authorization_ui_sources"}},
            {name: digest for name, digest in manifest["payloads"].items()
             if name not in {"authorization_ui", "authorization_ui_sources"}},
        )
        self.assertEqual(
            recovery_values["authorization_ui"],
            (self.install_root / "current" / "authorization_ui").read_bytes(),
        )
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "touchid_ui_recovery_not_required"):
            MANAGER.recover_touchid_ui(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                recovery_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )

    def test_launcher_migration_rejects_unexpected_replacement_hash(self):
        self.install()
        generation, candidate = self.native_host_candidate_binding()
        _values, _hashes, source_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        old_hash = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "stable_launcher_pair_transition_required",
        ):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                old_hash, "0" * 64,
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
                expected_source_release_id=source_id,
                op_binary=self.op_binary, gpgv_binary=self.gpgv_binary,
            )

    def test_candidate_floor_rejects_mutable_checkout_launcher_migration(self):
        self.install()
        old_hash = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open(
            "ab",
        ) as handle:
            handle.write(b"\n# mutable checkout replacement\n")
        replacement_hash = MANAGER.sha256_bytes(
            (self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes()
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "stable_launcher_pair_transition_required",
        ):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, old_hash, replacement_hash,
            )
        self.assertEqual(
            MANAGER.sha256_bytes(self.launcher.read_bytes()), old_hash,
        )

    def test_candidate_bound_launcher_migration_uses_archive_bytes(self):
        self.install()
        receipt = json.loads((
            self.repo / MANAGER.PAYLOAD_SOURCES[
                "native_host_products_notarization"
            ]
        ).read_text(encoding="ascii"))
        generation = (
            self.repo / ".private/native-host-product-candidates"
            / (receipt["release_commit"] + "-"
               + receipt["notary_submission_id"])
            / "generation"
        ).resolve()
        candidate = MANAGER.native_host_candidate_record(
            self.repo, generation,
        )
        _values, _hashes, source_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        original = self.launcher.read_bytes()
        archive_launcher = original + b"\n# exact retained candidate\n"
        mutable_launcher = original + b"\n# transient mutable checkout\n"
        (self.repo / MANAGER.LAUNCHER_SOURCE).write_bytes(mutable_launcher)
        old_hash = MANAGER.sha256_bytes(original)
        replacement_hash = MANAGER.sha256_bytes(archive_launcher)
        with (
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                return_value=archive_launcher,
            ),
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "stable_launcher_pair_transition_required",
            ),
        ):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, old_hash, replacement_hash,
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
                expected_source_release_id=source_id,
                op_binary=self.op_binary, gpgv_binary=self.gpgv_binary,
            )
        self.assertEqual(self.launcher.read_bytes(), original)

    def test_launcher_parent_and_backup_authority_reject_acls_but_allow_xattrs(self):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        self.install()
        launcher_bytes = self.launcher.read_bytes()
        launcher_sha256 = hashlib.sha256(launcher_bytes).hexdigest()
        subprocess.run(
            [
                "/usr/bin/xattr", "-w",
                "com.zebeth.securesandbox.test", "launcher",
                str(self.launcher),
            ],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(
            MANAGER.read_trusted_stable_launcher(self.launcher, self.uid),
            launcher_bytes,
        )

        backup_root = self.install_root / "launcher-backups"
        backup_root.chmod(0o755)
        backup = backup_root / launcher_sha256
        if not backup.exists():
            backup.write_bytes(launcher_bytes)
        backup.chmod(0o755)
        subprocess.run(
            [
                "/usr/bin/xattr", "-w",
                "com.zebeth.securesandbox.test", "backup", str(backup),
            ],
            check=True, capture_output=True, text=True,
        )
        backup.chmod(0o555)
        backup_root.chmod(0o555)
        MANAGER.verify_launcher_migration_backup(
            self.install_root, self.uid, launcher_sha256,
        )

        cases = (
            (
                self.launcher.parent, "everyone allow write",
                lambda: MANAGER.read_trusted_stable_launcher(
                    self.launcher, self.uid,
                ),
            ),
            (
                self.launcher, "everyone deny read",
                lambda: MANAGER.read_trusted_stable_launcher(
                    self.launcher, self.uid,
                ),
            ),
            (
                backup_root, "everyone allow write",
                lambda: MANAGER.verify_launcher_migration_backup(
                    self.install_root, self.uid, launcher_sha256,
                ),
            ),
            (
                backup, "everyone deny read",
                lambda: MANAGER.verify_launcher_migration_backup(
                    self.install_root, self.uid, launcher_sha256,
                ),
            ),
        )
        for target, rule, operation in cases:
            with self.subTest(target=target.name, rule=rule):
                added = subprocess.run(
                    ["/bin/chmod", "+a", rule, str(target)],
                    check=False, capture_output=True, text=True,
                )
                if added.returncode != 0:
                    self.skipTest("extended ACL fixture unavailable")
                try:
                    with self.assertRaises(MANAGER.ReleaseFailure):
                        operation()
                finally:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(target)], check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

    def test_candidate_bound_install_and_verify_ignore_checkout_launcher(self):
        deployed = self.install()
        receipt = json.loads((
            self.repo / MANAGER.PAYLOAD_SOURCES[
                "native_host_products_notarization"
            ]
        ).read_text(encoding="ascii"))
        generation = (
            self.repo / ".private/native-host-product-candidates"
            / (receipt["release_commit"] + "-"
               + receipt["notary_submission_id"])
            / "generation"
        ).resolve()
        candidate = MANAGER.native_host_candidate_record(
            self.repo, generation,
        )
        launcher = self.launcher.read_bytes()
        (self.repo / MANAGER.LAUNCHER_SOURCE).write_bytes(
            launcher + b"\n# mutable checkout substitution\n"
        )
        with mock.patch.object(
            MANAGER, "native_host_candidate_tracked_source",
            return_value=launcher,
        ):
            result = MANAGER.install(
                self.repo, self.install_root, self.launcher, self.state,
                self.uid, self.op_binary, self.gpgv_binary,
                deployed["release_id"],
                native_host_generation=generation,
                expected_native_host_candidate=candidate,
            )
        self.assertEqual(result["release_id"], deployed["release_id"])
        self.assertEqual(self.launcher.read_bytes(), launcher)

    def test_bare_verify_uses_only_public_candidate_authority(self):
        deployed = self.install()
        candidate_root = Path(
            MANAGER.native_host_candidate_authority(
                self.install_root, deployed["release_id"], self.uid,
            )["candidate_record"]["generation_path"]
        ).parent
        candidate_root.chmod(0o000)
        try:
            with (
                mock.patch.object(
                    MANAGER.os, "geteuid", return_value=self.uid + 1,
                ),
                mock.patch.object(
                    MANAGER, "developer_id_team_floor",
                    side_effect=AssertionError("private developer floor read"),
                ),
                mock.patch.object(
                    MANAGER, "native_host_candidate_floor",
                    side_effect=AssertionError("private candidate floor read"),
                ),
                mock.patch.object(
                    MANAGER, "native_host_candidate_record",
                    side_effect=AssertionError("private candidate reopened"),
                ),
                mock.patch.object(
                    MANAGER, "source_payload",
                    side_effect=AssertionError("private preimage reopened"),
                ),
                mock.patch.object(
                    MANAGER, "native_host_candidate_tracked_source",
                    side_effect=AssertionError("private source reopened"),
                ),
            ):
                verified = MANAGER.verify(
                    self.repo, self.install_root, self.launcher, self.uid,
                    self.op_binary, self.gpgv_binary,
                )
        finally:
            candidate_root.chmod(0o700)
        self.assertEqual(verified["release_id"], deployed["release_id"])
        enforcement = MANAGER.developer_id_team_enforcement(
            self.install_root, self.uid,
        )
        self.assertIsNotNone(enforcement)
        assert enforcement is not None
        self.assertEqual(
            verified["developer_id_team_floor_sha256"],
            enforcement[0]["authoritative_floor_sha256"],
        )
    def test_rollback_status_survives_unavailable_repository(self):
        first = self.install()["release_id"]
        generation, record = self.native_host_candidate_binding()
        values, _hashes, _release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=record,
        )
        second = self.alternate_native_host_candidate({
            "controller": values["controller"] + b"\n# second release\n",
        })
        self.install(second)
        (self.repo / "scripts/pki-host-anchor.py").unlink()
        result = self.authorized_rollback(first)
        self.assertEqual(result["status"], "rolled_back")
        self.assertTrue(result["repo_match"])

    def test_restrictive_umask_cannot_change_installed_modes(self):
        previous = os.umask(0o077)
        try:
            self.install()
        finally:
            os.umask(previous)
        release = (self.install_root / "current").resolve()
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "authorization_broker").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "controller").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "control_client").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "gpgv").stat().st_mode & 0o777, 0o555)
        self.assertEqual((release / "installer_verifier").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "pki_anchor").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "release_manager").stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.install_root / "current").lstat().st_mode & 0o777, 0o755)
        for name in ("seed_gateway", "seed_research", "seed_target"):
            self.assertEqual((release / name).stat().st_mode & 0o777, 0o444)
        self.assertEqual((release / "ssh_config").stat().st_mode & 0o777, 0o444)

    def test_candidate_publishers_recover_owner_masked_staging(self):
        generation, candidate = self.native_host_candidate_binding()
        _values, hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
            native_host_generation=generation,
            expected_native_host_candidate=candidate,
        )
        self.install()

        developer_floor = MANAGER.developer_id_team_floor(
            self.install_root, self.uid,
        )
        (self.install_root / MANAGER.DEVELOPER_ID_TEAM_ENFORCEMENT_NAME).unlink()

        def crash_developer(name):
            if name == "developer-id-enforcement-staging-opened":
                raise MANAGER.ReleaseFailure("simulated-stage-crash")

        previous = os.umask(0o377)
        try:
            with (
                mock.patch.object(
                    MANAGER, "developer_id_team_enforcement_checkpoint",
                    side_effect=crash_developer,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "simulated-stage-crash",
                ),
            ):
                MANAGER.establish_developer_id_team_enforcement(
                    self.install_root, self.uid,
                    developer_floor[0], developer_floor[1],
                )
        finally:
            os.umask(previous)
        MANAGER.establish_developer_id_team_enforcement(
            self.install_root, self.uid,
            developer_floor[0], developer_floor[1],
        )

        for name in (
            MANAGER.NATIVE_HOST_CANDIDATE_FLOOR_NAME,
            MANAGER.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME,
        ):
            (self.install_root / name).unlink()

        def crash_candidate(name):
            if name == "candidate-enforcement-staging-opened":
                raise MANAGER.ReleaseFailure("simulated-stage-crash")

        floor_arguments = {
            "release_id": release_id,
            "candidate_record": candidate,
            "establishment_mode": (
                MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
            ),
            "predecessor_release_id": (
                MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
        }
        previous = os.umask(0o377)
        try:
            with (
                mock.patch.object(
                    MANAGER, "native_host_candidate_bootstrap_checkpoint",
                    side_effect=crash_candidate,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "simulated-stage-crash",
                ),
            ):
                MANAGER.establish_native_host_candidate_floor(
                    self.install_root, self.uid, **floor_arguments,
                )
        finally:
            os.umask(previous)
        MANAGER.establish_native_host_candidate_floor(
            self.install_root, self.uid, **floor_arguments,
        )

        authority = (
            self.install_root / MANAGER.NATIVE_HOST_CANDIDATE_AUTHORITY_DIRECTORY
            / f"{release_id}.json"
        )
        authority.unlink()

        def crash_authority(name):
            if name == "authority-staging-opened":
                raise MANAGER.ReleaseFailure("simulated-stage-crash")

        authority_arguments = {
            "release_id": release_id,
            "payloads": hashes,
            "candidate_record": candidate,
            "launcher_sha256": MANAGER.sha256_bytes(
                (self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes()
            ),
        }
        previous = os.umask(0o377)
        try:
            with (
                mock.patch.object(
                    MANAGER, "native_host_candidate_authority_checkpoint",
                    side_effect=crash_authority,
                ),
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure, "simulated-stage-crash",
                ),
            ):
                MANAGER.publish_native_host_candidate_authority(
                    self.install_root, self.uid, **authority_arguments,
                )
        finally:
            os.umask(previous)
        MANAGER.publish_native_host_candidate_authority(
            self.install_root, self.uid, **authority_arguments,
        )
        self.assertEqual(stat.S_IMODE(authority.stat().st_mode), 0o444)

    def test_current_release_excludes_the_1password_bridge(self):
        self.install()
        release = (self.install_root / "current").resolve()
        self.assertFalse((release / "op_agents").exists())
        self.op_binary.write_bytes(b"changed-op\n")
        MANAGER.verify(self.repo, self.install_root, self.launcher, self.uid,
                       self.op_binary, self.gpgv_binary)

    def test_incomplete_old_lock_is_atomically_reclaimed(self):
        self.state.mkdir(parents=True)
        lock = self.state / "coordination.lock"
        lock.mkdir()
        old = time.time() - LAUNCHER.LOCK_INCOMPLETE_GRACE_SECONDS - 1
        os.utime(lock, (old, old))
        acquired = LAUNCHER.acquire_lock(self.state, timeout=0.2)
        self.assertEqual(acquired, lock)
        LAUNCHER.release_lock(acquired)
        self.assertFalse(lock.exists())

    def test_recent_incomplete_lock_fails_closed(self):
        self.state.mkdir(parents=True)
        (self.state / "coordination.lock").mkdir()
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "coordination_lock_timeout"):
            LAUNCHER.acquire_lock(self.state, timeout=0.05)


class ControllerBehaviorTests(unittest.TestCase):
    RUN_ID = "12345678-1234-4123-8123-123456789abc"
    LEASE_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    @staticmethod
    def harness_binding():
        return make_harness_binding(
            harness_id="claude-code", generation_id="d" * 64,
            manifest_sha256="e" * 64, executable_sha256="f" * 64,
            inventory_sha256="1" * 64, adapter_id="claude-core-v1",
            adapter_sha256="2" * 64,
        )

    @staticmethod
    def session_policy(source_id=None):
        return {
            "schema": "secure-sandbox-session-policy-runtime-v1",
            "source_id": source_id,
            "source_manifest_sha256": "6" * 64 if source_id is not None else None,
            "persona_sha256": "7" * 64,
            "tool_catalog_sha256": "8" * 64,
            "extension_set_sha256": "9" * 64,
        }

    @classmethod
    def runtime_authority(cls, session_id=None, source_id=None, profile_sha256=None):
        policy = cls.session_policy(source_id)
        context = make_session_context_binding(
            session_id=session_id or cls.RUN_ID,
            source_id=policy["source_id"],
            source_manifest_sha256=policy["source_manifest_sha256"],
            persona_sha256=policy["persona_sha256"],
            tool_catalog_sha256=policy["tool_catalog_sha256"],
            extension_set_sha256=policy["extension_set_sha256"],
        )
        brokered = make_brokered_binding(
            adapter="anthropic-messages-v1", model="abliterated-model-large-v2",
            profile_id="abliterated-glm", profile_sha256=profile_sha256 or "c" * 64,
            provider_mode="mock", vendor_id="abliteration",
        )
        stack = make_model_stack_binding("brokered-model-profile", brokered)
        return make_runtime_authority(
            model_stack_binding=stack,
            session_context_binding=context,
            harness_binding=cls.harness_binding(),
        )

    @classmethod
    def gateway_lease(cls, session_id=None, source_id=None, **changes):
        lease = {
            "schema": "secure-sandbox-run-lease-v3",
            "run_id": cls.RUN_ID,
            "lease_id": cls.LEASE_ID,
            "profile": "standard",
            "issued_at": 2000000000,
            "expires_at": 2000000600,
            "maximum_expires_at": 2000003600,
            "runtime_authority": cls.runtime_authority(session_id, source_id),
            "brokered_transport": {
                "schema": "secure-sandbox-brokered-run-transport-v1",
                "relay_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
            },
            "limits": {
                "max_requests": 10, "max_input_tokens": 1000,
                "max_output_tokens": 1000, "max_cost_microusd": 1000,
            },
            "pricing": {
                "input_microusd_per_million_tokens": 1,
                "output_microusd_per_million_tokens": 1,
            },
            "renewals": 0,
        }
        return {**lease, **changes}

    @classmethod
    def gateway_summary(cls, lease=None, reason="completed"):
        lease = lease or cls.gateway_lease()
        return {
            "schema": "secure-sandbox-run-lease-summary-v2",
            "lease": lease,
            "final_counters": cls.gateway_counter(lease),
            "finalized_at": 2000000000,
            "reason": reason,
        }

    @staticmethod
    def gateway_counter(lease):
        return {
            "schema": "secure-sandbox-run-lease-counter-v1",
            "run_id": lease["run_id"], "lease_id": lease["lease_id"],
            "requests": 0, "input_tokens": 0, "output_tokens": 0,
            "cost_microusd": 0, "reservations": {},
            "settled_reservations": [], "updated_at": 2000000000,
        }

    @classmethod
    def gateway_active_status(cls, lease=None):
        lease = lease or cls.gateway_lease()
        return {"lease": lease, "counters": cls.gateway_counter(lease), "summary": None}

    @classmethod
    def research_lease(cls, lease=None):
        lease = lease or cls.gateway_lease()
        digest = hashlib.sha256(
            (json.dumps(lease, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        ).hexdigest()
        return {
            "schema": "secure-sandbox-research-run-lease-v3",
            "run_id": lease["run_id"], "lease_id": lease["lease_id"],
            "expires_at": lease["expires_at"],
            "maximum_expires_at": lease["maximum_expires_at"],
            "runtime_authority": lease["runtime_authority"],
            "gateway_lease": lease, "gateway_lease_sha256": digest,
        }

    @classmethod
    def watchdog_status(cls, lease=None, phase="active"):
        lease = lease or cls.gateway_lease()
        authority = lease["runtime_authority"]
        gateway_digest = hashlib.sha256(
            (json.dumps(lease, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        ).hexdigest()
        return {
            "schema": "secure-sandbox-run-lifecycle-v3", "phase": phase,
            "run_id": lease["run_id"], "lease_id": lease["lease_id"],
            "session_id": authority["session_context_binding"]["session_id"],
            "expires_at": lease["expires_at"],
            "unit": f"secure-sandbox-run-{lease['run_id']}.scope",
            "runtime_authority_sha256": authority["binding_sha256"],
            "gateway_lease_sha256": gateway_digest,
        }

    @staticmethod
    def harness_lease_fields():
        return {
            "harness_id": "claude-code", "harness_generation_id": "d" * 64,
            "harness_manifest_sha256": "e" * 64,
            "harness_executable_sha256": "f" * 64,
            "harness_inventory_sha256": "1" * 64,
            "harness_adapter_id": "claude-core-v1",
            "harness_adapter_sha256": "2" * 64,
            "harness_binding_sha256": "cf911d30597efce0b317b19a6f4e03c604079b4179f931aae5665e34ba1121b1",
        }

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.release = self.root / "release"
        self.bin = self.root / "bin"
        self.release.mkdir()
        self.bin.mkdir()
        (self.release / "ssh_config").write_text(
            (REPO / "config/ssh_config.example").read_text()
            .replace("REPLACE_WITH_ABSOLUTE_REPOSITORY_PATH", str(self.root)),
            encoding="utf-8",
        )
        self.log = self.root / "ssh.log"
        mocks = {
            "op-agents": "#!/bin/bash\nprintf 'secret\\n'\n",
            "uuidgen": "#!/bin/bash\nprintf '12345678-1234-4123-8123-123456789abc\\n'\n",
            "sleep": "#!/bin/bash\nexit 0\n",
            "date": "#!/bin/bash\nif [[ \"${1:-}\" == -r ]]; then printf '2033-05-18T03:33:20Z\\n'; else printf '2000000000\\n'; fi\n",
            "ssh": """#!/bin/bash
printf '%s\\n' "$*" >>"$SSH_LOG"
case "$*" in
  *"date -u +%s"*) printf '2000000000\\n' ;;
  *"model_profile_status.py"*) printf '%s\\n' "$SSH_MODEL_PROFILE_JSON" ;;
  *"harness-generation.py active-runtime"*|*"harness-generation.py generation-runtime"*) printf '%s\\n' '{"binding_sha256":"cf911d30597efce0b317b19a6f4e03c604079b4179f931aae5665e34ba1121b1","harness_adapter_id":"claude-core-v1","harness_adapter_sha256":"2222222222222222222222222222222222222222222222222222222222222222","harness_executable_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","harness_generation_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","harness_id":"claude-code","harness_inventory_sha256":"1111111111111111111111111111111111111111111111111111111111111111","harness_manifest_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","schema":"secure-sandbox-harness-runtime-binding-v1"}' ;;
  *"session_policy_runtime.py"*) printf '%s\n' "$SSH_SESSION_POLICY_JSON" ;;
  *"run_lease.py issue-v3"*)
    if [[ "${SSH_ISSUE_REPLY_MODE:-success}" == lost_before_mutation ]]; then
      if [[ ! -e "$SSH_ISSUE_MARKER" ]]; then /usr/bin/touch "$SSH_ISSUE_MARKER"; exit 255; fi
      printf '%s\\n' "$SSH_LEASE_JSON"
    elif [[ "${SSH_ISSUE_REPLY_MODE:-success}" == partial_after_mutation ]]; then
      if [[ ! -e "$SSH_ISSUE_MARKER" ]]; then /usr/bin/touch "$SSH_ISSUE_MARKER"; exit 255; fi
      printf '%s\\n' '{"error":"lease_state_invalid"}' >&2; exit 1
    elif [[ "${SSH_ISSUE_REPLY_MODE:-success}" == lost_after_mutation ]]; then exit 255
    elif [[ "${SSH_ISSUE_REPLY_MODE:-success}" == rejected ]]; then exit 1
    elif [[ "${SSH_ISSUE_REPLY_MODE:-success}" == malformed ]]; then printf '{}\\n'
    elif [[ -n "${SSH_LEASE_JSON:-}" ]]; then printf '%s\\n' "$SSH_LEASE_JSON"
    else printf '%s\\n' '{"schema":"secure-sandbox-run-lease-v2","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","adapter":"anthropic-messages-v1","model":"abliterated-model-large-v2","model_profile_id":"abliterated-glm","model_profile_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","vendor_id":"abliteration","harness_id":"claude-code","harness_generation_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","harness_manifest_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","harness_executable_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","harness_inventory_sha256":"1111111111111111111111111111111111111111111111111111111111111111","harness_adapter_id":"claude-core-v1","harness_adapter_sha256":"2222222222222222222222222222222222222222222222222222222222222222","harness_binding_sha256":"cf911d30597efce0b317b19a6f4e03c604079b4179f931aae5665e34ba1121b1","limits":{},"pricing":{},"renewals":0}'
    fi ;;
  *"run_lease.py status"*)
    if [[ -n "${SSH_GATEWAY_STATUS_JSON:-}" ]]; then printf '%s\\n' "$SSH_GATEWAY_STATUS_JSON"
    else
      printf '%s\\n' '{"error":"FileNotFoundError"}' >&2
      printf '%s\\n' '{"request_id":"99999999-9999-4999-8999-999999999999","schema":"secure-sandbox-control-client-failure-v1","status":1}' >&2
      exit 1
    fi ;;
  *"run_lease.py finalize"*)
    if [[ -n "${SSH_GATEWAY_SUMMARY+x}" ]]; then printf '%s\n' "$SSH_GATEWAY_SUMMARY"
    else
      reason=completed
      case "$*" in *session_failed*) reason=session_failed;; *operator_closed*) reason=operator_closed;; *expired*) reason=expired;; *launch_failed*) reason=launch_failed;; esac
      printf '{"schema":"secure-sandbox-run-lease-summary-v1","lease":{"schema":"secure-sandbox-run-lease-v2","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","adapter":"anthropic-messages-v1","model":"abliterated-model-large-v2","model_profile_id":"abliterated-glm","model_profile_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","vendor_id":"abliteration","harness_id":"claude-code","harness_generation_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","harness_manifest_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","harness_executable_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","harness_inventory_sha256":"1111111111111111111111111111111111111111111111111111111111111111","harness_adapter_id":"claude-core-v1","harness_adapter_sha256":"2222222222222222222222222222222222222222222222222222222222222222","harness_binding_sha256":"cf911d30597efce0b317b19a6f4e03c604079b4179f931aae5665e34ba1121b1","limits":{},"pricing":{},"renewals":0},"final_counters":{"schema":"secure-sandbox-run-lease-counter-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","requests":0,"input_tokens":0,"output_tokens":0,"cost_microusd":0,"updated_at":2000000000},"finalized_at":2000000000,"reason":"%s"}\n' "$reason"
    fi ;;
  *"run_lease_watchdog.py arm-v3"*)
    if [[ "${SSH_ARM_REPLY_MODE:-success}" == lost_after_mutation ]]; then exit 255
    elif [[ "${SSH_ARM_REPLY_MODE:-success}" == signal_after_mutation ]]; then
      /bin/kill -TERM "$SECURE_SANDBOX_TEST_CONTROLLER_PID"; exit 255
    elif [[ "${SSH_ARM_REPLY_MODE:-success}" == malformed ]]; then printf '{}\\n'
    elif [[ "${SSH_ARM_STATUS:-0}" != 0 ]]; then exit "$SSH_ARM_STATUS"
    else printf '%s\\n' "$SSH_RESEARCH_LEASE_JSON"
    fi ;;
  *"run_lease_watchdog.py status"*)
    if [[ -n "${SSH_WATCHDOG_STATUS_JSON:-}" ]]; then printf '%s\\n' "$SSH_WATCHDOG_STATUS_JSON"
    else
      printf '%s\\n' "FileNotFoundError: [Errno 2] No such file or directory: '/var/lib/secure-sandbox/run-lifecycle/active.json'" >&2
      printf '%s\\n' '{"request_id":"99999999-9999-4999-8999-999999999999","schema":"secure-sandbox-control-client-failure-v1","status":1}' >&2
      exit 1
    fi ;;
  *"run_lease_watchdog.py close"*) exit "${SSH_CLOSE_STATUS:-0}" ;;
  *"session_registry.py refresh-contains"*) exit "${SSH_REFRESH_STATUS:-0}" ;;
  *"session_registry.py refresh"*) exit "${SSH_REFRESH_STATUS:-0}" ;;
  *"session_registry.py contains"*) exit "${SSH_CONTAINS_STATUS:-0}" ;;
  *"pki_generation.py verify"*) printf '{"generation_id":"12345678-1234-4123-8123-123456789abc","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\\n' ;;
  *"research-claude"*) exit "${SSH_FINAL_STATUS:-0}" ;;
esac
exit 0
""",
        }
        for name, body in mocks.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        controller = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        for original, replacement in {
            "/usr/bin/ssh": str(self.bin / "ssh"),
            "/usr/bin/uuidgen": str(self.bin / "uuidgen"),
            "/bin/date": str(self.bin / "date"),
            "/bin/sleep": str(self.bin / "sleep"),
            "/usr/local/libexec/secure-sandbox-host/releases/$release_id": str(
                self.release
            ),
        }.items():
            controller = controller.replace(original, replacement)
        (self.release / "controller").write_text(controller, encoding="utf-8")
        (self.release / "controller").chmod(0o755)
        (self.release / "control_client").write_text(
            """#!/bin/bash
set -e
shift 3
host="$1"; shift
mode="$1"; shift
operation="$1"; shift
if [[ "$mode" == pipe ]]; then
  payload="$(/bin/cat)"
  printf '%s\t%s\t%s\n' "$host" "$operation" "$payload" >>"$SSH_PIPE_LOG"
elif [[ "$mode" != run ]]; then
  exit 64
fi
case "$operation" in
  lease-issue-v3) command="run_lease.py issue-v3 $*" ;;
  lease-status) command="run_lease.py status '$1'" ;;
  model-profile-status) command="model_profile_status.py" ;;
  harness-active-runtime) command="harness-generation.py active-runtime" ;;
  harness-generation-runtime) command="harness-generation.py generation-runtime '$1'" ;;
  session-policy-runtime) command="session_policy_runtime.py '$1'" ;;
  lease-finalize) command="run_lease.py finalize '$1' '$2'" ;;
  watchdog-arm-v3) command="run_lease_watchdog.py arm-v3" ;;
  watchdog-status) command="run_lease_watchdog.py status '$1'" ;;
  watchdog-close) command="run_lease_watchdog.py close '$1'" ;;
  watchdog-commit) command="run_lease_watchdog.py commit '$1' '$2'" ;;
  session-refresh) command="session_registry.py refresh" ;;
  session-refresh-contains) command="session_registry.py refresh-contains '$1'" ;;
  session-contains) command="session_registry.py contains '$1'" ;;
  capture-ready) command="capture-ready" ;;
  pki-verify) command="pki_generation.py verify" ;;
  execution-approval-next) exit 3 ;;
  *) exit 64 ;;
esac
exec SSH_MOCK_PLACEHOLDER "$host" "$command"
""".replace("SSH_MOCK_PLACEHOLDER", str(self.bin / "ssh")),
            encoding="utf-8",
        )
        (self.release / "control_client").chmod(0o755)
        (self.release / "pki_anchor").write_text(
            "#!/bin/bash\nprintf '{\"generation_id\":\"12345678-1234-4123-8123-123456789abc\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\\n'\n",
            encoding="utf-8",
        )
        (self.release / "pki_anchor").chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def run_controller(self, *arguments, final_status="0", lease_json=None, arm_status="0", close_status="0",
                       gateway_summary=None, refresh_status="0", contains_status="0",
                       active_model_profile=None, session_policy_override=None,
                       issue_reply_mode="success", gateway_status_json=None,
                       arm_reply_mode="success", watchdog_status_json=None):
        state = self.home / "Library/Application Support/SecureSandbox/controller-state"
        state.mkdir(parents=True, exist_ok=True)
        state.chmod(0o700)
        active = state / "active"
        active.mkdir(parents=True, exist_ok=True)
        script = f'''marker="$HOME/Library/Application Support/SecureSandbox/controller-state/active/$$-test.json"
printf '{{"pid":%s,"release_id":"%s"}}\\n' "$$" "{'a' * 64}" >"$marker"
SECURE_SANDBOX_TEST_CONTROLLER_PID="$$" SECURE_SANDBOX_ACTIVE_MARKER="$marker" \
SECURE_SANDBOX_RELEASE_ID="{'a' * 64}" SECURE_SANDBOX_RELEASE_DIR="$RELEASE_DIR" \
  exec "$CONTROLLER" "$@"
'''
        source_id = arguments[arguments.index("--source") + 1] if "--source" in arguments else None
        session_id = arguments[arguments.index("--resume") + 1] if "--resume" in arguments else self.RUN_ID
        try:
            default_lease = self.gateway_lease(session_id=session_id, source_id=source_id)
            policy = self.session_policy(source_id)
        except ValueError:
            default_lease = self.gateway_lease()
            policy = self.session_policy(None)
        if session_policy_override is not None:
            policy = session_policy_override
        selected_lease = json.loads(lease_json) if lease_json is not None else default_lease
        if arm_reply_mode == "signal_after_mutation":
            reason = "operator_closed"
        elif (issue_reply_mode != "success" or arm_status != "0"
              or arm_reply_mode != "success"):
            reason = "launch_failed"
        else:
            reason = "session_failed" if final_status != "0" else "completed"
        if gateway_summary is None:
            try:
                gateway_summary = json.dumps(self.gateway_summary(selected_lease, reason))
            except (KeyError, TypeError):
                gateway_summary = json.dumps(self.gateway_summary(default_lease, reason))
        try:
            research_lease = self.research_lease(selected_lease)
        except (KeyError, TypeError):
            research_lease = self.research_lease(default_lease)
        if gateway_status_json is None and issue_reply_mode in {"lost_after_mutation", "malformed"}:
            gateway_status_json = self.gateway_active_status(selected_lease)
        if watchdog_status_json is None and arm_reply_mode in {
            "lost_after_mutation", "malformed", "signal_after_mutation",
        }:
            watchdog_status_json = self.watchdog_status(selected_lease)
        gateway_status_raw = (json.dumps(gateway_status_json, separators=(",", ":"), sort_keys=True)
                              if isinstance(gateway_status_json, dict)
                              else (gateway_status_json or ""))
        watchdog_status_raw = (json.dumps(watchdog_status_json, separators=(",", ":"), sort_keys=True)
                               if isinstance(watchdog_status_json, dict)
                               else (watchdog_status_json or ""))
        env = os.environ.copy()
        if active_model_profile is None:
            active_model_profile = {
                "schema": "secure-sandbox-active-model-profile-v1",
                "mode": "mock", "adapter": "anthropic-messages-v1",
                "model": "abliterated-model-large-v2",
                "profile_id": "abliterated-glm", "profile_sha256": "c" * 64,
                "vendor_id": "abliteration",
                "upstream_origin": "https://api.abliteration.ai",
            }
        env.update({
            "HOME": str(self.home),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "SSH_LOG": str(self.log),
            "SSH_PIPE_LOG": str(self.root / "pipe.log"),
            "SSH_FINAL_STATUS": final_status,
            "SSH_ISSUE_REPLY_MODE": issue_reply_mode,
            "SSH_ISSUE_MARKER": str(self.root / "issue-once.marker"),
            "SSH_GATEWAY_STATUS_JSON": gateway_status_raw,
            "SSH_ARM_STATUS": arm_status,
            "SSH_ARM_REPLY_MODE": arm_reply_mode,
            "SSH_WATCHDOG_STATUS_JSON": watchdog_status_raw,
            "SSH_RESEARCH_LEASE_JSON": json.dumps(
                research_lease, separators=(",", ":"), sort_keys=True),
            "SSH_CLOSE_STATUS": close_status,
            "SSH_REFRESH_STATUS": refresh_status,
            "SSH_CONTAINS_STATUS": contains_status,
            "SSH_SESSION_POLICY_JSON": json.dumps(policy, separators=(",", ":"), sort_keys=True),
            "SSH_MODEL_PROFILE_JSON": json.dumps(
                active_model_profile, separators=(",", ":"), sort_keys=True),
            "SSH_LEASE_JSON": json.dumps(selected_lease, separators=(",", ":"), sort_keys=True),
            "SSH_GATEWAY_SUMMARY": gateway_summary,
            "CONTROLLER": str(self.release / "controller"),
            "RELEASE_DIR": str(self.release),
            "SECURE_SANDBOX_STATE_ROOT": str(self.home / "Library/Application Support/SecureSandbox/controller-state"),
        })
        return subprocess.run(["/bin/bash", "-c", script, "test", *arguments], env=env, text=True, capture_output=True)

    def test_new_session_uses_bash32_safe_branch_and_cleans_marker(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("research-claude --session-id", self.log.read_text(encoding="utf-8"))
        self.assertEqual(list((self.home / "Library/Application Support/SecureSandbox/controller-state/active").iterdir()), [])
        catalog = json.loads((self.home / "Library/Application Support/SecureSandbox/controller-state/session-runs.json").read_text())
        self.assertEqual(catalog["schema"], "secure-sandbox-session-runs-v5")
        record = catalog["sessions"][self.RUN_ID]
        self.assertEqual(record["runtime_authority"], self.runtime_authority())

    def test_attested_active_model_profile_is_accepted_as_an_exact_status_variant(self):
        profile = {
            "schema": "secure-sandbox-active-model-profile-v1",
            "mode": "mock", "adapter": "anthropic-messages-v1",
            "model": "abliterated-model-large-v2",
            "profile_id": "abliterated-glm", "profile_sha256": "c" * 64,
            "vendor_id": "abliteration",
            "upstream_origin": "https://api.abliteration.ai",
            "activation_id": self.RUN_ID, "plan_sha256": "3" * 64,
        }
        result = self.run_controller(active_model_profile=profile)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_or_extended_active_model_profile_fails_closed(self):
        base = {
            "schema": "secure-sandbox-active-model-profile-v1",
            "mode": "mock", "adapter": "anthropic-messages-v1",
            "model": "abliterated-model-large-v2",
            "profile_id": "abliterated-glm", "profile_sha256": "c" * 64,
            "vendor_id": "abliteration",
            "upstream_origin": "https://api.abliteration.ai",
        }
        for profile in ({**base, "activation_id": self.RUN_ID},
                        {**base, "unexpected": "field"}):
            with self.subTest(profile=profile):
                result = self.run_controller(active_model_profile=profile)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid Gateway model profile status", result.stderr)

    def test_issue_and_arm_use_canonical_content_bound_v3_payloads(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t", 2) for line in (self.root / "pipe.log").read_text().splitlines()]
        by_operation = {operation: json.loads(payload) for _host, operation, payload in rows}
        issue = by_operation["lease-issue-v3"]
        self.assertEqual(issue["schema"], "secure-sandbox-run-lease-issue-v3")
        self.assertEqual(issue["session_id"], self.RUN_ID)
        self.assertEqual(issue["session_policy"], self.session_policy())
        self.assertEqual(issue["harness_binding"], self.harness_binding())
        arm = by_operation["watchdog-arm-v3"]
        self.assertEqual(arm, {
            "schema": "secure-sandbox-research-run-arm-v3",
            "gateway_lease": self.gateway_lease(),
        })

    def test_issue_lost_reply_after_mutation_is_read_back_and_finalized(self):
        result = self.run_controller(issue_reply_mode="lost_after_mutation")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py issue-v3", log)
        self.assertIn("run_lease.py status", log)
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("launch_failed", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_malformed_issue_reply_after_mutation_is_read_back_and_finalized(self):
        result = self.run_controller(issue_reply_mode="malformed")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py status", log)
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_issue_transport_loss_before_mutation_is_replayed_and_finalized(self):
        result = self.run_controller(issue_reply_mode="lost_before_mutation")
        self.assertEqual(result.returncode, 1)
        log = self.log.read_text(encoding="utf-8")
        self.assertGreaterEqual(log.count("run_lease.py issue-v3"), 2)
        self.assertIn("run_lease.py status", log)
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_repeated_issue_rejection_without_exact_readback_is_unresolved(self):
        result = self.run_controller(issue_reply_mode="rejected")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertGreaterEqual(log.count("run_lease.py issue-v3"), 2)
        self.assertIn("run_lease.py status", log)
        self.assertNotIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_partial_gateway_publication_is_never_mistaken_for_absence(self):
        result = self.run_controller(issue_reply_mode="partial_after_mutation")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertGreaterEqual(log.count("run_lease.py issue-v3"), 2)
        self.assertGreaterEqual(log.count("run_lease.py status"), 2)
        self.assertNotIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_issue_readback_with_wrong_runtime_authority_is_not_finalized(self):
        wrong = self.gateway_active_status(self.gateway_lease(
            session_id="44444444-4444-4444-8444-444444444444",
        ))
        result = self.run_controller(
            issue_reply_mode="lost_after_mutation", gateway_status_json=wrong,
        )
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py status", log)
        self.assertNotIn("run_lease.py finalize", log)

    def test_selected_source_is_passed_only_to_new_research_session(self):
        source = "11111111-1111-4111-8111-111111111111"
        result = self.run_controller("--source", source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"research-claude --session-id 12345678-1234-4123-8123-123456789abc --source {source}",
                      self.log.read_text(encoding="utf-8"))

    def test_selected_source_policy_must_identify_the_requested_source(self):
        source = "11111111-1111-4111-8111-111111111111"
        result = self.run_controller(
            "--source", source, session_policy_override=self.session_policy(None),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Research session policy", result.stderr)
        self.assertNotIn("run_lease.py issue-v3", self.log.read_text(encoding="utf-8"))

    def test_selected_source_rejects_invalid_or_resumed_context_before_remote_access(self):
        source = "11111111-1111-4111-8111-111111111111"
        session = "22222222-2222-4222-8222-222222222222"
        for arguments in (("--source", "invalid"), ("--source", source, "--resume", session),
                          ("--source", source, "--source", source)):
            with self.subTest(arguments=arguments):
                result = self.run_controller(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())

    def test_watchdog_arm_failure_finalizes_gateway_without_closing_missing_lifecycle(self):
        result = self.run_controller(arm_status="1")
        self.assertEqual(result.returncode, 1)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("launch_failed", log)
        self.assertIn("run_lease_watchdog.py status", log)
        self.assertNotIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_watchdog_arm_lost_reply_after_mutation_is_read_back_closed_and_committed(self):
        result = self.run_controller(arm_reply_mode="lost_after_mutation")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py arm-v3", log)
        self.assertIn("run_lease_watchdog.py status", log)
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("run_lease_watchdog.py commit", log)

    def test_signal_after_durable_watchdog_arm_is_reconciled_before_gateway_finalize(self):
        result = self.run_controller(arm_reply_mode="signal_after_mutation")
        self.assertEqual(result.returncode, 143, result.stderr)
        log = self.log.read_text(encoding="utf-8")
        arm = log.index("run_lease_watchdog.py arm-v3")
        status = log.index("run_lease_watchdog.py status")
        close = log.index("run_lease_watchdog.py close")
        finalize = log.index("run_lease.py finalize")
        commit = log.index("run_lease_watchdog.py commit")
        self.assertLess(arm, status)
        self.assertLess(status, close)
        self.assertLess(close, finalize)
        self.assertLess(finalize, commit)
        self.assertIn("operator_closed", log)
        self.assertNotIn("research-claude", log)

    def test_malformed_watchdog_arm_reply_after_mutation_is_closed(self):
        result = self.run_controller(arm_reply_mode="malformed")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py status", log)
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertIn("run_lease_watchdog.py commit", log)

    def test_watchdog_readback_with_wrong_binding_is_never_closed(self):
        wrong = self.watchdog_status()
        wrong["lease_id"] = "44444444-4444-4444-8444-444444444444"
        result = self.run_controller(
            arm_reply_mode="lost_after_mutation", watchdog_status_json=wrong,
        )
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py status", log)
        self.assertNotIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)
        self.assertNotIn("run_lease.py finalize", log)

    def test_execution_approval_relay_fails_closed_after_repeated_transport_errors(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('if (( failures >= 3 )); then', text)
        self.assertIn('/bin/kill -TERM "$controller_pid"', text)
        self.assertNotIn('/bin/sleep 0.2', text)

    def test_execution_approval_relay_persists_bounded_content_free_diagnostics(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('approval-relay-last.json', text)
        self.assertIn('secure-sandbox-approval-relay-event-v1', text)
        self.assertIn('os.O_EXCL | os.O_NOFOLLOW', text)
        self.assertIn('os.replace(temporary, path)', text)
        self.assertIn('relay_event authorization "$broker_error"', text)
        self.assertIn('relay_event poll transport_failed', text)

    def test_touchid_ui_uses_real_appkit_lifecycle_and_forces_window_front(self):
        text = (REPO / "macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/main.swift").read_text(
            encoding="utf-8"
        )
        launched = text.index("func applicationDidFinishLaunching")
        active_space = text.index("window.collectionBehavior.insert(.moveToActiveSpace)")
        level = text.index("window.level = .modalPanel")
        activate = text.index("application.activate(ignoringOtherApps: true)")
        key = text.index("window.makeKeyAndOrderFront(nil)")
        front = text.index("window.orderFrontRegardless()")
        arrange = text.index("application.arrangeInFront(nil)")
        expiry = text.index("TimeInterval(request.expiresAt)")
        timer = text.index("let expiryTimer = Timer(")
        modal_mode = text.index("RunLoop.main.add(expiryTimer, forMode: .modalPanel)")
        modal = text.index("alert.runModal()")
        run = text.index("application.run()")
        self.assertNotIn("application.finishLaunching()", text)
        self.assertIn("application.activationPolicy() == .regular", text)
        self.assertIn("stopModal(withCode: .abort)", text)
        self.assertLess(launched, active_space)
        self.assertLess(active_space, level)
        self.assertLess(level, activate)
        self.assertLess(activate, key)
        self.assertLess(key, front)
        self.assertLess(front, arrange)
        self.assertLess(arrange, expiry)
        self.assertLess(expiry, timer)
        self.assertLess(timer, modal_mode)
        self.assertLess(modal_mode, modal)
        self.assertLess(modal, run)

    def test_resume_preserves_uuid_and_registry_check(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        state = self.home / "Library/Application Support/SecureSandbox/controller-state"
        state.mkdir(parents=True, exist_ok=True); state.chmod(0o700)
        catalog = state / "session-runs.json"
        authority = self.runtime_authority(session_id=session)
        catalog.write_text(json.dumps({
            "schema":"secure-sandbox-session-runs-v5", "sessions": {session: {
                "adapter":"anthropic-messages-v1", "last_started_at":1999999999,
                "model":"abliterated-model-large-v2", "run_ids":[], "runs":1,
                "runtime_authority":authority, "vendor_id":"abliteration",
            }},
        }))
        catalog.chmod(0o600)
        result = self.run_controller("--resume", session)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("session_registry.py refresh-contains", log)
        self.assertIn(f"research-claude --resume {session}", log)

    def test_resume_authority_mismatch_finalizes_the_unarmed_gateway_lease(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        state = self.home / "Library/Application Support/SecureSandbox/controller-state"
        state.mkdir(parents=True, exist_ok=True); state.chmod(0o700)
        catalog = state / "session-runs.json"
        prior = self.runtime_authority(session_id=session, profile_sha256="4" * 64)
        catalog.write_text(json.dumps({
            "schema": "secure-sandbox-session-runs-v5", "sessions": {session: {
                "adapter": "anthropic-messages-v1", "last_started_at": 1999999999,
                "model": "abliterated-model-large-v2", "run_ids": [], "runs": 1,
                "runtime_authority": prior, "vendor_id": "abliteration",
            }},
        }) + "\n", encoding="ascii")
        catalog.chmod(0o600)
        issued = self.gateway_lease(session_id=session)
        summary = json.dumps(self.gateway_summary(issued, "launch_failed"))
        result = self.run_controller("--resume", session, gateway_summary=summary)
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py issue-v3", log)
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py arm-v3", log)

    def test_v4_resume_requires_explicit_runtime_authority_migration(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        state = self.home / "Library/Application Support/SecureSandbox/controller-state"
        state.mkdir(parents=True, exist_ok=True); state.chmod(0o700)
        (state / "session-runs.json").write_text(json.dumps({
            "schema": "secure-sandbox-session-runs-v4",
            "sessions": {session: {
                "adapter": "anthropic-messages-v1", "last_started_at": 1,
                "model": "abliterated-model-large-v2", "model_profile_id": "abliterated-glm",
                "model_profile_sha256": "c" * 64, "run_ids": [], "runs": 1,
                "vendor_id": "abliteration", **self.harness_lease_fields(),
            }},
        }) + "\n", encoding="ascii")
        (state / "session-runs.json").chmod(0o600)
        result = self.run_controller("--resume", session)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit migration", result.stderr)
        self.assertNotIn("run_lease.py issue-v3", self.log.read_text(encoding="utf-8"))

    def test_resume_fails_closed_when_registry_refresh_fails(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        result = self.run_controller("--resume", session, refresh_status="23")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("session_registry.py refresh-contains", log)
        self.assertNotIn("run_lease.py issue", log)
        self.assertNotIn("research-claude --resume", log)

    def test_interrupted_remote_session_still_finalizes_and_cleans(self):
        result = self.run_controller(final_status="130")
        self.assertEqual(result.returncode, 130)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("session_failed", log)
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertIn("run_lease_watchdog.py commit", log)
        self.assertNotIn("manage_run_id.py clear", log)
        active = self.home / "Library/Application Support/SecureSandbox/controller-state/active"
        self.assertEqual(list(active.iterdir()), [])

    def test_controller_waits_on_explicit_session_child_for_signal_cleanup(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('interrupt_run()', text)
        self.assertIn('/bin/kill -HUP "$session_pid"', text)
        self.assertIn('session_pid=$!', text)
        self.assertIn('wait "$session_pid"', text)
        self.assertIn('lease_reason=operator_closed', text)

    def test_commit_binds_exact_gateway_summary_file_bytes(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.gateway_summary()
        durable = json.dumps(summary, separators=(",", ":"), sort_keys=True) + "\n"
        expected = hashlib.sha256(durable.encode("utf-8")).hexdigest()
        self.assertIn(
            f"run_lease_watchdog.py commit '12345678-1234-4123-8123-123456789abc' '{expected}'",
            self.log.read_text(encoding="utf-8"),
        )

    def test_invalid_resume_is_rejected_before_remote_access(self):
        result = self.run_controller("--resume", "not-a-uuid")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_close_failure_overrides_session_success_and_skips_gateway_commit(self):
        result = self.run_controller(close_status="1")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_invalid_gateway_summary_blocks_research_commit(self):
        result = self.run_controller(gateway_summary="")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_gateway_summary_must_bind_run_lease_reason_and_counter_schema(self):
        wrong = json.dumps({"schema":"secure-sandbox-run-lease-summary-v1",
                            "lease":{"schema":"secure-sandbox-run-lease-v1",
                                     "run_id":"12345678-1234-4123-8123-123456789abc",
                                     "lease_id":"12345678-1234-4123-8123-123456789abc"},
                            "final_counters":{},"finalized_at":2000000000,
                            "reason":"completed"})
        result = self.run_controller(gateway_summary=wrong)
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

    def test_renewed_gateway_summary_preserves_immutable_lease_binding(self):
        lease = self.gateway_lease()
        renewed = {**lease, "expires_at": 2000000900, "renewals": 1}
        summary = self.gateway_summary(renewed)
        result = self.run_controller(lease_json=json.dumps(lease),
                                     gateway_summary=json.dumps(summary))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

        tampered = {**summary, "lease": {**renewed, "brokered_transport": {
            **renewed["brokered_transport"], "policy_sha256": "c" * 64,
        }}}
        self.log.unlink()
        result = self.run_controller(lease_json=json.dumps(lease),
                                     gateway_summary=json.dumps(tampered))
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

    def test_gateway_expiry_shell_expression_is_rejected_without_execution(self):
        sentinel = self.root / "arithmetic-executed"
        malicious = json.dumps({
            "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "expires_at": f"x[$(/usr/bin/touch {sentinel})]",
        })
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sentinel.exists())
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_gateway_lease_id_shell_metacharacters_are_rejected_before_research(self):
        malicious = json.dumps({"lease_id": "' ; id ; '", "expires_at": 2000000600})
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_launcher_environment_is_allowlisted(self):
        marker = self.root / "marker"
        dangerous = {
            "BASH_ENV": "/tmp/evil", "ENV": "/tmp/evil", "SHELLOPTS": "xtrace",
            "BASHOPTS": "extdebug", "PYTHONPATH": "/tmp/evil", "DYLD_INSERT_LIBRARIES": "/tmp/evil",
        }
        with mock.patch.dict(os.environ, dangerous, clear=False):
            environment = LAUNCHER.controller_environment(marker, "a" * 64)
        self.assertFalse(set(dangerous) & set(environment))
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")

    def test_launcher_executes_captured_controller_bytes_after_inode_mutation(self):
        controller_path = self.root / "controller"
        original = (
            b"#!/bin/bash\n"
            b"printf 'captured|%s|%s|%s\\n' \"$0\" \"$1\" "
            b"\"$SECURE_SANDBOX_RELEASE_DIR\"\n"
        )
        mutated = original.replace(b"captured", b"mutated!")
        self.assertEqual(len(original), len(mutated))
        controller_path.write_bytes(original)
        writer = os.open(controller_path, os.O_RDWR)
        try:
            command = LAUNCHER.verified_controller_command(
                controller_path.read_bytes()
            )
            os.pwrite(writer, mutated, 0)
            os.fsync(writer)
            completed = subprocess.run(
                [
                    "/bin/bash", "-c", command,
                    str(controller_path), "argument",
                ],
                check=False, capture_output=True, text=True,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "SECURE_SANDBOX_RELEASE_DIR": str(self.release),
                },
            )
        finally:
            os.close(writer)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout,
            f"captured|{controller_path}|argument|{self.release}\n",
        )
        self.assertEqual(controller_path.read_bytes(), mutated)

    def test_controller_requires_launcher_bound_release_directory(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'release_dir="${SECURE_SANDBOX_RELEASE_DIR:-}"', text,
        )
        self.assertNotIn('dirname "${BASH_SOURCE[0]}"', text)
        self.assertIn('"$0" == "$release_dir/controller"', text)
        launcher = (
            REPO / "scripts/secure-sandbox-claude-launcher.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"/bin/bash", "-c", controller_command', launcher)

    def test_attributed_host_pair_recovery_rejects_notice_to_sudo_swaps(self):
        target = {
            "candidate_authority_sha256": "1" * 64,
            "launcher_sha256": "2" * 64,
            "release_id": "3" * 64,
            "release_tree_identity_sha256": "4" * 64,
        }
        transition = {
            "operation": "install",
            "source_stable_sha256": None,
            "source_pair": None,
            "target_pair": target,
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "5" * 64,
        }

        def projection(value):
            record = MANAGER.host_release_launcher_pair_pending_record(
                operation=value["operation"],
                transition_id=value["transition_id"],
                transition_sha256=value["transition_sha256"],
                prior_stable_sha256=value["source_stable_sha256"],
                source_pair=value["source_pair"],
                target_pair=value["target_pair"],
            )
            digest = MANAGER.sha256_bytes(
                MANAGER.host_release_launcher_pair_record_bytes(record)
            )
            return record, digest

        original_public, original_digest = projection(transition)
        expected = {
            "expected_public_pending_sha256": original_digest,
            "expected_transition_id": transition["transition_id"],
            "expected_transition_sha256": transition["transition_sha256"],
            "expected_operation": transition["operation"],
            "expected_target_release_id": target["release_id"],
            "expected_target_candidate_authority_sha256": target[
                "candidate_authority_sha256"
            ],
            "expected_target_release_tree_identity_sha256": target[
                "release_tree_identity_sha256"
            ],
            "expected_target_launcher_sha256": target["launcher_sha256"],
        }
        swapped_transition = {
            **transition,
            "target_pair": {**target, "release_id": "6" * 64},
        }
        swapped_public, swapped_digest = projection(swapped_transition)
        descriptor = os.open("/dev/null", os.O_RDONLY)
        with (
            mock.patch.object(
                MANAGER, "read_pending_host_pair_transition",
                return_value=(transition, descriptor),
            ),
            mock.patch.object(
                MANAGER, "host_release_launcher_pair_public",
                return_value=(original_public, original_digest),
            ),
            mock.patch.object(
                MANAGER, "execute_host_pair_transition",
                return_value=({"pair": target}, "7" * 64),
            ) as execute,
        ):
            recovered = MANAGER.recover_host_pair_transition.__wrapped__(
                Path("/install"), Path("/launcher"), Path("/state"), 0,
                **expected,
            )
        self.assertEqual(
            recovered["status"], "host_pair_transition_recovered",
        )
        execute.assert_called_once_with(
            Path("/install"), Path("/launcher"), 0, transition,
            raise_after_source_restore=False,
        )

        scenarios = (
            (transition, swapped_public, swapped_digest),
            (swapped_transition, original_public, original_digest),
            (swapped_transition, swapped_public, swapped_digest),
        )
        recovery = MANAGER.recover_host_pair_transition.__wrapped__
        for private, public, public_digest in scenarios:
            descriptor = os.open("/dev/null", os.O_RDONLY)
            with (
                self.subTest(
                    private_release=private["target_pair"]["release_id"],
                    public_release=public["target_pair"]["release_id"],
                ),
                mock.patch.object(
                    MANAGER, "read_pending_host_pair_transition",
                    return_value=(private, descriptor),
                ),
                mock.patch.object(
                    MANAGER, "host_release_launcher_pair_public",
                    return_value=(public, public_digest),
                ),
                mock.patch.object(
                    MANAGER, "execute_host_pair_transition",
                ) as execute,
                self.assertRaisesRegex(
                    MANAGER.ReleaseFailure,
                    "host_pair_transition_recovery_binding_changed",
                ),
            ):
                recovery(
                    Path("/install"), Path("/launcher"), Path("/state"), 0,
                    **expected,
                )
            execute.assert_not_called()

    def test_attributed_host_pair_recovery_requires_complete_binding(self):
        recovery = MANAGER.recover_host_pair_transition.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "read_pending_host_pair_transition",
            ) as pending,
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "host_pair_transition_recovery_binding_incomplete",
            ),
        ):
            recovery(
                Path("/install"), Path("/launcher"), Path("/state"), 0,
                expected_transition_id=(
                    "11111111-1111-4111-8111-111111111111"
                ),
            )
        pending.assert_not_called()

    def test_clean_authorization_predecessor_is_exact_and_replayable(self):
        values = {
            name: (name + "\n").encode("utf-8")
            for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        hashes = {
            name: hashlib.sha256(value).hexdigest()
            for name, value in values.items()
        }
        predecessor_id = MANAGER.release_identity(hashes)
        launcher_bytes = b"#!/bin/sh\nexit 0\n"
        checkpoints = (
            "authorization-clean-predecessor-published",
            "authorization-clean-predecessor-selected",
            "authorization-clean-launcher-published",
        )
        for failure in checkpoints:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                install_root = root / "host"
                MANAGER.prepare_install_root_for_lock(
                    install_root, os.geteuid(),
                )
                launcher_parent = root / "bin"
                launcher_parent.mkdir(mode=0o755)
                launcher = launcher_parent / "secure-sandbox-claude"

                def checkpoint(name):
                    if name == failure:
                        raise MANAGER.ReleaseFailure("crash:" + name)

                with (
                    mock.patch.object(
                        MANAGER, "native_coordination_bootstrap_checkpoint",
                        side_effect=checkpoint,
                    ),
                    self.assertRaisesRegex(
                        MANAGER.ReleaseFailure, "crash:" + failure,
                    ),
                ):
                    MANAGER.materialize_clean_authorization_predecessor(
                        install_root, launcher, os.geteuid(), values,
                        predecessor_id, launcher_bytes,
                    )

                selected = MANAGER.materialize_clean_authorization_predecessor(
                    install_root, launcher, os.geteuid(), values,
                    predecessor_id, launcher_bytes,
                )
                self.assertEqual(selected.name, predecessor_id)
                self.assertEqual(launcher.read_bytes(), launcher_bytes)
                self.assertEqual(
                    (
                        install_root
                        / MANAGER.AUTHORIZATION_COORDINATION_PREDECESSOR_NAME
                    ).resolve().name,
                    predecessor_id,
                )
                _path, manifest = MANAGER.verified_release(
                    install_root,
                    install_root / "releases" / predecessor_id,
                    os.geteuid(), allow_legacy=True,
                    _bootstrap_without_developer_id_floor=True,
                    _bootstrap_without_native_coordination_floor=True,
                    _bootstrap_without_candidate_admission_floor=True,
                    _direct_release_id=predecessor_id,
                )
                self.assertEqual(manifest["payloads"], hashes)

    def test_clean_authorization_predecessor_rejects_ambiguous_state(self):
        values = {
            name: (name + "\n").encode("utf-8")
            for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        predecessor_id = MANAGER.release_identity({
            name: hashlib.sha256(value).hexdigest()
            for name, value in values.items()
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            MANAGER.prepare_install_root_for_lock(
                install_root, os.geteuid(),
            )
            (install_root / "unexpected").write_text("evidence")
            launcher_parent = root / "bin"
            launcher_parent.mkdir(mode=0o755)
            launcher = launcher_parent / "secure-sandbox-claude"
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_bootstrap_clean_state_ambiguous",
            ):
                MANAGER.materialize_clean_authorization_predecessor(
                    install_root, launcher, os.geteuid(), values,
                    predecessor_id, b"launcher",
                )
            self.assertFalse(os.path.lexists(launcher))

    def test_clean_authorization_predecessor_checks_launcher_before_release(self):
        values = {
            name: (name + "\n").encode("utf-8")
            for name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        predecessor_id = MANAGER.release_identity({
            name: hashlib.sha256(value).hexdigest()
            for name, value in values.items()
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "host"
            MANAGER.prepare_install_root_for_lock(
                install_root, os.geteuid(),
            )
            launcher_parent = root / "bin"
            launcher_parent.mkdir(mode=0o755)
            launcher = launcher_parent / "secure-sandbox-claude"
            launcher.write_bytes(b"unrelated-launcher")
            launcher.chmod(0o755)
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_bootstrap_clean_state_ambiguous",
            ):
                MANAGER.materialize_clean_authorization_predecessor(
                    install_root, launcher, os.geteuid(), values,
                    predecessor_id, b"candidate-launcher",
                )
            self.assertEqual(list(install_root.iterdir()), [])

    def test_clean_authorization_bootstrap_checks_hashes_before_scaffold(self):
        source_id = "a" * 64
        authorization_manifest = b"candidate-manifest\n"
        operation = MANAGER.bootstrap_authorization.__wrapped__
        with (
            mock.patch.object(
                MANAGER, "source_payload",
                return_value=({
                    "authorization_ui_bundle": authorization_manifest,
                }, {}, source_id),
            ),
            mock.patch.object(
                MANAGER, "native_host_candidate_tracked_source",
                return_value=b"candidate-launcher",
            ),
            mock.patch.object(
                MANAGER, "materialize_clean_authorization_predecessor",
            ) as materialize,
            self.assertRaisesRegex(
                MANAGER.ReleaseFailure,
                "authorization_bootstrap_clean_launcher_binding_invalid",
            ),
        ):
            operation(
                Path("/repo"), Path("/install"), Path("/launcher"),
                Path("/state"), os.geteuid(), source_id,
                "b" * 64, "c" * 64,
                {"generation_path": "/candidate"},
                MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                hashlib.sha256(authorization_manifest).hexdigest(),
                expected_bootstrap_predecessor_release_id="d" * 64,
                clean_machine_bootstrap=True,
            )
        materialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
