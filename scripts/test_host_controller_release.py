#!/usr/bin/env python3

import importlib.util
import contextlib
import hashlib
import json
import os
import plistlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
import io
from pathlib import Path
from unittest import mock

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


class NativeCredentialPackagingContractTests(unittest.TestCase):
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
            'value.get("issues") != []',
            "--keychain-profile \"$notary_profile\"",
            "stapler staple",
            "stapler validate",
            "spctl --assess --type open",
            "hdiutil verify",
            "secure-sandbox-native-host-products-manifest-v1",
            "secure-sandbox-native-host-products-notarization-v1",
            '"stapler_validated":True',
            '"gatekeeper_assessed":True',
            '"notary_log_sha256"',
        )
        for value in required:
            self.assertIn(value, script)
        self.assertLess(
            script.index("SecureSandboxNativeHostProducts.manifest.json"),
            script.index("hdiutil create"),
        )
        self.assertNotIn("source=Notarized Developer ID", script)

    def test_native_component_builder_cleans_read_only_signed_stage(self):
        script = (
            REPO / "scripts/build-native-credential-components.sh"
        ).read_text(encoding="utf-8")
        chmod = '/bin/chmod -R u+w "$build_root"'
        remove = '/bin/rm -rf -- "$build_root"'
        self.assertIn(chmod, script)
        self.assertIn(remove, script)
        self.assertLess(script.index(chmod), script.index(remove))

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
                    "team_id": "ABCDE" + "12345",
                },
            ):
                MANAGER.verify_native_host_products_container({
                    **values,
                    "native_host_products_container": b"dmg",
                    "native_host_products_manifest": encoded,
                    "native_host_products_notarization": b"receipt",
                })

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

    def test_session_manager_is_current_only_and_preserves_predecessor_inventories(self):
        self.assertIn("native_stack_session_manager", MANAGER.PAYLOAD_NAMES)
        self.assertEqual(
            MANAGER.EXPECTED_MODES["native_stack_session_manager"], 0o755,
        )
        self.assertEqual(
            set(MANAGER.PRE_NATIVE_SESSION_MANAGER_PAYLOAD_NAMES),
            set(MANAGER.PAYLOAD_NAMES) - {"native_stack_session_manager"},
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

    def test_exact_service_stop_rejects_bootout_failure_before_plist_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            plist = Path(temporary) / "service.plist"
            plist.write_text("service\n", encoding="ascii")
            failed = subprocess.CompletedProcess([], 5, "", "denied")
            with (
                mock.patch.object(
                    MANAGER, "launchd_service_pid_or_absent",
                    side_effect=[71, 71],
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
                    MANAGER, "launchd_service_pid_or_absent",
                    side_effect=[71, 71, 71, None],
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
                    MANAGER, "launchd_service_pid_or_absent",
                    side_effect=[None, 72],
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


class HostControllerReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "config").mkdir()
        (self.repo / "seeds").mkdir()
        (self.repo / ".private").mkdir()
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
        for relative in [*MANAGER.PAYLOAD_SOURCES.values(),
                         *MANAGER.NATIVE_STACK_SUPPORT_SOURCES.values(),
                         MANAGER.LAUNCHER_SOURCE, *touchid_sources]:
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, self.repo / relative)
        shutil.copytree(
            REPO / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            self.repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            copy_function=shutil.copy2,
        )
        shutil.copytree(
            REPO / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_SOURCE,
            self.repo / MANAGER.NATIVE_CREDENTIAL_HELPER_APP_SOURCE,
            copy_function=shutil.copy2,
        )
        self.install_root = self.root / "installed"
        self.launcher = self.root / "bin/secure-sandbox-claude"
        self.state = self.root / "state"
        self.uid = os.geteuid()
        self.op_binary = self.root / "op"
        self.op_binary.write_bytes(b"test-op-binary\n")
        self.op_binary.chmod(0o755)
        self.gpgv_binary = self.root / "gpgv"
        self.gpgv_binary.write_bytes(b"test-gpgv-binary\n")
        self.gpgv_binary.chmod(0o755)
        # A live protocol-v2 installation deliberately makes the host floor
        # root-only. Unit tests must never inherit that machine-global state.
        self.execution_approval_floor = mock.patch.object(
            MANAGER, "EXECUTION_APPROVAL_FLOOR", self.root / "minimum-floor.json"
        )
        self.execution_approval_floor.start()

    def tearDown(self):
        self.execution_approval_floor.stop()
        self.temporary.cleanup()

    def install(self):
        return MANAGER.install(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            self.op_binary, self.gpgv_binary,
        )

    def test_install_and_verify_are_content_bound(self):
        deployed = self.install()
        verified = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
        self.assertEqual(deployed["release_id"], verified["release_id"])
        self.assertEqual((loaded_path.name, loaded_id), (verified["release_id"], verified["release_id"]))
        self.assertEqual(os.readlink(self.install_root / "current"), f"releases/{verified['release_id']}")
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_release_source_mismatch"):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )

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
            "native_stack_support":0o444,
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

    def test_native_credential_launch_agent_template_is_exactly_rendered(self):
        template = self.repo / MANAGER.PAYLOAD_SOURCES[
            "native_credential_helper_service"
        ]
        template.write_bytes(
            template.read_bytes()
            + b"\n<!-- __SECURE_SANDBOX_NATIVE_CREDENTIAL_HELPER_EXECUTABLE__ -->\n"
        )
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "native_credential_helper_service_template_invalid",
        ):
            MANAGER.source_payload(self.repo, self.op_binary, self.gpgv_binary)

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
        _values, _hashes, expected = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed after authorization\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "source_release_id_unexpected"):
            MANAGER.install(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                self.op_binary, self.gpgv_binary, expected,
            )

    def test_local_secure_enclave_config_is_bound_to_repo_owner_under_sudo(self):
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            _values, hashes, release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(release_id, MANAGER.release_identity(hashes))

    def test_capacity_recovery_archives_inactive_releases_without_deleting_history(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 3):
            first = self.install()["release_id"]
            for suffix in ("second", "third"):
                with (self.repo / "scripts/claude-run-controller.sh").open(
                    "a", encoding="utf-8"
                ) as handle:
                    handle.write(f"# {suffix}\n")
                latest = self.install()["release_id"]
            self.assertNotEqual(first, latest)
            # A power loss in the narrow chmod-before-rename window leaves an
            # inactive source writable only by root; recovery must resume.
            (self.install_root / "releases" / first).chmod(0o755)
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            self.assertEqual(plan["archive_release_ids"], [first])
            with mock.patch.object(
                MANAGER, "enforce_execution_approval_floor",
                wraps=MANAGER.enforce_execution_approval_floor,
            ) as floor:
                result = MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"], plan["previous_release_id"],
                    plan["plan_sha256"],
                )
            # Current and rollback remain activation-floor checked.  The
            # inactive target is integrity-verified but deliberately exempt
            # because archival makes it non-selectable.
            self.assertEqual(floor.call_count, 2)
            self.assertEqual(result["archived"], 1)
            self.assertFalse((self.install_root / "releases" / first).exists())
            self.assertTrue((self.install_root / "release-archive" / first).is_dir())
            self.assertEqual((self.install_root / "current").resolve().name,
                             plan["current_release_id"])
            self.assertEqual((self.install_root / "previous").resolve().name,
                             plan["previous_release_id"])
            with (self.repo / "scripts/claude-run-controller.sh").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write("# fourth\n")
            self.assertEqual(self.install()["status"], "deployed")

    def test_capacity_recovery_rejects_changed_plan_before_moving_releases(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 3):
            first = self.install()["release_id"]
            for suffix in ("second", "third"):
                with (self.repo / "scripts/claude-run-controller.sh").open(
                    "a", encoding="utf-8"
                ) as handle:
                    handle.write(f"# {suffix}\n")
                self.install()
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

    def test_launcher_rejects_payload_tampering(self):
        self.install()
        controller = (self.install_root / "current").resolve() / "controller"
        controller.chmod(0o755)
        with controller.open("a", encoding="utf-8") as handle:
            handle.write("# tampered\n")
        controller.chmod(0o555)
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "payload_hash_mismatch"):
            LAUNCHER.load_release(self.install_root, self.uid)

    def test_failed_syntax_check_does_not_change_current(self):
        original = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("if then\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "controller_syntax_invalid"):
            self.install()
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_service_bootstrap_failure_restores_previous_current_release(self):
        original = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        with (mock.patch.object(MANAGER, "manages_live_touchid_service", return_value=True),
              mock.patch.object(MANAGER, "install_touchid_service",
                                side_effect=MANAGER.ReleaseFailure("service failed")),
              mock.patch.object(MANAGER, "stop_touchid_service")):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "service failed"):
                self.install()
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_touchid_service_plist_is_atomically_installed_with_root_style_mode(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "authorization_service"
        source.write_bytes((REPO / MANAGER.PAYLOAD_SOURCES["authorization_service"]).read_bytes())
        plist = self.root / "LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
        plist.parent.mkdir()
        absent = subprocess.CompletedProcess([], 113, "", "")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(MANAGER.subprocess, "run", side_effect=[absent, completed, completed]) as run:
            MANAGER.install_touchid_service(release, plist)
        self.assertEqual(plist.read_bytes(), source.read_bytes())
        self.assertEqual(plist.stat().st_mode & 0o777, 0o644)
        self.assertEqual(run.call_args_list[-1].args[0][0:3],
                         ["/bin/launchctl", "bootstrap", "system"])

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
        live = active / "live.json"
        live.write_text(json.dumps({"pid": os.getpid(), "release_id": "a" * 64}), encoding="ascii")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_controller_invocations"):
            self.install()
        live.write_text(json.dumps({"pid": 2147483647, "release_id": "a" * 64}), encoding="ascii")
        self.install()
        self.assertFalse(live.exists())

    def test_second_release_can_roll_back(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        second = self.install()["release_id"]
        self.assertNotEqual(first, second)
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, None, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["release_id"], first)
        self.assertFalse(result["repo_match"])
        self.assertEqual((self.install_root / "previous").resolve().name, second)

    def test_first_v1_install_does_not_advertise_legacy_rollback(self):
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
        loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
        self.assertEqual((loaded_path.name, loaded_id), (legacy_id, legacy_id))
        self.install()
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

    def test_stable_launcher_change_requires_explicit_migration(self):
        self.install()
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# incompatible launcher change\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "stable_launcher_change_requires_migration"):
            self.install()

    def test_launcher_migration_is_old_hash_gated_and_backed_up(self):
        self.install()
        old_bytes = self.launcher.read_bytes()
        old_hash = MANAGER.sha256_bytes(old_bytes)
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        replacement_hash = MANAGER.sha256_bytes((self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes())
        result = MANAGER.migrate_launcher(
            self.repo, self.install_root, self.launcher, self.state, self.uid, old_hash, replacement_hash
        )
        self.assertEqual(result["previous_launcher_sha256"], old_hash)
        self.assertEqual(Path(result["backup"]).read_bytes(), old_bytes)
        self.assertEqual(MANAGER.sha256_bytes(self.launcher.read_bytes()), result["launcher_sha256"])
        deployed = self.install()
        self.assertEqual(
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )["release_id"],
            deployed["release_id"],
        )

    def test_authorization_bootstrap_binds_launcher_transition_and_is_restart_safe(self):
        old_release = self.install()["release_id"]
        old_launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# authorization bootstrap launcher\n")
        with (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_broker"]).open(
            "a", encoding="utf-8"
        ) as handle:
            handle.write("# authorization bootstrap broker\n")
        replacement_sha256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes()
        )
        _values, _hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        current_manifest = json.loads(
            ((self.install_root / "current").resolve() / "manifest.json").read_text()
        )
        current_manifest["payloads"] = {
            name: digest for name, digest in current_manifest["payloads"].items()
            if name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        legacy_id = MANAGER.release_identity(current_manifest["payloads"])
        legacy = self.install_root / "releases" / legacy_id
        legacy.mkdir()
        for name in current_manifest["payloads"]:
            shutil.copyfile((self.install_root / "releases" / old_release / name), legacy / name)
            (legacy / name).chmod(MANAGER.EXPECTED_MODES[name])
        current_manifest["release_id"] = legacy_id
        (legacy / "manifest.json").write_text(json.dumps(current_manifest), encoding="utf-8")
        (legacy / "manifest.json").chmod(0o444)
        legacy.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")

        with mock.patch.object(
            MANAGER, "install", side_effect=MANAGER.ReleaseFailure("simulated_post_migration_crash")
        ):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "simulated_post_migration_crash"):
                MANAGER.bootstrap_authorization(
                    self.repo, self.install_root, self.launcher, self.state, self.uid,
                    release_id, old_launcher_sha256, replacement_sha256,
                    self.op_binary, self.gpgv_binary,
                )
        self.assertEqual(MANAGER.sha256_bytes(self.launcher.read_bytes()), replacement_sha256)
        self.assertEqual((self.install_root / "current").resolve().name, legacy_id)

        result = MANAGER.bootstrap_authorization(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            release_id, replacement_sha256, replacement_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "authorization_bootstrapped")
        self.assertFalse(result["launcher_migrated"])
        self.assertEqual(result["previous_release_id"], legacy_id)
        self.assertEqual((self.install_root / "current").resolve().name, release_id)

    def test_maintenance_schema_bootstrap_accepts_exact_predecessor_once(self):
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

        result = MANAGER.bootstrap_maintenance_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "maintenance_schema_bootstrapped")
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_maintenance_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_touchid_schema_bootstrap_accepts_exact_predecessor_once(self):
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

        result = MANAGER.bootstrap_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], old_release)
        recovered = MANAGER.bootstrap_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

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

    def test_profiled_touchid_schema_bootstrap_is_exactly_current_and_one_time(self):
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

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_profiled_touchid_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_profiled_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, old_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "profiled_touchid_schema_bootstrapped")
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_profiled_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])
        rolled_back = MANAGER.rollback(
            self.repo, self.install_root, self.state, old_release, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(rolled_back["release_id"], old_release)
        self.assertEqual((self.install_root / "current").resolve().name, old_release)

    def test_touchid_bundle_v2_schema_bootstrap_is_exactly_current_and_one_time(self):
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
        predecessor = self.install()["release_id"]
        bundle_path.write_text(
            json.dumps(bundle_v2, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _values, _hashes, source_release = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_touchid_bundle_v2_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_touchid_bundle_v2_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, predecessor, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_bundle_v2_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], predecessor)
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_touchid_bundle_v2_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_model_profile_schema_bootstrap_is_exactly_current_and_one_time(self):
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

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_model_profile_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_model_profile_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, old_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "model_profile_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], old_release)
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_model_profile_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_native_stack_schema_bootstrap_is_exactly_current_and_one_time(self):
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
            loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
            self.assertEqual((loaded_path.name, loaded_id), (old_release, old_release))
            launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "current_release_id_unexpected"
            ):
                MANAGER.bootstrap_native_stack_schema(
                    self.repo, self.install_root, self.launcher, self.state, self.uid,
                    source_release, "0" * 64, launcher_sha256, launcher_sha256,
                    self.op_binary, self.gpgv_binary,
                )
            result = MANAGER.bootstrap_native_stack_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, old_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
            self.assertEqual(result["status"], "native_stack_schema_bootstrapped")
            self.assertEqual(result["previous_release_id"], old_release)
            self.assertEqual((self.install_root / "current").resolve().name, source_release)
            recovered = MANAGER.bootstrap_native_stack_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, source_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_authorization_icon_schema_bootstrap_is_exactly_current_and_one_time(self):
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

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_authorization_icon_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_authorization_icon_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, old_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "authorization_icon_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], old_release)
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_authorization_icon_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_operator_ceremony_broker_recovery_accepts_only_exact_predecessor(self):
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
        _values, _hashes, successor = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
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
        result = MANAGER.recover_operator_ceremony_broker(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            successor, predecessor, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "operator_ceremony_broker_recovered")
        self.assertEqual(result["previous_release_id"], predecessor)
        self.assertEqual((self.install_root / "current").resolve().name, successor)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "operator_ceremony_broker_recovery_predecessor_invalid",
        ):
            MANAGER.recover_operator_ceremony_broker(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                successor, successor, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
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
        old_hash = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "replacement_launcher_hash_unexpected"):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                old_hash, "0" * 64,
            )

    def test_rollback_status_survives_unavailable_repository(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        self.install()
        (self.repo / "scripts/pki-host-anchor.py").unlink()
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, first, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "rolled_back")
        self.assertIsNone(result["repo_match"])

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
        shutil.copyfile(REPO / "config/ssh_config", self.release / "ssh_config")
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
SECURE_SANDBOX_RELEASE_ID="{'a' * 64}" exec "$CONTROLLER" "$@"
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


if __name__ == "__main__":
    unittest.main()
