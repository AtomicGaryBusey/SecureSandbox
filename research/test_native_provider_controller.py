#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from research import native_provider_controller as controller
from shared import harness_runtime_binding, native_vendor_stack


ROOT = Path(__file__).resolve().parent.parent
OPERATION_ID = "11111111-1111-4111-8111-111111111111"


def request(schema: str, **fields: object) -> dict:
    return {"schema": schema, **fields,
            "request_sha256": controller.digest(fields)}


class NativeProviderControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        catalog = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(
                encoding="ascii")
        )
        self.stack = catalog["stacks"][0]
        self.stack["harness"]["generation_id"] = "a" * 64
        self.stack["account_binding"]["account_subject_sha256"] = hmac.new(
            b"k" * 32,
            b"anthropic-account-v1\x00alex@example.invalid",
            hashlib.sha256,
        ).hexdigest()
        self.stack["account_binding"]["workspace_sha256"] = hmac.new(
            b"k" * 32,
            b"anthropic-workspace-v1\x00raw-workspace-label",
            hashlib.sha256,
        ).hexdigest()
        self.catalog = {"schema": native_vendor_stack.CATALOG_SCHEMA,
                        "stacks": [self.stack]}
        self.catalog_path = self.root / "catalog.json"
        self.catalog_path.write_bytes(native_vendor_stack.canonical_bytes(self.catalog))
        self.catalog_path.chmod(0o644)
        self.catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(self.catalog)).hexdigest()
        self.stack_sha256 = native_vendor_stack.stack_revision(self.stack)
        self.harness = harness_runtime_binding.make_binding(
            harness_id="claude-code", generation_id="a" * 64,
            manifest_sha256="b" * 64, executable_sha256="c" * 64,
            inventory_sha256="d" * 64,
            adapter_id="claude-native-oauth-v1", adapter_sha256="e" * 64)
        self.identity = SimpleNamespace(
            pw_uid=os.geteuid(), pw_gid=os.getegid(),
            pw_dir="/var/empty", pw_shell="/usr/sbin/nologin")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def status_request(self, *, inspect: bool = True) -> dict:
        fields = {
            "operation_id": OPERATION_ID,
            "stack_id": self.stack["stack_id"],
            "stack_sha256": self.stack_sha256,
            "catalog_sha256": self.catalog_sha256,
        }
        if not inspect:
            fields.update(plan_sha256="1" * 64, authorization_sha256="2" * 64)
        return request(
            controller.INSPECT_REQUEST_SCHEMA if inspect
            else controller.STATUS_REQUEST_SCHEMA, **fields)

    def provider_request(self, action: str, runtime: object = None) -> dict:
        return request(
            controller.PROVIDER_REQUEST_SCHEMA,
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, action=action,
            stack_sha256=self.stack_sha256,
            harness_generation_id="a" * 64, runtime_authority=runtime)

    @staticmethod
    def signed_in_runner(*_args, **_kwargs):
        raw = json.dumps({
            "loggedIn": True, "authMethod": "claude.ai",
            "apiProvider": "firstParty", "analyticsDisabled": True,
            "projectsDirectory": "/tmp/config/projects",
            "configDirectory": "/tmp/config", "loginExpiresAt": None,
            "email": "alex@example.invalid", "orgId": "raw-workspace-label",
            "orgName": "Raw Organization Name", "subscriptionType": "ultra",
        }, separators=(",", ":"), sort_keys=True).encode()
        return subprocess.CompletedProcess([], 0, raw, b"")

    def test_exact_requests_reject_extra_fields_wrong_scope_and_mutation(self) -> None:
        good = self.provider_request("status-verify")
        self.assertEqual(controller.validate_provider_request(good), good)
        for changed in (
            {**good, "token": "forbidden"},
            {**good, "request_sha256": "0" * 64},
            self.provider_request("entitlement-verify", None),
            self.provider_request("status-verify", {"unexpected": True}),
        ):
            with self.assertRaises(controller.NativeProviderControllerError):
                controller.validate_provider_request(changed)

    def test_binding_key_requires_exact_root_equivalent_0400_32_bytes(self) -> None:
        key = self.root / "binding.key"
        key.write_bytes(b"k" * 32)
        key.chmod(0o400)
        self.assertEqual(controller.load_binding_key(
            key, trusted_uid=os.geteuid(), trusted_gid=os.getegid()), b"k" * 32)
        for mode, raw in ((0o600, b"k" * 32), (0o400, b"short")):
            key.chmod(0o600)
            key.write_bytes(raw)
            key.chmod(mode)
            with self.assertRaisesRegex(
                controller.NativeProviderControllerError, "binding_key_untrusted"):
                controller.load_binding_key(
                    key, trusted_uid=os.geteuid(), trusted_gid=os.getegid())

    def test_qualification_authority_is_exact_and_content_free(self) -> None:
        qualification = request(
            controller.QUALIFICATION_REQUEST_SCHEMA,
            action_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256=self.stack_sha256,
            session_id=OPERATION_ID,
            persona_sha256=controller.QUALIFICATION_PERSONA_SHA256,
            tool_catalog_sha256=controller.QUALIFICATION_TOOL_CATALOG_SHA256,
            extension_set_sha256=controller.QUALIFICATION_EXTENSION_SET_SHA256)
        reply = controller.qualification_authority(
            qualification, catalog_path=self.catalog_path,
            runtime_loader=lambda _generation: self.harness)
        self.assertEqual(set(reply), {"schema", "authority", "evidence_sha256"})
        encoded = controller.canonical(reply).lower()
        for forbidden in (b"token", b"email", b"raw-workspace-label"):
            self.assertNotIn(forbidden, encoded)

    def test_status_hmacs_raw_provider_labels_and_reports_retained_custody(self) -> None:
        config_root = self.root / "config"
        config_directory = config_root / self.stack["stack_id"] / "claude-config"
        config_directory.mkdir(parents=True, mode=0o700)
        config_directory.chmod(0o700)
        runner = self.signed_in_runner

        def adjusted_runner(*args, **kwargs):
            result = runner(*args, **kwargs)
            value = json.loads(result.stdout)
            value["configDirectory"] = str(config_directory)
            value["projectsDirectory"] = str(config_directory / "projects")
            return subprocess.CompletedProcess([], 0, json.dumps(
                value, separators=(",", ":"), sort_keys=True).encode(), b"")

        with mock.patch.object(
            controller.native_claude_adapter, "executable_for_harness",
            return_value=Path("/bin/true")
        ), mock.patch.object(controller, "load_binding_key", return_value=b"k" * 32):
            status = controller.operational_status(
                self.status_request(), inspect=True,
                catalog_path=self.catalog_path, config_root=config_root,
                tombstone_root=self.root / "missing-tombstones",
                state_root=self.root / "missing-state",
                grant_path=self.root / "missing-grant",
                session_root=self.root / "missing-sessions",
                now=1_800_000_000,
                runtime_loader=lambda _generation: self.harness,
                claude_runner=adjusted_runner, command_prefix=(),
                identity=self.identity, trusted_uid=os.geteuid())
        self.assertEqual(status["authentication"]["state"], "signed-in")
        self.assertEqual(status["account_binding"]["state"], "bound")
        self.assertEqual(status["credential_custody"]["state"], "retained")
        encoded = controller.canonical(status).lower()
        for raw in (b"alex@example.invalid", b"raw-workspace-label",
                    b"raw organization name", b"ultra"):
            self.assertNotIn(raw, encoded)

    def test_credential_destroy_creates_durable_content_free_absence_tombstone(self) -> None:
        state = self.root / "state"
        tombstones = self.root / "tombstones"
        state.mkdir(mode=0o700)
        tombstones.mkdir(mode=0o700)
        config_root = self.root / "config"
        config = config_root / self.stack["stack_id"] / "claude-config"
        config.mkdir(parents=True, mode=0o700)
        signed_out = {
            "loggedIn": False, "authMethod": "none", "apiProvider": "firstParty",
            "analyticsDisabled": True, "projectsDirectory": str(config / "projects"),
            "configDirectory": str(config), "loginExpiresAt": None,
        }

        def runner(*_args, **_kwargs):
            return subprocess.CompletedProcess([], 1, json.dumps(
                signed_out, separators=(",", ":"), sort_keys=True).encode(), b"")

        with mock.patch.object(
            controller.native_claude_adapter, "executable_for_harness",
            return_value=Path("/bin/true")
        ), mock.patch.object(controller, "load_binding_key", return_value=b"k" * 32), \
                mock.patch.object(controller, "_identity", return_value=self.identity):
            result = controller.provider_action(
                self.provider_request("credential-destroy"),
                catalog_path=self.catalog_path, state_root=state,
                tombstone_root=tombstones, config_root=config_root,
                now=1_800_000_000,
                runtime_loader=lambda _generation: self.harness,
                claude_runner=runner, command_prefix=(),
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())
            custody = controller.credential_custody_observation(
                self.stack, stack_sha256=self.stack_sha256,
                now=1_800_000_001, config_root=config_root,
                tombstone_root=tombstones, trusted_uid=os.geteuid(),
                identity=self.identity)
        self.assertEqual(result["status"], "verified")
        self.assertFalse(config.exists())
        self.assertEqual(custody["state"], "absent")
        self.assertIsNotNone(custody["tombstone_sha256"])
        encoded = (controller.canonical(result) + controller.canonical(custody)).lower()
        self.assertNotIn(b"claude-config", encoded)
        self.assertNotIn(b"token", encoded)

    def test_signin_consumes_one_exact_content_free_login_proof(self) -> None:
        state = self.root / "state"
        proofs = self.root / "proofs"
        state.mkdir(mode=0o700)
        proofs.mkdir(mode=0o700)
        authentication = {"state": "signed-in", "observed_at": 1_800_000_000,
                          "evidence_sha256": "3" * 64}
        account = {"state": "bound",
                   "account_subject_sha256": self.stack["account_binding"]["account_subject_sha256"],
                   "workspace_sha256": self.stack["account_binding"]["workspace_sha256"],
                   "observed_at": 1_800_000_000, "evidence_sha256": "4" * 64}
        controller.write_login_proof(
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256=self.stack_sha256,
            harness_generation_id="a" * 64, authentication=authentication,
            account_binding=account, proof_root=proofs,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        result = controller.provider_action(
            self.provider_request("signin-begin"),
            catalog_path=self.catalog_path, state_root=state,
            login_proof_root=proofs, now=1_800_000_001,
            runtime_loader=lambda _generation: self.harness,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        self.assertEqual(result["status"], "verified")
        self.assertFalse((proofs / f"{OPERATION_ID}.json").exists())
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError,
            "interactive_login_channel_required",
        ):
            controller.provider_action(
                self.provider_request("signin-begin"),
                catalog_path=self.catalog_path, state_root=state,
                login_proof_root=proofs, now=1_800_000_002,
                runtime_loader=lambda _generation: self.harness,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())

    def test_lifecycle_idle_is_catalog_content_free_and_rejects_live_session(self) -> None:
        lifecycle = self.root / "lifecycle"
        lifecycle.mkdir(mode=0o700)
        idle = request(
            controller.IDLE_REQUEST_SCHEMA, promotion_id=OPERATION_ID,
            plan_sha256="1" * 64, catalog_sha256=self.catalog_sha256)
        reply = controller.lifecycle_idle(
            idle, session_root=self.root / "absent", lifecycle_root=lifecycle,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        self.assertEqual(reply["state"], "idle")
        self.assertTrue((lifecycle / "promotion-fence.json").is_file())
        released = controller.lifecycle_release(request(
            controller.RELEASE_REQUEST_SCHEMA, promotion_id=OPERATION_ID,
            plan_sha256="1" * 64, catalog_sha256=self.catalog_sha256),
            lifecycle_root=lifecycle, trusted_uid=os.geteuid(),
            trusted_gid=os.getegid())
        self.assertEqual(released["state"], "released")
        self.assertFalse((lifecycle / "promotion-fence.json").exists())
        sessions = self.root / "sessions"
        sessions.mkdir()
        (sessions / OPERATION_ID).mkdir()
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "lifecycle_busy"):
            controller.lifecycle_idle(
                idle, session_root=sessions, lifecycle_root=lifecycle,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())

    def test_prebinding_status_exposes_only_opaque_observed_digests(self) -> None:
        self.stack["account_binding"]["account_subject_sha256"] = None
        self.stack["account_binding"]["workspace_sha256"] = None
        self.catalog_path.write_bytes(native_vendor_stack.canonical_bytes(self.catalog))
        self.catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(self.catalog)).hexdigest()
        self.stack_sha256 = native_vendor_stack.stack_revision(self.stack)
        config_root = self.root / "config"
        config = config_root / self.stack["stack_id"] / "claude-config"
        config.mkdir(parents=True, mode=0o700)

        def runner(*_args, **_kwargs):
            result = self.signed_in_runner()
            value = json.loads(result.stdout)
            value["configDirectory"] = str(config)
            value["projectsDirectory"] = str(config / "projects")
            return subprocess.CompletedProcess([], 0, json.dumps(
                value, separators=(",", ":"), sort_keys=True).encode(), b"")

        with mock.patch.object(
            controller.native_claude_adapter, "executable_for_harness",
            return_value=Path("/bin/true")
        ), mock.patch.object(controller, "load_binding_key", return_value=b"k" * 32):
            status = controller.operational_status(
                self.status_request(), inspect=True,
                catalog_path=self.catalog_path, config_root=config_root,
                tombstone_root=self.root / "missing-tombstones",
                state_root=self.root / "missing-state",
                grant_path=self.root / "missing-grant",
                session_root=self.root / "missing-sessions",
                now=1_800_000_000,
                runtime_loader=lambda _generation: self.harness,
                claude_runner=runner, command_prefix=(), identity=self.identity,
                trusted_uid=os.geteuid())
        self.assertEqual(status["authentication"]["state"], "signed-in")
        self.assertEqual(status["account_binding"]["state"], "observed")
        self.assertRegex(status["account_binding"]["account_subject_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["account_binding"]["workspace_sha256"], r"^[0-9a-f]{64}$")
        encoded = controller.canonical(status).lower()
        for raw in (b"alex@example.invalid", b"raw-workspace-label",
                    b"raw organization name", b"ultra"):
            self.assertNotIn(raw, encoded)


if __name__ == "__main__":
    unittest.main()
