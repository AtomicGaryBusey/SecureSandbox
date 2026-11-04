#!/usr/bin/env python3

from __future__ import annotations

import contextlib
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

    def test_session_authority_requires_exact_source_and_policy_readback(self) -> None:
        fields = {
            "operation_id": OPERATION_ID,
            "stack_sha256": self.stack_sha256,
            "catalog_sha256": self.catalog_sha256,
            "session_id": "22222222-2222-4222-8222-222222222222",
            "source_id": None, "source_manifest_sha256": None,
            "persona_sha256": "1" * 64,
            "tool_catalog_sha256": "2" * 64,
            "extension_set_sha256": "3" * 64,
        }
        session_request = request(
            controller.SESSION_AUTHORITY_REQUEST_SCHEMA, **fields)
        measured = {
            "schema": controller.session_policy_runtime.SCHEMA,
            **{field: fields[field] for field in (
                "source_id", "source_manifest_sha256", "persona_sha256",
                "tool_catalog_sha256", "extension_set_sha256")},
        }
        reply = controller.session_authority(
            session_request, catalog_path=self.catalog_path,
            runtime_loader=lambda _generation: self.harness,
            policy_loader=lambda source: measured if source == "none" else {})
        self.assertEqual(set(reply), {"schema", "authority", "evidence_sha256"})
        self.assertEqual(
            reply["authority"]["session_context_binding"]["session_id"],
            fields["session_id"])
        changed = {**measured, "persona_sha256": "9" * 64}
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "readback_mismatch"
        ):
            controller.session_authority(
                session_request, catalog_path=self.catalog_path,
                runtime_loader=lambda _generation: self.harness,
                policy_loader=lambda _source: changed)

    def test_session_plan_authority_measures_policy_without_caller_digests(
        self,
    ) -> None:
        fields = {
            "operation_id": OPERATION_ID,
            "stack_id": self.stack["stack_id"],
            "stack_sha256": self.stack_sha256,
            "catalog_sha256": self.catalog_sha256,
            "session_id": "22222222-2222-4222-8222-222222222222",
            "source_id": None,
        }
        plan_request = request(
            controller.SESSION_PLAN_AUTHORITY_REQUEST_SCHEMA, **fields
        )
        measured = {
            "schema": controller.session_policy_runtime.SCHEMA,
            "source_id": None,
            "source_manifest_sha256": None,
            "persona_sha256": "1" * 64,
            "tool_catalog_sha256": "2" * 64,
            "extension_set_sha256": "3" * 64,
        }
        reply = controller.session_plan_authority(
            plan_request, catalog_path=self.catalog_path,
            runtime_loader=lambda _generation: self.harness,
            policy_loader=lambda source: measured if source == "none" else {},
        )
        self.assertEqual(
            set(reply), {"schema", "authority", "evidence_sha256"}
        )
        context = reply["authority"]["session_context_binding"]
        self.assertEqual(context["session_id"], fields["session_id"])
        self.assertEqual(context["source_id"], fields["source_id"])
        self.assertNotIn("persona_sha256", plan_request)
        changed = dict(plan_request)
        changed["stack_id"] = "substituted-stack"
        changed_body = {
            key: value for key, value in changed.items()
            if key not in {"schema", "request_sha256"}
        }
        changed["request_sha256"] = controller.digest(changed_body)
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "stack_mismatch"
        ):
            controller.session_plan_authority(
                changed, catalog_path=self.catalog_path,
                runtime_loader=lambda _generation: self.harness,
                policy_loader=lambda _source: measured,
            )

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
        handles = self.root / "handles"
        state.mkdir(mode=0o700)
        proofs.mkdir(mode=0o700)
        handles.mkdir(mode=0o700)
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
        controller.native_claude_login_replay.claim_handle(
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256=self.stack_sha256,
            catalog_sha256=self.catalog_sha256, root=handles,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        result = controller.provider_action(
            self.provider_request("signin-begin"),
            catalog_path=self.catalog_path, state_root=state,
            login_proof_root=proofs, login_handle_root=handles,
            now=1_800_000_001,
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
                login_proof_root=proofs, login_handle_root=handles,
                now=1_800_000_002,
                runtime_loader=lambda _generation: self.harness,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())

    def test_login_compaction_is_exact_touchid_bound_and_content_free(self) -> None:
        handles = self.root / "handles"
        proofs = self.root / "proofs"
        handles.mkdir(mode=0o700)
        proofs.mkdir(mode=0o700)
        key = self.root / "binding.key"
        key.write_bytes(b"k" * 32)
        key.chmod(0o400)
        controller.native_claude_login_replay.claim_handle(
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256=self.stack_sha256,
            catalog_sha256=self.catalog_sha256, root=handles,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        controller.native_claude_login_replay.finalize_handle(
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256=self.stack_sha256,
            result_evidence_sha256="8" * 64, root=handles,
            trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            now=1_800_000_000)
        compact = request(
            controller.LOGIN_COMPACT_REQUEST_SCHEMA,
            operation_id="22222222-2222-4222-8222-222222222222",
            plan_sha256="6" * 64, authorization_sha256="7" * 64)
        with mock.patch.object(
            controller.native_lifecycle_fence, "admission_open",
            return_value=contextlib.nullcontext(),
        ):
            result = controller.compact_login_replay(
                compact, binding_key_path=key, handle_root=handles,
                proof_root=proofs, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), now=lambda: 1_800_000_001)
        self.assertEqual(result, {
            "schema": controller.PROVIDER_RESULT_SCHEMA,
            "action_id": compact["operation_id"],
            "action": "claude-login-compact",
            "plan_sha256": compact["plan_sha256"],
            "authorization_sha256": compact["authorization_sha256"],
            "status": "verified",
            "evidence_sha256": result["evidence_sha256"],
        })
        self.assertNotIn(b"email", controller.canonical(result).lower())

    def test_mythos_access_does_not_fabricate_cvp_program_entitlement(self) -> None:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        authority = controller.make_authority(
            self.stack, self.harness, session_id=OPERATION_ID,
            persona_sha256=controller.QUALIFICATION_PERSONA_SHA256,
            tool_catalog_sha256=controller.QUALIFICATION_TOOL_CATALOG_SHA256,
            extension_set_sha256=controller.QUALIFICATION_EXTENSION_SET_SHA256)
        entitlement = json.dumps({
            "subtype": "success", "is_error": False,
            "result": "SECURE_SANDBOX_ENTITLEMENT_READY",
            "modelUsage": {
                controller.native_claude_adapter.CLAUDE_MODEL_ID: {
                    "inputTokens": 1, "outputTokens": 1}},
        }, separators=(",", ":")).encode()

        def runner(command, **_kwargs):
            if "status" in command:
                return self.signed_in_runner()
            return subprocess.CompletedProcess([], 0, entitlement, b"")

        with mock.patch.object(
            controller.native_claude_adapter, "executable_for_harness",
            return_value=Path("/bin/true")
        ), mock.patch.object(
            controller.native_claude_adapter, "executable_for_authority",
            return_value=Path("/bin/true")
        ), mock.patch.object(controller, "load_binding_key", return_value=b"k" * 32):
            result = controller.provider_action(
                self.provider_request("entitlement-verify", authority),
                catalog_path=self.catalog_path, state_root=state,
                now=1_800_000_000,
                runtime_loader=lambda _generation: self.harness,
                claude_runner=runner, command_prefix=(),
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())
        self.assertEqual(result["status"], "verified")
        persisted = controller._read_state(
            self.stack_sha256, state_root=state,
            trusted_uid=os.geteuid())
        self.assertEqual(persisted["model_entitlement"]["state"], "verified")
        self.assertEqual(persisted["program_entitlement"]["state"], "unknown")
        self.assertEqual(
            persisted["model_entitlement"]["assurance"], "provider-enforced")
        self.assertEqual(persisted["program_entitlement"]["assurance"], "unknown")

    def test_touchid_program_attestation_is_exact_and_operator_external(self) -> None:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        attestation = request(
            controller.PROGRAM_ATTESTATION_REQUEST_SCHEMA,
            operation_id=OPERATION_ID, plan_sha256="1" * 64,
            authorization_sha256="2" * 64,
            stack_sha256=self.stack_sha256,
            harness_generation_id="a" * 64,
            account_subject_sha256=(
                self.stack["account_binding"]["account_subject_sha256"]),
            workspace_sha256=self.stack["account_binding"]["workspace_sha256"],
            program_id="anthropic-cvp", program_tier="defense",
            program_requirements_version="anthropic-cvp-defense-2026-10-31",
            attestation_receipt_sha256="5" * 64)
        result = controller.program_attestation(
            attestation, catalog_path=self.catalog_path, state_root=state,
            now=1_800_000_000, trusted_uid=os.geteuid(),
            trusted_gid=os.getegid())
        self.assertEqual(result["action"], "program-attest")
        persisted = controller._read_state(
            self.stack_sha256, state_root=state,
            trusted_uid=os.geteuid())
        self.assertEqual(persisted["program_entitlement"]["state"], "verified")
        self.assertEqual(
            persisted["program_entitlement"]["assurance"], "operator-external")
        self.assertEqual(
            persisted["program_attestation"]["assurance"], "operator-external")
        self.assertNotIn("vendor-verified", controller.canonical(persisted).decode())
        changed = dict(attestation)
        changed["workspace_sha256"] = "6" * 64
        changed["request_sha256"] = controller.digest({
            key: changed[key] for key in changed
            if key not in {"schema", "request_sha256"}})
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "scope_mismatch"):
            controller.program_attestation(
                changed, catalog_path=self.catalog_path, state_root=state,
                now=1_800_000_001, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid())

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

    def test_projection_isolation_status_is_fresh_exact_and_content_free(self) -> None:
        observed_at = 1_800_000_000
        value = request(
            controller.PROJECTION_ISOLATION_REQUEST_SCHEMA,
            operation_id=OPERATION_ID)
        reply = controller.projection_isolation_status(
            value, now=observed_at,
            observer=lambda: {
                "research_release_id": "a" * 64,
                "isolation_attestation_sha256": "b" * 64,
                "observed_at": observed_at,
                "expires_at": observed_at + 120,
            })
        self.assertEqual(set(reply), {
            "schema", "operation_id", "research_release_id",
            "isolation_attestation_sha256", "observed_at", "expires_at",
            "evidence_sha256",
        })
        self.assertEqual(reply["schema"],
                         controller.PROJECTION_ISOLATION_REPLY_SCHEMA)
        self.assertEqual(reply["evidence_sha256"], controller.digest({
            key: reply[key] for key in reply if key != "evidence_sha256"}))
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "observation_stale"
        ):
            controller.projection_isolation_status(
                value, now=observed_at,
                observer=lambda: {
                    "research_release_id": "a" * 64,
                    "isolation_attestation_sha256": "b" * 64,
                    "observed_at": observed_at - 121,
                    "expires_at": observed_at + 1,
                })

    def test_projection_isolation_status_rejects_when_observer_unavailable(self) -> None:
        value = request(
            controller.PROJECTION_ISOLATION_REQUEST_SCHEMA,
            operation_id=OPERATION_ID)
        with self.assertRaisesRegex(
            controller.NativeProviderControllerError, "unqualified"
        ):
            controller.projection_isolation_status(value)


if __name__ == "__main__":
    unittest.main()
