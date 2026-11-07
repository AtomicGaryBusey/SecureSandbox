#!/usr/bin/env python3

import base64
import contextlib
import hashlib
import io
import importlib.util
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.test_native_stack_manager import runtime_for, status_for


SCRIPT = Path(__file__).with_name("operator-authorization.py")
SPEC = importlib.util.spec_from_file_location("operator_authorization", SCRIPT)
AUTH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUTH)


class OperatorAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.uid = os.geteuid()
        self.identity = SimpleNamespace(pw_dir=str(self.home))
        self.pwd = mock.patch.object(AUTH.pwd, "getpwuid", return_value=self.identity)
        self.pwd.start()
        self.touchid_ui = mock.patch.object(AUTH, "DEFAULT_TOUCHID_UI", self.root / "missing-ui")
        self.touchid_ui.start()
        self.team_id = "ABCDE" + "12345"
        self.access_group = self.team_id + ".org.zebeth.SecureSandbox.AuthorizationUI"
        self.signing_policy = mock.patch.object(
            AUTH, "touchid_signing_policy", return_value={
                "access_group": self.access_group,
                "application_identifier": self.access_group,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": self.team_id,
            },
        )
        self.signing_policy.start()

    def tearDown(self):
        self.signing_policy.stop()
        self.touchid_ui.stop()
        self.pwd.stop()
        self.temporary.cleanup()

    @contextlib.contextmanager
    def extended_acl(self, path: Path, rule: str):
        if sys.platform != "darwin":
            self.skipTest("Darwin extended ACL contract")
        added = subprocess.run(
            ["/bin/chmod", "+a", rule, str(path)],
            check=False, capture_output=True, text=True,
        )
        if added.returncode != 0:
            self.skipTest("extended ACL fixture unavailable")
        try:
            yield
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(path)], check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    def parameters(self):
        return {"generation_id": "12345678-1234-4123-8123-123456789abc"}

    def native_host_candidate(self, repo: Path) -> dict[str, object]:
        commit = "c" * 40
        generation = (
            repo / ".private/native-host-product-candidates"
            / (commit + "-12345678-1234-4123-8123-123456789abc")
            / "generation"
        )
        generation.mkdir(parents=True, exist_ok=True)
        evidence = generation.parent / "evidence"
        evidence.mkdir(mode=0o700, exist_ok=True)
        preimage = evidence / AUTH.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
        if not preimage.exists():
            preimage.write_bytes(b"p" * 1024)
            preimage.chmod(0o400)
        info = generation.lstat()
        preimage_info = preimage.lstat()
        return {
            "schema": AUTH.NATIVE_HOST_CANDIDATE_SCHEMA,
            "build_custody": "trusted-login-principal-v1",
            "generation_path": str(generation),
            "generation_device": info.st_dev,
            "generation_inode": info.st_ino,
            "generation_tree_sha256": "1" * 64,
            "host_release_preimage_path": str(preimage),
            "host_release_preimage_device": preimage_info.st_dev,
            "host_release_preimage_inode": preimage_info.st_ino,
            "host_release_preimage_size": preimage_info.st_size,
            "host_release_preimage_sha256": "6" * 64,
            "host_release_preimage_schema": (
                AUTH.NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA
            ),
            "release_commit": commit,
            "signing_config_sha256": "2" * 64,
            "source_archive_sha256": "3" * 64,
            "source_tree_sha256": "4" * 64,
            "developer_id_certificate_sha1": "5" * 40,
            "notary_submission_id": (
                "12345678-1234-4123-8123-123456789abc"
            ),
        }

    def host_install_parameters(self, repo: Path) -> dict[str, object]:
        candidate = self.native_host_candidate(repo)
        payloads = {
            name: hashlib.sha256(name.encode("ascii")).hexdigest()
            for name in AUTH.EXPECTED_RELEASE_MODES
        }
        plan = {
            "candidate_record_sha256": hashlib.sha256(
                AUTH.canonical_v2(candidate)
            ).hexdigest(),
            "payloads": payloads,
            "release_id": AUTH.host_release_identity(payloads),
            "schema": AUTH.HOST_RELEASE_TARGET_PLAN_SCHEMA,
            "source_stable_sha256": "7" * 64,
            "target_launcher_sha256": "8" * 64,
        }
        return {
            "repo": str(repo),
            "state_root": str(
                self.home
                / "Library/Application Support/SecureSandbox/controller-state"
            ),
            "authorized_target_plan": plan,
            "authorized_target_plan_sha256": hashlib.sha256(
                AUTH.canonical(plan)
            ).hexdigest(),
            "native_host_candidate": candidate,
        }

    def host_rollback_parameters(self, repo: Path) -> dict[str, object]:
        plan = {
            "operation": "rollback",
            "schema": AUTH.HOST_RELEASE_ROLLBACK_PLAN_SCHEMA,
            "source_stable_sha256": "1" * 64,
            "target_candidate_authority_sha256": "2" * 64,
            "target_launcher_sha256": "3" * 64,
            "target_release_id": "4" * 64,
            "target_release_tree_identity_sha256": "5" * 64,
        }
        return {
            "repo": str(repo),
            "state_root": str(
                self.home
                / "Library/Application Support/SecureSandbox/controller-state"
            ),
            "authorized_target_plan": plan,
            "authorized_target_plan_sha256": hashlib.sha256(
                AUTH.canonical(plan)
            ).hexdigest(),
        }

    def bound_request_fixture(
        self, request_id: str = "12345678-1234-4123-8123-123456789abc",
    ):
        now = int(time.time())
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": now, "expires_at": now + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid, "declared_agent": "Codex",
            "declared_session": "request-binding-test",
            "identity_evidence": "operator-declared",
            "purpose": "Begin exact PKI rotation",
            "resource": AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
            "operation": "pki-anchor-begin", "parameters": self.parameters(),
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        observed, binding = AUTH.open_request_binding(
            path, self.uid, request_sha256
        )
        self.assertEqual(observed, value)
        return now, path, request_sha256, binding

    def model_profile_plan(self):
        current = {"adapter":"anthropic-messages-v1", "mode":"production",
                   "model":"old-model", "profile_id":"old-profile",
                   "profile_sha256":"b" * 64, "vendor_id":"old-vendor"}
        plan = {
            "activation_id":"12345678-1234-4123-8123-123456789abc",
            "broker":{"adapter":"anthropic-messages-v1", "allowed_models":["new-model"],
                      "client_timeout_seconds":15, "credential_scheme":"bearer",
                      "max_request_bytes":1024, "max_response_bytes":2048,
                      "max_tokens":128, "mode":"mock", "oauth_ipv4":[],
                      "profile_id":"new-profile", "profile_sha256":"a" * 64,
                      "rate_limit_requests":2, "rate_limit_window_seconds":60,
                      "settings":{"maximum_output_tokens":128},
                      "upstream_ipv4":[], "upstream_origin":"https://example.test",
                      "upstream_timeout_seconds":30, "vendor_id":"new-vendor"},
            "created_at":2_000_000_000, "credential_reference":"op://Agents/Test/token",
            "current":{"gateway":current, "research":current},
            "current_generation_sha256":hashlib.sha256(AUTH.canonical_v2(
                {"gateway":current, "research":current})).hexdigest(),
            "expires_at":2_000_000_300, "lease_profiles":{"profiles":{}},
            "schema":"secure-sandbox-model-profile-activation-plan-v1",
        }
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical_v2(plan)).hexdigest()
        return plan

    def native_stack_status_fixture(self):
        stack = json.loads(
            (SCRIPT.parent.parent / "config/native-vendor-stacks.example.json").read_text()
        )["stacks"][1]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64

        def observation(state, **extra):
            return {"state":state, "observed_at":2_000_000_000,
                    "evidence_sha256":"d" * 64, **extra}

        status = AUTH.native_stack_operations.make_status(
            stack=stack,
            harness=observation(
                "admitted", generation_id="a" * 64, binding_sha256="e" * 64,
            ),
            authentication=observation("signed-in"),
            credential_custody={
                "state":"retained", "observed_at":2_000_000_000,
                "evidence_sha256":"9" * 64, "tombstone_sha256":None,
                "projection_count":0,
            },
            account_binding=observation(
                "bound", account_subject_sha256="b" * 64,
                workspace_sha256="c" * 64,
            ),
            program_entitlement=observation(
                "verified", assurance="operator-external"
            ),
            model_entitlement=observation(
                "verified", assurance="provider-enforced"
            ),
            network={"phase":"closed", "grant_sha256":None, "expires_at":None,
                     "observed_at":2_000_000_000},
            activation=observation("inactive", receipt_sha256=None),
            live_run_count=0,
        )
        return stack, status

    def native_stack_plan(self, action="activate"):
        stack, status = self.native_stack_status_fixture()
        return AUTH.native_stack_operations.make_plan(
            stack=stack, status=status, action=action, created_at=2_000_000_000,
            action_id="77777777-7777-4777-8777-777777777777",
        )

    def native_program_plan(self):
        stack = json.loads(
            (SCRIPT.parent.parent / "config/native-vendor-stacks.example.json").read_text()
        )["stacks"][0]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64

        def observation(state, **extra):
            return {"state":state, "observed_at":2_000_000_000,
                    "evidence_sha256":"d" * 64, **extra}

        status = AUTH.native_stack_operations.make_status(
            stack=stack,
            harness=observation(
                "admitted", generation_id="a" * 64, binding_sha256="e" * 64,
            ),
            authentication=observation("signed-in"),
            credential_custody={
                "state":"retained", "observed_at":2_000_000_000,
                "evidence_sha256":"9" * 64, "tombstone_sha256":None,
                "projection_count":0,
            },
            account_binding=observation(
                "bound", account_subject_sha256="b" * 64,
                workspace_sha256="c" * 64,
            ),
            program_entitlement=observation("unknown", assurance="unknown"),
            model_entitlement=observation(
                "verified", assurance="provider-enforced"
            ),
            network={"phase":"closed", "grant_sha256":None,
                     "expires_at":None, "observed_at":2_000_000_000},
            activation=observation("inactive", receipt_sha256=None),
            live_run_count=0,
        )
        plan = AUTH.native_program_attestation.make_plan(
            stack=stack, catalog_sha256="2" * 64, status_value=status,
            attestation_id="99999999-9999-4999-8999-999999999999",
            created_at=2_000_000_000,
        )
        return stack, status, plan

    def projection_reconciliation_plan(self, host_release_id="4" * 64):
        stack, _status = self.native_stack_status_fixture()
        return AUTH.native_projection_reconciliation.make_plan(
            recovery_operation_id=(
                "66666666-6666-4666-8666-666666666666"
            ),
            original_operation_id=(
                "77777777-7777-4777-8777-777777777777"
            ),
            session_id="00000000-0000-4000-8000-000000000009",
            stack_id=stack["stack_id"],
            stack_sha256=AUTH.native_vendor_stack.stack_revision(stack),
            session_authority_sha256="5" * 64,
            process_identifier=4242, process_start_time_us=123456,
            consumer_executable_sha256="6" * 64,
            guest_absence_evidence_sha256="7" * 64,
            egress_closed_evidence_sha256="8" * 64,
            host_release_id=host_release_id,
            created_at=2_000_000_000,
        )

    def projection_identity_recovery_plan(self, host_release_id="4" * 64):
        stack, _status = self.native_stack_status_fixture()
        return AUTH.native_projection_identity_recovery.make_plan(
            recovery_operation_id=(
                "66666666-6666-4666-8666-666666666666"
            ),
            original_operation_id=(
                "77777777-7777-4777-8777-777777777777"
            ),
            session_id="00000000-0000-4000-8000-000000000009",
            stack_id=stack["stack_id"],
            stack_sha256=AUTH.native_vendor_stack.stack_revision(stack),
            session_authority_sha256="5" * 64,
            host_release_id=host_release_id,
            created_at=2_000_000_000,
        )

    def native_deployment_plan_response(
        self, host_release_id="a" * 64, *, now=2_000_000_000,
    ):
        gateway = AUTH.native_deployment.make_status(
            role="gateway", package_sha256=None, release_id=None,
            catalog_sha256=None, closed_evidence_sha256=None,
            observed_at=now, state="absent", generation_kind="absent")
        research = AUTH.native_deployment.make_status(
            role="research", package_sha256=None, release_id=None,
            catalog_sha256=None, closed_evidence_sha256=None,
            observed_at=now, state="absent", generation_kind="absent")
        plan = AUTH.native_deployment.make_plan(
            deployment_id="00000000-0000-4000-8000-000000000000",
            host_release_id=host_release_id, catalog_sha256="b" * 64,
            gateway_package_sha256="c" * 64,
            research_package_sha256="d" * 64,
            previous_gateway_package_sha256=None,
            previous_research_package_sha256=None,
            previous_gateway_status_sha256=(
                AUTH.native_deployment.stable_status_sha256(gateway)),
            previous_research_status_sha256=(
                AUTH.native_deployment.stable_status_sha256(research)),
            created_at=now, expires_at=now + 3600)
        body = {
            "plan": plan, "prior_gateway": gateway,
            "prior_research": research,
            "payload_container_sha256": "e" * 64,
        }
        return {
            "schema": AUTH.NATIVE_DEPLOYMENT_PLAN_RESPONSE_SCHEMA,
            **body, "response_sha256": AUTH.native_deployment.digest(body),
        }

    def native_deployment_recovery_plan(self, response=None):
        response = response or self.native_deployment_plan_response()
        body = {
            "active_journal_sha256": "f" * 64,
            "deployment_id": response["plan"]["deployment_id"],
            "host_release_id": response["plan"]["host_release_id"],
            "phase": "recovery-required", "observed_pair": "prior-prior",
            "allowed_actions": ["rollback", "resume"],
            "plan_response": response,
            "gateway_status_sha256": response["plan"][
                "previous_gateway_status_sha256"],
            "research_status_sha256": response["plan"][
                "previous_research_status_sha256"],
        }
        return {
            "schema": AUTH.NATIVE_DEPLOYMENT_RECOVERY_PLAN_SCHEMA,
            **body,
            "recovery_plan_sha256": AUTH.native_deployment.digest(body),
        }

    def native_deployment_authorization(
        self, response=None, *, operation=None, action=None,
    ):
        response = response or self.native_deployment_plan_response()
        operation = operation or AUTH.native_deployment.APPLY_OPERATION
        action = action or (
            "apply" if operation == AUTH.native_deployment.APPLY_OPERATION
            else "resume")
        return AUTH.native_deployment.make_authorization(
            response["plan"],
            authorization_id="00000000-0000-4000-8000-000000000003",
            request_sha256="1" * 64, pending_receipt_sha256="2" * 64,
            requesting_agent_sha256="3" * 64,
            requesting_session_sha256="4" * 64,
            authorized_at=2_000_000_100, expires_at=2_000_000_220,
            operation=operation, recovery_action=action,
            active_journal_sha256=(
                None if operation == AUTH.native_deployment.APPLY_OPERATION
                else "f" * 64),
        )

    def native_deployment_terminal(
        self, response=None, authorization=None, *, phase="committed",
    ):
        response = response or self.native_deployment_plan_response()
        authorization = authorization or self.native_deployment_authorization(
            response)
        plan = response["plan"]
        if phase == "committed":
            gateway = AUTH.native_deployment.stable_status_projection(
                AUTH.native_deployment.make_status(
                    role="gateway", state="verified",
                    generation_kind="protected",
                    package_sha256=plan["gateway_package_sha256"],
                    release_id="5" * 64, catalog_sha256=None,
                    closed_evidence_sha256="6" * 64, observed_at=1))
            research = AUTH.native_deployment.stable_status_projection(
                AUTH.native_deployment.make_status(
                    role="research", state="verified",
                    generation_kind="protected",
                    package_sha256=plan["research_package_sha256"],
                    release_id="7" * 64,
                    catalog_sha256=plan["catalog_sha256"],
                    closed_evidence_sha256="8" * 64, observed_at=1))
        else:
            gateway = AUTH.native_deployment.stable_status_projection(
                response["prior_gateway"])
            research = AUTH.native_deployment.stable_status_projection(
                response["prior_research"])
        evidence = {
            "gateway_status": gateway, "research_status": research,
            "gateway_status_sha256": (
                AUTH.native_deployment.status_projection_sha256(gateway)),
            "research_status_sha256": (
                AUTH.native_deployment.status_projection_sha256(research)),
            "fence_evidence_sha256": None, "result_sha256": None,
            "terminal_sha256": "9" * 64, "outcome": phase,
        }
        body = {
            "deployment_id": plan["deployment_id"], "sequence": 6,
            "phase": phase, "plan": plan,
            "apply_authorization_sha256": authorization[
                "authorization_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "host_release_id": plan["host_release_id"],
            "payload_container_sha256": response[
                "payload_container_sha256"],
            "prior_gateway": response["prior_gateway"],
            "prior_research": response["prior_research"],
            "event": phase, "evidence": evidence, "transport": None,
            "prior_record_sha256": "a" * 64, "updated_at": 2_000_000_200,
        }
        return {
            "schema": "secure-sandbox-native-deployment-journal-record-v1",
            **body, "record_sha256": AUTH.native_deployment.digest(body),
        }

    def native_catalog_plan(self, host_release_id="a" * 64):
        return AUTH.native_stack_catalog_promotion.make_plan(
            source_uid=max(1, self.uid), source_sha256="b" * 64,
            previous_catalog_sha256="c" * 64,
            host_release_id=host_release_id, now=2_000_000_000,
            promotion_id="00000000-0000-4000-8000-000000000001",
        )

    def native_catalog_authorization(self, plan=None):
        plan = plan or self.native_catalog_plan()
        value = {
            "schema": AUTH.native_stack_catalog_promotion.AUTHORIZATION_SCHEMA,
            "authorization_id": "00000000-0000-4000-8000-000000000004",
            "request_sha256": "1" * 64,
            "pending_receipt_sha256": "2" * 64,
            "promotion_id": plan["promotion_id"],
            "plan_sha256": plan["plan_sha256"],
            "method": "touch-id", "password_fallback": False,
            "authorized_at": 2_000_000_010,
            "expires_at": 2_000_000_120,
            "host_release_id": plan["host_release_id"],
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = (
            AUTH.native_stack_catalog_promotion.sha256(value)
        )
        return value

    def native_catalog_gate(self, state="active"):
        body = {
            "state": state,
            "active_promotion_id": (
                "00000000-0000-4000-8000-000000000001"
                if state == "active" else None
            ),
            "active_state_sha256": "5" * 64 if state == "active" else None,
        }
        return {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_GATE_SCHEMA,
            **body, "gate_sha256": AUTH.native_deployment.digest(body),
        }

    def native_catalog_recovery_terminal(self, host_release_id="a" * 64):
        body = {
            "state": "finalized",
            "promotion_id": "00000000-0000-4000-8000-000000000001",
            "catalog_sha256": "b" * 64,
            "host_release_id": host_release_id,
            "promotion_receipt_sha256": "6" * 64,
            "replay_authority_sha256": "7" * 64,
            "expected_gate_sha256": self.native_catalog_gate()[
                "gate_sha256"],
            "recovery_intent_sha256": "8" * 64,
        }
        return {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_TERMINAL_SCHEMA,
            **body, "terminal_sha256": AUTH.native_deployment.digest(body),
        }

    def native_catalog_public_status(self, host_release_id="a" * 64):
        body = {
            "promotion_id": "00000000-0000-4000-8000-000000000001",
            "catalog_sha256": "b" * 64,
            "host_release_id": host_release_id,
            "promotion_receipt_sha256": "6" * 64,
            "published_at": 2_000_000_100,
            "stacks": [],
        }
        return {
            "schema": AUTH.NATIVE_CATALOG_PUBLIC_STATUS_SCHEMA,
            **body, "status_sha256": AUTH.native_deployment.digest(body),
        }

    def native_catalog_promotion_receipt(self, plan=None, authorization=None):
        plan = plan or self.native_catalog_plan()
        authorization = authorization or self.native_catalog_authorization(plan)
        body = {
            "promotion_id": plan["promotion_id"],
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "authorization_receipt_sha256": authorization[
                "pending_receipt_sha256"],
            "source_sha256": plan["source_sha256"],
            "previous_catalog_sha256": plan["previous_catalog_sha256"],
            "catalog_sha256": plan["catalog_sha256"],
            "host_release_id": plan["host_release_id"],
            "promoted_at": 2_000_000_100,
            "status": "authorized-for-publication",
        }
        return {
            "schema": AUTH.native_stack_catalog_promotion.RECEIPT_SCHEMA,
            **body,
            "receipt_sha256": AUTH.native_stack_catalog_promotion.sha256(body),
        }

    def native_stack_authorization(self, plan):
        value = {
            "schema":"secure-sandbox-native-stack-touchid-authorization-v1",
            "authorization_id":"88888888-8888-4888-8888-888888888888",
            "request_sha256":"1" * 64,
            "pending_receipt_sha256":"2" * 64,
            "action_id":plan["action_id"],
            "action":plan["action"],
            "plan_sha256":plan["plan_sha256"],
            "method":"touch-id",
            "password_fallback":False,
            "authorized_at":2_000_000_100,
            "expires_at":2_000_000_220,
            "host_release_id":"3" * 64,
            "requesting_agent_sha256":"4" * 64,
            "requesting_session_sha256":"5" * 64,
        }
        value["authorization_sha256"] = hashlib.sha256(
            AUTH.canonical_v2(value)
        ).hexdigest()
        return value

    def staged_native_catalog(self):
        value = json.loads(
            (SCRIPT.parent.parent / "config/native-vendor-stacks.example.json").read_text()
        )
        catalog = AUTH.native_vendor_stack.validate_catalog(value)
        raw = AUTH.native_vendor_stack.canonical_bytes(catalog)
        path = self.home / "native-vendor-stacks.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        return path.resolve(), catalog, raw

    def harness_plan_wrapper(self, operation="activate"):
        plan = {
            "schema": ("secure-sandbox-harness-activation-plan-v1"
                       if operation in {"activate", "rollback"}
                       else "secure-sandbox-harness-management-plan-v1"),
            "plan_id":"11111111-1111-4111-8111-111111111111",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "operation":operation, "created_at":2_000_000_000, "expires_at":2_000_000_300,
        }
        if operation in {"activate", "rollback"}:
            plan["candidate"] = {"generation_id":"a" * 64}; reference = None
        else:
            plan["generation_id"] = "a" * 64; reference = {"generation_id":"a" * 64}
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical(plan)).hexdigest()
        wrapper = {"schema":"secure-sandbox-harness-consumer-plan-v1",
                   "stage_id":"33333333-3333-4333-8333-333333333333",
                   "plan":plan, "reference":reference}
        wrapper["wrapper_sha256"] = hashlib.sha256(AUTH.canonical(wrapper)).hexdigest()
        return wrapper

    def acceptance_plan(self, case_id, category, operation):
        plan = {
            "schema":"secure-sandbox-harness-lifecycle-acceptance-interactive-plan-v1",
            "plan_id":"11111111-1111-4111-8111-111111111111",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "campaign_id":"33333333-3333-4333-8333-333333333333",
            "campaign_sha256":"a" * 64, "machine_identity_sha256":"b" * 64,
            "source_commit":"c" * 40, "case_id":case_id,
            "procedure_sha256":"d" * 64, "category":category,
            "operation":operation, "generation_id":"e" * 64,
            "operator_uid":self.uid, "created_at":2_000_000_000,
            "expires_at":2_000_000_300, "candidate_authority":"none",
            "production_material_used":False, "production_store_access":False,
        }
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical(plan)).hexdigest()
        return plan

    def test_acceptance_broker_routes_runtime_and_management_consumers(self):
        authorization = {
            "schema":"secure-sandbox-harness-touchid-authorization-v1",
            "authorization_id":"44444444-4444-4444-8444-444444444444",
        }
        cases = (
            ("legacy-session-touchid-migration", "runtime", "migrate",
             "harness-lifecycle-acceptance-runtime.py"),
            ("rollback-explicit", "management", "rollback",
             "harness-lifecycle-acceptance-management.py"),
            ("retire-zero-reference", "management", "retire",
             "harness-lifecycle-acceptance-management.py"),
            ("reject-retire-referenced", "management", "retire",
             "harness-lifecycle-acceptance-management.py"),
            ("revoke-generation", "management", "revoke",
             "harness-lifecycle-acceptance-management.py"),
        )
        for case_id, category, operation, executable in cases:
            plan = self.acceptance_plan(case_id, category, operation)
            with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
                AUTH.validate_parameters(
                    "harness-acceptance-authorize", {"plan":plan}, self.home,
                )
            command = AUTH.operation_command(
                {"operation":"harness-acceptance-authorize",
                 "parameters":{"plan":plan}}, Path("/protected/release"),
                operator_uid=self.uid, authorization=authorization,
            )
            self.assertTrue(command[2].endswith("/scripts/" + executable))
            self.assertEqual(command[3], "consume")

        wrong = self.acceptance_plan(
            "rollback-explicit", "authorization", "authorize",
        )
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError, "harness_acceptance_plan_invalid"):
            AUTH.validate_parameters(
                "harness-acceptance-authorize", {"plan":wrong}, self.home,
            )

    def test_harness_authorization_binds_exact_plan_and_touchid_receipt_command(self):
        wrapper = self.harness_plan_wrapper()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            AUTH.validate_parameters("harness-generation-activate", {"plan":wrapper}, self.home)
        authorization = {
            "schema":"secure-sandbox-harness-touchid-authorization-v1",
            "authorization_id":"44444444-4444-4444-8444-444444444444",
            "plan_id":wrapper["plan"]["plan_id"], "plan_sha256":wrapper["plan"]["plan_sha256"],
            "transaction_id":wrapper["plan"]["transaction_id"], "operation":"activate",
            "method":"touch-id", "password_fallback":False, "authorized_at":2_000_000_100,
            "expires_at":2_000_000_220, "requesting_agent_sha256":"c" * 64,
            "requesting_session_sha256":"d" * 64,
        }
        authorization["authorization_sha256"] = hashlib.sha256(
            AUTH.canonical(authorization)
        ).hexdigest()
        command = AUTH.operation_command(
            {"operation":"harness-generation-activate", "parameters":{"plan":wrapper}},
            Path("/protected/release"), operator_uid=501, authorization=authorization,
        )
        self.assertEqual(command[:3], ["/protected/release/harness_lifecycle_manager",
                                      "apply", "activate"])
        self.assertIn("--operator-uid", command)
        self.assertIn("--authorization-json", command)
        wrapper["plan"]["expires_at"] += 1
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100), \
                self.assertRaisesRegex(AUTH.AuthorizationError, "wrapper_invalid"):
            AUTH.validate_parameters("harness-generation-activate", {"plan":wrapper}, self.home)

    def test_harness_recovery_requires_exact_pending_journal(self):
        recovery = {"schema":"secure-sandbox-harness-consumer-recovery-v1",
                    "pending":True, "journal_sha256":"a" * 64}
        AUTH.validate_parameters("harness-generation-recover", {"recovery":recovery}, self.home)
        recovery["pending"] = False
        with self.assertRaisesRegex(AUTH.AuthorizationError, "recovery_state_invalid"):
            AUTH.validate_parameters("harness-generation-recover", {"recovery":recovery}, self.home)

    def test_model_profile_authorization_binds_current_generation_and_exact_review(self):
        plan = self.model_profile_plan()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            AUTH.validate_parameters("model-profile-activate", {"plan":plan}, self.home)
        details = AUTH.operation_details({
            "operation":"model-profile-activate", "parameters":{"plan":plan}
        })
        self.assertTrue(any("Current generation SHA-256" in line for line in details))
        self.assertTrue(any("Settings:" in line for line in details))
        plan["current"]["gateway"]["model"] = "changed"
        unsigned = {key:value for key, value in plan.items() if key != "plan_sha256"}
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical_v2(unsigned)).hexdigest()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100), \
                self.assertRaisesRegex(AUTH.AuthorizationError, "plan_invalid"):
            AUTH.validate_parameters("model-profile-activate", {"plan":plan}, self.home)

    def test_native_stack_authorization_is_exact_content_free_and_touchid_visible(self):
        plan = self.native_stack_plan()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            AUTH.validate_parameters("native-stack-activate", {"plan":plan}, self.home)
        details = AUTH.operation_details({
            "operation":"native-stack-activate", "parameters":{"plan":plan},
        })
        for expected in (
            "Native action: activate", "Vendor / harness: openai / codex",
            "Program / tier: openai-daybreak / blue", "Model: gpt-6-sol",
            "Gateway cannot independently enforce native request bodies",
        ):
            self.assertTrue(any(expected in line for line in details), expected)
        command = AUTH.operation_command(
            {"operation":"native-stack-activate", "parameters":{"plan":plan}},
            Path("/protected/release"),
            authorization=self.native_stack_authorization(plan),
        )
        self.assertEqual(command[:4], [
            "/usr/bin/python3", "-I", "/protected/release/native_stack_manager", "apply",
        ])
        self.assertNotIn("token", " ".join(command).lower())
        self.assertIn("--authorization-json", command)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "native_stack_plan_invalid"):
            changed = json.loads(json.dumps(plan))
            changed["identity"]["model_id"] = "gpt-6-luna"
            with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
                AUTH.validate_parameters(
                    "native-stack-activate", {"plan":changed}, self.home,
                )
        with self.assertRaisesRegex(AUTH.AuthorizationError, "native_stack_operation_mismatch"):
            with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
                AUTH.validate_parameters(
                    "native-stack-logout", {"plan":plan}, self.home,
                )
        self.assertEqual(AUTH.authorization_execution_timeout("native-stack-signin-begin"), 1200)

    def test_anthropic_signin_routes_to_two_phase_interactive_manager(self):
        stack = json.loads(
            (SCRIPT.parent.parent / "config/native-vendor-stacks.example.json").read_text()
        )["stacks"][0]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        def observation(state: str, **extra: object) -> dict:
            return {
                "state": state, "observed_at": 2_000_000_000,
                "evidence_sha256": "d" * 64, **extra,
            }

        status = AUTH.native_stack_operations.make_status(
            stack=stack,
            harness=observation(
                "admitted", generation_id="a" * 64,
                binding_sha256="e" * 64,
            ),
            authentication=observation("signed-out"),
            credential_custody={
                "state": "retained", "observed_at": 2_000_000_000,
                "evidence_sha256": "9" * 64, "tombstone_sha256": None,
                "projection_count": 0,
            },
            account_binding=observation(
                "bound", account_subject_sha256="b" * 64,
                workspace_sha256="c" * 64,
            ),
            program_entitlement=observation(
                "verified", assurance="operator-external"
            ),
            model_entitlement=observation(
                "verified", assurance="provider-enforced"
            ),
            network={
                "phase": "closed", "grant_sha256": None,
                "expires_at": None, "observed_at": 2_000_000_000,
            },
            activation=observation("inactive", receipt_sha256=None),
            live_run_count=0,
        )
        plan = AUTH.native_stack_operations.make_plan(
            stack=stack, status=status, action="signin-begin",
            action_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            created_at=2_000_000_000,
        )
        authorization = self.native_stack_authorization(plan)
        command = AUTH.operation_command(
            {
                "operation": "native-stack-signin-begin",
                "parameters": {"plan": plan},
            },
            Path("/protected/release"), authorization=authorization,
        )
        self.assertEqual(command[:4], [
            "/usr/bin/python3", "-I",
            "/protected/release/native_stack_manager",
            "prepare-interactive",
        ])

    def test_terminal_claim_is_one_shot_and_finalizes_only_after_stream_success(self):
        operation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        record = AUTH.native_terminal_handle.make_record(
            handle_id=operation_id, kind="claude-login",
            operation_id=operation_id, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256="3" * 64,
            catalog_sha256="4" * 64, session_id=operation_id,
            remote_arguments=[
                operation_id, "1" * 64, "2" * 64, "3" * 64, "4" * 64,
            ],
            issued_at=2_000_000_000, expires_at=2_000_000_120,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = AUTH.native_terminal_handle.publish(
                record, root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            claim_body = {
                "kind": public["kind"],
                "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            claim = {
                "schema": AUTH.native_terminal_handle.CLAIM_SCHEMA,
                **claim_body,
                "request_sha256": AUTH.native_terminal_handle.sha256(
                    claim_body
                ),
            }
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            completed: list[list[str]] = []

            def privileged(command: list[str], _timeout: int):
                completed.append(command)
                return subprocess.CompletedProcess(command, 0, b"{}\n", b"")

            try:
                with mock.patch.object(AUTH.time, "time", return_value=2_000_000_001), \
                        mock.patch.object(AUTH, "run_terminal_bridge", return_value=0), \
                        mock.patch.object(AUTH, "run_privileged_operation", privileged):
                    AUTH.handle_native_terminal_claim(
                        left, claim, Path("/protected/release"),
                        expected_root_uid=os.geteuid(),
                        expected_root_gid=os.getegid(), terminal_root=root,
                    )
                self.assertIn("finalize-interactive", completed[0])
                with mock.patch.object(AUTH.time, "time", return_value=2_000_000_001), \
                        self.assertRaisesRegex(
                            AUTH.AuthorizationError, "replay_denied"
                        ):
                    AUTH.handle_native_terminal_claim(
                        left, claim, Path("/protected/release"),
                        expected_root_uid=os.geteuid(),
                        expected_root_gid=os.getegid(), terminal_root=root,
                    )
            finally:
                left.close(); right.close()

    def test_terminal_client_must_wait_for_ready_before_sending_bytes(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        message = {
            "schema": AUTH.native_terminal_handle.CLAIM_SCHEMA,
            "kind": "claude-login",
            "handle_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "handle_sha256": "1" * 64,
            "request_sha256": "2" * 64,
        }
        try:
            right.sendall(AUTH.canonical(message) + b"early-terminal-byte")
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "trailing_data"
            ):
                AUTH.read_touchid_line(left)
        finally:
            left.close(); right.close()

    def test_claimed_terminal_handle_aborts_when_bridge_launch_or_wait_fails(self):
        for failure in (
            AUTH.AuthorizationError("native_terminal_bridge_launch_failed"),
            OSError("waitpid failed"),
        ):
            with self.subTest(failure=type(failure).__name__), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                operation_id = str(uuid.uuid4())
                record = AUTH.native_terminal_handle.make_record(
                    handle_id=operation_id, kind="claude-login",
                    operation_id=operation_id, plan_sha256="1" * 64,
                    authorization_sha256="2" * 64,
                    stack_sha256="3" * 64, catalog_sha256="4" * 64,
                    session_id=operation_id,
                    remote_arguments=[
                        operation_id, "1" * 64, "2" * 64,
                        "3" * 64, "4" * 64,
                    ],
                    issued_at=2_000_000_000, expires_at=2_000_000_120,
                )
                public = AUTH.native_terminal_handle.publish(
                    record, root=root, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )
                body = {
                    "kind": public["kind"],
                    "handle_id": public["handle_id"],
                    "handle_sha256": public["handle_sha256"],
                }
                claim = {
                    "schema": AUTH.native_terminal_handle.CLAIM_SCHEMA,
                    **body,
                    "request_sha256": AUTH.native_terminal_handle.sha256(body),
                }
                left, right = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_STREAM
                )
                completed: list[list[str]] = []

                def privileged(command: list[str], _timeout: int):
                    completed.append(command)
                    return subprocess.CompletedProcess(
                        command, 0, b"{}\n", b""
                    )

                try:
                    with mock.patch.object(
                        AUTH.time, "time", return_value=2_000_000_001
                    ), mock.patch.object(
                        AUTH, "run_terminal_bridge", side_effect=failure
                    ), mock.patch.object(
                        AUTH, "run_privileged_operation", privileged
                    ), self.assertRaisesRegex(
                        AUTH.AuthorizationError, "terminal_bridge_failed"
                    ):
                        AUTH.handle_native_terminal_claim(
                            left, claim, Path("/protected/release"),
                            expected_root_uid=os.geteuid(),
                            expected_root_gid=os.getegid(),
                            terminal_root=root,
                        )
                    self.assertEqual(len(completed), 1)
                    self.assertIn("abort-interactive", completed[0])
                finally:
                    left.close(); right.close()

    def test_terminal_bridge_spawn_wait_and_reap_errors_fail_closed(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(
                AUTH.os, "posix_spawn", side_effect=OSError("spawn")
            ), self.assertRaisesRegex(
                AUTH.AuthorizationError, "bridge_launch_failed"
            ):
                AUTH.run_terminal_bridge(
                    left, Path("/protected/release"), read_fd, timeout=1
                )

            with mock.patch.object(
                AUTH.os, "posix_spawn", return_value=123
            ), mock.patch.object(
                AUTH.os, "waitpid",
                side_effect=[OSError("wait"), (123, 1 << 8)],
            ), mock.patch.object(AUTH.os, "killpg"), \
                    self.assertRaisesRegex(
                        AUTH.AuthorizationError, "bridge_failed"
                    ):
                AUTH.run_terminal_bridge(
                    left, Path("/protected/release"), read_fd, timeout=1
                )

            with mock.patch.object(
                AUTH.os, "posix_spawn", return_value=124
            ), mock.patch.object(
                AUTH.time, "monotonic", side_effect=[0.0, 2.0, 2.0, 5.0]
            ), mock.patch.object(
                AUTH.os, "waitpid",
                side_effect=[OSError("reap"), (124, 9 << 8)],
            ), mock.patch.object(AUTH.os, "killpg"), \
                    self.assertRaisesRegex(
                        AUTH.AuthorizationError, "bridge_failed"
                    ):
                AUTH.run_terminal_bridge(
                    left, Path("/protected/release"), read_fd, timeout=1
                )
        finally:
            os.close(read_fd); os.close(write_fd)
            left.close(); right.close()

    def test_terminal_bridge_closes_unrelated_broker_descriptors(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        handle_read, handle_write = os.pipe()
        sentinel_read, sentinel_write = os.pipe()
        try:
            with mock.patch.object(
                AUTH.os, "posix_spawn", return_value=123
            ) as spawn, mock.patch.object(
                AUTH.os, "waitpid", return_value=(123, 0)
            ):
                self.assertEqual(AUTH.run_terminal_bridge(
                    left, Path("/protected/release"), handle_read, timeout=1
                ), 0)
            actions = spawn.call_args.kwargs["file_actions"]
            self.assertTrue(spawn.call_args.kwargs["setsid"])
            self.assertNotIn("setpgroup", spawn.call_args.kwargs)
            for descriptor in (
                sentinel_read, sentinel_write, handle_read, handle_write,
            ):
                if descriptor >= 4:
                    self.assertIn((os.POSIX_SPAWN_CLOSE, descriptor), actions)
        finally:
            for descriptor in (
                handle_read, handle_write, sentinel_read, sentinel_write,
            ):
                os.close(descriptor)
            left.close(); right.close()

    def test_native_stack_root_dispatch_rejects_non_touchid_method(self):
        plan = self.native_stack_plan()
        request_id = "99999999-9999-4999-8999-999999999999"
        value = {
            "schema":AUTH.SCHEMA,
            "request_id":request_id,
            "created_at":2_000_000_100,
            "expires_at":2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid":self.uid,
            "declared_agent":"Codex",
            "declared_session":"native-root-bypass",
            "identity_evidence":"operator-declared",
            "purpose":"Reject password bypass",
            "resource":AUTH.OPERATION_RESOURCES["native-stack-activate"],
            "operation":"native-stack-activate",
            "parameters":{"plan":plan},
            "ceremony":"approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        with mock.patch.object(AUTH, "protected_release_directory") as protected, \
                self.assertRaisesRegex(AUTH.AuthorizationError, "touchid_required"):
            AUTH.execute_request(
                self.uid, request_id, request_sha256,
                receipt_root=self.root / "native-receipts",
                now=2_000_000_100,
                broker_path=self.root / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="administrator-password",
            )
        protected.assert_not_called()

    def test_manifest_signing_policy_is_exact_and_self_consistent(self):
        policy = {
            "access_group":self.access_group,
            "application_identifier":self.access_group,
            "bundle_id":"org.zebeth.SecureSandbox.AuthorizationUI",
            "team_id":self.team_id,
        }
        self.assertEqual(AUTH.manifest_signing_policy({
            "schema":"secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy":policy,
        }), policy)
        broken = dict(policy, access_group=self.team_id + ".org.example.Other")
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signing_policy_invalid"):
            AUTH.manifest_signing_policy({
                "schema":"secure-sandbox-touchid-ui-bundle-v2",
                "signing_policy":broken,
            })

    def execution_parameters(self):
        fixtures = [{"path":"fixtures/input.txt", "bytes":4, "sha256":"a" * 64}]
        return {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":"11111111-1111-4111-8111-111111111111",
            "created_at":2_000_000_000, "expires_at":2_000_000_090,
            "run_id":"22222222-2222-4222-8222-222222222222",
            "session_id":"33333333-3333-4333-8333-333333333333",
            "source_id":"44444444-4444-4444-8444-444444444444",
            "source_manifest_sha256":"b" * 64, "code_sha256":"c" * 64,
            "fixture_manifest":fixtures,
            "fixture_manifest_sha256":hashlib.sha256(json.dumps(
                fixtures, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "d" * 64,
        }

    def test_prompt_binds_declared_identity_purpose_operation_nonce_and_digest(self):
        calls = []

        def runner(command, timeout):
            calls.append((command, timeout))
            if len(calls) == 1:
                return SimpleNamespace(returncode=0, stdout="Continue\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = AUTH.request_authorization(
            "Codex", "thread-7", "Begin reviewed PKI rotation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
            "pki-anchor-begin", self.parameters(), now=2_000_000_000, runner=runner,
        )
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        message = calls[0][0][-1]
        self.assertIn("Declared agent: Codex", message)
        self.assertIn("Declared session: thread-7", message)
        self.assertIn("Purpose: Begin reviewed PKI rotation", message)
        self.assertIn("Operation: pki-anchor-begin", message)
        self.assertIn("Ceremony: APPROVAL", message)
        self.assertRegex(message, r"One-time nonce: [0-9a-f-]{36}")
        self.assertRegex(message, r"Request digest: [0-9a-f]{64}")
        native_prompt = calls[1][0][-1]
        self.assertIn("Codex [thread-7]", native_prompt)
        self.assertIn("Nonce:", native_prompt)
        self.assertIn("Digest:", native_prompt)
        self.assertEqual(
            calls[1][1], AUTH.authorization_client_timeout("pki-anchor-begin")
        )
        self.assertEqual(list(AUTH.request_directory(self.home).glob("*.json")), [])

    def test_cancel_prevents_native_authorization(self):
        calls = []

        def runner(command, timeout):
            calls.append(command)
            return SimpleNamespace(returncode=1, stdout="", stderr="cancelled")

        with self.assertRaisesRegex(AUTH.AuthorizationError, "operator_cancelled"):
            AUTH.request_authorization(
                "Claude", "session-1", "Begin PKI rotation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                "pki-anchor-begin", self.parameters(), runner=runner,
            )
        self.assertEqual(len(calls), 1)

    def test_cancel_test_is_bound_and_has_unambiguous_instructions(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_CANCELLED_EXIT, stdout="", stderr="",
            outcome="cancelled",
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationTerminalError, "operator_cancelled") as caught:
            AUTH.request_authorization(
                "Codex", "cancel-ceremony", "Prove cancellation",
                AUTH.OPERATION_RESOURCES["authorization-probe"],
                "authorization-probe", {"challenge": str(uuid.uuid4())},
                runner=runner, native_ui_path=ui, ceremony="cancel-test",
            )
        request_path = Path(runner.call_args.args[0][
            runner.call_args.args[0].index("--request-path") + 1
        ])
        self.assertEqual(caught.exception.operation, "authorization-probe")
        self.assertIsNotNone(caught.exception.request_id)
        self.assertFalse(request_path.exists())

    def test_cancel_test_without_native_ui_never_reaches_fallback(self):
        runner = mock.Mock()
        with self.assertRaisesRegex(
                AUTH.AuthorizationTerminalError, "cancel_test_ui_required"):
            AUTH.request_authorization(
                "Codex", "cancel-no-ui", "Prove cancellation",
                AUTH.OPERATION_RESOURCES["authorization-probe"],
                "authorization-probe", {"challenge":str(uuid.uuid4())},
                runner=runner, native_ui_path=self.root / "absent-ui",
                ceremony="cancel-test",
            )
        runner.assert_not_called()

    def test_expiry_result_is_distinct_from_operator_cancellation(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_EXPIRED_EXIT, stdout="", stderr="",
            outcome="expired",
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationTerminalError, "request_expired"):
            AUTH.request_authorization(
                "Codex", "expiry", "Prove expiry",
                AUTH.OPERATION_RESOURCES["authorization-probe"],
                "authorization-probe", {"challenge":str(uuid.uuid4())},
                runner=runner, native_ui_path=ui, ceremony="cancel-test",
            )

    def test_terminal_diagnostics_are_content_free_and_retry_explicit(self):
        cancelled = AUTH.diagnostic_record(
            "operator_cancelled", "12345678-1234-4123-8123-123456789abc",
            "authorization-probe",
        )
        self.assertEqual(cancelled["retry"], "new-request")
        self.assertEqual(cancelled["action"], "start_new_request_when_ready")
        ambiguous = AUTH.diagnostic_record(
            "touchid_ui_result_missing", None, "host-controller-install",
        )
        self.assertEqual(ambiguous["outcome"], "ambiguous")
        self.assertEqual(ambiguous["retry"], "forbidden")
        self.assertEqual(
            ambiguous["action"], "inspect_authorization_receipt_before_retry"
        )
        self.assertNotIn("purpose", ambiguous)
        self.assertNotIn("resource", ambiguous)

    def test_child_failure_output_cannot_select_policy_diagnostic(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        forged = json.dumps({
            "error":"operator_cancelled", "schema":AUTH.TOUCHID_SCHEMA,
            "status":"rejected",
        }) + "\nrequest_expired\n"
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=1, stdout=forged, stderr=forged, outcome="broker-result",
        ))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                AUTH.AuthorizationTerminalError,
                "privileged_operation_outcome_ambiguous"):
            AUTH.request_authorization(
                "Codex", "forged-diagnostic", "Reject forged child policy",
                AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
                self.parameters(), runner=runner, native_ui_path=ui,
            )
        self.assertEqual(output.getvalue(), "")

    def test_operation_timeout_is_ambiguous_and_not_retryable(self):
        value = AUTH.diagnostic_record(
            "privileged_operation_timeout", None, "host-controller-install",
        )
        self.assertEqual(value["outcome"], "ambiguous")
        self.assertEqual(value["retry"], "forbidden")

    def test_main_emits_one_terminal_content_free_diagnostic(self):
        request_id = "12345678-1234-4123-8123-123456789abc"
        arguments = [
            "operator-authorization.py", "request",
            "--agent", "Codex", "--session", "diagnostic-test",
            "--purpose", "must not appear", "--resource", "must not appear",
            "--operation", "authorization-probe", "--parameters-json", "{}",
        ]
        stderr = io.StringIO()
        with (mock.patch.object(sys, "argv", arguments),
              mock.patch.object(
                  AUTH, "request_authorization",
                  side_effect=AUTH.AuthorizationTerminalError(
                      "operator_cancelled", request_id, "authorization-probe",
                  ),
              ), contextlib.redirect_stderr(stderr)):
            self.assertEqual(AUTH.main(), 1)
        lines = stderr.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        value = json.loads(lines[0])
        self.assertEqual(value, AUTH.diagnostic_record(
            "operator_cancelled", request_id, "authorization-probe",
        ))
        self.assertNotIn("must not appear", stderr.getvalue())

    def test_native_ui_touchid_success_replaces_both_applescript_dialogs(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        calls = []

        def runner(command, timeout):
            calls.append((command, timeout))
            return SimpleNamespace(returncode=0, stdout="operation-output\n", stderr="",
                                   outcome="broker-result")

        self.assertEqual(AUTH.request_authorization(
            "Codex", "touchid-live", "Touch ID acceptance",
            AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
            self.parameters(), runner=runner, native_ui_path=ui,
        ), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][0], str(ui))
        self.assertIn("--request-sha256", calls[0][0])
        self.assertNotIn("osascript", calls[0][0])
        self.assertEqual(
            calls[0][1], AUTH.authorization_client_timeout("pki-anchor-begin")
        )

    def test_default_touchid_app_receives_ceremony_inclusive_deadline(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        result = SimpleNamespace(
            returncode=0, stdout="operation-output\n", stderr="",
            outcome="broker-result",
        )
        with mock.patch.object(AUTH, "DEFAULT_TOUCHID_UI", ui), \
                mock.patch.object(
                    AUTH, "run_touchid_app", return_value=result
                ) as run_touchid:
            self.assertEqual(AUTH.request_authorization(
                "Codex", "touchid-live", "Touch ID acceptance",
                AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                "pki-anchor-begin", self.parameters(),
            ), 0)
        self.assertEqual(
            run_touchid.call_args.args[4],
            AUTH.authorization_client_timeout("pki-anchor-begin"),
        )

    def test_native_ui_password_fallback_is_explicit_and_skips_duplicate_preflight(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        calls = []

        def runner(command, timeout):
            calls.append(command)
            if len(calls) == 1:
                return SimpleNamespace(returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT,
                                       stdout="", stderr="", outcome="password-fallback")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        self.assertEqual(AUTH.request_authorization(
            "Codex", "password-fallback", "Fallback acceptance",
            AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
            self.parameters(), runner=runner, native_ui_path=ui,
        ), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], str(ui))
        self.assertEqual(calls[1][0:2], ["/usr/bin/osascript", "-e"])
        self.assertIn("administrator privileges", calls[1][2])

    def test_execution_approval_rejects_password_fallback(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT, stdout="", stderr="",
            outcome="password-fallback",
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "touchid_required"):
            AUTH.request_authorization(
                "Codex", "execution-approval", "Approve exact execution",
                AUTH.OPERATION_RESOURCES["execution-approval-sign"],
                "execution-approval-sign", self.execution_parameters(),
                now=2_000_000_000, runner=runner, native_ui_path=ui,
            )
        runner.assert_called_once()

    def test_native_stack_requires_touchid_with_no_password_or_missing_ui_fallback(self):
        plan = self.native_stack_plan()
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        fallback = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT,
            stdout="", stderr="", outcome="password-fallback",
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "touchid_required"):
            AUTH.request_authorization(
                "Codex", "native-stack", "Activate native stack",
                AUTH.OPERATION_RESOURCES["native-stack-activate"],
                "native-stack-activate", {"plan":plan},
                now=2_000_000_100, runner=fallback, native_ui_path=ui,
            )
        fallback.assert_called_once()

        absent = self.root / "absent-native-ui"
        no_ui_runner = mock.Mock()
        with self.assertRaisesRegex(AUTH.AuthorizationError, "touchid_ui_required"):
            AUTH.request_authorization(
                "Codex", "native-stack", "Activate native stack",
                AUTH.OPERATION_RESOURCES["native-stack-activate"],
                "native-stack-activate", {"plan":plan},
                now=2_000_000_100, runner=no_ui_runner, native_ui_path=absent,
            )
        no_ui_runner.assert_not_called()

    def test_host_pair_operations_have_no_password_or_missing_ui_fallback(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        for operation in (
            "host-controller-install", "host-controller-rollback",
        ):
            with self.subTest(operation=operation, path="password-fallback"):
                repo = self.home / f"{operation}-fallback"
                repo.mkdir()
                parameters = (
                    self.host_install_parameters(repo)
                    if operation == "host-controller-install"
                    else self.host_rollback_parameters(repo)
                )
                fallback = mock.Mock(return_value=SimpleNamespace(
                    returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT,
                    stdout="", stderr="", outcome="password-fallback",
                ))
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError, "touchid_required",
                ):
                    AUTH.request_authorization(
                        "Codex", "host-pair", "Change exact host pair",
                        AUTH.OPERATION_RESOURCES[operation], operation,
                        parameters, now=2_000_000_100, runner=fallback,
                        native_ui_path=ui,
                    )
                fallback.assert_called_once()
                self.assertNotEqual(
                    fallback.call_args.args[0][0], "/usr/bin/osascript",
                )

            with self.subTest(operation=operation, path="missing-ui"):
                repo = self.home / f"{operation}-missing-ui"
                repo.mkdir()
                parameters = (
                    self.host_install_parameters(repo)
                    if operation == "host-controller-install"
                    else self.host_rollback_parameters(repo)
                )
                no_ui_runner = mock.Mock()
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError, "touchid_ui_required",
                ):
                    AUTH.request_authorization(
                        "Codex", "host-pair", "Change exact host pair",
                        AUTH.OPERATION_RESOURCES[operation], operation,
                        parameters, now=2_000_000_100,
                        runner=no_ui_runner,
                        native_ui_path=self.root / "absent-host-pair-ui",
                    )
                no_ui_runner.assert_not_called()

    def test_host_pair_root_dispatch_rejects_password_authorization(self):
        now = 2_000_000_100
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        for index, operation in enumerate((
            "host-controller-install", "host-controller-rollback",
        ), start=1):
            with self.subTest(operation=operation):
                repo = self.home / f"{operation}-root-bypass"
                repo.mkdir()
                parameters = (
                    self.host_install_parameters(repo)
                    if operation == "host-controller-install"
                    else self.host_rollback_parameters(repo)
                )
                request_id = (
                    f"{index:08d}-{index:04d}-4{index:03d}-"
                    f"8{index:03d}-{index:012d}"
                )
                value = {
                    "schema": AUTH.SCHEMA, "request_id": request_id,
                    "created_at": now,
                    "expires_at": now + AUTH.REQUEST_TTL_SECONDS,
                    "invoking_uid": self.uid, "declared_agent": "Codex",
                    "declared_session": "host-pair-root-bypass",
                    "identity_evidence": "operator-declared",
                    "purpose": "Reject password bypass",
                    "resource": AUTH.OPERATION_RESOURCES[operation],
                    "operation": operation, "parameters": parameters,
                    "ceremony": "approve",
                }
                path = directory / f"{request_id}.json"
                AUTH.write_request(path, value)
                request_sha256 = hashlib.sha256(
                    AUTH.canonical(value)
                ).hexdigest()
                with mock.patch.object(
                    AUTH, "protected_release_directory",
                ) as protected, self.assertRaisesRegex(
                    AUTH.AuthorizationError, "touchid_required",
                ):
                    AUTH.execute_request(
                        self.uid, request_id, request_sha256,
                        receipt_root=self.root / "host-pair-receipts",
                        now=now,
                        broker_path=self.root / "authorization_broker",
                        expected_root_uid=self.uid,
                        authorization_method="administrator-password",
                    )
                protected.assert_not_called()

    def test_failed_password_fallback_suppresses_child_output(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        calls = 0

        def runner(_command, _timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(
                    returncode=AUTH.TOUCHID_PASSWORD_FALLBACK_EXIT,
                    stdout="", stderr="", outcome="password-fallback",
                )
            return SimpleNamespace(
                returncode=1, stdout="sensitive child output\n",
                stderr=json.dumps({
                    "error":"request_expired", "schema":AUTH.SCHEMA,
                    "status":"rejected",
                }) + "\n",
            )

        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                AUTH.AuthorizationTerminalError,
                "privileged_operation_outcome_ambiguous"):
            AUTH.request_authorization(
                "Codex", "password-failure", "Failure output suppression",
                AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
                self.parameters(), runner=runner, native_ui_path=ui,
            )
        self.assertEqual(output.getvalue(), "")

    def test_execution_approval_parameters_are_content_bound(self):
        parameters = self.execution_parameters()
        AUTH.validate_parameters("execution-approval-sign", parameters, self.home)
        details = "\n".join(AUTH.operation_details({
            "operation":"execution-approval-sign", "parameters":parameters,
        }))
        self.assertIn("Source manifest SHA-256: " + "b" * 64, details)
        self.assertIn("fixtures/input.txt (4 bytes", details)
        changed = {**parameters, "fixture_manifest":[{**parameters["fixture_manifest"][0], "bytes":5}]}
        with self.assertRaisesRegex(AUTH.AuthorizationError, "fixture_manifest_hash_mismatch"):
            AUTH.validate_parameters("execution-approval-sign", changed, self.home)

    def test_execution_approval_key_exposes_only_public_half(self):
        key_root = self.root / "execution-approval"
        key_root.mkdir(mode=0o700)
        key = key_root / "id_ed25519"
        with mock.patch.object(AUTH.os, "chown"):
            value = AUTH.execution_approval_key_initialize(key_root, key, self.uid)
        self.assertEqual(value["status"], "ready")
        self.assertEqual(key_root.stat().st_mode & 0o777, 0o711)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.with_suffix(".pub").stat().st_mode & 0o777, 0o644)

    def test_v2_der_parser_enforces_canonical_low_s_and_no_trailing_bytes(self):
        canonical = AUTH.encode_p256_der(1, 1)
        self.assertEqual(AUTH.parse_p256_der(canonical), (1, 1))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(AUTH.encode_p256_der(1, AUTH.P256_ORDER - 1))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(canonical + b"\x00")
        nonminimal = bytes.fromhex("300702020001020101")
        with self.assertRaisesRegex(AUTH.AuthorizationError, "signature_invalid"):
            AUTH.parse_p256_der(nonminimal)

    def test_v2_spki_and_base64_are_exact(self):
        point = b"\x04" + b"\x01" * 64
        der = AUTH.P256_SPKI_PREFIX + point
        self.assertEqual(AUTH.validate_p256_spki(der), hashlib.sha256(der).hexdigest())
        encoded = __import__("base64").b64encode(der).decode("ascii")
        self.assertEqual(AUTH.canonical_base64_decode(encoded, "public", 256), der)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "public_invalid"):
            AUTH.canonical_base64_decode(encoded + "\n", "public", 256)

    def test_secure_enclave_migration_advances_floor_and_retires_software_key(self):
        root = self.root / "execution-approval-v2"
        root.mkdir(mode=0o711)
        generation = "55555555-5555-4555-8555-555555555555"
        transaction = "66666666-6666-4666-8666-666666666666"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        encoded = __import__("base64").b64encode(spki).decode("ascii")
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":1, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"f" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":100,
            "prepared_host_boot":"boot-old",
            "prepared_at":101, "public_key_spki_der_b64":encoded,
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"b" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        def proof(status, expected_prior, journal):
            return {
                "schema":"secure-sandbox-execution-approval-transition-result-v2",
                "status":status, "transaction_id":transaction,
                "generation_id":generation, "generation_epoch":1,
                "previous_generation_id":None, "previous_generation_epoch":None,
                "operator_uid":self.uid, "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
                "public_key_sha256":pending["public_key_sha256"],
                "host_release_id":"a" * 64, "research_release_id":"f" * 64,
                "expected_prior_phase":expected_prior,
                "prior_record_sha256":None if expected_prior == "none" else "9" * 64,
                "journal_sha256":journal * 64, "phase_receipt_sha256":"8" * 64,
                "acceptance_binding_sha256":None,
            }
        fence = proof("fenced", "prepared", "c")
        activated = AUTH.execution_approval_migration_activate(
            transaction, fence, root=root, expected_uid=self.uid, now=102,
        )
        self.assertEqual(activated["status"], "host_activated")
        retried = AUTH.execution_approval_migration_activate(
            transaction, fence, root=root, expected_uid=self.uid, now=999,
        )
        self.assertEqual(retried, activated)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.execution_approval_migration_activate(
                transaction, {**fence, "journal_sha256":"9" * 64},
                root=root, expected_uid=self.uid, now=999,
            )
        floor = AUTH.secure_enclave_floor(root, self.uid)
        self.assertEqual((floor["minimum_protocol"], floor["minimum_epoch"]), (2, 1))
        self.assertEqual((root / AUTH.EXECUTION_APPROVAL_PUBLIC.name).stat().st_mode & 0o777, 0o644)
        pending_after_activation = json.loads(
            (root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()
        )
        pending_after_activation.update({
            "acceptance_attempt_number":3,
            "acceptance_binding_sha256":"7" * 64,
        })
        AUTH.atomic_receipt(
            root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending_after_activation
        )
        acceptance = proof("acceptance", "acceptance", "d")
        acceptance["acceptance_binding_sha256"] = "7" * 64
        verifier = {
            "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
            "status":"verified",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":1, "host_release_id":"a" * 64,
            "research_release_id":"f" * 64,
            "acceptance_binding_sha256":acceptance["acceptance_binding_sha256"],
            "prepared_host_boot_sha256":hashlib.sha256(b"boot-old").hexdigest(),
            "verified_host_boot_sha256":hashlib.sha256(b"boot-new").hexdigest(),
        }
        verifier["verifier_sha256"] = hashlib.sha256(
            AUTH.canonical_v2(verifier)
        ).hexdigest()
        AUTH.atomic_receipt(root / "acceptance-verifier.json", verifier)
        legacy_completion_directory = root / AUTH.EXECUTION_APPROVAL_COMPLETIONS.name
        legacy_completion_directory.mkdir(mode=0o700)
        unexpected = legacy_completion_directory / "unexpected"
        unexpected.write_bytes(b"fail closed")
        unexpected.chmod(0o600)
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "execution_approval_completion_directory_untrusted",
                ):
            AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"],
                root=root, expected_uid=self.uid, now=103,
            )
        self.assertEqual(
            json.loads(
                (root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()
            )["phase"],
            "committed",
        )
        unexpected.unlink()
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"):
            committed = AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"], root=root,
                expected_uid=self.uid, now=103,
            )
        self.assertEqual(committed["status"], "committed")
        self.assertEqual(
            legacy_completion_directory.stat().st_mode & 0o777, 0o711
        )
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "committed")
        self.assertEqual(
            completion["acceptance_verifier_sha256"], verifier["verifier_sha256"]
        )
        key = root / "id_ed25519"
        key.write_bytes(b"private")
        key.chmod(0o600)
        key.with_suffix(".pub").write_bytes(b"public")
        key.with_suffix(".pub").chmod(0o644)
        retired = AUTH.execution_approval_software_retire(
            transaction, root=root, key=key, expected_uid=self.uid, now=104,
        )
        self.assertEqual(retired["status"], "software_retired")
        self.assertFalse(key.exists())
        self.assertFalse(key.with_suffix(".pub").exists())
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "software_retired")
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"):
            retried_commit = AUTH.execution_approval_migration_commit(
                transaction, acceptance, "e" * 64, verifier["verifier_sha256"], root=root,
                expected_uid=self.uid, now=999,
            )
        self.assertEqual(retried_commit["status"], "committed")
        self.assertEqual(json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())["phase"],
                         "software_retired")
        # Simulate a crash after the prior verifier was archived and removed,
        # but before the terminal pending record was retired from its live name.
        history = root / "history"
        history.mkdir(mode=0o700)
        AUTH.atomic_receipt(
            history / f"{transaction}.acceptance-verifier.json", verifier
        )
        (root / "acceptance-verifier.json").unlink()
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root):
            rotated = AUTH.prepare_secure_enclave_challenge(
                {"invoking_uid":self.uid,
                 "request_id":"77777777-7777-4777-8777-777777777777",
                 "parameters":{"research_release_id":"f" * 64}}, "f" * 64,
                Path("/protected") / ("a" * 64), self.uid, now=105,
            )
        self.assertEqual(rotated["generation_epoch"], 2)
        self.assertNotEqual(rotated["generation_id"], generation)
        self.assertTrue((root / "history" / f"{transaction}.json").exists())
        self.assertTrue(
            (root / "history" / f"{transaction}.acceptance-verifier.json").exists()
        )
        self.assertFalse((root / "acceptance-verifier.json").exists())
        completion = AUTH.read_public_completion_receipt(
            transaction, root=root, expected_uid=self.uid
        )
        self.assertEqual(completion["status"], "software_retired")
        forbidden = {"code", "fixtures", "stdout", "stderr", "biometric", "private_key"}
        stack = [completion]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                self.assertTrue(forbidden.isdisjoint(item))
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        receipt_path = (
            root / AUTH.EXECUTION_APPROVAL_COMPLETIONS.name / f"{transaction}.json"
        )
        substituted = dict(completion)
        substituted["public_key_sha256"] = "0" * 64
        receipt_path.write_bytes(AUTH.canonical(substituted))
        receipt_path.chmod(0o644)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "execution_approval_completion_untrusted"
        ):
            AUTH.read_public_completion_receipt(
                transaction, root=root, expected_uid=self.uid
            )

    def test_host_authorizes_append_only_cas_bound_acceptance_attempts(self):
        root = self.root / "acceptance-authority"
        root.mkdir(mode=0o711)
        transaction = "11111111-1111-4111-8111-111111111111"
        generation = "22222222-2222-4222-8222-222222222222"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "phase":"host_activated", "transaction_id":transaction,
            "generation_id":generation, "generation_epoch":3,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "public_key_sha256":"a" * 64, "operator_uid":self.uid,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "host_release_id":"b" * 64, "research_release_id":"c" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)

        def attempt(number, previous):
            return {
                "transaction_id":transaction, "generation_id":generation,
                "generation_epoch":3, "acceptance_attempt_id":str(uuid.uuid4()),
                "acceptance_attempt_number":number,
                "previous_acceptance_binding_sha256":previous,
                "run_id":str(uuid.uuid4()), "session_id":str(uuid.uuid4()),
                "source_id":str(uuid.uuid4()), "code_sha256":"d" * 64,
                "fixture_manifest_sha256":"e" * 64, "timeout_seconds":5,
                "runtime_image_id":"sha256:" + "f" * 64,
                "expires_at":2_000_000_300,
            }

        first_attempt = attempt(1, None)
        first = AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_000,
        )
        self.assertEqual(first["acceptance_attempt_number"], 1)
        self.assertEqual(first, AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_100,
        ))
        # Simulate power loss after the immutable attempt artifact was fsynced
        # but before the pending pointer advanced.  Redelivery must repair the
        # pointer without minting a different authorization timestamp.
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        self.assertEqual(first, AUTH.execution_approval_authorize_acceptance(
            transaction, first_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_400,
        ))
        expired = AUTH.execution_approval_authorize_acceptance(
            transaction, attempt(2, first["acceptance_binding_sha256"]),
            root=root, expected_uid=self.uid, now=2_000_000_400,
        )
        self.assertEqual(expired["status"], "not_issued_expired")
        self.assertFalse((root / "acceptance-attempts" / f"{transaction}.2.json").exists())
        with self.assertRaisesRegex(AUTH.AuthorizationError, "acceptance_attempt_conflict"):
            AUTH.execution_approval_authorize_acceptance(
                transaction, attempt(2, "0" * 64), root=root,
                expected_uid=self.uid, now=2_000_000_100,
            )
        second_attempt = attempt(2, first["acceptance_binding_sha256"])
        second = AUTH.execution_approval_authorize_acceptance(
            transaction, second_attempt, root=root, expected_uid=self.uid,
            now=2_000_000_100,
        )
        self.assertEqual(second["acceptance_attempt_number"], 2)
        self.assertEqual(second["previous_acceptance_binding_sha256"],
                         first["acceptance_binding_sha256"])
        self.assertTrue((root / "acceptance-attempts" / f"{transaction}.1.json").exists())
        self.assertTrue((root / "acceptance-attempts" / f"{transaction}.2.json").exists())

    def test_acceptance_authorization_dispatches_to_protected_broker(self):
        transaction = "11111111-1111-4111-8111-111111111111"
        acceptance = {
            "transaction_id":transaction,
            "generation_id":"22222222-2222-4222-8222-222222222222",
            "generation_epoch":3,
            "acceptance_attempt_id":"33333333-3333-4333-8333-333333333333",
            "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "run_id":"44444444-4444-4444-8444-444444444444",
            "session_id":"55555555-5555-4555-8555-555555555555",
            "source_id":"66666666-6666-4666-8666-666666666666",
            "code_sha256":"a" * 64, "fixture_manifest_sha256":"b" * 64,
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "c" * 64,
            "expires_at":2_000_000_300,
        }
        release = self.root / ("d" * 64)
        value = {
            "operation":"execution-approval-migration-authorize-acceptance",
            "parameters":{"transaction_id":transaction, "acceptance":acceptance},
        }
        command = AUTH.operation_command(value, release)
        self.assertEqual(command[:2], [
            str(release / "authorization_broker"),
            "execution-approval-migration-authorize-acceptance",
        ])
        self.assertEqual(command[2:4], ["--transaction-id", transaction])
        self.assertEqual(command[4], "--acceptance-json")
        self.assertEqual(json.loads(command[5]), acceptance)
        details = AUTH.operation_details(value)
        self.assertIn("Acceptance attempt: 1", details)
        self.assertIn("Attempt ID: " + acceptance["acceptance_attempt_id"], details)

    def test_acceptance_verifier_correlates_exact_host_receipt_and_is_idempotent(self):
        root = self.root / "acceptance-verifier"
        root.mkdir(mode=0o700)
        receipt_root = self.root / "authorization-receipts"
        receipt_root.mkdir(mode=0o700)
        transaction = "11111111-1111-4111-8111-111111111111"
        generation = "22222222-2222-4222-8222-222222222222"
        approval_id = "33333333-3333-4333-8333-333333333333"
        evidence = {
            "schema":"secure-sandbox-execution-approval-acceptance-evidence-v1",
            "status":"verified", "transaction_id":transaction,
            "generation_id":generation, "generation_epoch":3,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "run_id":"44444444-4444-4444-8444-444444444444",
            "session_id":"55555555-5555-4555-8555-555555555555",
            "acceptance_attempt_id":"99999999-9999-4999-8999-999999999999",
            "acceptance_attempt_number":1,
            "approval_id":approval_id, "approval_attestation_sha256":"c" * 64,
            "research_receipt_id":"66666666-6666-4666-8666-666666666666",
            "research_receipt_sha256":"d" * 64,
            "consumed_marker_sha256":"e" * 64,
            "acceptance_binding_sha256":"f" * 64, "verified_at":100,
        }
        active = {
            "generation_id":generation, "generation_epoch":3,
            "public_key_sha256":"1" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
        }
        pending = {
            "phase":"host_activated", **{name:evidence[name] for name in (
                "transaction_id", "generation_id", "generation_epoch",
                "host_release_id", "research_release_id",
            )}, "prepared_host_boot":"boot-old",
            "acceptance_attempt_id":evidence["acceptance_attempt_id"],
            "acceptance_attempt_number":evidence["acceptance_attempt_number"],
            "acceptance_binding_sha256":evidence["acceptance_binding_sha256"],
        }
        receipt = {
            "schema":AUTH.RECEIPT_SCHEMA, "status":"succeeded", "outcome":"approved",
            "operation":"execution-approval-sign",
            "approval_id":approval_id, "approval_key_generation_id":generation,
            "approval_key_generation_epoch":3,
            "approval_public_key_sha256":"1" * 64,
            "approval_signature_algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "approval_attestation_sha256":"c" * 64,
        }
        AUTH.atomic_receipt(receipt_root / "77777777-7777-4777-8777-777777777777.json", receipt)
        AUTH.atomic_receipt(receipt_root / "88888888-8888-4888-8888-888888888888.json", {
            **receipt, "operation":"execution-approval-migration-verify-acceptance",
        })
        def read_state(path, _schema, _uid):
            return json.loads(path.read_bytes()) if path.parent == receipt_root else pending
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-old"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state", side_effect=read_state), \
                self.assertRaisesRegex(AUTH.AuthorizationError, "actual_host_reboot_required"):
            AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=200,
            )
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state", side_effect=read_state):
            result = AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=200,
            )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["approval_id"], approval_id)
        self.assertEqual(result["host_receipt_sha256"],
                         hashlib.sha256(AUTH.canonical(receipt)).hexdigest())
        self.assertEqual(result["prepared_host_boot_sha256"],
                         hashlib.sha256(b"boot-old").hexdigest())
        self.assertEqual(result["verified_host_boot_sha256"],
                         hashlib.sha256(b"boot-new").hexdigest())
        self.assertRegex(result["verifier_sha256"], r"^[0-9a-f]{64}$")
        existing = json.loads((root / "acceptance-verifier.json").read_bytes())
        with mock.patch.object(AUTH, "host_boot_identity", return_value="boot-new"), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=active), \
                mock.patch.object(AUTH, "read_secure_enclave_state",
                                  side_effect=lambda path, schema, uid: (
                                      existing if path.name == "acceptance-verifier.json"
                                      else json.loads(path.read_bytes())
                                      if path.parent == receipt_root else pending)):
            self.assertEqual(AUTH.execution_approval_acceptance_verify(
                evidence, root=root, receipt_root=receipt_root,
                expected_uid=self.uid, now=999,
            ), existing)

        command = AUTH.operation_command({
            "operation":"execution-approval-migration-verify-acceptance",
            "parameters":{"research_evidence":evidence},
        }, Path("/protected/release"))
        self.assertEqual(command[:2], [
            "/protected/release/authorization_broker",
            "execution-approval-acceptance-verify",
        ])
        self.assertEqual(command[2], "--research-evidence-json")

    def test_protocol_v2_floor_never_falls_back_to_software_signing(self):
        root = self.root / "execution-approval-floor"
        root.mkdir(mode=0o711)
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_FLOOR.name, {
            "schema":"secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol":2, "minimum_epoch":7, "updated_at":100,
        })
        value = {"operation":"execution-approval-sign", "invoking_uid":self.uid}
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "active_secure_enclave_state", return_value=None), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError, "execution_approval_v2_authority_unavailable"
                ):
            AUTH.touchid_v2_challenge(
                value, "a" * 64, Path("/protected/") / ("b" * 64), self.uid,
            )
        key = root / "id_ed25519"
        with self.assertRaisesRegex(AUTH.AuthorizationError, "execution_approval_v1_retired"):
            AUTH.execution_approval_key_initialize(root, key, self.uid)
        self.assertFalse(key.exists())
        with self.assertRaisesRegex(AUTH.AuthorizationError, "execution_approval_v1_retired"):
            AUTH.sign_execution_approval(
                json.dumps(self.execution_parameters()),
                "88888888-8888-4888-8888-888888888888", "b" * 64,
                root=root, key=key, expected_uid=self.uid,
            )

    def test_secure_enclave_state_rejects_acls_but_allows_xattrs(self):
        root = self.root / "execution-approval-acl"
        root.mkdir(mode=0o711)
        floor_path = root / AUTH.EXECUTION_APPROVAL_FLOOR.name
        floor = {
            "schema": "secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol": 2,
            "minimum_epoch": 7,
            "updated_at": 100,
        }
        AUTH.atomic_receipt(floor_path, floor)

        if sys.platform == "darwin":
            for target in (root, floor_path):
                result = subprocess.run(
                    [
                        "/usr/bin/xattr", "-w",
                        "org.zebeth.securesandbox.acl-test", "allowed",
                        str(target),
                    ],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(AUTH.secure_enclave_floor(root, self.uid), floor)

        cases = (
            (root, "everyone allow write",
             "execution_approval_key_directory_untrusted"),
            (root, "everyone deny write",
             "execution_approval_key_directory_untrusted"),
            (floor_path, "everyone allow read,write",
             "execution_approval_state_invalid"),
            (floor_path, "everyone deny read,write",
             "execution_approval_state_invalid"),
        )
        for target, rule, error in cases:
            with self.subTest(target=target.name, rule=rule):
                with self.extended_acl(target, rule), self.assertRaisesRegex(
                    AUTH.AuthorizationError, error,
                ):
                    AUTH.secure_enclave_floor(root, self.uid)

    def test_cancellation_only_challenge_reads_verified_release_identity(self):
        release = self.make_release()
        manifest = json.loads((release / "manifest.json").read_text())
        value = {"request_id":"12345678-1234-4123-8123-123456789abc"}
        challenge = AUTH.cancellation_only_challenge(value, "a" * 64, release)
        self.assertEqual(challenge, {
            "schema":"secure-sandbox-touchid-challenge-v2",
            "mode":"cancel-only",
            "request_id":value["request_id"],
            "request_sha256":"a" * 64,
            "host_release_id":release.name,
            "authorization_ui_bundle_sha256":manifest["payloads"][
                "authorization_ui_bundle"
            ],
        })

    def test_secure_enclave_signing_rejects_nonconfigured_invoking_uid(self):
        active = {
            "generation_id":"11111111-1111-4111-8111-111111111111",
            "generation_epoch":2, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval."
                              "11111111-1111-4111-8111-111111111111",
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "public_key_spki_der_b64":"c3BraQ==",
            "public_key_sha256":"c" * 64,
        }
        value = {
            "operation":"execution-approval-sign",
            "invoking_uid":self.uid + 1,
        }
        with mock.patch.object(
            AUTH, "active_secure_enclave_state", return_value=active
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "execution_approval_operator_mismatch"
        ):
            AUTH.touchid_v2_challenge(
                value, "d" * 64, Path("/protected") / ("a" * 64), self.uid
            )

    def test_prepared_retry_is_lookup_only_and_cannot_substitute_key(self):
        root = self.root / "prepared-retry"
        root.mkdir(mode=0o711)
        transaction = "99999999-9999-4999-8999-999999999999"
        generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        encoded = __import__("base64").b64encode(spki).decode("ascii")
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":transaction, "generation_id":generation,
            "generation_epoch":2, "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":"a" * 64, "research_release_id":"b" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":90, "prepared_at":91,
            "public_key_spki_der_b64":encoded,
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"c" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        challenge = {
            "request_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "request_sha256":"d" * 64,
            **{name:pending[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "allow_creation":False,
        }
        attestation = {
            "schema":"secure-sandbox-execution-approval-preparation-v2",
            "authorization_request_id":challenge["request_id"],
            "authorization_request_sha256":challenge["request_sha256"],
            **{name:pending[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "prepared_at":100,
        }
        envelope = {
            "schema":"secure-sandbox-execution-approval-preparation-envelope-v2",
            "attestation":attestation,
            "signature_der_b64":__import__("base64").b64encode(AUTH.encode_p256_der(1, 1)).decode("ascii"),
        }
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "verify_p256_signature"):
            result = AUTH.verify_secure_enclave_preparation(
                envelope, challenge, now=100, expected_uid=self.uid,
            )
            self.assertEqual(result["public_key_sha256"], pending["public_key_sha256"])
            self.assertEqual(json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes()), pending)
            changed = dict(attestation)
            alternate = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x02" * 64
            changed["public_key_spki_der_b64"] = __import__("base64").b64encode(alternate).decode("ascii")
            changed["public_key_sha256"] = hashlib.sha256(alternate).hexdigest()
            with self.assertRaisesRegex(AUTH.AuthorizationError, "key_substitution"):
                AUTH.verify_secure_enclave_preparation(
                    {**envelope, "attestation":changed}, challenge,
                    now=100, expected_uid=self.uid,
                )

    def test_failed_prepare_rebinds_through_bounded_exact_rollback_chain(self):
        root = self.root / "prepare-release-rebind"
        root.mkdir(mode=0o711)
        old_release = "a" * 64
        new_release = "b" * 64
        research_release = "c" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":old_release,
            "research_release_id":research_release,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepare_requested", "created_at":90,
            "prepared_host_boot":"boot-old",
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":research_release},
        }
        release = Path("/protected/releases") / new_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / old_release,
                ):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, release, self.uid, now=100,
            )
            repeated = AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, release, self.uid, now=101,
            )
        self.assertTrue(challenge["allow_creation"])
        self.assertEqual(challenge["host_release_id"], new_release)
        self.assertEqual(challenge["application_tag"], pending["application_tag"])
        self.assertEqual(repeated["host_release_id"], new_release)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(rebound["host_prepare_release_rebindings"], [{
            "from_host_release_id":old_release,
            "to_host_release_id":new_release,
            "rebound_at":100,
        }])

        releases = ["e" * 64, "f" * 64]
        prior = new_release
        for offset, successor in enumerate(releases, start=2):
            with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                    mock.patch.object(
                        AUTH, "protected_release_directory",
                        return_value=Path("/protected/releases") / prior,
                    ):
                next_challenge = AUTH.prepare_secure_enclave_challenge(
                    value, "d" * 64, Path("/protected/releases") / successor,
                    self.uid, now=100 + offset,
                )
            self.assertEqual(next_challenge["host_release_id"], successor)
            prior = successor

        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / prior,
                ), self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.prepare_secure_enclave_challenge(
                value, "d" * 64, Path("/protected/releases") / ("9" * 64),
                self.uid, now=104,
            )

        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(len(rebound["host_prepare_release_rebindings"]), 3)
        self.assertEqual(rebound["host_prepare_release_rebindings"][-1], {
            "from_host_release_id":"e" * 64,
            "to_host_release_id":"f" * 64,
            "rebound_at":103,
        })

    def test_failed_prepare_rebind_migrates_legacy_record_and_requires_exact_previous(self):
        root = self.root / "prepare-release-legacy-rebind"
        root.mkdir(mode=0o711)
        old_release = "a" * 64
        current_release = "b" * 64
        next_release = "c" * 64
        research_release = "d" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":current_release,
            "research_release_id":research_release,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepare_requested", "created_at":90,
            "prepared_host_boot":"boot-old",
            "host_prepare_release_rebinding":{
                "from_host_release_id":old_release,
                "to_host_release_id":current_release,
                "rebound_at":95,
            },
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":research_release},
        }
        release = Path("/protected/releases") / next_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / old_release,
                ), self.assertRaisesRegex(AUTH.AuthorizationError, "migration_conflict"):
            AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=100,
            )
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(
                    AUTH, "protected_release_directory",
                    return_value=Path("/protected/releases") / current_release,
                ):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=101,
            )
        self.assertEqual(challenge["host_release_id"], next_release)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertNotIn("host_prepare_release_rebinding", rebound)
        self.assertEqual(rebound["host_prepare_release_rebindings"], [
            pending["host_prepare_release_rebinding"],
            {
                "from_host_release_id":current_release,
                "to_host_release_id":next_release,
                "rebound_at":101,
            },
        ])

    def test_prepared_key_is_resigned_for_bounded_research_release_repair(self):
        root = self.root / "prepared-research-release-repair"
        root.mkdir(mode=0o711)
        host_release = "a" * 64
        old_research = "b" * 64
        new_research = "c" * 64
        generation = "11111111-1111-4111-8111-111111111111"
        spki = AUTH.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
        pending = {
            "schema":"secure-sandbox-execution-approval-migration-v2",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "generation_id":generation, "generation_epoch":1,
            "operator_uid":self.uid,
            "application_tag":"org.zebeth.SecureSandbox.execution-approval." + generation,
            "access_group":self.access_group,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "host_release_id":host_release,
            "research_release_id":old_research,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "phase":"host_prepared", "created_at":90,
            "prepared_host_boot":"boot-old", "prepared_at":95,
            "public_key_spki_der_b64":base64.b64encode(spki).decode("ascii"),
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "preparation_attestation_sha256":"d" * 64,
        }
        AUTH.atomic_receipt(root / AUTH.EXECUTION_APPROVAL_PENDING.name, pending)
        value = {
            "operation":"execution-approval-key-init",
            "invoking_uid":self.uid,
            "request_id":"33333333-3333-4333-8333-333333333333",
            "parameters":{"research_release_id":new_research},
        }
        release = Path("/protected/releases") / host_release
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root):
            challenge = AUTH.prepare_secure_enclave_challenge(
                value, "e" * 64, release, self.uid, now=100,
            )
        self.assertFalse(challenge["allow_creation"])
        self.assertEqual(challenge["research_release_id"], new_research)
        rebound = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(rebound["research_prepare_release_rebindings"], [{
            "from_research_release_id":old_research,
            "to_research_release_id":new_research,
            "rebound_at":100,
        }])
        attestation = {
            "schema":"secure-sandbox-execution-approval-preparation-v2",
            "authorization_request_id":challenge["request_id"],
            "authorization_request_sha256":challenge["request_sha256"],
            **{name:challenge[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "operator_uid",
                "application_tag", "access_group", "algorithm", "host_release_id",
                "research_release_id", "public_key_spki_der_b64", "public_key_sha256",
            )},
            "prepared_at":101,
        }
        envelope = {
            "schema":"secure-sandbox-execution-approval-preparation-envelope-v2",
            "attestation":attestation,
            "signature_der_b64":base64.b64encode(AUTH.encode_p256_der(1, 1)).decode("ascii"),
        }
        with mock.patch.object(AUTH, "EXECUTION_APPROVAL_ROOT", root), \
                mock.patch.object(AUTH, "verify_p256_signature"):
            result = AUTH.verify_secure_enclave_preparation(
                envelope, challenge, now=101, expected_uid=self.uid,
            )
        self.assertEqual(result["research_release_id"], new_research)
        repaired = json.loads((root / AUTH.EXECUTION_APPROVAL_PENDING.name).read_bytes())
        self.assertEqual(repaired["prepared_at"], 101)
        self.assertEqual(
            repaired["preparation_attestation_sha256"],
            hashlib.sha256(AUTH.canonical_v2(attestation)).hexdigest(),
        )

    def test_native_ui_cancel_never_reaches_password_broker(self):
        ui = self.root / "authorization_ui"
        ui.write_bytes(b"signed-ui")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=AUTH.TOUCHID_CANCELLED_EXIT, stdout="", stderr="",
            outcome="cancelled",
        ))
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operator_cancelled"):
            AUTH.request_authorization(
                "Codex", "cancel-touchid", "Cancel acceptance",
                AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "pki-anchor-begin",
                self.parameters(), runner=runner, native_ui_path=ui,
            )
        runner.assert_called_once()

    def test_touchid_ui_registration_binds_exact_bundle_and_fails_closed(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        (bundle / "Contents/Info.plist").write_bytes(b"plist")
        runner = mock.Mock(return_value=SimpleNamespace(returncode=0))
        AUTH.register_touchid_ui(executable, runner=runner)
        self.assertEqual(
            runner.call_args.args[0],
            [str(AUTH.LSREGISTER), "-f", str(bundle.resolve())],
        )
        self.assertEqual(runner.call_args.kwargs["timeout"], 15)
        runner.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "touchid_ui_registration_failed"
        ):
            AUTH.register_touchid_ui(executable, runner=runner)

    def test_touchid_ui_launch_uses_launchservices_and_exact_result_channel(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "11111111-1111-4111-8111-111111111111"
        request_path = self.root / f"{request_id}.json"
        request_value = {"operation":"pki-anchor-begin"}
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()

        def launch(command, timeout):
            stdout_path = Path(command[command.index("-o") + 1])
            stderr_path = Path(command[command.index("--stderr") + 1])
            result_path = Path(command[command.index("--result-path") + 1])
            stdout_path.write_text("broker-output\n", encoding="utf-8")
            stderr_path.write_text("broker-diagnostic\n", encoding="utf-8")
            result_path.write_bytes(AUTH.canonical({
                "outcome":"cancelled",
                "request_id": request_id,
                "request_sha256": digest,
                "schema": "secure-sandbox-touchid-ui-result-v2",
                "status": AUTH.TOUCHID_CANCELLED_EXIT,
            }))
            result_path.chmod(0o600)
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui") as register,
              mock.patch.object(AUTH, "run_process", side_effect=launch) as run):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        register.assert_called_once_with(executable)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["/usr/bin/open", "-n", "-W", "-F"])
        self.assertIn("--result-path", command)
        self.assertEqual(result.returncode, AUTH.TOUCHID_CANCELLED_EXIT)
        self.assertEqual(result.stdout, "broker-output\n")
        self.assertEqual(result.stderr, "broker-diagnostic\n")
        self.assertEqual(result.outcome, "cancelled")
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))

    def test_whole_touchid_lifecycle_timeout_is_ambiguous(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "11111111-1111-4111-8111-111111111111"
        request_path = self.root / f"{request_id}.json"
        request_value = {"operation":"pki-anchor-begin"}
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()
        with (mock.patch.object(AUTH, "register_touchid_ui"),
              mock.patch.object(
                  AUTH, "run_process",
                  side_effect=AUTH.AuthorizationError("authorization_dialog_timeout"),
              ), self.assertRaisesRegex(
                  AUTH.AuthorizationError, "touchid_lifecycle_timeout"
              )):
            AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock",
                180, self.uid,
            )
        policy = AUTH.diagnostic_record(
            "touchid_lifecycle_timeout", request_id, "pki-anchor-begin"
        )
        self.assertEqual(policy["outcome"], "ambiguous")
        self.assertEqual(policy["retry"], "forbidden")

    def test_exact_legacy_ui_allows_only_bounded_schema_checked_successes(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "22222222-2222-4222-8222-222222222222"
        request_path = self.root / f"{request_id}.json"
        request_value = {
            "operation":"execution-approval-migration-authorize-acceptance",
        }
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()
        (self.root / "manifest.json").write_text(json.dumps({
            "payloads": {
                "authorization_ui_bundle": AUTH.LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256,
            },
        }), encoding="utf-8")

        def launch(command, timeout):
            Path(command[command.index("-o") + 1]).write_text(
                json.dumps({
                    "schema": "secure-sandbox-execution-approval-acceptance-authorization-v1",
                    "status": "authorized",
                }) + "\n", encoding="utf-8",
            )
            Path(command[command.index("--stderr") + 1]).write_text("", encoding="utf-8")
            # Successful broker execution consumes the one-time request before
            # the predecessor UI exits and before the compatibility parser runs.
            request_path.unlink()
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui"),
              mock.patch.object(AUTH, "run_process", side_effect=launch),
              mock.patch.object(AUTH, "protected_release_directory", return_value=self.root)):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))

        allowed = {
            "execution-approval-migration-authorize-acceptance": {
                "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
                "status":"not_issued_expired",
            },
            "execution-approval-migration-verify-acceptance": {
                "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
                "status":"verified",
            },
            "execution-approval-sign": {
                "schema":AUTH.EXECUTION_APPROVAL_V2_ENVELOPE,
                "attestation":{}, "signature_der_b64":"MEUCIQ==",
            },
            "execution-approval-migration-commit": {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"committed",
            },
        }
        for operation, output in allowed.items():
            self.assertTrue(AUTH.legacy_launchservices_success(operation, output))
        self.assertFalse(AUTH.legacy_launchservices_success(
            "execution-approval-software-retire",
            {"schema":"secure-sandbox-execution-approval-migration-result-v2",
             "status":"software_retired"},
        ))
        self.assertFalse(AUTH.legacy_launchservices_success(
            "execution-approval-sign", {"schema":AUTH.EXECUTION_APPROVAL_V2_ENVELOPE},
        ))
        rejection_cases = [
            ("execution-approval-migration-authorize-acceptance", {
                "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
                "status":"cancelled",
            }),
            ("execution-approval-migration-verify-acceptance", {
                "schema":"secure-sandbox-execution-approval-acceptance-verifier-v1",
                "status":"rejected",
            }),
            ("execution-approval-migration-commit", {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"software_retired",
            }),
            ("host-controller-install", {
                "schema":"secure-sandbox-host-controller-release-v1",
                "status":"deployed", "release_id":"not-a-digest",
            }),
            ("execution-approval-software-retire", {
                "schema":"secure-sandbox-execution-approval-migration-result-v2",
                "status":"software_retired",
            }),
        ]
        for operation, output in rejection_cases:
            with self.subTest(operation=operation, output=output):
                self.assertFalse(AUTH.legacy_launchservices_success(operation, output))

    def test_exact_legacy_ui_preserves_only_structured_broker_rejection(self):
        bundle = self.root / AUTH.TOUCHID_UI_APP_NAME
        executable = bundle / AUTH.TOUCHID_UI_EXECUTABLE
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"signed-ui")
        request_id = "33333333-3333-4333-8333-333333333333"
        request_path = self.root / f"{request_id}.json"
        request_value = {"operation":"execution-approval-migration-commit"}
        request_path.write_bytes(AUTH.canonical(request_value))
        request_path.chmod(0o600)
        digest = hashlib.sha256(AUTH.canonical(request_value)).hexdigest()
        (self.root / "manifest.json").write_text(json.dumps({
            "payloads": {
                "authorization_ui_bundle": AUTH.LEGACY_LAUNCHSERVICES_UI_BUNDLE_SHA256,
            },
        }), encoding="utf-8")
        rejection = {
            "error":"execution_approval_acceptance_verifier_invalid",
            "schema":AUTH.SCHEMA,
            "status":"rejected",
        }

        def launch(command, timeout):
            Path(command[command.index("-o") + 1]).write_text("", encoding="utf-8")
            Path(command[command.index("--stderr") + 1]).write_text(
                json.dumps(rejection, sort_keys=True) + "\n", encoding="utf-8",
            )
            request_path.unlink()
            return subprocess.CompletedProcess(command, 0, "", "")

        with (mock.patch.object(AUTH, "register_touchid_ui"),
              mock.patch.object(AUTH, "run_process", side_effect=launch),
              mock.patch.object(AUTH, "protected_release_directory", return_value=self.root)):
            result = AUTH.run_touchid_app(
                executable, request_path, digest, self.root / "broker.sock", 180, self.uid,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr), rejection)
        self.assertFalse(any(self.root.glob(f".{request_id}.*")))
        self.assertTrue(AUTH.legacy_launchservices_rejection(rejection))
        self.assertFalse(AUTH.legacy_launchservices_rejection({
            **rejection, "status":"committed",
        }))
        self.assertFalse(AUTH.legacy_launchservices_rejection({
            **rejection, "error":"error with spaces",
        }))

    def test_concurrent_requests_fail_closed_before_second_prompt(self):
        entered = threading.Event()
        release = threading.Event()
        first_result = []

        def slow_runner(command, timeout):
            if "SecureSandbox Authorization" in command[2]:
                entered.set()
                release.wait(2)
                return SimpleNamespace(returncode=0, stdout="Continue\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def first():
            first_result.append(AUTH.request_authorization(
                "Codex", "session-a", "First operation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                "pki-anchor-begin", self.parameters(), runner=slow_runner,
            ))

        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(entered.wait(1))
        with mock.patch.object(AUTH, "LOCK_TIMEOUT_SECONDS", 0.1):
            with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_request_in_progress"):
                AUTH.request_authorization(
                    "Claude", "session-b", "Second operation", AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                    "pki-anchor-begin", self.parameters(), runner=slow_runner,
                )
        release.set()
        thread.join(2)
        self.assertEqual(first_result, [0])

    def test_separate_process_request_lock_prevents_any_second_prompt(self):
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        lock_path = directory / "active.lock"
        holder = subprocess.Popen(
            [
                sys.executable, "-c",
                "import fcntl,os,sys; "
                "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600); "
                "fcntl.flock(fd,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.readline()",
                str(lock_path),
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            runner = mock.Mock()
            with mock.patch.object(AUTH, "LOCK_TIMEOUT_SECONDS", 0.1):
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError, "authorization_request_in_progress"
                ):
                    AUTH.request_authorization(
                        "Claude", "separate-process", "Second operation",
                        AUTH.OPERATION_RESOURCES["pki-anchor-begin"],
                        "pki-anchor-begin", self.parameters(), runner=runner,
                    )
            runner.assert_not_called()
        finally:
            assert holder.stdin is not None
            holder.stdin.write("\n")
            holder.stdin.flush()
            holder.communicate(timeout=3)

    def test_parameter_allowlist_rejects_arbitrary_command(self):
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_not_allowed"):
            AUTH.validate_parameters("shell", {"command": "id"}, self.home)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "pki-anchor-begin", {**self.parameters(), "command": "id"}, self.home
            )
        repo = self.home / "repo"
        repo.mkdir()
        parameters = self.host_install_parameters(repo)
        AUTH.validate_parameters("host-controller-install", parameters, self.home)
        install_value = {
            "declared_agent": "Codex", "declared_session": "thread-7",
            "ceremony": "approve",
            "purpose": "Publish", "resource": "host controller",
            "operation": "host-controller-install", "parameters": parameters,
            "request_id": "12345678-1234-4123-8123-123456789abc", "expires_at": 123,
        }
        release_id = parameters["authorized_target_plan"]["release_id"]
        self.assertIn("Pre-install target release: " + release_id,
                      AUTH.preflight_message(install_value, "b" * 64))
        command = AUTH.operation_command(install_value, Path("/protected/release"))
        self.assertEqual(command[:2], ["/usr/bin/python3", "-I"])
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1],
            release_id,
        )
        self.assertEqual(
            command[command.index("--authorized-target-plan-sha256") + 1],
            parameters["authorized_target_plan_sha256"],
        )
        candidate_argument = json.loads(
            command[command.index("--native-host-candidate-json") + 1]
        )
        self.assertEqual(candidate_argument, parameters["native_host_candidate"])
        message = AUTH.preflight_message(install_value, "b" * 64)
        self.assertIn(
            "Retained candidate record SHA-256: "
            + parameters["authorized_target_plan"]["candidate_record_sha256"],
            message,
        )
        self.assertIn(
            "Pre-install payload SHA-256 map: "
            + AUTH.canonical(
                parameters["authorized_target_plan"]["payloads"]
            ).decode("ascii").strip(),
            message,
        )
        self.assertIn(
            "Authorized pre-install target plan SHA-256: "
            + parameters["authorized_target_plan_sha256"], message,
        )
        self.assertNotIn("Candidate identity:", message)
        self.assertNotIn("Installed target authority", message)
        changed_plan = {
            **parameters["authorized_target_plan"],
            "target_launcher_sha256": "b" * 63,
        }
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "authorized_target_plan_invalid",
        ):
            AUTH.validate_parameters(
                "host-controller-install",
                {
                    **parameters,
                    "authorized_target_plan": changed_plan,
                    "authorized_target_plan_sha256": hashlib.sha256(
                        AUTH.canonical(changed_plan)
                    ).hexdigest(),
                },
                self.home,
            )

    def test_authorization_probe_is_side_effect_free_and_strictly_typed(self):
        challenge = "12345678-1234-4123-8123-123456789abc"
        AUTH.validate_parameters("authorization-probe", {"challenge": challenge}, self.home)
        value = {"operation": "authorization-probe", "parameters": {"challenge": challenge}}
        self.assertEqual(
            AUTH.operation_command(value, Path("/protected/release")),
            ["/usr/bin/printf", "touchid-authorization-probe:%s\\n", challenge],
        )
        self.assertEqual(AUTH.operation_details(value), [f"Acceptance challenge: {challenge}"])
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "authorization-probe", {"challenge": challenge, "command": "id"}, self.home
            )

    def test_host_install_candidate_binding_is_closed_and_inode_bound(self):
        repo = self.home / "candidate-binding-repo"
        repo.mkdir()
        parameters = self.host_install_parameters(repo)
        candidate = parameters["native_host_candidate"]
        AUTH.validate_parameters(
            "host-controller-install", parameters, self.home,
        )
        for changed in (
            {**candidate, "build_custody": "isolated-build-principal-v1"},
            {**candidate, "generation_tree_sha256": "1" * 63},
            {**candidate, "generation_inode": candidate["generation_inode"] + 1},
            {
                **candidate,
                "host_release_preimage_inode": (
                    candidate["host_release_preimage_inode"] + 1
                ),
            },
            {**candidate, "host_release_preimage_sha256": "6" * 63},
            {**candidate, "unexpected": "field"},
        ):
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "native_host_candidate_invalid",
            ):
                AUTH.validate_parameters(
                    "host-controller-install",
                    {**parameters, "native_host_candidate": changed},
                    self.home,
                )
        original = Path(candidate["generation_path"])
        parked = original.parent / "generation.parked"
        original.rename(parked)
        original.mkdir()
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_host_candidate_invalid",
        ):
            AUTH.validate_parameters(
                "host-controller-install", parameters, self.home,
            )

    def test_host_rollback_forwards_exact_plan_and_broker_authorization(self):
        parameters = self.host_rollback_parameters(self.home)
        AUTH.validate_parameters(
            "host-controller-rollback", parameters, self.home,
        )
        value = {
            "operation": "host-controller-rollback",
            "parameters": parameters,
            "request_id": "12345678-1234-4123-8123-123456789abc",
        }
        command = AUTH.operation_command(value, Path("/protected/release"))
        self.assertEqual(
            command[command.index("--release-id") + 1], "4" * 64,
        )
        self.assertEqual(
            command[command.index("--authorized-target-plan-sha256") + 1],
            parameters["authorized_target_plan_sha256"],
        )
        self.assertEqual(
            command[command.index("--authorization-request-id") + 1],
            value["request_id"],
        )
        self.assertEqual(
            command[command.index("--authorization-request-sha256") + 1],
            hashlib.sha256(AUTH.canonical(value)).hexdigest(),
        )

    def test_launcher_migration_is_rejected_after_pair_floor(self):
        repo = self.home / "launcher-migration-candidate-repo"
        repo.mkdir()
        candidate = self.native_host_candidate(repo)
        parameters = {
            "repo": str(repo),
            "state_root": str(
                self.home
                / "Library/Application Support/SecureSandbox/controller-state"
            ),
            "expected_source_release_id": "a" * 64,
            "native_host_candidate": candidate,
            "expected_installed_sha256": "b" * 64,
            "expected_replacement_sha256": "c" * 64,
        }
        self.assertNotIn(
            "host-controller-migrate-launcher", AUTH.OPERATION_RESOURCES,
        )
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_not_allowed"):
            AUTH.validate_parameters(
                "host-controller-migrate-launcher",
                parameters,
                self.home,
            )

    def test_all_operation_parameters_are_rendered_for_the_operator(self):
        base = {
            "declared_agent": "Codex", "declared_session": "thread-7", "purpose": "Review",
            "ceremony": "approve",
            "request_id": "12345678-1234-4123-8123-123456789abc", "expires_at": 123,
        }
        rollback = self.host_rollback_parameters(self.home)
        cases = [
            ("host-controller-rollback", rollback,
             "Installed target authority SHA-256: " + "2" * 64),
            ("pki-anchor-begin", self.parameters(), "PKI generation: 12345678"),
            ("pki-anchor-commit", {
                "generation_id": "12345678-1234-4123-8123-123456789abc",
                "manifest_sha256": "d" * 64, "expected_current": None,
            }, "Manifest SHA-256: " + "d" * 64),
        ]
        for operation, parameters, expected in cases:
            value = {**base, "operation": operation, "parameters": parameters,
                     "resource": AUTH.OPERATION_RESOURCES[operation]}
            self.assertIn(expected, AUTH.preflight_message(value, "e" * 64))

    def test_vm_displayed_component_hashes_are_forwarded_to_coordinator(self):
        parameters = {
            "repo": str(self.home.resolve()), "plan_sha256": "a" * 64,
            "prlctl_sha256": "b" * 64,
            "installer_sha256": AUTH.AUTOINSTALL_INSTALLER_SHA256,
            "seed_sha256": {"gateway": "c" * 64, "research": "d" * 64, "target": "e" * 64},
            "layout_profile": "neo-8gb",
            "layout": {"gateway": {"cpus": 1, "memory_mib": 1536, "disk_mib": 12288},
                       "research": {"cpus": 2, "memory_mib": 2560, "disk_mib": 51200},
                       "target": {"cpus": 1, "memory_mib": 1536, "disk_mib": 40960}},
            "host_memory_bytes": 8 * 1024**3,
        }
        AUTH.validate_parameters("vm-reprovision", parameters, self.home)
        for changed in (
            {**parameters, "layout_profile": "standard"},
            {**parameters, "layout": {**parameters["layout"], "research": {
                **parameters["layout"]["research"], "memory_mib": 6144}}},
            {**parameters, "host_memory_bytes": 16 * 1024**3},
        ):
            with self.assertRaises(AUTH.AuthorizationError):
                AUTH.validate_parameters("vm-reprovision", changed, self.home)
        value = {"operation": "vm-reprovision", "parameters": parameters, "invoking_uid": self.uid}
        command = AUTH.operation_command(value, Path("/protected/release"))
        expected_flags = {
            "--expected-plan-sha256": parameters["plan_sha256"],
            "--expected-prlctl-sha256": parameters["prlctl_sha256"],
            "--expected-installer-sha256": parameters["installer_sha256"],
            "--expected-seed-gateway-sha256": parameters["seed_sha256"]["gateway"],
            "--expected-seed-research-sha256": parameters["seed_sha256"]["research"],
            "--expected-seed-target-sha256": parameters["seed_sha256"]["target"],
            "--layout-profile": "neo-8gb",
            "--expected-layout-profile": "neo-8gb",
            "--expected-layout-sha256": hashlib.sha256(AUTH.canonical(parameters["layout"])).hexdigest(),
            "--expected-host-memory-bytes": str(8 * 1024**3),
        }
        for flag, expected in expected_flags.items():
            self.assertEqual(command[command.index(flag) + 1], expected)

    def test_legacy_preservation_request_is_strictly_typed_and_forwarded(self):
        uuid_value = "{00000000-0000-4000-8000-000000000001}"
        parameters = {
            "repo": str(self.home.resolve()), "generation": "20261021T040946Z",
            "plan_operation": "preserve", "recovery_transaction_sha256": None,
            "plan_sha256": "a" * 64, "prlctl_sha256": "b" * 64,
            "protected_control_client_sha256": "c" * 64,
            "protected_ssh_config_sha256": "d" * 64,
            "legacy_vm_uuid": {role: uuid_value for role in ("gateway", "research", "target")},
            "source_tree_sha256": {role: "e" * 64 for role in ("gateway", "research", "target")},
            "transport_vm_uuid": {
                "SecureSandbox-Gateway": uuid_value,
                "SecureSandbox-Research": uuid_value,
            },
            "tools": {name: "f" * 64 for name in AUTH.PRESERVATION_TOOL_NAMES},
        }
        AUTH.validate_parameters("vm-preserve-legacy", parameters, self.home)
        value = {"operation": "vm-preserve-legacy", "parameters": parameters,
                 "invoking_uid": self.uid}
        command = AUTH.operation_command(value, Path("/protected/release"))
        self.assertEqual(command[command.index("--generation") + 1], parameters["generation"])
        self.assertEqual(command[command.index("--expected-plan-sha256") + 1], parameters["plan_sha256"])
        details = "\n".join(AUTH.operation_details(value))
        self.assertIn(parameters["legacy_vm_uuid"]["research"], details)
        self.assertIn(
            "Protected control client SHA-256: " + parameters["protected_control_client_sha256"],
            details,
        )
        self.assertIn(
            "Protected SSH configuration SHA-256: " + parameters["protected_ssh_config_sha256"],
            details,
        )
        self.assertIn(
            "Migration planner SHA-256: " + parameters["tools"]["preservation_planner"],
            details,
        )
        self.assertIn(
            "Migration executor SHA-256: " + parameters["tools"]["preservation_executor"],
            details,
        )
        self.assertIn(
            "Migration tool-set SHA-256: "
            + hashlib.sha256(AUTH.canonical(parameters["tools"])).hexdigest(),
            details,
        )
        self.assertIn("Legacy disk-chain content trees:", details)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "operation_parameters_invalid"):
            AUTH.validate_parameters(
                "vm-preserve-legacy", {**parameters, "command": "id"}, self.home
            )
        self.assertGreater(AUTH.authorization_execution_timeout("vm-preserve-legacy"), 8 * 60 * 60)

    def test_visual_control_characters_are_rejected(self):
        for value in ("line\nbreak", "right-to-left\u202eoverride", "delete\x7f"):
            with self.assertRaisesRegex(AUTH.AuthorizationError, "purpose_invalid"):
                AUTH.clean_text(value, "purpose", AUTH.MAX_PURPOSE)

    def test_expired_and_tampered_requests_are_rejected(self):
        request_id = "12345678-1234-4123-8123-123456789abc"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id, "created_at": 100,
            "expires_at": 100 + AUTH.REQUEST_TTL_SECONDS, "invoking_uid": self.uid,
            "declared_agent": "Codex", "declared_session": "session-1",
            "identity_evidence": "operator-declared", "purpose": "Rotate PKI",
            "resource": AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "operation": "pki-anchor-begin",
            "parameters": self.parameters(), "ceremony": "approve",
        }
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_expired"):
            AUTH.verify_request(value, self.uid, request_id, 1000)
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        expected = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        path.write_bytes(path.read_bytes() + b" ")
        path.chmod(0o600)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_digest_mismatch"):
            AUTH.read_request(path, self.uid, expected)

    def test_bound_request_rejects_same_bytes_path_replacement_before_mutation(self):
        now, path, request_sha256, binding = self.bound_request_fixture()
        replacement = path.with_name("replacement.json")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)
        try:
            with mock.patch.object(AUTH, "run_privileged_operation") as mutation, \
                    self.assertRaisesRegex(
                        AUTH.AuthorizationError, "request_.*changed"
                    ):
                AUTH.execute_request(
                    self.uid, binding.path.stem, request_sha256,
                    expected_root_uid=self.uid, now=now,
                    authorization_method="touch-id",
                    request_binding=binding,
                )
            mutation.assert_not_called()
        finally:
            AUTH.close_request_binding(binding)

    def test_bound_request_rejects_parent_directory_swap_before_mutation(self):
        now, path, request_sha256, binding = self.bound_request_fixture()
        raw = path.read_bytes()
        original_directory = path.parent.with_name("authorization-requests.old")
        path.parent.rename(original_directory)
        path.parent.mkdir(mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
        substituted_directory = path.parent.with_name(
            "authorization-requests.substituted"
        )
        path.parent.rename(substituted_directory)
        original_directory.rename(path.parent)
        try:
            with mock.patch.object(AUTH, "run_privileged_operation") as mutation, \
                    self.assertRaisesRegex(
                        AUTH.AuthorizationError, "request_directory_changed"
                    ):
                AUTH.execute_request(
                    self.uid, binding.path.stem, request_sha256,
                    expected_root_uid=self.uid, now=now,
                    authorization_method="touch-id",
                    request_binding=binding,
                )
            mutation.assert_not_called()
        finally:
            AUTH.close_request_binding(binding)

    def test_bound_request_rejects_hardlink_before_mutation(self):
        now, _path, request_sha256, binding = self.bound_request_fixture()
        os.link(binding.path, self.root / "request-hardlink.json")
        try:
            with mock.patch.object(AUTH, "run_privileged_operation") as mutation, \
                    self.assertRaisesRegex(
                        AUTH.AuthorizationError, "request_file_changed"
                    ):
                AUTH.execute_request(
                    self.uid, binding.path.stem, request_sha256,
                    expected_root_uid=self.uid, now=now,
                    authorization_method="touch-id",
                    request_binding=binding,
                )
            mutation.assert_not_called()
        finally:
            AUTH.close_request_binding(binding)

    def make_release(
        self, *, include_coordination_contract=True,
        include_candidate_feature=True,
    ):
        release_root = self.root / "installed/releases"
        release_root.mkdir(parents=True, exist_ok=True)
        payloads = {}
        bundle_contents = {
            "Contents/Info.plist": b"plist\n",
            "Contents/MacOS/SecureSandboxAuthorizationUI": b"signed-ui\n",
            "Contents/PkgInfo": b"APPL????",
            "Contents/_CodeSignature/CodeResources": b"signature\n",
            "Contents/embedded.provisionprofile": b"profile\n",
        }
        bundle_manifest = {
            "bundle": AUTH.TOUCHID_UI_APP_NAME,
            "files": {
                name: {
                    "mode": 0o555 if name == AUTH.TOUCHID_UI_EXECUTABLE.as_posix() else 0o444,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for name, data in bundle_contents.items()
            },
            "schema": "secure-sandbox-touchid-ui-bundle-v2",
            "signing_policy": {
                "access_group": self.access_group,
                "application_identifier": self.access_group,
                "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
                "team_id": self.team_id,
            },
        }
        contents = {
            "authorization_broker": b"#!/usr/bin/python3\n",
            "authorization_service": b"plist\n",
            "authorization_ui_bundle": AUTH.canonical(bundle_manifest),
            "authorization_ui_sources": b"{}\n",
            "control_client": b"#!/usr/bin/python3\n# client\n",
            "controller": b"#!/bin/bash\n",
            "gpgv": b"test-gpgv\n",
            "installer_verifier": b"#!/usr/bin/python3\n# verifier\n",
            "harness_lifecycle_manager": b"#!/usr/bin/python3\n# harness lifecycle manager\n",
            "model_profile_manager": b"#!/usr/bin/python3\n# model profile manager\n",
            "native_stack_manager": b"#!/usr/bin/python3\n# native stack manager\n",
            "native_stack_session_manager": (
                b"#!/usr/bin/python3\n# native stack session manager\n"
            ),
            "native_stack_backend": b"#!/usr/bin/python3\n# native stack backend\n",
            "native_stack_catalog_promoter": b"#!/usr/bin/python3\n# catalog promoter\n",
            "native_stack_deployer": b"#!/usr/bin/python3\n# native deployer\n",
            "native_stack_terminal_bridge": b"#!/usr/bin/python3\n# terminal bridge\n",
            "native_stack_credential_client": b"signed-backend\n",
            "native_projection_consumer": b"signed-consumer\n",
            "native_credential_helper_bundle": b"{}\n",
            "native_credential_helper_service": b"plist\n",
            "native_host_products_container": b"dmg\n",
            "native_host_products_manifest": b"{}\n",
            "native_host_products_notarization": b"{}\n",
            "native_stack_support": b"PK\x05\x06" + (b"\0" * 18),
            "native_deployment_payloads": b"PK\x05\x06" + (b"\0" * 18),
            "release_manager": b"#!/usr/bin/python3\n",
            "pki_anchor": b"#!/usr/bin/python3\n",
            "seed_verifier": b"#!/usr/bin/python3\n# seed\n",
            "seed_gateway": b"gateway-seed\n",
            "seed_research": b"research-seed\n",
            "seed_target": b"target-seed\n",
            "ssh_config": b"Host test\n",
            "vm_maintenance": b"#!/usr/bin/python3\n# maintenance\n",
        }
        if include_coordination_contract:
            contents["native_host_products_notarization_signature"] = b"S" * 512
            features = sorted(
                AUTH.NATIVE_STACK_COORDINATION_REQUIRED_FEATURES
                | ({AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE}
                   if include_candidate_feature else set())
            )
            contents["native_stack_coordination_contract"] = AUTH.canonical({
                "epoch": 1,
                "features": features,
                "schema": AUTH.NATIVE_STACK_COORDINATION_CONTRACT_SCHEMA,
            })
        for name, data in contents.items():
            payloads[name] = hashlib.sha256(data).hexdigest()
        release_id = hashlib.sha256(b"".join(
            f"{name}\0{payloads[name]}\n".encode("ascii") for name in sorted(payloads)
        )).hexdigest()
        release = release_root / release_id
        release.mkdir()
        for name, data in contents.items():
            (release / name).write_bytes(data)
            (release / name).chmod(AUTH.EXPECTED_RELEASE_MODES[name])
        bundle = release / AUTH.TOUCHID_UI_APP_NAME
        for relative, data in bundle_contents.items():
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(bundle_manifest["files"][relative]["mode"])
        for directory in sorted(
            (path for path in bundle.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts), reverse=True,
        ):
            directory.chmod(0o555)
        bundle.chmod(0o555)
        manifest = {"schema": "secure-sandbox-host-controller-release-v1",
                    "release_id": release_id, "payloads": payloads}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        if include_coordination_contract:
            floor = release.parent.parent / AUTH.NATIVE_STACK_COORDINATION_FLOOR_NAME
            if not floor.exists():
                floor_raw = AUTH.canonical({
                    "schema": AUTH.NATIVE_STACK_COORDINATION_FLOOR_SCHEMA,
                    "minimum_epoch": 1,
                    "established_from_release_id": release_id,
                    "established_from_contract_sha256": hashlib.sha256(
                        contents["native_stack_coordination_contract"]
                    ).hexdigest(),
                })
                floor.write_bytes(floor_raw)
                floor.chmod(0o600)
                enforcement = (
                    release.parent.parent
                    / AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
                )
                enforcement.write_bytes(AUTH.canonical({
                    "schema": (
                        AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA
                    ),
                    "minimum_epoch": 1,
                    "minimum_features": sorted(
                        AUTH.NATIVE_STACK_COORDINATION_REQUIRED_FEATURES
                    ),
                    "authoritative_floor_sha256": hashlib.sha256(
                        floor_raw).hexdigest(),
                }))
                enforcement.chmod(0o444)
                candidate_enforcement = (
                    release.parent.parent
                    / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
                )
                inventory_sha256 = hashlib.sha256(AUTH.canonical({
                    "payload_names": sorted(payloads),
                    "schema": AUTH.NATIVE_HOST_CANDIDATE_INVENTORY_SCHEMA,
                })).hexdigest()
                candidate_floor = (
                    release.parent.parent
                    / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
                )
                candidate_floor_raw = AUTH.canonical({
                    "schema": AUTH.NATIVE_HOST_CANDIDATE_FLOOR_SCHEMA,
                    "establishment_mode": "authorization-bootstrap",
                    "established_from_predecessor_release_id": "f" * 64,
                    "established_from_release_id": release_id,
                    "candidate_record_sha256": "b" * 64,
                    "required_feature": (
                        AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
                    ),
                    "required_payload_inventory_sha256": inventory_sha256,
                })
                candidate_floor.write_bytes(candidate_floor_raw)
                candidate_floor.chmod(0o600)
                candidate_enforcement.write_bytes(AUTH.canonical({
                    "schema": (
                        AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA
                    ),
                    "required_feature": (
                        AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
                    ),
                    "required_payload_inventory_sha256": (
                        inventory_sha256
                    ),
                    "authoritative_floor_sha256": hashlib.sha256(
                        candidate_floor_raw
                    ).hexdigest(),
                }))
                candidate_enforcement.chmod(0o444)
        release.chmod(0o555)
        return release

    def make_request(self, now=2_000_000_000):
        request_id = "12345678-1234-4123-8123-123456789abc"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id, "created_at": now,
            "expires_at": now + AUTH.REQUEST_TTL_SECONDS, "invoking_uid": self.uid,
            "declared_agent": "Codex", "declared_session": "thread-7",
            "identity_evidence": "operator-declared", "purpose": "Begin PKI rotation",
            "resource": AUTH.OPERATION_RESOURCES["pki-anchor-begin"], "operation": "pki-anchor-begin",
            "parameters": self.parameters(), "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        path = directory / f"{request_id}.json"
        AUTH.write_request(path, value)
        return request_id, value, hashlib.sha256(AUTH.canonical(value)).hexdigest(), path

    def test_root_execution_is_at_most_once_and_receipt_is_content_free(self):
        release = self.make_release()
        request_id, value, request_sha256, request_path = self.make_request()
        receipt_root = self.root / "receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(AUTH, "run_privileged_operation", return_value=completed) as run:
            status = AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            )
        self.assertEqual(status, 0)
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(release.resolve() / "pki_anchor"))
        self.assertNotIn("/bin/sh", command)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["authorization_method"], "administrator-password")
        self.assertEqual(receipt["request_sha256"], request_sha256)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("stdout", receipt)
        AUTH.write_request(request_path, value)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "request_already_consumed"):
            AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            )

    def test_host_install_receipt_remains_pending_until_new_broker_attests(self):
        release = self.make_release()
        now = 2_000_000_000
        request_id = "12345678-1234-4123-8123-123456789abc"
        repo = self.home / "repo"
        repo.mkdir()
        parameters = self.host_install_parameters(repo)
        value = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": now,
            "expires_at": now + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "thread-7",
            "identity_evidence": "operator-declared",
            "purpose": "Publish reviewed host release",
            "resource": AUTH.OPERATION_RESOURCES["host-controller-install"],
            "operation": "host-controller-install",
            "parameters": parameters,
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        transition_id = "11111111-1111-4111-8111-111111111111"
        pending_result = {
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "host_pair_transition_pending",
            "operation": "install",
            "transition_id": transition_id,
            "transition_sha256": "f" * 64,
            "authorization_request_id": request_id,
            "authorized_target_plan_sha256": parameters[
                "authorized_target_plan_sha256"
            ],
            "target_release_id": parameters[
                "authorized_target_plan"
            ]["release_id"],
            "expires_at": now + 120,
            "recovered_after_child_failure": True,
        }
        result = subprocess.CompletedProcess(
            [], 137, b"", b"killed\n",
        )
        receipt_root = self.root / "install-receipts"
        with mock.patch.object(
            AUTH, "recoverable_host_install_activation",
            return_value=pending_result,
        ):
            status = AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=now,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", result_override=result,
            )
        self.assertEqual(status, 0)
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "activation_pending")
        self.assertIsNone(receipt["completed_at"])
        self.assertIsNone(receipt["exit_status"])
        self.assertEqual(receipt["host_pair_transition_id"], transition_id)
        self.assertEqual(
            receipt["host_pair_transition_sha256"],
            pending_result["transition_sha256"],
        )
        self.assertEqual(
            receipt["host_pair_authorized_target_plan_sha256"],
            parameters["authorized_target_plan_sha256"],
        )
        initial = dict(receipt)
        for name in (
            "host_pair_transition_id", "host_pair_transition_sha256",
            "authorization_pending_receipt_sha256",
        ):
            initial.pop(name)
        initial.update({
            "status": "executing", "completed_at": None,
            "exit_status": None, "stdout_sha256": None,
            "stderr_sha256": None,
        })
        self.assertEqual(
            receipt["authorization_pending_receipt_sha256"],
            hashlib.sha256(AUTH.canonical(initial)).hexdigest(),
        )

    def test_host_pair_pending_result_must_be_live_at_child_completion(self):
        release = self.make_release()
        started = 2_000_000_000
        request_id = "12345678-1234-4123-8123-123456789abc"
        repo = self.home / "completion-expiry-repo"
        repo.mkdir()
        parameters = self.host_install_parameters(repo)
        value = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": started,
            "expires_at": started + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "completion-expiry",
            "identity_evidence": "operator-declared",
            "purpose": "Publish reviewed host release",
            "resource": AUTH.OPERATION_RESOURCES["host-controller-install"],
            "operation": "host-controller-install",
            "parameters": parameters,
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        AUTH.write_request(directory / f"{request_id}.json", value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        pending_result = {
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "host_pair_transition_pending",
            "operation": "install",
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "f" * 64,
            "authorization_request_id": request_id,
            "authorized_target_plan_sha256": parameters[
                "authorized_target_plan_sha256"
            ],
            "target_release_id": parameters[
                "authorized_target_plan"
            ]["release_id"],
            "expires_at": (
                started + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS
            ),
            "recovered_after_child_failure": True,
        }
        failed_child = subprocess.CompletedProcess([], 137, b"", b"killed\n")
        receipt_root = self.root / "completion-expiry-receipts"
        with (
            mock.patch.object(
                AUTH, "recoverable_host_install_activation",
                return_value=pending_result,
            ),
            mock.patch.object(
                AUTH.time, "time",
                side_effect=(
                    started,
                    started,
                    started + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS,
                ),
            ) as clock,
            self.assertRaisesRegex(
                AUTH.AuthorizationError,
                "host_pair_transition_pending_invalid",
            ),
        ):
            AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id",
                result_override=failed_child,
                emit_output=False,
            )
        self.assertEqual(clock.call_count, 3)

    def test_host_pair_expiry_only_rejects_pristine_ordinary_prepared_state(self):
        created = 2_000_000_000
        ordinary = {
            "schema": AUTH.HOST_PAIR_TRANSITION_SCHEMA,
            "bootstrap": False,
            "created_at": created,
            "expires_at": created + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS,
            "finalization": None,
            "terminal": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".install-transition.json"
            path.write_bytes(AUTH.canonical({
                "schema": AUTH.HOST_PAIR_TRANSITION_SCHEMA,
            }))
            path.chmod(0o600)

            with (
                mock.patch.object(
                    AUTH, "validate_host_pair_transition",
                    return_value=ordinary,
                ),
                mock.patch.object(
                    AUTH, "match_public_host_pair_transition_state",
                    return_value="prepared",
                ),
                mock.patch.object(
                    AUTH.time, "time", return_value=ordinary["expires_at"],
                ),
                self.assertRaisesRegex(
                    AUTH.AuthorizationError, "host_pair_transition_expired",
                ),
            ):
                AUTH.pending_host_install_record(
                    expected_uid=os.geteuid(), path=path,
                )

            for label, transition, public_state in (
                ("public-pending", ordinary, "public_pending"),
                ("bootstrap-prepared", dict(ordinary, bootstrap=True), "prepared"),
                (
                    "durable-finalization",
                    dict(ordinary, finalization={"durable": True}),
                    "prepared",
                ),
            ):
                with (
                    self.subTest(case=label),
                    mock.patch.object(
                        AUTH, "validate_host_pair_transition",
                        return_value=transition,
                    ),
                    mock.patch.object(
                        AUTH, "match_public_host_pair_transition_state",
                        return_value=public_state,
                    ),
                    mock.patch.object(
                        AUTH.time, "time",
                        return_value=ordinary["expires_at"] + 1,
                    ),
                ):
                    self.assertEqual(
                        AUTH.pending_host_install_record(
                            expected_uid=os.geteuid(), path=path,
                        ),
                        transition,
                    )

    def test_same_release_activation_pending_still_restarts_broker(self):
        release = self.root / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        current = release.parent.parent / "current"
        current.symlink_to(Path("releases") / release.name)
        result = subprocess.CompletedProcess(
            [], 0,
            json.dumps({"status": "host_pair_transition_pending"}).encode(),
            b"",
        )
        self.assertTrue(AUTH.operation_result_requires_broker_restart(
            release, "host-controller-install", 0, result,
        ))
        self.assertTrue(AUTH.operation_result_requires_broker_restart(
            release, "host-controller-install", 1, result,
        ))

    def test_child_failure_recovers_durable_transition_instead_of_failed_receipt(self):
        release = self.make_release()
        now = 2_000_000_000
        request_id = "12345678-1234-4123-8123-123456789abc"
        repo = self.home / "recovery-repo"
        repo.mkdir()
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": now, "expires_at": now + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid, "declared_agent": "Codex",
            "declared_session": "release-child-crash",
            "identity_evidence": "operator-declared",
            "purpose": "Publish reviewed host release",
            "resource": AUTH.OPERATION_RESOURCES["host-controller-install"],
            "operation": "host-controller-install",
            "parameters": self.host_install_parameters(repo),
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        transition_id = "11111111-1111-4111-8111-111111111111"
        recovered = {
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "host_pair_transition_pending",
            "operation": "install",
            "transition_id": transition_id,
            "transition_sha256": "b" * 64,
            "authorization_request_id": request_id,
            "authorized_target_plan_sha256": value["parameters"][
                "authorized_target_plan_sha256"
            ],
            "target_release_id": value["parameters"][
                "authorized_target_plan"
            ]["release_id"],
            "expires_at": now + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS,
            "recovered_after_child_failure": True,
        }
        failed_child = subprocess.CompletedProcess(
            [], 137, b"", b"killed\n",
        )
        receipt_root = self.root / "child-crash-receipts"
        with mock.patch.object(
            AUTH, "recoverable_host_install_activation",
            return_value=recovered,
        ) as recovery:
            status = AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=now,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", result_override=failed_child,
                emit_output=False,
            )
        self.assertEqual(status, 0)
        recovery.assert_called_once()
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "activation_pending")
        self.assertEqual(receipt["host_pair_transition_id"], transition_id)
        self.assertEqual(
            receipt["host_pair_authorized_target_plan_sha256"],
            value["parameters"]["authorized_target_plan_sha256"],
        )
        self.assertIsNone(receipt["completed_at"])
        self.assertIsNone(receipt["exit_status"])

    def test_pair_transition_cannot_reuse_receipt_for_a_different_plan(self):
        request_id = "12345678-1234-4123-8123-123456789abc"
        request_sha256 = "1" * 64
        receipt_plan_sha256 = "2" * 64
        transition_plan_sha256 = "3" * 64
        executing = {
            "schema": AUTH.RECEIPT_SCHEMA,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "operation": "host-controller-install",
            "status": "executing",
            "host_pair_authorized_target_plan_sha256": (
                receipt_plan_sha256
            ),
        }
        source_pair = {
            "candidate_authority_sha256": "4" * 64,
            "launcher_identity": {
                "ctime_ns": 1, "dev": 2, "gid": 0, "ino": 3,
                "kind": "file", "mode": 0o755, "mtime_ns": 4,
                "nlink": 1, "sha256": "5" * 64, "size": 100,
                "uid": 0,
            },
            "launcher_sha256": "5" * 64,
            "release_id": "6" * 64,
            "release_tree_identity_sha256": "7" * 64,
        }
        target_pair = {
            "candidate_authority_sha256": "8" * 64,
            "launcher_sha256": "9" * 64,
            "release_id": "a" * 64,
            "release_tree_identity_sha256": "b" * 64,
        }
        old_services = {}
        transition = {
            "schema": AUTH.HOST_PAIR_TRANSITION_SCHEMA,
            "operation": "install", "bootstrap": False,
            "bootstrap_admission": None,
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "0" * 64,
            "created_at": 2_000_000_000,
            "expires_at": (
                2_000_000_000 + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS
            ),
            "authorization_request_id": request_id,
            "authorization_request_sha256": request_sha256,
            "authorization_pending_receipt_sha256": hashlib.sha256(
                AUTH.canonical(executing)
            ).hexdigest(),
            "authorized_target_plan_sha256": transition_plan_sha256,
            "source_stable_sha256": "c" * 64,
            "source_pair": source_pair, "target_pair": target_pair,
            "target_candidate_authority_sha256": (
                target_pair["candidate_authority_sha256"]
            ),
            "source_launcher_generation_sha256": (
                source_pair["launcher_sha256"]
            ),
            "target_launcher_generation_sha256": (
                target_pair["launcher_sha256"]
            ),
            "old_current_target": f"releases/{source_pair['release_id']}",
            "old_previous_target": None, "native_uid": self.uid,
            "old_services": old_services,
            "old_services_sha256": hashlib.sha256(
                AUTH.canonical(old_services)
            ).hexdigest(),
            "developer_id_team_id": "ABCDE12345",
            "developer_id_team_floor_sha256": "d" * 64,
            "finalization": None,
            "terminal": None,
        }
        transition["transition_sha256"] = (
            AUTH.host_pair_transition_digest(transition)
        )
        public_pending = {
            "schema": AUTH.HOST_PAIR_PENDING_SCHEMA,
            "required_feature": AUTH.HOST_PAIR_REQUIRED_FEATURE,
            "operation": transition["operation"],
            "transition_id": transition["transition_id"],
            "transition_sha256": transition["transition_sha256"],
            "prior_stable_sha256": transition["source_stable_sha256"],
            "source_pair": source_pair, "target_pair": target_pair,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".install-transition.json"
            pair_path = root / "host-release-launcher-pair.json"
            path.write_bytes(AUTH.canonical(transition))
            path.chmod(0o600)
            pair_path.write_bytes(AUTH.canonical(public_pending))
            pair_path.chmod(0o444)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_pair_transition_untrusted",
            ):
                AUTH.recoverable_host_install_activation(
                    request_id, request_sha256, executing,
                    expected_uid=os.geteuid(), path=path,
                    pair_path=pair_path,
                )
            conflicting_public = dict(public_pending)
            conflicting_public["target_pair"] = dict(
                target_pair, release_id="e" * 64,
            )
            pair_path.chmod(0o600)
            pair_path.write_bytes(AUTH.canonical(conflicting_public))
            pair_path.chmod(0o444)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_pair_public_pending_conflict",
            ):
                AUTH.recoverable_host_install_activation(
                    request_id, request_sha256, executing,
                    expected_uid=os.geteuid(), path=path,
                    pair_path=pair_path,
                )
            malformed_transition = dict(transition)
            malformed_transition.pop("finalization")
            path.write_bytes(AUTH.canonical(malformed_transition))
            path.chmod(0o600)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_pair_transition_invalid",
            ):
                AUTH.recoverable_host_install_activation(
                    request_id, request_sha256, executing,
                    expected_uid=os.geteuid(), path=path,
                    pair_path=pair_path,
                )

    def test_manager_completed_pair_receipt_preserves_exact_plan_binding(self):
        request_id = "12345678-1234-4123-8123-123456789abc"
        request_sha256 = "1" * 64
        plan_sha256 = "2" * 64
        transition_id = "11111111-1111-4111-8111-111111111111"
        transition_sha256 = "3" * 64
        completed_at = 2_000_000_010
        pending = {
            "schema": AUTH.RECEIPT_SCHEMA, "request_id": request_id,
            "request_sha256": request_sha256, "status": "executing",
            "started_at": 2_000_000_000, "completed_at": None,
            "operation": "host-controller-install",
            "declared_agent": "Codex", "declared_session": "pair-receipt",
            "identity_evidence": "operator-declared",
            "authorization_method": "touch-id", "ceremony": "approve",
            "purpose": "Publish exact host pair",
            "resource": AUTH.OPERATION_RESOURCES["host-controller-install"],
            "exit_status": None, "stdout_sha256": None,
            "stderr_sha256": None,
            "host_pair_authorized_target_plan_sha256": plan_sha256,
        }
        pair = {
            "candidate_authority_sha256": "4" * 64,
            "launcher_identity": {
                "ctime_ns": 1, "dev": 2, "gid": 0, "ino": 3,
                "kind": "file", "mode": 0o755, "mtime_ns": 4,
                "nlink": 1, "sha256": "5" * 64, "size": 100,
                "uid": 0,
            },
            "launcher_sha256": "5" * 64,
            "release_id": "6" * 64,
            "release_tree_identity_sha256": "7" * 64,
        }
        committed_pair_sha256 = hashlib.sha256(
            AUTH.canonical(pair)
        ).hexdigest()
        service_evidence = {
            "committed_pair_sha256": committed_pair_sha256,
            "current_target": f"releases/{pair['release_id']}",
            "operation": "install",
            "previous_target": "releases/" + "8" * 64,
            "schema": AUTH.HOST_PAIR_SERVICE_EVIDENCE_SCHEMA,
            "services": {}, "transition_sha256": transition_sha256,
        }
        service_evidence_sha256 = hashlib.sha256(
            AUTH.canonical(service_evidence)
        ).hexdigest()
        finalization_sha256 = "9" * 64
        completed = dict(pending)
        completed.update({
            "status": "succeeded", "completed_at": completed_at,
            "exit_status": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "host_pair_committed_pair_sha256": committed_pair_sha256,
            "host_pair_finalization_sha256": finalization_sha256,
            "host_pair_service_evidence_sha256": service_evidence_sha256,
            "host_pair_transition_id": transition_id,
            "host_pair_transition_sha256": transition_sha256,
        })
        completed_raw = AUTH.canonical(completed)
        terminal = {
            "schema": AUTH.HOST_PAIR_TERMINAL_SCHEMA,
            "status": "target_committed", "operation": "install",
            "transition_id": transition_id,
            "transition_sha256": transition_sha256,
            "committed_pair": pair,
            "authorization_request_id": request_id,
            "authorization_request_sha256": request_sha256,
            "authorized_target_plan_sha256": plan_sha256,
            "completed_at": completed_at,
            "service_evidence": service_evidence,
            "service_evidence_sha256": service_evidence_sha256,
            "error": None,
            "authorization_receipt_sha256": hashlib.sha256(
                completed_raw
            ).hexdigest(),
            "finalization_sha256": finalization_sha256,
            "terminal_sha256": "0" * 64,
        }
        terminal["terminal_sha256"] = AUTH.host_pair_terminal_digest(terminal)
        stable = {
            "schema": AUTH.HOST_PAIR_STABLE_SCHEMA,
            "required_feature": AUTH.HOST_PAIR_REQUIRED_FEATURE,
            "pair": pair, "committed_transition_id": transition_id,
            "committed_transition_sha256": transition_sha256,
            "committed_terminal_sha256": hashlib.sha256(
                AUTH.canonical(terminal)
            ).hexdigest(),
        }
        receipt_root = self.root / "pair-completed-receipts"
        receipt_root.mkdir()
        receipt_path = receipt_root / f"{request_id}.json"
        receipt_path.write_bytes(completed_raw)
        receipt_path.chmod(0o600)
        install_root = self.root / "pair-completed-install"
        transitions = install_root / "install-transitions"
        transitions.mkdir(parents=True)
        transitions.chmod(0o755)
        pair_path = install_root / "host-release-launcher-pair.json"
        pair_path.write_bytes(AUTH.canonical(stable))
        pair_path.chmod(0o444)
        terminal_path = transitions / f"{transition_id}.json"
        terminal_path.write_bytes(AUTH.canonical(terminal))
        terminal_path.chmod(0o444)
        observed = AUTH.manager_completed_host_pair_receipt(
            receipt_path, pending, expected_uid=self.uid,
            install_root=install_root,
        )
        self.assertEqual(observed, completed)
        self.assertEqual(
            observed["host_pair_authorized_target_plan_sha256"],
            plan_sha256,
        )
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_pair_transition_receipt_untrusted",
        ):
            AUTH.manager_completed_host_pair_receipt(
                receipt_path,
                dict(
                    pending,
                    host_pair_authorized_target_plan_sha256="a" * 64,
                ),
                expected_uid=self.uid, install_root=install_root,
            )

    def test_pre_floor_pair_bootstrap_recovery_accepts_selected_predecessor(self):
        target_release = "a" * 64
        bootstrap = {
            "schema": AUTH.HOST_PAIR_TRANSITION_SCHEMA,
            "bootstrap": True,
            "bootstrap_admission": {
                "candidate_record_sha256": "c" * 64,
                "established_from_predecessor_release_id": "b" * 64,
                "established_from_release_id": target_release,
                "establishment_mode": "authorization-bootstrap",
                "native_host_candidate_floor_sha256": "d" * 64,
                "schema": AUTH.HOST_PAIR_BOOTSTRAP_ADMISSION_SCHEMA,
            },
            "source_pair": None,
            "target_pair": {"release_id": target_release},
        }
        with mock.patch.object(
            AUTH, "pending_host_install_record", return_value=bootstrap,
        ):
            self.assertEqual(
                AUTH.pending_host_install_role(
                    Path("/protected/releases") / target_release,
                ),
                "target",
            )
            self.assertEqual(
                AUTH.pending_host_install_role(
                    Path("/protected/releases") / ("b" * 64),
                ),
                "source",
            )
            with self.assertRaisesRegex(
                AUTH.AuthorizationError,
                "host_pair_transition_release_mismatch",
            ):
                AUTH.pending_host_install_role(
                    Path("/protected/releases") / ("c" * 64),
                )

    def test_pair_broker_grace_accepts_only_verified_parent_publication(self):
        transition = {
            "schema": AUTH.HOST_PAIR_TRANSITION_SCHEMA,
            "transition_id": "11111111-1111-4111-8111-111111111111",
        }
        with (
            mock.patch.object(
                AUTH, "pending_host_install_record",
                side_effect=[transition, None],
            ),
            mock.patch.object(
                AUTH, "committed_host_pair_terminal_for_transition",
                return_value=({}, {}, "a" * 64),
            ) as committed,
            mock.patch.object(AUTH.time, "sleep") as sleep,
        ):
            self.assertTrue(AUTH.await_parent_host_pair_publication(
                transition, timeout=1.0, poll_interval=0.01,
            ))
        committed.assert_called_once_with(transition)
        sleep.assert_called_once_with(0.01)

        with (
            mock.patch.object(
                AUTH, "pending_host_install_record",
                return_value=transition,
            ),
            mock.patch.object(AUTH.time, "monotonic", side_effect=[1.0, 2.0]),
            mock.patch.object(AUTH.time, "sleep") as sleep,
        ):
            self.assertFalse(AUTH.await_parent_host_pair_publication(
                transition, timeout=0.5, poll_interval=0.01,
            ))
        sleep.assert_not_called()

        with (
            mock.patch.object(
                AUTH, "pending_host_install_record",
                return_value={**transition, "transition_id": (
                    "22222222-2222-4222-8222-222222222222"
                )},
            ),
            self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_pair_transition_changed",
            ),
        ):
            AUTH.await_parent_host_pair_publication(transition)

    def test_child_failure_recovery_accepts_only_exact_bound_transition(self):
        executing = {
            "schema": AUTH.RECEIPT_SCHEMA,
            "request_id": "12345678-1234-4123-8123-123456789abc",
            "request_sha256": "1" * 64,
            "operation": "host-controller-install",
            "status": "executing", "completed_at": None,
            "exit_status": None,
        }
        old_services = {
            "authorization": {
                "pid": 71, "euid": 0,
                "start_generation": [1_800_000_000, 123_456],
                "executable": "/usr/bin/python3",
                "arguments": ["/usr/bin/python3", "-I", "/broker"],
            }
        }
        transition = {
            "schema": "secure-sandbox-host-install-transition-v1",
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "created_at": 2_000_000_000,
            "expires_at": (
                2_000_000_000 + AUTH.HOST_INSTALL_TRANSITION_TTL_SECONDS
            ),
            "authorization_request_id": executing["request_id"],
            "authorization_request_sha256": executing["request_sha256"],
            "authorization_pending_receipt_sha256": hashlib.sha256(
                AUTH.canonical(executing)
            ).hexdigest(),
            "candidate_release_id": "2" * 64,
            "candidate_manifest_sha256": "3" * 64,
            "candidate_authorization_manifest_sha256": "4" * 64,
            "developer_id_team_id": "ABCDE12345",
            "developer_id_team_floor_sha256": "5" * 64,
            "fallback_release_id": "6" * 64,
            "old_current_target": "releases/" + "6" * 64,
            "old_previous_target": None,
            "native_uid": self.uid,
            "old_services": old_services,
            "old_services_sha256": hashlib.sha256(
                AUTH.canonical(old_services)
            ).hexdigest(),
            "terminal": None,
        }
        immutable = {
            name: item for name, item in transition.items()
            if name not in {"terminal", "transition_sha256"}
        }
        transition["transition_sha256"] = hashlib.sha256(
            AUTH.canonical(immutable)
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "transition.json"
            path.write_bytes(AUTH.canonical(transition))
            path.chmod(0o600)
            activation = AUTH.recoverable_host_install_activation(
                executing["request_id"], executing["request_sha256"],
                executing, expected_uid=os.geteuid(), path=path,
            )
            self.assertEqual(
                activation["transition_sha256"],
                transition["transition_sha256"],
            )
            pair_path = Path(temporary) / "host-release-launcher-pair.json"
            pair_path.write_text("pair floor active\n", encoding="ascii")
            pair_path.chmod(0o444)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_pair_transition_legacy_active",
            ):
                AUTH.recoverable_host_install_activation(
                    executing["request_id"], executing["request_sha256"],
                    executing, expected_uid=os.geteuid(), path=path,
                    pair_path=pair_path,
                )
            pair_path.unlink()
            with self.extended_acl(
                path, "everyone allow read,write",
            ):
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "host_install_transition_untrusted",
                ):
                    AUTH.recoverable_host_install_activation(
                        executing["request_id"], executing["request_sha256"],
                        executing, expected_uid=os.geteuid(), path=path,
                    )
                with self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "host_install_transition_untrusted",
                ):
                    AUTH.pending_host_install_record(
                        expected_uid=os.geteuid(), path=path,
                    )
            transition["candidate_release_id"] = "7" * 64
            path.write_bytes(AUTH.canonical(transition))
            path.chmod(0o600)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_install_transition_untrusted",
            ):
                AUTH.recoverable_host_install_activation(
                    executing["request_id"], executing["request_sha256"],
                    executing, expected_uid=os.geteuid(), path=path,
                )

    def test_committed_host_terminal_requires_pending_absence_and_exact_public_bytes(self):
        body = {
            "schema": "secure-sandbox-host-install-terminal-v1",
            "status": "deployed_verified",
            "transition_id": "11111111-1111-4111-8111-111111111111",
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
            "old_authorization_start_generation": [10, 20],
            "authorization_pid": 81,
            "authorization_start_generation": [11, 21],
            "native_credential_pid": 82,
            "native_credential_start_generation": [12, 22],
            "service_evidence_sha256": "7" * 64,
            "authorization_receipt_sha256": "8" * 64,
            "completed_at": 2_000_000_010,
            "error": None,
        }
        terminal = dict(body)
        terminal["terminal_sha256"] = hashlib.sha256(
            AUTH.canonical(body)
        ).hexdigest()
        install_root = self.root / "host"
        install_root.mkdir(mode=0o755)
        directory = install_root / "install-transitions"
        directory.mkdir(mode=0o755)
        public = directory / f"{terminal['transition_id']}.json"
        public.write_bytes(AUTH.canonical(terminal))
        public.chmod(0o444)
        self.assertEqual(
            AUTH.committed_host_install_terminal(
                terminal, expected_uid=self.uid, install_root=install_root,
            ),
            terminal,
        )
        for target in (install_root, directory, public):
            with self.subTest(target=target.name):
                with self.extended_acl(
                    target, "everyone allow write",
                ), self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "host_install_committed_terminal_untrusted",
                ):
                    AUTH.committed_host_install_terminal(
                        terminal, expected_uid=self.uid,
                        install_root=install_root,
                    )
        pending = install_root / ".install-transition.json"
        pending.write_text("pending\n", encoding="ascii")
        pending.chmod(0o600)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "host_install_transition_still_pending",
        ):
            AUTH.committed_host_install_terminal(
                terminal, expected_uid=self.uid, install_root=install_root,
            )

    def test_restarted_broker_requires_terminal_activation_before_serving(self):
        release = self.root / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        terminal = {
            "schema": "secure-sandbox-host-install-terminal-v1",
            "status": "deployed_verified",
            "candidate_release_id": release.name,
            "authorization_pid": 71,
            "terminal_sha256": "b" * 64,
        }
        pending = mock.Mock()
        pending.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1,
        )
        completed = subprocess.CompletedProcess(
            [], 0, json.dumps(terminal).encode("ascii"), b"",
        )
        with (
            mock.patch.object(AUTH, "HOST_INSTALL_PENDING", pending),
            mock.patch.object(
                AUTH, "pending_host_install_record", return_value=None,
            ) as pending_record,
            mock.patch.object(
                AUTH, "run_privileged_operation", return_value=completed,
            ) as run,
            mock.patch.object(AUTH.os, "getpid", return_value=81),
            mock.patch.object(AUTH.os, "urandom", return_value=b"n" * 32),
            mock.patch.object(
                AUTH, "committed_host_install_terminal",
                return_value=terminal,
            ) as committed,
            mock.patch.object(
                AUTH, "preexisting_host_install_terminal",
                return_value=terminal,
            ) as preexisting,
            mock.patch.object(AUTH.socket, "socketpair") as socketpair,
            mock.patch.object(AUTH.threading, "Thread") as thread_type,
        ):
            listener = mock.Mock()
            listener.fileno.return_value = 44
            parent = mock.Mock()
            child = mock.Mock()
            child.fileno.return_value = 45
            socketpair.return_value = (parent, child)
            responder = mock.Mock()
            thread_type.return_value = responder
            result = AUTH.finalize_pending_host_install(release, listener)
        self.assertEqual(result, terminal)
        pending_record.assert_called_once_with()
        command = run.call_args.args[0]
        self.assertIn("finalize-install-transition", command)
        self.assertIn(release.name, command)
        self.assertIn("81", command)
        self.assertIn("44", command)
        self.assertIn("45", command)
        self.assertIn((b"n" * 32).hex(), command)
        self.assertEqual(run.call_args.kwargs["pass_fds"], (44, 45))
        responder.start.assert_called_once_with()
        responder.join.assert_called_once_with(timeout=1.0)
        child.close.assert_called_once_with()
        parent.close.assert_called_once_with()
        committed.assert_called_once_with(terminal)
        preexisting.assert_called_once_with(release)

    def test_fresh_finalize_rejects_mismatched_broker_pid_even_after_publication(self):
        release = self.root / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        terminal = {
            "schema": "secure-sandbox-host-install-terminal-v1",
            "status": "deployed_verified",
            "candidate_release_id": release.name,
            "authorization_pid": 71,
            "terminal_sha256": "b" * 64,
        }
        pending = mock.Mock()
        pending.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1,
        )
        completed = subprocess.CompletedProcess(
            [], 0, json.dumps(terminal).encode("ascii"), b"",
        )
        with (
            mock.patch.object(AUTH, "HOST_INSTALL_PENDING", pending),
            mock.patch.object(
                AUTH, "pending_host_install_record", return_value=None,
            ) as pending_record,
            mock.patch.object(
                AUTH, "run_privileged_operation", return_value=completed,
            ),
            mock.patch.object(AUTH.os, "getpid", return_value=81),
            mock.patch.object(AUTH.os, "urandom", return_value=b"n" * 32),
            mock.patch.object(
                AUTH, "committed_host_install_terminal",
                return_value=terminal,
            ),
            mock.patch.object(
                AUTH, "preexisting_host_install_terminal", return_value=None,
            ),
            mock.patch.object(AUTH.socket, "socketpair") as socketpair,
            mock.patch.object(AUTH.threading, "Thread") as thread_type,
            self.assertRaisesRegex(
                AUTH.AuthorizationError, "host_install_activation_unverified",
            ),
        ):
            listener = mock.Mock()
            listener.fileno.return_value = 44
            parent = mock.Mock()
            child = mock.Mock()
            child.fileno.return_value = 45
            socketpair.return_value = (parent, child)
            thread_type.return_value = mock.Mock()
            AUTH.finalize_pending_host_install(release, listener)
        pending_record.assert_called_once_with()

    def test_restarted_broker_accepts_only_typed_host_failure_fence(self):
        release = self.root / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        terminal = {
            "schema": "secure-sandbox-host-install-terminal-v1",
            "status": "failed_fenced",
            "candidate_release_id": "b" * 64,
            "authorization_pid": 0,
            "terminal_sha256": "c" * 64,
        }
        pending = mock.Mock()
        pending.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1,
        )
        completed = subprocess.CompletedProcess(
            [], 0, json.dumps(terminal).encode("ascii"), b"",
        )
        with (
            mock.patch.object(AUTH, "HOST_INSTALL_PENDING", pending),
            mock.patch.object(
                AUTH, "pending_host_install_record", return_value=None,
            ) as pending_record,
            mock.patch.object(
                AUTH, "run_privileged_operation", return_value=completed,
            ),
            mock.patch.object(
                AUTH, "preexisting_host_install_terminal", return_value=None,
            ),
            mock.patch.object(AUTH.os, "getpid", return_value=81),
            mock.patch.object(AUTH.socket, "socketpair") as socketpair,
            mock.patch.object(AUTH.threading, "Thread") as thread_type,
        ):
            listener = mock.Mock()
            listener.fileno.return_value = 44
            parent, child = mock.Mock(), mock.Mock()
            child.fileno.return_value = 45
            socketpair.return_value = (parent, child)
            thread_type.return_value = mock.Mock()
            result = AUTH.finalize_pending_host_install(release, listener)
        self.assertEqual(result, terminal)
        pending_record.assert_called_once_with()

    def test_native_root_dispatch_binds_touchid_request_and_pending_receipt(self):
        release = self.make_release()
        plan = self.native_stack_plan()
        request_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        value = {
            "schema":AUTH.SCHEMA,
            "request_id":request_id,
            "created_at":2_000_000_100,
            "expires_at":2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid":self.uid,
            "declared_agent":"Codex",
            "declared_session":"native-binding",
            "identity_evidence":"operator-declared",
            "purpose":"Activate exact native stack",
            "resource":AUTH.OPERATION_RESOURCES["native-stack-activate"],
            "operation":"native-stack-activate",
            "parameters":{"plan":plan},
            "ceremony":"approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "native-authorization-receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"{}\n", stderr=b"")
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=completed
        ) as run:
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_100,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id",
            ), 0)
        command = run.call_args.args[0]
        authorization = json.loads(
            command[command.index("--authorization-json") + 1]
        )
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        self.assertEqual(authorization["request_sha256"], request_sha256)
        self.assertEqual(authorization["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(authorization["host_release_id"], release.name)
        body = {
            key:item for key, item in authorization.items()
            if key != "authorization_sha256"
        }
        self.assertEqual(
            authorization["authorization_sha256"],
            hashlib.sha256(AUTH.canonical_v2(body)).hexdigest(),
        )
        final_receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_text()
        )
        pending = dict(final_receipt)
        pending.update({
            "status":"executing", "completed_at":None, "exit_status":None,
            "stdout_sha256":None, "stderr_sha256":None,
        })
        self.assertEqual(
            authorization["pending_receipt_sha256"],
            hashlib.sha256(AUTH.canonical(pending)).hexdigest(),
        )
        serialized = " ".join(command).lower()
        for forbidden in ("access_token", "refresh_token", "authorization_code", "pkce"):
            self.assertNotIn(forbidden, serialized)

    def test_program_attestation_has_distinct_touchid_ticket_and_durable_commit(self):
        release = self.make_release()
        _stack, _status, plan = self.native_program_plan()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            AUTH.validate_parameters(
                AUTH.native_program_attestation.OPERATION,
                {"plan": plan}, self.home,
            )
        details = "\n".join(AUTH.operation_details({
            "operation": AUTH.native_program_attestation.OPERATION,
            "parameters": {"plan": plan},
        }))
        self.assertIn("operator attestation only", details)
        self.assertIn("operator-external (never provider-verified)", details)
        self.assertIn("Program / tier: anthropic-cvp / defense", details)

        request_id = "abababab-abab-" + "4bab-8bab-abababababab"
        value = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": 2_000_000_100,
            "expires_at": 2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "cvp-declaration",
            "identity_evidence": "operator-declared",
            "purpose": "Declare exact Anthropic CVP Defense enrollment",
            "resource": AUTH.native_program_attestation.RESOURCE,
            "operation": AUTH.native_program_attestation.OPERATION,
            "parameters": {"plan": plan},
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "program-receipts"
        commit_root = self.root / "program-commits"
        captured = {}

        def run(command, timeout, input_bytes=None):
            self.assertEqual(command, [
                "/usr/bin/python3", "-I",
                str(release.resolve() / "native_stack_backend"),
                "program-attest",
            ])
            self.assertIsNotNone(input_bytes)
            ticket = json.loads(input_bytes)
            self.assertEqual(
                input_bytes, AUTH.canonical_v2(ticket)
            )
            captured["ticket"] = ticket
            authorization = ticket["authorization"]
            result = {
                "schema": "secure-sandbox-native-stack-provider-result-v1",
                "action_id": plan["attestation_id"],
                "action": "program-attest",
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": authorization["authorization_sha256"],
                "status": "verified", "evidence_sha256": "d" * 64,
            }
            return SimpleNamespace(
                returncode=0, stdout=AUTH.canonical_v2(result), stderr=b""
            )

        with mock.patch.object(AUTH, "run_privileged_operation", side_effect=run), \
                mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            execution_status = AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_100,
                program_attestation_root=commit_root,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id",
                emit_output=False,
            )
        self.assertEqual(execution_status, 0)
        ticket = captured["ticket"]
        authorization = ticket["authorization"]
        self.assertEqual(
            ticket["schema"],
            "secure-sandbox-native-program-attestation-host-ticket-v1",
        )
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        self.assertEqual(authorization["request_sha256"], request_sha256)
        self.assertEqual(authorization["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(authorization["host_release_id"], release.name)
        ticket_body = {
            key: ticket[key] for key in ("schema", "plan", "authorization")
        }
        self.assertEqual(
            ticket["ticket_sha256"],
            hashlib.sha256(AUTH.canonical_v2(ticket_body)).hexdigest(),
        )
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(
            receipt["native_program_provider_evidence_sha256"], "d" * 64
        )
        commit_path = commit_root / f"{plan['stack_sha256']}.json"
        commit = json.loads(commit_path.read_bytes())
        self.assertEqual(
            AUTH.native_program_attestation.validate_commit(commit), commit
        )
        self.assertEqual(commit["assurance"], "operator-external")
        self.assertEqual(
            commit["operator_receipt_sha256"],
            hashlib.sha256(AUTH.canonical(receipt)).hexdigest(),
        )
        self.assertEqual(commit_path.stat().st_mode & 0o777, 0o600)

    def test_projection_reconciliation_touchid_receipt_binds_exact_custody(self):
        release = self.make_release()
        plan = self.projection_reconciliation_plan(release.name)
        request_id = "55555555-5555-4555-8555-555555555555"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": 2_000_000_010,
            "expires_at": 2_000_000_010 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "projection-recovery",
            "identity_evidence": "operator-declared",
            "purpose": "Reconcile exact stranded credential projection",
            "resource": AUTH.OPERATION_RESOURCES[
                AUTH.native_projection_reconciliation.OPERATION
            ],
            "operation": AUTH.native_projection_reconciliation.OPERATION,
            "parameters": {"plan": plan}, "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        AUTH.write_request(directory / f"{request_id}.json", value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "projection-receipts"
        captured = {}

        def run(command, _timeout, input_bytes=None):
            self.assertIsNone(input_bytes)
            self.assertEqual(command[:4], [
                "/usr/bin/python3", "-I",
                str(release.resolve() / "native_stack_session_manager"),
                "projection-reconcile",
            ])
            authorization = json.loads(
                command[command.index("--authorization-json") + 1]
            )
            captured["authorization"] = authorization
            body = {
                "outcome": "verified",
                "recovery_operation_id": plan["recovery_operation_id"],
                "original_operation_id": plan["original_operation_id"],
                "process_identifier": plan["process_identifier"],
                "process_start_time_us": plan["process_start_time_us"],
                "consumer_executable_sha256": plan[
                    "consumer_executable_sha256"
                ],
                "session_authority_sha256": plan[
                    "session_authority_sha256"
                ],
                "reconciliation_evidence_sha256": "a" * 64,
            }
            reply = {
                "schema": AUTH.native_projection_reconciliation.REPLY_SCHEMA,
                **body,
                "reply_sha256": (
                    AUTH.native_projection_reconciliation.sha256(body)
                ),
            }
            return subprocess.CompletedProcess(
                command, 0,
                AUTH.native_projection_reconciliation.canonical_bytes(reply),
                b"",
            )

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ), mock.patch.object(AUTH.time, "time", return_value=2_000_000_010):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_010,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", emit_output=False,
            ), 0)
        authorization = captured["authorization"]
        self.assertEqual(
            authorization["recovery_operation_id"],
            plan["recovery_operation_id"],
        )
        self.assertEqual(
            authorization["original_operation_id"],
            plan["original_operation_id"],
        )
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(
            receipt["native_projection_recovery_operation_id"],
            plan["recovery_operation_id"],
        )
        self.assertEqual(
            receipt["native_projection_original_operation_id"],
            plan["original_operation_id"],
        )
        serialized = json.dumps(receipt).lower()
        for forbidden in ("access_token", "refresh_token", "oauth"):
            self.assertNotIn(forbidden, serialized)

    def test_projection_identity_touchid_import_is_distinct_and_content_free(self):
        release = self.make_release()
        plan = self.projection_identity_recovery_plan(release.name)
        request_id = "55555555-5555-4555-8555-555555555555"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": 2_000_000_010,
            "expires_at": 2_000_000_010 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "projection-identity-recovery",
            "identity_evidence": "operator-declared",
            "purpose": "Recover exact committed projection identity",
            "resource": AUTH.OPERATION_RESOURCES[
                AUTH.native_projection_identity_recovery.OPERATION
            ],
            "operation": AUTH.native_projection_identity_recovery.OPERATION,
            "parameters": {"plan": plan}, "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        AUTH.write_request(directory / f"{request_id}.json", value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "projection-identity-receipts"
        captured = {}

        def run(command, _timeout, input_bytes=None):
            self.assertIsNone(input_bytes)
            self.assertEqual(command[:4], [
                "/usr/bin/python3", "-I",
                str(release.resolve() / "native_stack_session_manager"),
                "projection-identity-recover",
            ])
            authorization = json.loads(
                command[command.index("--authorization-json") + 1]
            )
            captured["authorization"] = authorization
            body = {
                "outcome": "verified",
                "recovery_operation_id": plan["recovery_operation_id"],
                "original_operation_id": plan["original_operation_id"],
                "process_identifier": 4242,
                "process_start_time_us": 123456,
                "consumer_executable_sha256": "6" * 64,
                "session_authority_sha256": plan[
                    "session_authority_sha256"
                ],
                "identity_evidence_sha256": "a" * 64,
            }
            reply = {
                "schema": (
                    AUTH.native_projection_identity_recovery.REPLY_SCHEMA
                ),
                **body,
                "reply_sha256": (
                    AUTH.native_projection_identity_recovery.sha256(body)
                ),
            }
            return subprocess.CompletedProcess(
                command, 0,
                AUTH.native_projection_identity_recovery.canonical_bytes(
                    reply
                ),
                b"",
            )

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ), mock.patch.object(AUTH.time, "time", return_value=2_000_000_010):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_010,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", emit_output=False,
            ), 0)
        authorization = captured["authorization"]
        self.assertEqual(
            authorization["schema"],
            AUTH.native_projection_identity_recovery.AUTHORIZATION_SCHEMA,
        )
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_bytes()
        )
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(
            receipt["native_projection_identity_recovery_plan_sha256"],
            plan["plan_sha256"],
        )
        self.assertEqual(
            receipt["native_projection_identity_evidence_sha256"],
            "a" * 64,
        )
        serialized = json.dumps(receipt).lower()
        for forbidden in ("access_token", "refresh_token", "oauth"):
            self.assertNotIn(forbidden, serialized)

    def test_catalog_promotion_dispatch_binds_source_plan_release_and_touchid_receipt(self):
        release = self.make_release()
        source, catalog, raw = self.staged_native_catalog()
        plan = AUTH.native_stack_catalog_promotion.make_plan(
            source_uid=self.uid,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            previous_catalog_sha256=None,
            host_release_id=release.name,
            now=2_000_000_000,
            promotion_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_100):
            AUTH.validate_parameters(
                AUTH.native_stack_catalog_promotion.OPERATION,
                {"plan": plan, "source": str(source)},
                self.home,
            )
        details = "\n".join(AUTH.operation_details({
            "operation": AUTH.native_stack_catalog_promotion.OPERATION,
            "parameters": {"plan": plan, "source": str(source)},
        }))
        self.assertIn("Catalog promotion is inert", details)
        for stack in catalog["stacks"]:
            self.assertIn(stack["stack_id"], details)
            self.assertIn(AUTH.native_vendor_stack.stack_revision(stack), details)

        request_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        value = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": 2_000_000_100,
            "expires_at": 2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "catalog-promotion",
            "identity_evidence": "operator-declared",
            "purpose": "Promote exact native catalog",
            "resource": AUTH.native_stack_catalog_promotion.RESOURCE,
            "operation": AUTH.native_stack_catalog_promotion.OPERATION,
            "parameters": {"plan": plan, "source": str(source)},
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "catalog-promotion-receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"{}\n", stderr=b"")
        with mock.patch.object(
            AUTH, "run_native_catalog_promotion_consume",
            return_value=completed,
        ) as run:
            self.assertEqual(
                AUTH.execute_request(
                    self.uid,
                    request_id,
                    request_sha256,
                    receipt_root,
                    now=2_000_000_100,
                    broker_path=release / "authorization_broker",
                    expected_root_uid=self.uid,
                    authorization_method="touch-id",
                ),
                0,
            )
        self.assertEqual(run.call_args.args[:2], (release.resolve(), str(source)))
        self.assertEqual(run.call_args.kwargs, {
            "timeout": AUTH.authorization_execution_timeout(
                AUTH.native_stack_catalog_promotion.OPERATION),
            "expected_uid": self.uid,
        })
        promotion_request = run.call_args.args[2]
        validated_plan, authorization = (
            AUTH.native_stack_catalog_promotion.validate_request(
                promotion_request,
                now=2_000_000_100,
                expected_host_release_id=release.name,
            )
        )
        self.assertEqual(validated_plan, plan)
        self.assertEqual(authorization["request_sha256"], request_sha256)
        self.assertEqual(authorization["method"], "touch-id")
        self.assertFalse(authorization["password_fallback"])
        final_receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_text()
        )
        self.assertEqual(
            final_receipt["native_catalog_plan_sha256"], plan["plan_sha256"]
        )
        serialized = AUTH.canonical(promotion_request).decode("ascii").lower()
        for forbidden in (
            "access_token", "refresh_token", "authorization_code", "pkce"
        ):
            self.assertNotIn(forbidden, serialized)

    def test_catalog_promotion_rejects_plan_for_a_different_release_pre_receipt(self):
        release = self.make_release()
        source, _catalog, raw = self.staged_native_catalog()
        plan = AUTH.native_stack_catalog_promotion.make_plan(
            source_uid=self.uid,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            previous_catalog_sha256=None,
            host_release_id="f" * 64,
            now=2_000_000_000,
            promotion_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        )
        request_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        value = {
            "schema": AUTH.SCHEMA,
            "request_id": request_id,
            "created_at": 2_000_000_100,
            "expires_at": 2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid,
            "declared_agent": "Codex",
            "declared_session": "catalog-release-mismatch",
            "identity_evidence": "operator-declared",
            "purpose": "Reject wrong release",
            "resource": AUTH.native_stack_catalog_promotion.RESOURCE,
            "operation": AUTH.native_stack_catalog_promotion.OPERATION,
            "parameters": {"plan": plan, "source": str(source)},
            "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "catalog-release-mismatch-receipts"
        with mock.patch.object(AUTH, "run_privileged_operation") as run, \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "native_catalog_promotion_release_mismatch",
                ):
            AUTH.execute_request(
                self.uid,
                request_id,
                request_sha256,
                receipt_root,
                now=2_000_000_100,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id",
            )
        run.assert_not_called()
        self.assertFalse(receipt_root.exists())

    def test_expired_acceptance_plan_finishes_failed_receipt_without_dispatch(self):
        release = self.make_release()
        now = 2_000_000_000
        request_id = "12345678-1234-4123-8123-123456789abc"
        plan = {
            "schema":"secure-sandbox-harness-lifecycle-acceptance-interactive-plan-v1",
            "plan_id":"11111111-1111-4111-8111-111111111111",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "campaign_id":"33333333-3333-4333-8333-333333333333",
            "campaign_sha256":"a" * 64, "machine_identity_sha256":"b" * 64,
            "source_commit":"c" * 40, "case_id":"touchid-expired-plan",
            "procedure_sha256":"d" * 64, "category":"authorization",
            "operation":"authorize", "generation_id":"e" * 64,
            "operator_uid":self.uid, "created_at":now - 30, "expires_at":now,
            "candidate_authority":"none", "production_material_used":False,
            "production_store_access":False,
        }
        plan["plan_sha256"] = hashlib.sha256(AUTH.canonical(plan)).hexdigest()
        value = {
            "schema":AUTH.SCHEMA, "request_id":request_id, "created_at":now - 60,
            "expires_at":now - 60 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid":self.uid, "declared_agent":"Codex",
            "declared_session":"acceptance-expiry",
            "identity_evidence":"operator-declared",
            "purpose":"Verify expired acceptance plan rejection",
            "resource":AUTH.OPERATION_RESOURCES["harness-acceptance-authorize"],
            "operation":"harness-acceptance-authorize",
            "parameters":{"plan":plan}, "ceremony":"approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "expired-acceptance-receipts"
        with mock.patch.object(AUTH.time, "time", return_value=now), \
                mock.patch.object(AUTH, "run_privileged_operation") as run:
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=now,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid, authorization_method="touch-id",
            ), 1)
        run.assert_not_called()
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["exit_status"], 1)
        self.assertEqual(receipt["acceptance_plan_sha256"], plan["plan_sha256"])
        self.assertEqual(receipt["acceptance_case_id"], "touchid-expired-plan")
        self.assertEqual(receipt["acceptance_operator_uid"], self.uid)
        self.assertNotEqual(receipt["stderr_sha256"], hashlib.sha256(b"").hexdigest())

    def test_privileged_sink_rejects_cancel_test_before_receipt_or_dispatch(self):
        release = self.make_release()
        request_id, value, _digest, request_path = self.make_request()
        value["ceremony"] = "cancel-test"
        request_path.unlink()
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "cancel-receipts"
        with (mock.patch.object(AUTH, "protected_release_directory") as protected,
              mock.patch.object(AUTH, "run_privileged_operation") as run,
              self.assertRaisesRegex(
                  AUTH.AuthorizationError, "ceremony_execution_forbidden"
              )):
            AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_000, broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
            )
        protected.assert_not_called()
        run.assert_not_called()
        self.assertFalse(receipt_root.exists())

    def test_short_writes_cannot_truncate_receipts(self):
        release = self.make_release()
        request_id, _value, request_sha256, _request_path = self.make_request()
        receipt_root = self.root / "receipts"
        completed = SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")
        real_write = os.write

        def short_write(descriptor, data):
            return real_write(descriptor, data[:7])

        with (mock.patch.object(AUTH, "run_privileged_operation", return_value=completed),
              mock.patch.object(AUTH.os, "write", side_effect=short_write)):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root, now=2_000_000_000,
                broker_path=release / "authorization_broker", expected_root_uid=self.uid,
            ), 0)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["stdout_sha256"], hashlib.sha256(b"ok").hexdigest())

    def test_secure_enclave_migration_receipt_is_content_free_and_cas_bound(self):
        release = self.make_release()
        request_id = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        transaction_id = "fedcbafe-dcba-4fed-8cba-fedcbafedcba"
        value = {
            "schema":AUTH.SCHEMA, "request_id":request_id,
            "created_at":2_000_000_000,
            "expires_at":2_000_000_000 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid":self.uid, "declared_agent":"Codex",
            "declared_session":"secure-enclave-ddd",
            "identity_evidence":"operator-declared",
            "purpose":"Prepare Secure Enclave authority",
            "resource":AUTH.OPERATION_RESOURCES["execution-approval-key-init"],
            "operation":"execution-approval-key-init",
            "parameters":{"research_release_id":"f" * 64}, "ceremony":"approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        migration = {
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"prepared", "transaction_id":transaction_id,
            "generation_id":"55555555-5555-4555-8555-555555555555",
            "generation_epoch":1, "public_key_sha256":"a" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
            "operator_uid":self.uid, "host_release_id":"b" * 64,
            "research_release_id":"f" * 64,
            "previous_generation_id":None, "previous_generation_epoch":None,
            "preparation_attestation_sha256":"c" * 64,
        }
        completed = SimpleNamespace(
            returncode=0, stdout=AUTH.canonical_v2(migration), stderr=b""
        )
        receipt_root = self.root / "migration-receipts"
        with mock.patch.object(AUTH, "run_privileged_operation", return_value=completed):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_000, broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id",
            ), 0)
        receipt = json.loads((receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["migration_phase"], "prepared")
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["research_release_id"], "f" * 64)
        self.assertEqual(receipt["preparation_attestation_sha256"], "c" * 64)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("public_key_spki_der_b64", receipt)

    def test_release_identity_tampering_is_rejected(self):
        release = self.make_release()
        self.assertEqual(
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            ),
            release.resolve(strict=True),
        )
        manifest_path = release / "manifest.json"
        release.chmod(0o755)
        manifest_path.chmod(0o644)
        manifest = json.loads(manifest_path.read_text())
        manifest["release_id"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o444)
        release.chmod(0o555)
        with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_release_identity_invalid"):
            AUTH.protected_release_directory(release / "authorization_broker", self.uid)

    def test_protected_release_requires_exact_native_deployment_inventory(self):
        exact = self.make_release()
        self.assertEqual(
            AUTH.protected_release_directory(
                exact / "authorization_broker", self.uid,
            ),
            exact.resolve(strict=True),
        )
        self.assertEqual(
            set(json.loads((exact / "manifest.json").read_text())["payloads"]),
            set(AUTH.EXPECTED_RELEASE_MODES),
        )
        manifest_path = exact / "manifest.json"
        original = manifest_path.read_text(encoding="utf-8")
        for mutation in (
            "missing-native-stack-deployer",
            "missing-native-deployment-payloads",
            "additional",
        ):
            exact.chmod(0o755)
            manifest_path.chmod(0o644)
            manifest = json.loads(original)
            if mutation.startswith("missing-"):
                manifest["payloads"].pop(
                    mutation.removeprefix("missing-").replace("-", "_"),
                )
            else:
                manifest["payloads"]["native_deployment_extra"] = "a" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            manifest_path.chmod(0o444)
            exact.chmod(0o555)
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "authorization_manifest_invalid",
            ):
                AUTH.protected_release_directory(
                    exact / "authorization_broker", self.uid,
                )
        exact.chmod(0o755)
        manifest_path.chmod(0o644)
        manifest_path.write_text(original, encoding="utf-8")
        manifest_path.chmod(0o444)
        exact.chmod(0o555)

    def test_protected_release_admits_only_exact_coordination_predecessor(self):
        predecessor = self.make_release(include_coordination_contract=False)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "authorization_manifest_invalid"
        ):
            AUTH.protected_release_directory(
                predecessor / "authorization_broker", self.uid)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "authorization_coordination_predecessor_invalid",
        ):
            AUTH.protected_release_directory(
                predecessor / "authorization_broker", self.uid,
                allow_coordination_predecessor=True)
        previous = predecessor.parent.parent / "previous"
        previous.symlink_to(f"releases/{predecessor.name}")
        self.assertEqual(
            AUTH.protected_release_directory(
                previous / "authorization_broker", self.uid,
                allow_coordination_predecessor=True),
            predecessor.resolve(strict=True),
        )
        payloads = json.loads(
            (predecessor / "manifest.json").read_text())["payloads"]
        self.assertEqual(
            set(payloads), set(AUTH.PRE_NATIVE_STACK_COORDINATION_RELEASE_MODES))

    def test_active_broker_requires_coordination_floor_and_epoch(self):
        release = self.make_release()
        floor = release.parent.parent / AUTH.NATIVE_STACK_COORDINATION_FLOOR_NAME
        enforcement = (
            release.parent.parent
            / AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
        )
        floor.unlink()
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_stack_coordination_floor_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid)
        floor_raw = AUTH.canonical({
            "schema": AUTH.NATIVE_STACK_COORDINATION_FLOOR_SCHEMA,
            "minimum_epoch": 2,
            "established_from_release_id": release.name,
            "established_from_contract_sha256": "a" * 64,
        })
        floor.write_bytes(floor_raw)
        floor.chmod(0o600)
        enforcement.chmod(0o600)
        enforcement.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA,
            "minimum_epoch": 2,
            "minimum_features": sorted(
                AUTH.NATIVE_STACK_COORDINATION_REQUIRED_FEATURES),
            "authoritative_floor_sha256": hashlib.sha256(
                floor_raw).hexdigest(),
        }))
        enforcement.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_stack_coordination_contract_below_floor",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid)

    def test_active_broker_requires_cross_bound_coordination_enforcement(self):
        release = self.make_release()
        enforcement = (
            release.parent.parent
            / AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME
        )
        enforcement.unlink()
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_stack_coordination_enforcement_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid)
        enforcement.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA,
            "minimum_epoch": 1,
            "minimum_features": sorted(
                AUTH.NATIVE_STACK_COORDINATION_REQUIRED_FEATURES),
            "authoritative_floor_sha256": "f" * 64,
        }))
        enforcement.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_stack_coordination_enforcement_mismatch",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid)
        floor_raw = (
            release.parent.parent
            / AUTH.NATIVE_STACK_COORDINATION_FLOOR_NAME
        ).read_bytes()
        enforcement.chmod(0o600)
        enforcement.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_SCHEMA,
            "minimum_epoch": 1,
            "minimum_features": sorted({
                *AUTH.NATIVE_STACK_COORDINATION_REQUIRED_FEATURES,
                "future-two-way-gate-v2",
            }),
            "authoritative_floor_sha256": hashlib.sha256(
                floor_raw).hexdigest(),
        }))
        enforcement.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_stack_coordination_contract_below_floor",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid)

    def test_active_broker_requires_candidate_admission_enforcement(self):
        release = self.make_release()
        enforcement = (
            release.parent.parent
            / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME
        )
        enforcement.unlink()
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_enforcement_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )
        enforcement.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA,
            "required_feature": (
                AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            ),
            "required_payload_inventory_sha256": "f" * 64,
            "authoritative_floor_sha256": "a" * 64,
        }))
        enforcement.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_enforcement_invalid",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_host_trust_records_reject_extended_acls(self):
        release = self.make_release()
        root = release.parent.parent
        cases = (
            (
                root,
                "everyone allow write",
                "authorization_broker_release_untrusted",
            ),
            (
                root / AUTH.NATIVE_STACK_COORDINATION_ENFORCEMENT_NAME,
                "everyone allow write",
                "native_stack_coordination_enforcement_untrusted",
            ),
            (
                root / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME,
                "everyone allow write",
                "native_host_candidate_enforcement_untrusted",
            ),
            (
                root / AUTH.NATIVE_STACK_COORDINATION_FLOOR_NAME,
                "everyone allow read,write",
                "native_stack_coordination_floor_untrusted",
            ),
            (
                release.parent,
                "everyone allow write",
                "authorization_broker_release_untrusted",
            ),
            (
                release,
                "everyone allow write",
                "authorization_broker_release_untrusted",
            ),
            (
                release / "manifest.json",
                "everyone allow write",
                "authorization_manifest_untrusted",
            ),
            (
                release / "controller",
                "everyone allow write",
                "protected_payload_invalid:controller",
            ),
            (
                release / AUTH.TOUCHID_UI_APP_NAME,
                "everyone allow write",
                "authorization_ui_bundle_invalid",
            ),
            (
                release / AUTH.TOUCHID_UI_APP_NAME / "Contents",
                "everyone allow write",
                "authorization_ui_bundle_invalid",
            ),
            (
                release / AUTH.TOUCHID_UI_APP_NAME / "Contents/Info.plist",
                "everyone allow write",
                "authorization_ui_bundle_invalid",
            ),
        )
        for path, rule, error in cases:
            with self.subTest(path=path.name, rule=rule):
                with self.extended_acl(path, rule), self.assertRaisesRegex(
                    AUTH.AuthorizationError, error,
                ):
                    AUTH.protected_release_directory(
                        release / "authorization_broker", self.uid,
                    )

    def test_candidate_private_marker_rejects_read_and_write_acls(self):
        release = self.make_release()
        marker = (
            release.parent.parent / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
        )
        for rule in ("everyone allow read", "everyone allow write"):
            with self.subTest(rule=rule):
                with self.extended_acl(marker, rule), self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "native_host_candidate_floor_untrusted",
                ):
                    AUTH.protected_release_directory(
                        release / "authorization_broker", self.uid,
                    )

    def test_candidate_private_marker_acl_check_never_reads_private_bytes(self):
        release = self.make_release()
        root = release.parent.parent
        marker = root / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
        marker_identity = (marker.stat().st_dev, marker.stat().st_ino)
        read = AUTH.os.read

        def guarded_read(descriptor, size):
            opened = os.fstat(descriptor)
            self.assertNotEqual(
                (opened.st_dev, opened.st_ino), marker_identity,
                "candidate private floor content must remain unread",
            )
            return read(descriptor, size)

        with mock.patch.object(AUTH.os, "read", side_effect=guarded_read):
            value = AUTH.native_host_candidate_floor(
                root, self.uid, set(AUTH.EXPECTED_RELEASE_MODES),
            )
        self.assertEqual(
            value["schema"], AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA,
        )

    def test_candidate_floor_rejects_release_missing_required_feature(self):
        release = self.make_release(include_candidate_feature=False)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_contract_below_floor",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_candidate_public_first_partial_floor_fails_closed(self):
        release = self.make_release()
        (
            release.parent.parent
            / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
        ).unlink()
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_floor_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_candidate_pending_projection_fences_broker_before_publication(self):
        release = self.make_release(include_candidate_feature=False)
        root = release.parent.parent
        (root / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_NAME).unlink()
        (root / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME).unlink()
        pending = root / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME
        pending.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA,
            "required_feature": (
                AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            ),
            "required_payload_inventory_sha256": "a" * 64,
            "authoritative_floor_sha256": "b" * 64,
        }))
        pending.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_floor_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_candidate_pending_projection_conflicts_with_final_projection(self):
        release = self.make_release()
        root = release.parent.parent
        pending = root / AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_PENDING_NAME
        pending.write_bytes(AUTH.canonical({
            "schema": AUTH.NATIVE_HOST_CANDIDATE_ENFORCEMENT_SCHEMA,
            "required_feature": (
                AUTH.NATIVE_HOST_CANDIDATE_ADMISSION_FEATURE
            ),
            "required_payload_inventory_sha256": "a" * 64,
            "authoritative_floor_sha256": "b" * 64,
        }))
        pending.chmod(0o444)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_floor_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_candidate_private_floor_marker_must_remain_root_only(self):
        release = self.make_release()
        floor = (
            release.parent.parent / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
        )
        floor.chmod(0o644)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError,
            "native_host_candidate_floor_untrusted",
        ):
            AUTH.protected_release_directory(
                release / "authorization_broker", self.uid,
            )

    def test_candidate_private_floor_bytes_are_not_read_by_login_broker(self):
        release = self.make_release()
        floor = (
            release.parent.parent / AUTH.NATIVE_HOST_CANDIDATE_FLOOR_NAME
        )
        real_open = os.open

        def public_only_open(path, *args, **kwargs):
            if Path(path) == floor:
                raise PermissionError("simulated root-only private floor")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(AUTH.os, "open", side_effect=public_only_open):
            self.assertEqual(
                AUTH.protected_release_directory(
                    release / "authorization_broker", self.uid,
                ),
                release.resolve(strict=True),
            )

    def test_timeout_terminates_the_dialog_process_group(self):
        started = time.monotonic()
        with self.assertRaisesRegex(AUTH.AuthorizationError, "authorization_dialog_timeout"):
            AUTH.run_process(["/bin/sleep", "5"], 0.05)
        self.assertLess(time.monotonic() - started, 2)

    def test_timeout_terminates_privileged_operation_group(self):
        started = time.monotonic()
        result = AUTH.run_privileged_operation(["/bin/sleep", "5"], 0.05)
        self.assertEqual(result.returncode, 124)
        self.assertIn(b"privileged_operation_timeout", result.stderr)
        self.assertLess(time.monotonic() - started, 2)

    def test_touchid_protocol_is_canonical_bounded_and_exact(self):
        client, server = socket.socketpair()
        try:
            value = {
                "request_id": "12345678-1234-4123-8123-123456789abc",
                "request_sha256": "a" * 64,
                "schema": AUTH.TOUCHID_SCHEMA,
            }
            client.sendall(AUTH.canonical(value))
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(AUTH.read_touchid_message(server), value)
        finally:
            client.close()
            server.close()

    def test_touchid_cancellation_receipt_is_content_free_and_generation_bound(self):
        receipt_root = self.root / "receipts"
        parameters = self.execution_parameters()
        value = {
            "schema":AUTH.SCHEMA,
            "request_id":"88888888-8888-4888-8888-888888888888",
            "declared_agent":"Codex", "declared_session":"cancel-v2",
            "purpose":"Cancel exact execution",
            "resource":AUTH.OPERATION_RESOURCES["execution-approval-sign"],
            "operation":"execution-approval-sign", "parameters":parameters,
            "ceremony":"cancel-test",
        }
        challenge = {
            "mode":"secure-enclave-sign", "host_release_id":"c" * 64,
            "authorization_ui_bundle_sha256":"d" * 64,
            "generation_id":"99999999-9999-4999-8999-999999999999",
            "generation_epoch":4,
            "public_key_sha256":"a" * 64,
            "algorithm":AUTH.EXECUTION_APPROVAL_V2_ALGORITHM,
        }
        public_root = self.root / "public-receipts"
        AUTH.record_touchid_cancellation(
            value, "b" * 64, challenge, receipt_root, public_root,
            self.uid, now=123,
        )
        receipt = json.loads((receipt_root / f"{value['request_id']}.json").read_text())
        self.assertEqual(receipt["status"], "cancelled")
        self.assertEqual(receipt["outcome"], "cancelled")
        self.assertEqual(receipt["ceremony"], "cancel-test")
        self.assertEqual(receipt["approval_id"], parameters["approval_id"])
        self.assertEqual(receipt["approval_key_generation_epoch"], 4)
        self.assertNotIn("parameters", receipt)
        self.assertNotIn("code_sha256", receipt)
        public = json.loads((public_root / f"{value['request_id']}.json").read_text())
        self.assertEqual(public["request_sha256"], "b" * 64)
        self.assertEqual(public["host_release_id"], "c" * 64)
        self.assertEqual(public["authorization_ui_bundle_sha256"], "d" * 64)
        self.assertEqual(public["authorization_receipt_sha256"],
                         hashlib.sha256(AUTH.canonical(receipt)).hexdigest())
        self.assertNotIn("purpose", public)

    def test_public_cancellation_receipt_mode_survives_restrictive_umask(self):
        receipt_root = self.root / "private-receipts"
        public_root = self.root / "public-receipts"
        value = {
            "schema":AUTH.SCHEMA,
            "request_id":"88888888-8888-4888-8888-888888888888",
            "declared_agent":"Codex", "declared_session":"cancel-umask",
            "purpose":"Cancel test", "resource":AUTH.OPERATION_RESOURCES[
                "authorization-probe"
            ],
            "operation":"authorization-probe",
            "parameters":{"challenge":"77777777-7777-4777-8777-777777777777"},
            "ceremony":"cancel-test",
        }
        challenge = {
            "mode":"cancel-only", "host_release_id":"c" * 64,
            "authorization_ui_bundle_sha256":"d" * 64,
        }
        prior_umask = os.umask(0o077)
        try:
            AUTH.record_touchid_cancellation(
                value, "b" * 64, challenge, receipt_root, public_root,
                self.uid, now=123,
            )
        finally:
            os.umask(prior_umask)
        self.assertEqual(public_root.stat().st_mode & 0o777, 0o755)
        self.assertEqual(
            (public_root / f"{value['request_id']}.json").stat().st_mode & 0o777,
            0o644,
        )

    def test_touchid_connection_binds_kernel_peer_and_records_method(self):
        client, server = socket.socketpair()
        value = {
            "request_id": "12345678-1234-4123-8123-123456789abc",
            "request_sha256": "b" * 64,
            "schema": AUTH.TOUCHID_SCHEMA,
        }
        client.sendall(AUTH.canonical(value))
        client.shutdown(socket.SHUT_WR)

        def execute(uid, request_id, request_sha256, **kwargs):
            self.assertEqual(uid, self.uid)
            self.assertEqual(request_id, value["request_id"])
            self.assertEqual(request_sha256, value["request_sha256"])
            self.assertEqual(kwargs["authorization_method"], "touch-id")
            kwargs["result_capture"].append(SimpleNamespace(
                returncode=0, stdout=b"ok\n", stderr=b""
            ))
            return 0

        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer") as verify,
                  mock.patch.object(
                      AUTH, "open_request_binding",
                      return_value=({"ceremony":"approve"}, None),
                  ),
                  mock.patch.object(AUTH, "verify_request"),
                  mock.patch.object(AUTH, "execute_request", side_effect=execute)):
                restart = AUTH.handle_touchid_connection(server, broker_path=self.root / "broker",
                                                         expected_root_uid=self.uid,
                                                         receipt_root=self.root / "receipts")
            response = client.recv(1024)
            magic, status, stdout_size, stderr_size = struct.unpack("!4sIII", response[:16])
            self.assertEqual((magic, status, stdout_size, stderr_size), (b"SSAR", 0, 3, 0))
            self.assertEqual(response[16:], b"ok\n")
            self.assertFalse(restart)
            verify.assert_called_once_with(Path("/signed-ui"), self.root, self.uid)
        finally:
            client.close()
            server.close()

    def test_revoked_request_cannot_commit_after_ui_challenge(self):
        client, server = socket.socketpair()
        request_id = "12345678-1234-4123-8123-123456789abc"
        request_sha256 = "b" * 64
        begin = {
            "schema":"secure-sandbox-touchid-approval-v2", "phase":"begin",
            "request_id":request_id, "request_sha256":request_sha256,
        }
        final = {
            "schema":"secure-sandbox-touchid-authorization-v2",
            "phase":"authorize", "request_id":request_id,
            "request_sha256":request_sha256,
        }
        request = {"ceremony":"approve", "operation":"pki-anchor-begin"}
        try:
            with (mock.patch.object(
                      AUTH, "peer_audit_identity",
                      return_value=(self.uid, b"x" * 32, Path("/signed-ui")),
                  ), mock.patch.object(
                      AUTH, "authorization_peer_kind", return_value="touch-id-ui",
                  ), mock.patch.object(
                      AUTH, "protected_release_directory", return_value=self.root,
                  ), mock.patch.object(AUTH, "verify_touchid_peer"), \
                  mock.patch.object(
                      AUTH, "read_touchid_line", side_effect=[begin, final],
                  ), mock.patch.object(
                      AUTH, "open_request_binding", return_value=(request, None),
                  ), mock.patch.object(
                      AUTH, "read_request",
                      side_effect=AUTH.AuthorizationError("request_revoked"),
                  ) as read_request, mock.patch.object(AUTH, "verify_request"), \
                  mock.patch.object(
                      AUTH, "touchid_v2_challenge",
                      return_value={"mode":"legacy-touch-id"},
                  ), mock.patch.object(
                      AUTH, "touchid_ui_bundle_sha256", return_value="c" * 64,
                  ), mock.patch.object(
                      AUTH, "run_privileged_operation"
                  ) as mutation):
                restart = AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                    receipt_root=self.root / "receipts",
                )
            response = client.recv(8192)
            frame = response[response.rindex(b"SSAR"):]
            _magic, status, stdout_size, stderr_size = struct.unpack(
                "!4sIII", frame[:16]
            )
            self.assertEqual((status, stdout_size), (1, 0))
            self.assertEqual(
                json.loads(frame[16:16 + stderr_size])["error"],
                "request_revoked",
            )
            self.assertFalse(restart)
            self.assertEqual(read_request.call_count, 1)
            mutation.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_native_inspect_query_invokes_only_exact_backend_and_returns_digested_status(self):
        stack, status = self.native_stack_status_fixture()
        body = {
            "operation_id": "99999999-9999-4999-8999-999999999999",
            "stack_id": stack["stack_id"],
            "stack_sha256": AUTH.native_vendor_stack.stack_revision(stack),
            "catalog_sha256": "a" * 64,
        }
        request = {
            "schema": AUTH.NATIVE_INSPECT_QUERY_SCHEMA,
            **body,
            "request_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }
        observed = {}

        class Process:
            returncode = 0
            pid = 123

            def communicate(self, input=None, timeout=None):
                observed["input"] = input
                observed["timeout"] = timeout
                return AUTH.native_stack_operations.canonical_bytes(status), None

        release = Path("/protected/release")
        with mock.patch.object(AUTH.subprocess, "Popen", return_value=Process()) as popen:
            reply = AUTH.native_inspect_query(request, release)
        self.assertEqual(
            popen.call_args.args[0],
            [str(release / "native_stack_backend"), "inspect-status"],
        )
        self.assertEqual(observed, {
            "input": AUTH.canonical(request),
            "timeout": 180,
        })
        self.assertEqual(reply["status"], status)
        reply_body = {
            "operation_id": request["operation_id"],
            "request_sha256": request["request_sha256"],
            "status": status,
        }
        self.assertEqual(
            reply["reply_sha256"],
            hashlib.sha256(AUTH.canonical(reply_body)).hexdigest(),
        )
        changed = dict(request, catalog_sha256="b" * 64)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_stack_inspect_query_invalid"
        ):
            AUTH.native_inspect_query(changed, release)

    def test_inspect_socket_requires_control_center_identity_without_touchid(self):
        stack, _status = self.native_stack_status_fixture()
        body = {
            "operation_id": "00000000-0000-4000-8000-000000000001",
            "stack_id": stack["stack_id"],
            "stack_sha256": AUTH.native_vendor_stack.stack_revision(stack),
            "catalog_sha256": "c" * 64,
        }
        request = {
            "schema": AUTH.NATIVE_INSPECT_QUERY_SCHEMA,
            **body,
            "request_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }
        response = {
            "schema": AUTH.NATIVE_INSPECT_REPLY_SCHEMA,
            "operation_id": request["operation_id"],
            "request_sha256": request["request_sha256"],
            "status": {"content-free": True},
            "reply_sha256": "d" * 64,
        }
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH,
                    "peer_audit_identity",
                    return_value=(self.uid, b"x" * 32, Path("/signed-control-center")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root
                ),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center"
                ),
                mock.patch.object(AUTH, "verify_control_center_peer") as verify,
                mock.patch.object(AUTH, "verify_touchid_peer") as touchid,
                mock.patch.object(AUTH, "native_inspect_query", return_value=response),
            ):
                restart = AUTH.handle_touchid_connection(
                    server,
                    broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                )
            self.assertEqual(json.loads(client.recv(65536)), response)
            self.assertFalse(restart)
            verify.assert_called_once_with(
                Path("/signed-control-center"), self.root, self.uid, b"x" * 32
            )
            touchid.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_session_plan_query_is_content_free_and_backend_bound(self):
        stack, _ = self.native_stack_status_fixture()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        plan = AUTH.native_stack_session.make_plan(
            action="session-start",
            action_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            session_id=authority["session_context_binding"]["session_id"],
            stack_id=stack["stack_id"],
            stack_sha256=AUTH.native_vendor_stack.stack_revision(stack),
            catalog_sha256="c" * 64,
            status_sha256=status["status_sha256"],
            runtime_authority_value=authority,
            source_id=None, source_manifest_sha256=None,
            resume_session_id=None, lease_profile_id="interactive",
            created_at=2_000_000_000,
        )
        body = {
            "action": "session-start", "action_id": plan["action_id"],
            "session_id": plan["session_id"], "stack_id": plan["stack_id"],
            "stack_sha256": plan["stack_sha256"],
            "catalog_sha256": plan["catalog_sha256"], "source_id": None,
            "resume_session_id": None, "lease_profile_id": "interactive",
        }
        request = {
            "schema": AUTH.NATIVE_SESSION_PLAN_QUERY_SCHEMA, **body,
            "request_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }

        class Process:
            returncode = 0
            pid = 123

            def communicate(self, input=None, timeout=None):
                self.input = input
                self.timeout = timeout
                return AUTH.native_stack_session.canonical_bytes(plan), None

        process = Process()
        release = Path("/protected/release")
        with mock.patch.object(
            AUTH.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            AUTH.time, "time", return_value=2_000_000_001
        ):
            reply = AUTH.native_session_plan_query(request, release)
        self.assertEqual(
            popen.call_args.args[0],
            [str(release / "native_stack_backend"), "session-plan"],
        )
        self.assertEqual(process.input, AUTH.canonical(request))
        self.assertEqual(reply["plan"], plan)
        self.assertNotIn("persona_sha256", request)

    def test_projection_recovery_plan_query_is_content_free_and_root_bound(self):
        release = Path("/protected") / ("4" * 64)
        plan = self.projection_reconciliation_plan(release.name)
        body = {
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
        }
        request = {
            "schema": AUTH.NATIVE_PROJECTION_PLAN_QUERY_SCHEMA,
            **body,
            "request_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }
        completed = subprocess.CompletedProcess(
            [], 0,
            AUTH.native_projection_reconciliation.canonical_bytes(plan), b"",
        )
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=completed
        ) as run, mock.patch.object(
            AUTH.time, "time", return_value=2_000_000_001
        ):
            reply = AUTH.native_projection_recovery_plan_query(
                request, release
            )
        self.assertEqual(reply["plan"], plan)
        self.assertEqual(
            run.call_args.args[0], [
                "/usr/bin/python3", "-I",
                str(release / "native_stack_session_manager"),
                "projection-recovery-plan", "--original-operation-id",
                plan["original_operation_id"], "--recovery-operation-id",
                plan["recovery_operation_id"],
            ]
        )
        serialized = AUTH.canonical(request).decode("ascii").lower()
        for forbidden in ("token", "credential", "authorization"):
            self.assertNotIn(forbidden, serialized)

    def test_projection_identity_plan_query_is_content_free_and_root_bound(self):
        release = Path("/protected") / ("4" * 64)
        plan = self.projection_identity_recovery_plan(release.name)
        body = {
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
        }
        request = {
            "schema": AUTH.NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA,
            **body,
            "request_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }
        completed = subprocess.CompletedProcess(
            [], 0,
            AUTH.native_projection_identity_recovery.canonical_bytes(plan),
            b"",
        )
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=completed
        ) as run, mock.patch.object(
            AUTH.time, "time", return_value=2_000_000_001
        ):
            reply = AUTH.native_projection_identity_recovery_plan_query(
                request, release
            )
        self.assertEqual(reply["plan"], plan)
        self.assertEqual(
            run.call_args.args[0], [
                "/usr/bin/python3", "-I",
                str(release / "native_stack_session_manager"),
                "projection-identity-recovery-plan",
                "--original-operation-id", plan["original_operation_id"],
                "--recovery-operation-id", plan["recovery_operation_id"],
            ]
        )
        serialized = AUTH.canonical(request).decode("ascii").lower()
        self.assertNotIn("token", serialized)
        self.assertNotIn("process_identifier", serialized)
        self.assertNotIn("consumer_executable", serialized)

    def test_projection_identity_plan_query_error_is_canonical_ndjson(self):
        request = {
            "schema": AUTH.NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA,
            "recovery_operation_id":
                "11111111-1111-4111-8111-111111111111",
            "original_operation_id":
                "22222222-2222-4222-8222-222222222222",
        }
        body = {
            name: request[name] for name in (
                "recovery_operation_id", "original_operation_id",
            )
        }
        request["request_sha256"] = hashlib.sha256(
            AUTH.canonical(body)
        ).hexdigest()
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH, "peer_audit_identity",
                    return_value=(self.uid, b"x" * 32, Path("/signed-control")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root,
                ),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center",
                ),
                mock.patch.object(AUTH, "verify_control_center_peer"),
                mock.patch.object(
                    AUTH, "native_projection_identity_recovery_plan_query",
                    side_effect=AUTH.AuthorizationError("injected_identity_error"),
                ),
            ):
                restart = AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                )
            response = client.recv(4096)
        finally:
            client.close()
            server.close()
        self.assertFalse(restart)
        self.assertEqual(response, AUTH.canonical({
            "schema": (
                "secure-sandbox-native-projection-identity-recovery-"
                "plan-query-error-v1"
            ),
            "status": "rejected", "error": "injected_identity_error",
        }))
        self.assertFalse(response.startswith(b"SSAR"))

    def test_host_install_failure_fence_rejects_even_recovery_queries(self):
        request = {
            "schema": AUTH.NATIVE_PROJECTION_IDENTITY_PLAN_QUERY_SCHEMA,
            "recovery_operation_id":
                "11111111-1111-4111-8111-111111111111",
            "original_operation_id":
                "22222222-2222-4222-8222-222222222222",
        }
        body = {
            name: request[name] for name in (
                "recovery_operation_id", "original_operation_id",
            )
        }
        request["request_sha256"] = hashlib.sha256(
            AUTH.canonical(body)
        ).hexdigest()
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH, "peer_audit_identity",
                    return_value=(self.uid, b"x" * 32, Path("/signed-control")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root,
                ),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center",
                ),
                mock.patch.object(AUTH, "verify_control_center_peer"),
                mock.patch.object(
                    AUTH, "native_projection_identity_recovery_plan_query",
                ) as execute,
            ):
                restart = AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid, host_install_fenced=True,
                )
            response = client.recv(4096)
        finally:
            client.close()
            server.close()
        self.assertFalse(restart)
        execute.assert_not_called()
        self.assertEqual(response, AUTH.canonical({
            "schema": (
                "secure-sandbox-native-projection-identity-recovery-"
                "plan-query-error-v1"
            ),
            "status": "rejected", "error": "host_install_recovery_required",
        }))

    def test_projection_reconciliation_review_is_explicit_and_distinct(self):
        plan = self.projection_reconciliation_plan()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_001):
            AUTH.validate_parameters(
                AUTH.native_projection_reconciliation.OPERATION,
                {"plan": plan}, self.home,
            )
        details = "\n".join(AUTH.operation_details({
            "operation": AUTH.native_projection_reconciliation.OPERATION,
            "parameters": {"plan": plan},
        }))
        self.assertIn("Credential recovery", details)
        self.assertIn(str(plan["process_identifier"]), details)
        self.assertIn(plan["guest_absence_evidence_sha256"], details)
        self.assertIn(plan["egress_closed_evidence_sha256"], details)
        authorization = {
            "schema": AUTH.native_projection_reconciliation.AUTHORIZATION_SCHEMA,
        }
        command = AUTH.operation_command(
            {
                "operation": AUTH.native_projection_reconciliation.OPERATION,
                "parameters": {"plan": plan},
            },
            Path("/protected") / ("4" * 64),
            authorization=authorization,
        )
        self.assertIn("projection-reconcile", command)
        self.assertNotIn("token", " ".join(command).lower())

    def test_projection_identity_review_is_explicit_and_never_claims_clear(self):
        plan = self.projection_identity_recovery_plan()
        with mock.patch.object(AUTH.time, "time", return_value=2_000_000_001):
            AUTH.validate_parameters(
                AUTH.native_projection_identity_recovery.OPERATION,
                {"plan": plan}, self.home,
            )
        details = "\n".join(AUTH.operation_details({
            "operation": AUTH.native_projection_identity_recovery.OPERATION,
            "parameters": {"plan": plan},
        }))
        self.assertIn("phase one", details)
        self.assertIn("does not clear credential custody", details)
        self.assertIn("second Touch ID", details)
        command = AUTH.operation_command(
            {
                "operation": AUTH.native_projection_identity_recovery.OPERATION,
                "parameters": {"plan": plan},
            },
            Path("/protected") / ("4" * 64),
            authorization={
                "schema": (
                    AUTH.native_projection_identity_recovery.AUTHORIZATION_SCHEMA
                )
            },
        )
        self.assertIn("projection-identity-recover", command)
        self.assertNotIn("token", " ".join(command).lower())

    def test_live_control_center_identity_cannot_be_replaced_by_bundle_path(self):
        bundle = self.root / "SecureSandbox.app"
        contents = bundle / "Contents"
        executable = contents / "MacOS" / "SecureSandbox"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"not the running image")
        executable.chmod(0o755)
        (contents / "Info.plist").write_bytes(AUTH.plistlib.dumps({
            "CFBundleIdentifier": AUTH.CONTROL_CENTER_BUNDLE_ID,
            "CFBundleExecutable": executable.name,
        }))
        token = struct.pack("=8I", 1, self.uid, 3, 4, 5, 6, 7, 8)
        observed: list[tuple[bytes, str, int]] = []
        AUTH.verify_control_center_peer(
            executable, self.root, self.uid, token,
            live_validator=lambda *values: observed.append(values),
        )
        self.assertEqual(observed, [(token, self.team_id, self.uid)])
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "live_identity_invalid"
        ):
            AUTH.verify_control_center_peer(
                executable, self.root, self.uid, token,
                live_validator=lambda *_values: (_ for _ in ()).throw(
                    AUTH.AuthorizationError(
                        "control_center_live_identity_invalid"
                    )
                ),
            )

    def test_static_runtime_flags_cannot_replace_live_dynamic_status(self):
        self.assertEqual(AUTH.CONTROL_CENTER_DYNAMIC_VALIDATION_FLAGS, 1 << 4)
        self.assertEqual(AUTH.CONTROL_CENTER_STATIC_COPY_FLAGS, 1 << 0)
        self.assertEqual(
            AUTH.CONTROL_CENTER_STATIC_VALIDATION_FLAGS,
            (1 << 0) | (1 << 3) | (1 << 4),
        )
        self.assertEqual(
            AUTH.CONTROL_CENTER_DYNAMIC_VALIDATION_FLAGS
            & ((1 << 0) | (1 << 3) | (1 << 23)),
            0,
        )
        self.assertEqual(
            AUTH.CONTROL_CENTER_STATIC_VALIDATION_FLAGS & (1 << 23),
            0,
        )
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "live_identity_invalid"
        ):
            AUTH.require_live_control_center_signing_record({
                "identifier": AUTH.CONTROL_CENTER_BUNDLE_ID,
                "team_identifier": self.team_id,
                "dynamic_status": 0,
                "static_flags": 0x0001_0000,
            }, expected_team=self.team_id)
        AUTH.require_live_control_center_signing_record({
            "identifier": AUTH.CONTROL_CENTER_BUNDLE_ID,
            "team_identifier": self.team_id,
            "dynamic_status": 0x0001_0000,
            "static_flags": 0,
        }, expected_team=self.team_id)

    def test_native_session_startup_recovery_is_exact_and_fail_closed(self):
        body = {
            "state": "closed", "active_session_count": 0,
            "reconciled_at": 2_000_000_000,
        }
        value = {
            "schema": "secure-sandbox-native-stack-session-recovery-v1",
            **body, "evidence_sha256": hashlib.sha256(
                AUTH.canonical(body)
            ).hexdigest(),
        }
        completed = subprocess.CompletedProcess(
            [], 0, AUTH.canonical(value), b""
        )
        release = Path("/protected/release")
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=completed
        ) as run:
            self.assertTrue(AUTH.reconcile_native_sessions(release))
        self.assertEqual(run.call_args.args[0][-1], "recover")
        recovery_required = subprocess.CompletedProcess(
            [], 1, b"", AUTH.canonical({
                "schema": (
                    "secure-sandbox-native-stack-session-manager-error-v1"
                ),
                "status": "rejected",
                "error": "native_stack_session_recovery_required",
            })
        )
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=recovery_required
        ):
            self.assertFalse(AUTH.reconcile_native_sessions(release))
        rejected = subprocess.CompletedProcess([], 1, b"{}\n", b"")
        with mock.patch.object(
            AUTH, "run_privileged_operation", return_value=rejected
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "startup_recovery_failed"
        ):
            AUTH.reconcile_native_sessions(release)

    def test_touchid_connection_rejects_different_peer_before_protocol_or_execution(self):
        client, server = socket.socketpair()
        client.shutdown(socket.SHUT_WR)
        try:
            with (mock.patch.object(
                      AUTH, "peer_audit_identity",
                      return_value=(self.uid, b"x" * 32, Path("/different/helper")),
                  ), mock.patch.object(
                      AUTH, "protected_release_directory", return_value=self.root,
                  ), mock.patch.object(
                      AUTH, "verify_touchid_peer",
                      side_effect=AUTH.AuthorizationError(
                          "touchid_peer_identity_mismatch"
                      ),
                  ) as verify, mock.patch.object(
                      AUTH, "execute_request"
                  ) as execute):
                restart = AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                    receipt_root=self.root / "receipts",
                )
            response = client.recv(4096)
            magic, status, stdout_size, stderr_size = struct.unpack(
                "!4sIII", response[:16]
            )
            self.assertEqual((magic, status, stdout_size), (b"SSAR", 1, 0))
            body = json.loads(response[16:16 + stderr_size])
            self.assertEqual(body, {
                "schema":AUTH.TOUCHID_SCHEMA, "status":"rejected",
                "error":"touchid_peer_identity_mismatch",
            })
            self.assertFalse(restart)
            verify.assert_called_once_with(Path("/different/helper"), self.root, self.uid)
            execute.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_broker_rejects_approval_message_for_cancel_test_ceremony(self):
        client, server = socket.socketpair()
        request_id = "12345678-1234-4123-8123-123456789abc"
        request_sha256 = "d" * 64
        begin = {
            "schema":"secure-sandbox-touchid-approval-v2", "phase":"begin",
            "request_id":request_id, "request_sha256":request_sha256,
        }
        approval = {
            "schema":"secure-sandbox-touchid-authorization-v2", "phase":"authorize",
            "request_id":request_id, "request_sha256":request_sha256,
        }
        request = {"ceremony":"cancel-test"}
        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer"),
                  mock.patch.object(AUTH, "read_touchid_line", side_effect=[begin, approval]),
                  mock.patch.object(
                      AUTH, "open_request_binding", return_value=(request, None),
                  ),
                  mock.patch.object(AUTH, "verify_request"),
                  mock.patch.object(AUTH, "cancellation_only_challenge",
                                    return_value={
                                        "mode":"cancel-only", "request_id":request_id,
                                        "request_sha256":request_sha256,
                                        "host_release_id":"e" * 64,
                                        "authorization_ui_bundle_sha256":"f" * 64,
                                    }),
                  mock.patch.object(AUTH, "touchid_v2_challenge") as mutating,
                  mock.patch.object(AUTH, "execute_request") as execute):
                AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid, receipt_root=self.root / "receipts",
                )
            response = client.recv(4096)
            response = response[response.index(b"SSAR"):]
            _, status, stdout_size, stderr_size = struct.unpack("!4sIII", response[:16])
            self.assertEqual((status, stdout_size), (1, 0))
            self.assertEqual(json.loads(response[16:16 + stderr_size])["error"],
                             "ceremony_decision_mismatch")
            execute.assert_not_called()
            mutating.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_legacy_broker_rejects_cancel_test_before_execution(self):
        client, server = socket.socketpair()
        request_id = "12345678-1234-4123-8123-123456789abc"
        request_sha256 = "d" * 64
        message = {
            "schema":AUTH.TOUCHID_SCHEMA, "request_id":request_id,
            "request_sha256":request_sha256,
        }
        client.sendall(AUTH.canonical(message))
        client.shutdown(socket.SHUT_WR)
        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer"),
                  mock.patch.object(
                      AUTH, "open_request_binding",
                      return_value=({"ceremony":"cancel-test"}, None),
                  ),
                  mock.patch.object(AUTH, "verify_request"),
                  mock.patch.object(AUTH, "execute_request") as execute):
                AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid, receipt_root=self.root / "receipts",
                )
            response = client.recv(4096)
            _, status, stdout_size, stderr_size = struct.unpack("!4sIII", response[:16])
            self.assertEqual((status, stdout_size), (1, 0))
            self.assertEqual(json.loads(response[16:16 + stderr_size])["error"],
                             "ceremony_protocol_mismatch")
            execute.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_touchid_connection_requests_restart_only_after_sending_release_response(self):
        client, server = socket.socketpair()
        value = {
            "request_id": "12345678-1234-4123-8123-123456789abc",
            "request_sha256": "c" * 64,
            "schema": AUTH.TOUCHID_SCHEMA,
        }
        client.sendall(AUTH.canonical(value))
        client.shutdown(socket.SHUT_WR)

        def execute(*_args, **kwargs):
            kwargs["result_capture"].append(SimpleNamespace(
                returncode=0, stdout=b"deployed\n", stderr=b""
            ))
            return 0

        try:
            with (mock.patch.object(AUTH, "peer_audit_identity",
                                    return_value=(self.uid, b"x" * 32, Path("/signed-ui"))),
                  mock.patch.object(AUTH, "protected_release_directory", return_value=self.root),
                  mock.patch.object(AUTH, "verify_touchid_peer"),
                  mock.patch.object(
                      AUTH, "open_request_binding",
                      return_value=({"ceremony":"approve"}, None),
                  ),
                  mock.patch.object(AUTH, "verify_request"),
                  mock.patch.object(AUTH, "execute_request", side_effect=execute),
                  mock.patch.object(AUTH, "selected_release_changed", return_value=True)):
                restart = AUTH.handle_touchid_connection(server, broker_path=self.root / "broker",
                                                         expected_root_uid=self.uid,
                                                         receipt_root=self.root / "receipts")
            response = client.recv(1024)
            self.assertEqual(response[16:], b"deployed\n")
            self.assertTrue(restart)
        finally:
            client.close()
            server.close()

    def test_native_deployment_queries_are_domain_separated(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        requests = {}
        for command, schema in AUTH.NATIVE_DEPLOYMENT_QUERY_SCHEMAS.items():
            body = {"query_id": query_id, "command": command}
            requests[command] = {
                "schema": schema, "query_id": query_id,
                "request_sha256": AUTH.native_deployment.digest(body),
            }
        self.assertEqual(len({
            value["request_sha256"] for value in requests.values()
        }), 3)
        with mock.patch.object(
            AUTH, "native_deployment_driver_result",
            return_value=self.native_deployment_plan_response(),
        ):
            changed = dict(requests["plan"])
            changed["schema"] = AUTH.NATIVE_DEPLOYMENT_QUERY_SCHEMAS["status"]
            with self.assertRaisesRegex(
                AUTH.AuthorizationError, "native_deployment_query_invalid"
            ):
                AUTH.native_deployment_query(changed, Path("/release"), "status")

    def test_native_deployment_gate_failure_is_recovery_only(self):
        ready = {
            "schema": AUTH.NATIVE_DEPLOYMENT_STATUS_SCHEMA,
            "state": "ready", "phase": None, "deployment_id": None,
            "host_release_id": None, "active_journal_sha256": None,
            "error_sha256": None,
        }
        body = {
            key: item for key, item in ready.items() if key != "schema"
        }
        ready["status_sha256"] = AUTH.native_deployment.digest(body)
        with mock.patch.object(
            AUTH, "native_deployment_driver_result", return_value=ready
        ):
            self.assertFalse(AUTH.native_deployment_recovery_required(
                Path("/release")))
        with mock.patch.object(
            AUTH, "native_deployment_driver_result",
            side_effect=AUTH.AuthorizationError("state_invalid"),
        ):
            self.assertTrue(AUTH.native_deployment_recovery_required(
                Path("/release")))

    def test_native_deployment_status_remains_content_free_when_gate_is_invalid(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        body = {"query_id": query_id, "command": "status"}
        request = {
            "schema": AUTH.NATIVE_DEPLOYMENT_QUERY_SCHEMAS["status"],
            "query_id": query_id,
            "request_sha256": AUTH.native_deployment.digest(body),
        }
        with mock.patch.object(
            AUTH, "native_deployment_driver_result",
            side_effect=AUTH.AuthorizationError(
                "journal_invalid:/private/secret-path"),
        ):
            reply = AUTH.native_deployment_query(
                request, Path("/release") / ("a" * 64), "status",
                expected_uid=self.uid)
        result = reply["result"]
        self.assertEqual(result["state"], "recovery-required")
        self.assertEqual(result["phase"], "state-invalid")
        self.assertIsNone(result["deployment_id"])
        self.assertIsNone(result["host_release_id"])
        self.assertNotIn("secret-path", AUTH.canonical(reply).decode("ascii"))
        AUTH.validate_native_deployment_status(result)

    def test_native_deployment_recovery_only_allows_status_but_blocks_plan(self):
        query_id = "00000000-0000-4000-8000-000000000002"

        def request(command):
            body = {"query_id": query_id, "command": command}
            return {
                "schema": AUTH.NATIVE_DEPLOYMENT_QUERY_SCHEMAS[command],
                "query_id": query_id,
                "request_sha256": AUTH.native_deployment.digest(body),
            }

        status_reply = {
            "schema": AUTH.NATIVE_DEPLOYMENT_REPLY_SCHEMAS["status"],
            "content-free": True,
        }
        for command in ("status", "plan"):
            client, server = socket.socketpair()
            client.sendall(AUTH.canonical(request(command)))
            client.shutdown(socket.SHUT_WR)
            try:
                with (
                    mock.patch.object(
                        AUTH, "peer_audit_identity",
                        return_value=(
                            self.uid, b"x" * 32,
                            Path("/signed-control-center")),
                    ),
                    mock.patch.object(
                        AUTH, "protected_release_directory",
                        return_value=self.root),
                    mock.patch.object(
                        AUTH, "authorization_peer_kind",
                        return_value="control-center"),
                    mock.patch.object(AUTH, "verify_control_center_peer"),
                    mock.patch.object(
                        AUTH, "native_deployment_query",
                        return_value=status_reply) as query,
                ):
                    AUTH.handle_touchid_connection(
                        server, broker_path=self.root / "broker",
                        expected_root_uid=self.uid,
                        deployment_recovery_only=True)
                response = json.loads(client.recv(65536))
                if command == "status":
                    self.assertEqual(response, status_reply)
                    query.assert_called_once()
                else:
                    self.assertEqual(
                        response["schema"],
                        AUTH.NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA)
                    self.assertIn("recovery_required", response["error"])
                    query.assert_not_called()
            finally:
                client.close()
                server.close()

    def test_native_deployment_terminal_is_intent_and_projection_bound(self):
        response = self.native_deployment_plan_response()
        authorization = self.native_deployment_authorization(response)
        terminal = self.native_deployment_terminal(response, authorization)
        self.assertEqual(
            AUTH.validate_native_deployment_terminal(
                terminal, plan_response=response,
                authorization=authorization),
            terminal,
        )
        opposite = self.native_deployment_terminal(
            response, authorization, phase="rolled-back")
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_result_invalid"
        ):
            AUTH.validate_native_deployment_terminal(
                opposite, plan_response=response,
                authorization=authorization)
        altered = json.loads(json.dumps(terminal))
        altered["evidence"]["research_status"]["catalog_sha256"] = "0" * 64
        altered["evidence"]["research_status_sha256"] = (
            AUTH.native_deployment.status_projection_sha256(
                altered["evidence"]["research_status"])
        )
        body = {
            key: item for key, item in altered.items()
            if key not in {"schema", "record_sha256"}
        }
        altered["record_sha256"] = AUTH.native_deployment.digest(body)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_result_invalid"
        ):
            AUTH.validate_native_deployment_terminal(
                altered, plan_response=response,
                authorization=authorization)

    def test_native_deployment_apply_uses_touchid_receipt_bound_authorization(self):
        release = self.make_release()
        response = self.native_deployment_plan_response(release.name)
        request_id = "00000000-0000-4000-8000-000000000005"
        value = {
            "schema": AUTH.SCHEMA, "request_id": request_id,
            "created_at": 2_000_000_100,
            "expires_at": 2_000_000_100 + AUTH.REQUEST_TTL_SECONDS,
            "invoking_uid": self.uid, "declared_agent": "Control Center",
            "declared_session": "00000000-0000-4000-8000-000000000006",
            "identity_evidence": "operator-declared",
            "purpose": "Deploy exact native runtime",
            "resource": AUTH.native_deployment.RESOURCE,
            "operation": AUTH.native_deployment.APPLY_OPERATION,
            "parameters": {"plan": response}, "ceremony": "approve",
        }
        directory = AUTH.request_directory(self.home)
        AUTH.secure_user_directory(directory, self.uid)
        request_path = directory / f"{request_id}.json"
        AUTH.write_request(request_path, value)
        request_sha256 = hashlib.sha256(AUTH.canonical(value)).hexdigest()
        receipt_root = self.root / "native-deployment-receipts"
        captured = {}

        def run(selected_release, arguments, **kwargs):
            self.assertEqual(selected_release, release.resolve())
            self.assertEqual(arguments[0], "consume")
            authorization = json.loads(
                arguments[arguments.index("--authorization-json") + 1])
            captured["authorization"] = authorization
            pending = json.loads(
                (receipt_root / f"{request_id}.json").read_text())
            self.assertEqual(
                authorization["pending_receipt_sha256"],
                hashlib.sha256(AUTH.canonical(pending)).hexdigest())
            self.assertEqual(authorization["operation"],
                             AUTH.native_deployment.APPLY_OPERATION)
            self.assertEqual(authorization["recovery_action"], "apply")
            self.assertFalse(authorization["password_fallback"])
            terminal = self.native_deployment_terminal(
                response, authorization)
            return subprocess.CompletedProcess(
                arguments, 0, AUTH.native_deployment.canonical(terminal), b"")

        with mock.patch.object(
            AUTH, "run_native_deployment_driver", side_effect=run
        ), mock.patch.object(
            AUTH.time, "time", return_value=2_000_000_100
        ):
            self.assertEqual(AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_100,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", emit_output=False,
            ), 0)
        receipt = json.loads(
            (receipt_root / f"{request_id}.json").read_text())
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["native_deployment_operation"],
                         AUTH.native_deployment.APPLY_OPERATION)
        self.assertEqual(receipt["native_deployment_recovery_action"], "apply")
        self.assertEqual(receipt["host_release_id"], release.name)
        self.assertEqual(receipt["native_deployment_terminal_phase"], "committed")
        AUTH.write_request(request_path, value)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "request_already_consumed"
        ), mock.patch.object(
            AUTH, "run_native_deployment_driver"
        ) as rerun, mock.patch.object(
            AUTH.time, "time", return_value=2_000_000_100
        ):
            AUTH.execute_request(
                self.uid, request_id, request_sha256, receipt_root,
                now=2_000_000_100,
                broker_path=release / "authorization_broker",
                expected_root_uid=self.uid,
                authorization_method="touch-id", emit_output=False)
        rerun.assert_not_called()

    def test_native_deployment_recover_rejects_wrong_action_and_release(self):
        response = self.native_deployment_plan_response()
        recovery = self.native_deployment_recovery_plan(response)
        AUTH.validate_parameters(
            AUTH.native_deployment.RECOVER_OPERATION,
            {"recovery": recovery, "action": "resume"}, self.home)
        changed = json.loads(json.dumps(recovery))
        changed["active_journal_sha256"] = "0" * 64
        body = {
            key: item for key, item in changed.items()
            if key not in {"schema", "recovery_plan_sha256"}
        }
        changed["recovery_plan_sha256"] = AUTH.native_deployment.digest(body)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_.*_invalid"
        ):
            AUTH.validate_native_deployment_recovery_plan(
                changed, expected_host_release_id="0" * 64)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_recovery_action_invalid"
        ):
            AUTH.validate_parameters(
                AUTH.native_deployment.RECOVER_OPERATION,
                {"recovery": recovery, "action": "force"}, self.home)

    def test_native_deployer_runner_holds_exact_host_and_deployer_fds(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        (install_root / "current").symlink_to(f"releases/{release.name}")
        observed = {}

        def run(command, timeout, input_bytes=None, pass_fds=()):
            observed["command"] = command
            observed["pass_fds"] = pass_fds
            self.assertEqual(os.fstat(pass_fds[0]).st_ino,
                             install_root.stat().st_ino)
            self.assertEqual(os.fstat(pass_fds[1]).st_ino,
                             (release / "native_stack_deployer").stat().st_ino)
            contender = os.open(install_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(BlockingIOError):
                    AUTH.fcntl.flock(
                        contender, AUTH.fcntl.LOCK_EX | AUTH.fcntl.LOCK_NB)
            finally:
                os.close(contender)
            return subprocess.CompletedProcess(command, 0, b"ok\n", b"")

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ):
            result = AUTH.run_native_deployment_driver(
                release, ["status"], timeout=10, expected_uid=self.uid,
                install_root=install_root)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertEqual(observed["command"][-1], "status")
        self.assertIn("--host-install-fd", observed["command"])
        self.assertIn("-B", observed["command"])
        self.assertIn("compile(bytes(source)", " ".join(observed["command"]))

    def test_privileged_exec_readers_reject_post_validation_acls(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        (install_root / "current").symlink_to(f"releases/{release.name}")
        manifest = release / "manifest.json"
        with self.extended_acl(manifest, "everyone allow write"), \
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "authorization_manifest_untrusted",
                ):
            AUTH._verified_release_manifest_payload_sha256(
                release, "native_stack_deployer", expected_uid=self.uid,
            )

        deployer = release / "native_stack_deployer"
        with (
            self.extended_acl(deployer, "everyone allow write"),
            mock.patch.object(
                AUTH, "protected_release_directory", return_value=release,
            ),
            mock.patch.object(AUTH, "run_privileged_operation") as run,
            self.assertRaisesRegex(
                AUTH.AuthorizationError,
                "native_deployment_deployer_untrusted",
            ),
        ):
            AUTH.run_native_deployment_driver(
                release, ["status"], timeout=10,
                expected_uid=self.uid, install_root=install_root,
            )
        run.assert_not_called()

        promoter = release / "native_stack_catalog_promoter"
        with (
            self.extended_acl(promoter, "everyone allow write"),
            mock.patch.object(
                AUTH, "protected_release_directory", return_value=release,
            ),
            mock.patch.object(AUTH, "run_privileged_operation") as run,
            self.assertRaisesRegex(
                AUTH.AuthorizationError, "native_catalog_promoter_untrusted",
            ),
        ):
            AUTH.native_catalog_promotion_gate_result(
                release, expected_uid=self.uid, install_root=install_root,
            )
        run.assert_not_called()

    def test_retained_payload_bootstrap_executes_exact_descriptor_bytes(self):
        payload = self.root / "retained-payload"
        payload.write_bytes(
            b"import json,sys\n"
            b"print(json.dumps(sys.argv, separators=(',', ':')))\n"
        )
        payload.chmod(0o755)
        descriptor = os.open(payload, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            completed = subprocess.run(
                [
                    "/usr/bin/python3", "-I", "-B", "-c",
                    AUTH._NATIVE_DEPLOYER_FD_BOOTSTRAP,
                    str(descriptor), str(payload), "alpha", "beta",
                ],
                stdin=subprocess.DEVNULL, capture_output=True, check=False,
                pass_fds=(descriptor,), timeout=10,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(completed.stdout), [str(payload), "alpha", "beta"])
        self.assertFalse((self.root / "__pycache__").exists())

    def test_native_deployer_runner_rejects_selector_change_before_return(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        current = install_root / "current"
        current.symlink_to(f"releases/{release.name}")

        def run(*_args, **_kwargs):
            current.unlink()
            current.symlink_to("releases/" + ("0" * 64))
            return subprocess.CompletedProcess([], 0, b"ok\n", b"")

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_host_release_untrusted"
        ):
            AUTH.run_native_deployment_driver(
                release, ["status"], timeout=10, expected_uid=self.uid,
                install_root=install_root)

    def test_native_deployer_runner_rejects_old_broker_new_selector_before_child(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        other = release.parent / ("0" * 64)
        other.mkdir(mode=0o555)
        (install_root / "current").symlink_to(f"releases/{other.name}")
        with (
            mock.patch.object(AUTH, "run_privileged_operation") as run,
            self.assertRaisesRegex(
                AUTH.AuthorizationError,
                "native_deployment_host_release_untrusted"),
        ):
            AUTH.run_native_deployment_driver(
                release, ["status"], timeout=10, expected_uid=self.uid,
                install_root=install_root)
        run.assert_not_called()

    def test_catalog_gate_and_recovery_requests_are_domain_separated(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        gate_body = {
            "query_id": query_id,
            "command": AUTH.NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
        }
        gate_request = {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA,
            "query_id": query_id,
            "request_sha256": AUTH.native_deployment.digest(gate_body),
        }
        recovery_body = {
            "recovery_id": query_id,
            "command": AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
            "expected_gate_sha256": "a" * 64,
        }
        recovery_request = {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA,
            "recovery_id": query_id,
            "expected_gate_sha256": "a" * 64,
            "request_sha256": AUTH.native_deployment.digest(recovery_body),
        }
        self.assertNotEqual(
            gate_request["request_sha256"], recovery_request["request_sha256"])
        with mock.patch.object(
            AUTH, "native_catalog_promotion_gate_result",
            return_value=self.native_catalog_gate(),
        ):
            changed = dict(gate_request)
            changed["request_sha256"] = recovery_request["request_sha256"]
            with self.assertRaisesRegex(
                AUTH.AuthorizationError,
                "native_catalog_promotion_gate_query_invalid",
            ):
                AUTH.native_catalog_promotion_gate_query(
                    changed, Path("/release"))

    def test_catalog_gate_and_manual_recovery_require_signed_control_center(self):
        gate_id = "00000000-0000-4000-8000-000000000002"
        gate_body = {
            "query_id": gate_id,
            "command": AUTH.NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
        }
        gate_request = {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_GATE_REQUEST_SCHEMA,
            "query_id": gate_id,
            "request_sha256": AUTH.native_deployment.digest(gate_body),
        }
        gate = self.native_catalog_gate()
        gate_reply_body = {
            "query_id": gate_id,
            "command": AUTH.NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
            "request_sha256": gate_request["request_sha256"],
            "host_release_id": "a" * 64,
            "gate": gate,
        }
        gate_reply = {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA,
            **gate_reply_body,
            "reply_sha256": AUTH.native_deployment.digest(gate_reply_body),
        }
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(gate_request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH, "peer_audit_identity",
                    return_value=(
                        self.uid, b"x" * 32, Path("/signed-control-center")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center"),
                mock.patch.object(AUTH, "verify_control_center_peer") as verify,
                mock.patch.object(AUTH, "verify_touchid_peer") as touchid,
                mock.patch.object(
                    AUTH, "native_catalog_promotion_gate_query",
                    return_value=gate_reply),
                mock.patch.object(AUTH, "selected_release_changed", return_value=False),
            ):
                self.assertFalse(AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid))
            self.assertEqual(json.loads(client.recv(65536)), gate_reply)
            verify.assert_called_once()
            touchid.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_catalog_manual_recovery_socket_binds_expected_gate_without_touchid(self):
        recovery_id = "00000000-0000-4000-8000-000000000002"
        gate = self.native_catalog_gate()
        body = {
            "recovery_id": recovery_id,
            "command": AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
            "expected_gate_sha256": gate["gate_sha256"],
        }
        request = {
            "schema": AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_REQUEST_SCHEMA,
            "recovery_id": recovery_id,
            "expected_gate_sha256": gate["gate_sha256"],
            "request_sha256": AUTH.native_deployment.digest(body),
        }
        terminal = self.native_catalog_recovery_terminal()
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH, "peer_audit_identity",
                    return_value=(
                        self.uid, b"x" * 32, Path("/signed-control-center")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center"),
                mock.patch.object(AUTH, "verify_control_center_peer") as verify,
                mock.patch.object(AUTH, "verify_touchid_peer") as touchid,
                mock.patch.object(
                    AUTH, "native_catalog_promotion_recover_result",
                    return_value=terminal) as recover,
                mock.patch.object(AUTH, "selected_release_changed", return_value=False),
            ):
                self.assertFalse(AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid))
            reply = json.loads(client.recv(65536))
            self.assertEqual(
                reply["schema"], AUTH.NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA)
            self.assertEqual(reply["terminal"], terminal)
            self.assertEqual(reply["request_sha256"], request["request_sha256"])
            recover.assert_called_once_with(
                self.root, gate["gate_sha256"], expected_uid=self.uid)
            verify.assert_called_once()
            touchid.assert_not_called()
        finally:
            client.close()
            server.close()

    def test_catalog_recovery_binds_initial_gate_terminal_and_final_status(self):
        gate = self.native_catalog_gate()
        terminal = self.native_catalog_recovery_terminal()
        ready = self.native_catalog_gate("ready")
        status = self.native_catalog_public_status()
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    side_effect=[gate, terminal, ready, status],
                ) as run,
            ):
                self.assertEqual(
                    AUTH.native_catalog_promotion_recover_result(
                        Path("/release") / ("a" * 64), gate["gate_sha256"],
                        expected_uid=self.uid, install_root=self.root),
                    terminal,
                )
            self.assertEqual(
                [call.args[2] for call in run.call_args_list],
                ["gate-status", "recover-active", "gate-status", "status"],
            )
            self.assertEqual(
                run.call_args_list[1].kwargs["timeout"],
                AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS,
            )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_recovery_rejects_expected_gate_substitution_before_mutation(self):
        gate = self.native_catalog_gate()
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    return_value=gate,
                ) as run,
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "native_catalog_recovery_gate_changed"),
            ):
                AUTH.native_catalog_promotion_recover_result(
                    Path("/release") / ("a" * 64), "0" * 64,
                    expected_uid=self.uid, install_root=self.root)
            self.assertEqual([call.args[2] for call in run.call_args_list], [
                "gate-status",
            ])
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_recovery_lost_reply_replays_terminal_from_ready_gate(self):
        active = self.native_catalog_gate()
        ready = self.native_catalog_gate("ready")
        terminal = self.native_catalog_recovery_terminal()
        status = self.native_catalog_public_status()
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    side_effect=[ready, terminal, ready, status],
                ) as run,
            ):
                self.assertEqual(
                    AUTH.native_catalog_promotion_recover_result(
                        Path("/release") / ("a" * 64),
                        active["gate_sha256"], expected_uid=self.uid,
                        install_root=self.root),
                    terminal,
                )
            self.assertEqual(
                [call.args[2] for call in run.call_args_list],
                ["gate-status", "recover-active", "gate-status", "status"],
            )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_recovery_ready_retry_preserves_prior_release_provenance(self):
        active = self.native_catalog_gate()
        ready = self.native_catalog_gate("ready")
        terminal = self.native_catalog_recovery_terminal(
            host_release_id="b" * 64)
        status = self.native_catalog_public_status(host_release_id="b" * 64)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    side_effect=[ready, terminal, ready, status],
                ),
            ):
                self.assertEqual(
                    AUTH.native_catalog_promotion_recover_result(
                        Path("/release") / ("a" * 64),
                        active["gate_sha256"], expected_uid=self.uid,
                        install_root=self.root),
                    terminal,
                )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_active_recovery_rejects_prior_release_terminal(self):
        active = self.native_catalog_gate()
        terminal = self.native_catalog_recovery_terminal(
            host_release_id="b" * 64)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    side_effect=[active, terminal]),
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "native_catalog_recovery_terminal_mismatch"),
            ):
                AUTH.native_catalog_promotion_recover_result(
                    Path("/release") / ("a" * 64),
                    active["gate_sha256"], expected_uid=self.uid,
                    install_root=self.root)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_public_status_allows_prior_release_provenance(self):
        status = self.native_catalog_public_status(host_release_id="b" * 64)
        self.assertEqual(
            AUTH.validate_native_catalog_public_status(status), status)
        with self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_catalog_public_status_invalid"
        ):
            AUTH.validate_native_catalog_public_status(
                status, expected_host_release_id="a" * 64)

    def test_native_deployment_and_catalog_share_bounded_root_timeout(self):
        self.assertEqual(
            AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS, 3_900)
        for operation in (
            AUTH.native_stack_catalog_promotion.OPERATION,
            AUTH.native_deployment.APPLY_OPERATION,
            AUTH.native_deployment.RECOVER_OPERATION,
        ):
            with self.subTest(operation=operation):
                self.assertEqual(
                    AUTH.authorization_execution_timeout(operation),
                    AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS,
                )

    def test_native_authorization_client_contains_delayed_approval_and_child(self):
        delayed_approval = AUTH.REQUEST_TTL_SECONDS - 1
        for operation in (
            AUTH.native_stack_catalog_promotion.OPERATION,
            AUTH.native_deployment.APPLY_OPERATION,
            AUTH.native_deployment.RECOVER_OPERATION,
        ):
            with self.subTest(operation=operation):
                root_timeout = AUTH.authorization_execution_timeout(operation)
                client_timeout = AUTH.authorization_client_timeout(operation)
                near_bound_child = root_timeout - 1
                self.assertEqual(
                    client_timeout,
                    root_timeout + AUTH.REQUEST_TTL_SECONDS
                    + AUTH.AUTHORIZATION_COMPLETION_MARGIN_SECONDS,
                )
                self.assertLess(
                    delayed_approval + near_bound_child, client_timeout
                )

    def test_catalog_gate_failure_is_recovery_only(self):
        with mock.patch.object(
            AUTH, "native_catalog_promotion_gate_result",
            return_value=self.native_catalog_gate("ready"),
        ):
            self.assertFalse(
                AUTH.native_catalog_promotion_recovery_required(
                    Path("/release")))
        with mock.patch.object(
            AUTH, "native_catalog_promotion_gate_result",
            side_effect=AUTH.AuthorizationError("gate_invalid"),
        ):
            self.assertTrue(
                AUTH.native_catalog_promotion_recovery_required(
                    Path("/release")))

    def test_catalog_promoter_runner_holds_and_passes_exact_host_fd(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        (install_root / "current").symlink_to(f"releases/{release.name}")
        gate = self.native_catalog_gate("ready")
        completed = subprocess.CompletedProcess(
            [], 0, AUTH.native_deployment.canonical(gate), b"")
        observed = {}

        def run(command, timeout, input_bytes=None, pass_fds=()):
            observed["command"] = command
            observed["pass_fds"] = pass_fds
            observed["timeout"] = timeout
            self.assertEqual(os.fstat(pass_fds[0]).st_ino, install_root.stat().st_ino)
            self.assertEqual(os.fstat(pass_fds[1]).st_ino,
                             (release / "native_stack_catalog_promoter").stat().st_ino)
            return completed

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ):
            self.assertEqual(
                AUTH.native_catalog_promotion_gate_result(
                    release, expected_uid=self.uid, install_root=install_root),
                gate,
            )
        self.assertEqual(observed["command"][-1], "gate-status")
        self.assertIn("--host-install-fd", observed["command"])
        self.assertIn("-B", observed["command"])
        self.assertIn("compile(bytes(source)", " ".join(observed["command"]))
        self.assertEqual(observed["timeout"], AUTH.AUTH_TIMEOUT_SECONDS)

    def test_fresh_catalog_consume_uses_locked_retained_promoter_and_long_timeout(self):
        plan = self.native_catalog_plan()
        authorization = self.native_catalog_authorization(plan)
        request = AUTH.native_stack_catalog_promotion.make_request(
            plan, authorization)
        receipt = self.native_catalog_promotion_receipt(plan, authorization)
        status_body = {
            "promotion_id": receipt["promotion_id"],
            "catalog_sha256": receipt["catalog_sha256"],
            "host_release_id": receipt["host_release_id"],
            "promotion_receipt_sha256": receipt["receipt_sha256"],
            "published_at": 2_000_000_100, "stacks": [],
        }
        status = {
            "schema": AUTH.NATIVE_CATALOG_PUBLIC_STATUS_SCHEMA,
            **status_body,
            "status_sha256": AUTH.native_deployment.digest(status_body),
        }
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        completed = subprocess.CompletedProcess(
            [], 0, AUTH.native_deployment.canonical(receipt), b"")
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_invoke_native_catalog_promoter_locked",
                    return_value=completed) as invoke,
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked",
                    side_effect=[self.native_catalog_gate("ready"), status]),
            ):
                self.assertEqual(AUTH.run_native_catalog_promotion_consume(
                    Path("/release") / ("a" * 64), "/staged/catalog.json",
                    request, timeout=AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS,
                    expected_uid=self.uid, install_root=self.root), completed)
            arguments = invoke.call_args.args[2]
            self.assertEqual(arguments[:3], [
                "consume", "--source", "/staged/catalog.json"])
            self.assertIn("--request-json", arguments)
            self.assertEqual(
                invoke.call_args.kwargs["timeout"],
                AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_fresh_catalog_consume_never_accepts_recovery_terminal(self):
        plan = self.native_catalog_plan()
        authorization = self.native_catalog_authorization(plan)
        request = AUTH.native_stack_catalog_promotion.make_request(
            plan, authorization)
        terminal = self.native_catalog_recovery_terminal()
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        completed = subprocess.CompletedProcess(
            [], 0, AUTH.native_deployment.canonical(terminal), b"")
        try:
            with (
                mock.patch.object(
                    AUTH, "_open_locked_selected_host_release",
                    return_value=descriptor),
                mock.patch.object(
                    AUTH, "_invoke_native_catalog_promoter_locked",
                    return_value=completed),
                mock.patch.object(
                    AUTH, "_run_native_catalog_promoter_locked") as inspect,
                self.assertRaisesRegex(
                    AUTH.AuthorizationError,
                    "native_catalog_promotion_receipt_invalid"),
            ):
                AUTH.run_native_catalog_promotion_consume(
                    Path("/release") / ("a" * 64),
                    "/staged/catalog.json", request,
                    timeout=AUTH.NATIVE_CATALOG_PROMOTION_TIMEOUT_SECONDS,
                    expected_uid=self.uid, install_root=self.root)
            inspect.assert_not_called()
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def test_catalog_promoter_runner_rejects_selector_change_after_child(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        current = install_root / "current"
        current.symlink_to(f"releases/{release.name}")
        gate = self.native_catalog_gate("ready")

        def run(*_args, **_kwargs):
            current.unlink()
            current.symlink_to("releases/" + ("0" * 64))
            return subprocess.CompletedProcess(
                [], 0, AUTH.native_deployment.canonical(gate), b"")

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_deployment_host_release_untrusted"
        ):
            AUTH.native_catalog_promotion_gate_result(
                release, expected_uid=self.uid, install_root=install_root)

    def test_catalog_promoter_runner_rejects_same_hash_inode_substitution(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        (install_root / "current").symlink_to(f"releases/{release.name}")
        gate = self.native_catalog_gate("ready")
        promoter = release / "native_stack_catalog_promoter"

        def run(*_args, **_kwargs):
            original = promoter.read_bytes()
            release.chmod(0o755)
            promoter.rename(release / "native_stack_catalog_promoter.old")
            promoter.write_bytes(original)
            promoter.chmod(0o755)
            release.chmod(0o555)
            return subprocess.CompletedProcess(
                [], 0, AUTH.native_deployment.canonical(gate), b"")

        with mock.patch.object(
            AUTH, "run_privileged_operation", side_effect=run
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_catalog_promoter_changed"
        ):
            AUTH.native_catalog_promotion_gate_result(
                release, expected_uid=self.uid, install_root=install_root)

    def test_catalog_promoter_runner_recomputes_manifest_release_identity(self):
        release = self.make_release().resolve()
        install_root = release.parent.parent
        install_root.chmod(0o755)
        (install_root / "current").symlink_to(f"releases/{release.name}")

        def substitute(_path, _uid):
            manifest_path = release / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["payloads"]["native_stack_catalog_promoter"] = "0" * 64
            release.chmod(0o755)
            manifest_path.chmod(0o600)
            manifest_path.write_bytes(AUTH.canonical(manifest))
            manifest_path.chmod(0o444)
            release.chmod(0o555)
            return release

        with mock.patch.object(
            AUTH, "protected_release_directory", side_effect=substitute
        ), self.assertRaisesRegex(
            AUTH.AuthorizationError, "native_catalog_promoter_untrusted"
        ):
            AUTH.native_catalog_promotion_gate_result(
                release, expected_uid=self.uid, install_root=install_root)

    def test_catalog_recovery_only_blocks_native_mutations_but_allows_gate(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        body = {
            "query_id": query_id,
            "command": "plan",
        }
        request = {
            "schema": AUTH.NATIVE_DEPLOYMENT_QUERY_SCHEMAS["plan"],
            "query_id": query_id,
            "request_sha256": AUTH.native_deployment.digest(body),
        }
        client, server = socket.socketpair()
        client.sendall(AUTH.canonical(request))
        client.shutdown(socket.SHUT_WR)
        try:
            with (
                mock.patch.object(
                    AUTH, "peer_audit_identity",
                    return_value=(
                        self.uid, b"x" * 32, Path("/signed-control-center")),
                ),
                mock.patch.object(
                    AUTH, "protected_release_directory", return_value=self.root),
                mock.patch.object(
                    AUTH, "authorization_peer_kind", return_value="control-center"),
                mock.patch.object(AUTH, "verify_control_center_peer"),
            ):
                AUTH.handle_touchid_connection(
                    server, broker_path=self.root / "broker",
                    expected_root_uid=self.uid,
                    catalog_promotion_recovery_only=True)
            response = json.loads(client.recv(65536))
            self.assertEqual(
                response["schema"], AUTH.NATIVE_DEPLOYMENT_QUERY_ERROR_SCHEMA)
            self.assertEqual(
                response["error"],
                "native_catalog_promotion_recovery_required")
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
