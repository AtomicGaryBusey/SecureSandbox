#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import native_stack_backend as backend
from scripts.test_native_stack_manager import status_for
from shared import native_stack_operations as operations
from shared import native_vendor_stack
from shared.test_native_vendor_stack import openai_stack


NOW = 2_000_000_000


def plan_for(action: str) -> tuple[dict, dict]:
    stack = openai_stack()
    plan = operations.make_plan(
        stack=stack,
        status=status_for(stack),
        action=action,
        created_at=NOW,
        action_id="11111111-1111-4111-8111-111111111111",
    )
    authorization = {
        "authorization_id": "22222222-2222-4222-8222-222222222222",
        "request_sha256": "1" * 64,
        "pending_receipt_sha256": "2" * 64,
        "authorization_sha256": "3" * 64,
        "authorized_at": NOW + 1,
        "expires_at": NOW + 121,
    }
    return plan, authorization


class NativeStackBackendTests(unittest.TestCase):
    def test_dns_policy_requires_two_stable_global_ipv4_observations(self) -> None:
        calls: dict[str, int] = {}

        def resolver(hostname: str) -> tuple[str, ...]:
            calls[hostname] = calls.get(hostname, 0) + 1
            return (
                ("8.8.8.8", "1.1.1.1")
                if calls[hostname] == 1
                else ("1.1.1.1", "9.9.9.9")
            )

        pins = backend.resolve_policy(
            "openai-codex-siwc-v1", "inference", resolver=resolver
        )
        self.assertTrue(pins)
        self.assertTrue(all(values == ["1.1.1.1"] for values in pins.values()))
        self.assertTrue(all(count == 2 for count in calls.values()))

    def test_activate_never_calls_credential_service_or_projects_session(self) -> None:
        plan, authorization = plan_for("activate")
        stack = openai_stack()
        observed_request: dict = {}

        def credential(_value):
            self.fail("activate must not call credential custody")

        def guest(operation: str, request: object) -> dict:
            self.assertEqual(operation, "native-provider-action")
            observed_request.update(request)
            return {
                "schema": backend.PROVIDER_RESULT_SCHEMA,
                "action_id": plan["action_id"],
                "action": plan["action"],
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": authorization["authorization_sha256"],
                "status": "verified",
                "evidence_sha256": "4" * 64,
            }

        result = backend.provider_action(
            plan, authorization, stack, credential=credential, guest=guest
        )
        self.assertEqual(result["status"], "verified")
        self.assertIsNone(observed_request["runtime_authority"])

    def test_refresh_ticket_is_pre_session_and_never_fabricates_session_digest(self) -> None:
        plan, authorization = plan_for("entitlement-verify")
        ticket = backend.make_credential_ticket(
            operation="refresh",
            action="entitlement-verify",
            plan=plan,
            authorization=authorization,
        )
        handoff = backend.credential_handoff(
            operation="refresh",
            operation_id=plan["action_id"],
            plan=plan,
            authorization=authorization,
        )
        self.assertIsNone(ticket["session_authority_sha256"])
        self.assertIsNone(handoff["session_authority_sha256"])

    def test_openai_status_maps_exact_xpc_custody_without_inferring_absence(self) -> None:
        stack = openai_stack()
        guest = status_for(stack)
        reply = {
            "reply_sha256": "5" * 64,
            "projection": None,
            "status": {
                "provider": "openAIChatGPT",
                "state": "ready",
                "client_id_sha256": "6" * 64,
                "account_subject_sha256": stack["account_binding"]["account_subject_sha256"],
                "workspace_sha256": stack["account_binding"]["workspace_sha256"],
                "scope_sha256": "7" * 64,
                "access_expires_at_ms": (NOW + 300) * 1000,
                "earliest_refresh_at_ms": (NOW + 200) * 1000,
                "refresh_expires_at_ms": (NOW + 600) * 1000,
                "custody_state": "retained",
                "custody_tombstone_sha256": None,
                "custody_projection_count": 0,
            },
        }
        merged = backend.merge_openai_status(guest, reply, stack, now=NOW)
        self.assertEqual(
            merged["credential_custody"],
            {
                "state": "retained",
                "observed_at": NOW,
                "evidence_sha256": "5" * 64,
                "tombstone_sha256": None,
                "projection_count": 0,
            },
        )
        ambiguous = copy.deepcopy(reply)
        ambiguous["status"]["state"] = "loggedOut"
        ambiguous["status"]["client_id_sha256"] = None
        ambiguous["status"]["account_subject_sha256"] = None
        ambiguous["status"]["workspace_sha256"] = None
        ambiguous["status"]["scope_sha256"] = None
        ambiguous["status"]["access_expires_at_ms"] = None
        ambiguous["status"]["earliest_refresh_at_ms"] = None
        ambiguous["status"]["refresh_expires_at_ms"] = None
        ambiguous["status"]["custody_state"] = "ambiguous"
        ambiguous["status"]["custody_projection_count"] = None
        merged = backend.merge_openai_status(guest, ambiguous, stack, now=NOW)
        self.assertEqual(merged["credential_custody"]["state"], "ambiguous")

    def test_inspect_request_is_bound_to_exact_root_catalog_revision(self) -> None:
        stack = openai_stack()
        catalog = {
            "schema": native_vendor_stack.CATALOG_SCHEMA,
            "stacks": [stack],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog)
            path.write_bytes(raw)
            path.chmod(0o600)
            body = {
                "operation_id": "33333333-3333-4333-8333-333333333333",
                "stack_id": stack["stack_id"],
                "stack_sha256": native_vendor_stack.stack_revision(stack),
                "catalog_sha256": hashlib.sha256(raw).hexdigest(),
            }
            request = {
                "schema": "secure-sandbox-native-stack-inspect-request-v1",
                **body,
                "request_sha256": backend.digest(body),
            }
            validated, selected, observed = backend.validate_inspect_request(
                request, catalog_path=path
            )
            self.assertEqual(validated, request)
            self.assertEqual(selected, stack)
            self.assertEqual(observed, body["catalog_sha256"])
            changed = json.loads(json.dumps(request))
            changed["stack_sha256"] = "f" * 64
            changed_body = {
                key: changed[key]
                for key in ("operation_id", "stack_id", "stack_sha256", "catalog_sha256")
            }
            changed["request_sha256"] = backend.digest(changed_body)
            with self.assertRaisesRegex(
                backend.NativeStackBackendError, "inspect_catalog_changed"
            ):
                backend.validate_inspect_request(changed, catalog_path=path)


if __name__ == "__main__":
    unittest.main()
