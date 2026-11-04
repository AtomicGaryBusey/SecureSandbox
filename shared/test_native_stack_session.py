#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from shared import harness_runtime_binding
from shared import model_stack_runtime_binding
from shared import native_stack_operations
from shared import native_stack_runtime_binding
from shared import native_stack_session
from shared import runtime_authority
from shared import session_context_binding


ROOT = Path(__file__).resolve().parent.parent


class NativeStackSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text()
        )["stacks"][1]
        self.stack["harness"]["generation_id"] = "a" * 64
        self.stack["account_binding"]["account_subject_sha256"] = "b" * 64
        self.stack["account_binding"]["workspace_sha256"] = "c" * 64
        native = native_stack_runtime_binding.make_binding(self.stack)
        harness = harness_runtime_binding.make_binding(
            harness_id="codex", generation_id="a" * 64,
            manifest_sha256="4" * 64, executable_sha256="d" * 64,
            inventory_sha256="5" * 64,
            adapter_id="codex-app-server-oauth-v1", adapter_sha256="6" * 64,
        )
        context = session_context_binding.make_binding(
            session_id="11111111-1111-4111-8111-111111111111",
            source_id="22222222-2222-4222-8222-222222222222",
            source_manifest_sha256="e" * 64,
            persona_sha256="1" * 64, tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        )
        self.authority = runtime_authority.make_binding(
            model_stack_binding=model_stack_runtime_binding.make_binding(
                model_stack_runtime_binding.NATIVE_MODE, native),
            session_context_binding=context, harness_binding=harness,
        )
        self.plan = native_stack_session.make_plan(
            action="session-start",
            action_id="33333333-3333-4333-8333-333333333333",
            session_id=context["session_id"], stack_id=self.stack["stack_id"],
            stack_sha256=native["stack_sha256"], catalog_sha256="4" * 64,
            status_sha256="5" * 64, runtime_authority_value=self.authority,
            source_id=context["source_id"],
            source_manifest_sha256=context["source_manifest_sha256"],
            resume_session_id=None, lease_profile_id="interactive",
            created_at=1_000,
        )

    def test_plan_binds_every_runtime_component(self) -> None:
        self.assertEqual(native_stack_session.validate_plan(self.plan), self.plan)
        self.assertEqual(
            self.plan["runtime_authority_sha256"], self.authority["binding_sha256"]
        )
        changed = copy.deepcopy(self.plan)
        changed["source_manifest_sha256"] = "9" * 64
        body = {key: changed[key] for key in changed if key not in {"schema", "plan_sha256"}}
        changed["plan_sha256"] = native_stack_session.sha256(body)
        with self.assertRaisesRegex(
            native_stack_session.NativeStackSessionError, "source_authority_mismatch"
        ):
            native_stack_session.validate_plan(changed)

    def test_plan_freshness_and_authorization_are_exact(self) -> None:
        with self.assertRaisesRegex(
            native_stack_session.NativeStackSessionError, "expired"
        ):
            native_stack_session.validate_plan(
                self.plan, now=1_180, require_fresh=True
            )
        body = {
            "authorization_id": "44444444-4444-4444-8444-444444444444",
            "plan_sha256": self.plan["plan_sha256"],
            "action": "session-start", "session_id": self.plan["session_id"],
            "runtime_authority_sha256": self.plan["runtime_authority_sha256"],
            "request_sha256": "6" * 64, "host_release_id": "7" * 64,
            "authorized_at": 1_010, "expires_at": 1_100,
            "status": "authorized",
        }
        authorization = {
            "schema": native_stack_session.AUTHORIZATION_SCHEMA, **body,
            "authorization_sha256": native_stack_session.sha256(body),
        }
        self.assertEqual(
            native_stack_session.validate_authorization(
                authorization, self.plan, now=1_050,
                expected_host_release_id="7" * 64,
            ),
            authorization,
        )

    def test_start_status_requires_activation_provider_assurance_and_no_run(self) -> None:
        def observation(state: str, **extra: object) -> dict:
            return {"state": state, "observed_at": 900,
                    "evidence_sha256": "8" * 64, **extra}
        status = native_stack_operations.make_status(
            stack=self.stack,
            harness=observation(
                "admitted", generation_id="a" * 64, binding_sha256="9" * 64),
            authentication=observation("signed-in"),
            credential_custody={
                "state": "retained", "observed_at": 900,
                "evidence_sha256": "1" * 64, "tombstone_sha256": None,
                "projection_count": 0,
            },
            account_binding=observation(
                "bound", account_subject_sha256="b" * 64,
                workspace_sha256="c" * 64),
            program_entitlement=observation(
                "verified", assurance="operator-external"),
            model_entitlement=observation(
                "verified", assurance="provider-enforced"),
            network={"phase": "closed", "grant_sha256": None,
                     "expires_at": None, "observed_at": 900},
            activation=observation("active", receipt_sha256="2" * 64),
            live_run_count=0,
        )
        self.assertEqual(
            native_stack_session.require_start_status(
                status, stack_sha256=self.plan["stack_sha256"]), status)
        changed = copy.deepcopy(status)
        changed["model_entitlement"]["assurance"] = "operator-external"
        changed["status_sha256"] = native_stack_operations.sha256({
            key: changed[key] for key in changed if key not in {"schema", "status_sha256"}
        })
        with self.assertRaisesRegex(
            native_stack_session.NativeStackSessionError, "not_startable"
        ):
            native_stack_session.require_start_status(
                changed, stack_sha256=self.plan["stack_sha256"])


if __name__ == "__main__":
    unittest.main()
