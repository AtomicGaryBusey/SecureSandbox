#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from scripts import native_stack_session_manager as manager_module
from scripts.test_native_stack_manager import runtime_for, status_for
from shared import native_egress
from shared import native_stack_session
from shared import native_terminal_handle
from shared import native_vendor_stack
from shared.test_native_vendor_stack import anthropic_stack


NOW = 2_000_000_000


class RecoveryBackend:
    def __init__(self, status: dict) -> None:
        self.status_value = status
        self.steps: list[str] = []
        self.stops = 0

    def recover_stop(self, plan, _authorization, _journal_sha256):
        self.stops += 1
        return {
            "schema": "secure-sandbox-native-claude-session-stop-reply-v1",
            "operation_id": plan["action_id"],
            "session_id": plan["session_id"], "state": "absent",
            "final_summary_sha256": "8" * 64,
            "evidence_sha256": "9" * 64,
        }

    def recover_status(self, _plan, _authorization, _journal_sha256):
        return copy.deepcopy(self.status_value)

    def rotation_step(self, step, plan, authorization, _grant):
        self.steps.append(step)
        return {
            "schema": "secure-sandbox-native-stack-step-result-v1",
            "action_id": plan["action_id"],
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "step": step, "status": "verified",
            "evidence_sha256": hashlib.sha256(step.encode()).hexdigest(),
        }


class NativeStackSessionManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = anthropic_stack()
        self.authority = runtime_for(self.stack)
        self.status = status_for(self.stack, activation="active")
        self.plan = native_stack_session.make_plan(
            action="session-start",
            action_id="11111111-1111-4111-8111-111111111111",
            session_id=self.authority["session_context_binding"]["session_id"],
            stack_id=self.stack["stack_id"],
            stack_sha256=native_vendor_stack.stack_revision(self.stack),
            catalog_sha256="1" * 64,
            status_sha256=self.status["status_sha256"],
            runtime_authority_value=self.authority,
            source_id=None, source_manifest_sha256=None,
            resume_session_id=None, lease_profile_id="interactive",
            created_at=NOW,
        )
        authorization_body = {
            "authorization_id": "22222222-2222-4222-8222-222222222222",
            "plan_sha256": self.plan["plan_sha256"],
            "action": self.plan["action"],
            "session_id": self.plan["session_id"],
            "runtime_authority_sha256": self.plan[
                "runtime_authority_sha256"
            ],
            "request_sha256": "2" * 64,
            "pending_receipt_sha256": "3" * 64,
            "host_release_id": "4" * 64, "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": "5" * 64,
            "requesting_session_sha256": "6" * 64,
            "authorized_at": NOW + 1, "expires_at": NOW + 121,
            "status": "authorized",
        }
        self.authorization = native_stack_session.validate_authorization(
            {
                "schema": native_stack_session.AUTHORIZATION_SCHEMA,
                **authorization_body,
                "authorization_sha256": native_stack_session.sha256(
                    authorization_body
                ),
            },
            self.plan, now=NOW + 2,
            expected_host_release_id="4" * 64,
        )
        hosts = native_egress.POLICIES[
            self.stack["network_policy_id"]
        ]["phases"][native_egress.PHASE_INFERENCE]["hosts"]
        self.grant = native_egress.make_grant(
            binding_kind="runtime-authority", binding_value=self.authority,
            phase=native_egress.PHASE_INFERENCE,
            resolved_ipv4={host: ["1.1.1.1"] for host in hosts},
            issued_at=NOW + 1, expires_at=NOW + 3601,
            grant_id="33333333-3333-4333-8333-333333333333",
        )
        self.lease = native_stack_session.make_session_lease(
            lease_profile_id="interactive", session_id=self.plan["session_id"],
            runtime_authority_sha256=self.plan["runtime_authority_sha256"],
            grant_id=self.grant["grant_id"],
            grant_sha256=self.grant["grant_sha256"],
            issued_at=self.grant["issued_at"],
            expires_at=self.grant["expires_at"],
        )
        record = native_terminal_handle.make_record(
            handle_id="44444444-4444-4444-8444-444444444444",
            kind="claude-session", operation_id=self.plan["action_id"],
            plan_sha256=self.plan["plan_sha256"],
            authorization_sha256=self.authorization["authorization_sha256"],
            stack_sha256=self.plan["stack_sha256"],
            catalog_sha256=self.plan["catalog_sha256"],
            session_id=self.plan["session_id"],
            remote_arguments=[self.plan["action_id"], "7" * 64],
            issued_at=NOW + 1, expires_at=NOW + 121,
        )
        self.public = native_terminal_handle.public_record(record)

    def journal(self, phase: str, completed_steps: list[str]) -> dict:
        value = {
            "schema": manager_module.JOURNAL_SCHEMA,
            "action_id": self.plan["action_id"],
            "session_id": self.plan["session_id"], "plan": self.plan,
            "authorization": self.authorization,
            "catalog_sha256": self.plan["catalog_sha256"],
            "grant": self.grant, "session_lease": self.lease,
            "public_handle": self.public, "phase": phase,
            "network_open": phase == "running",
            "completed_steps": completed_steps, "stop_reply": None,
            "error_code": None, "created_at": NOW + 2,
            "updated_at": NOW + 2, "journal_sha256": "0" * 64,
        }
        value["journal_sha256"] = manager_module.digest(
            manager_module._body(value)
        )
        return manager_module.validate_journal(value)

    def write_journal(self, root: Path, journal: dict) -> Path:
        root.mkdir(mode=0o700)
        path = root / f"{journal['action_id']}.json"
        manager_module.stack_manager.atomic_json(
            path, journal, os.geteuid()
        )
        return path

    def test_every_partial_open_phase_forces_full_close_before_fencing(self):
        phases: list[tuple[str, list[str]]] = []
        for index, step in enumerate(native_egress.ROTATION_PROTOCOL):
            phases.extend((
                (f"open-{index:02d}-{step}-pending", []),
                (f"open-{index:02d}-{step}-verified", [f"open:{step}"]),
            ))
        for phase, steps in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "state"
                path = self.write_journal(state, self.journal(phase, steps))
                backend = RecoveryBackend(self.status)
                manager = manager_module.NativeStackSessionManager(
                    backend, state_root=state, trusted_uid=os.geteuid(),
                    host_release_id="4" * 64, now=lambda: NOW + 10,
                )
                result = manager.recover()
                self.assertEqual(result["state"], "closed")
                self.assertEqual(
                    backend.steps,
                    list(manager_module.stack_manager.validate_close_only_protocol()),
                )
                observed = manager_module.validate_journal(
                    manager_module.stack_manager.trusted_canonical_document(
                        path, os.geteuid()
                    )
                )
                self.assertEqual(observed["phase"], "fenced")
                self.assertFalse(observed["network_open"])
                self.assertEqual(backend.stops, 1)

    def test_error_cleanup_never_claims_terminal_absence_without_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            journal = self.journal("running", ["open:stop-bound-runs"])
            path = self.write_journal(state, journal)
            manager = manager_module.NativeStackSessionManager(
                RecoveryBackend(self.status), state_root=state,
                trusted_uid=os.geteuid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            manager._close_or_fence(
                path, journal, RuntimeError("simulated_failure")
            )
            observed = manager_module.validate_journal(
                manager_module.stack_manager.trusted_canonical_document(
                    path, os.geteuid()
                )
            )
            self.assertEqual(observed["phase"], "recovery-required")
            self.assertFalse(observed["network_open"])


if __name__ == "__main__":
    unittest.main()
