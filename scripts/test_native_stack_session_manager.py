#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import native_stack_session_manager as manager_module
from scripts.test_native_stack_manager import runtime_for, status_for
from shared import native_egress
from shared import native_codex_ui_handle
from shared import native_projection_identity_recovery
from shared import native_projection_reconciliation
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


class ProjectionRecoveryBackend(RecoveryBackend):
    def __init__(self, status: dict) -> None:
        super().__init__(status)
        self.final_status = copy.deepcopy(status)
        self.reconciliations = 0
        self.identity_recoveries = 0

    def recover_projection_identity(
        self, plan, _authorization, _original_plan,
        _original_authorization, _journal_sha256,
    ):
        self.identity_recoveries += 1
        body = {
            "outcome": "verified",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "process_identifier": 4242,
            "process_start_time_us": 123456,
            "consumer_executable_sha256": "9" * 64,
            "session_authority_sha256": plan[
                "session_authority_sha256"
            ],
            "identity_evidence_sha256": "a" * 64,
        }
        return {
            "schema": native_projection_identity_recovery.REPLY_SCHEMA,
            **body,
            "reply_sha256": native_projection_identity_recovery.sha256(body),
        }

    def reconcile_projection(
        self, plan, _authorization, _original_plan,
        _original_authorization, _journal_sha256,
    ):
        self.reconciliations += 1
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
        self.status_value = copy.deepcopy(self.final_status)
        return {
            "schema": native_projection_reconciliation.REPLY_SCHEMA,
            **body,
            "reply_sha256": native_projection_reconciliation.sha256(body),
        }

    def stop(self, plan, _authorization):
        return self.recover_stop(plan, _authorization, "0" * 64)

    def status(self, _plan, _authorization, *, handle_id=None):
        return copy.deepcopy(self.status_value)


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
        self.handle_record = native_terminal_handle.make_record(
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
        self.public = native_terminal_handle.public_record(self.handle_record)

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
            "projection_identity": None, "projection_closure": None,
            "projection_identity_recovery_plan": None,
            "projection_identity_recovery_reply": None,
            "projection_recovery_plan": None,
            "projection_reconciliation": None,
            "projection_terminalization": None,
            "error_code": None, "created_at": NOW + 2,
            "updated_at": NOW + 2, "journal_sha256": "0" * 64,
        }
        value["journal_sha256"] = manager_module.digest(
            manager_module._body(value)
        )
        return manager_module.validate_journal(value)

    def codex_record(self) -> dict:
        return native_codex_ui_handle.make_record(
            handle_id="44444444-4444-4444-8444-444444444444",
            operation_id=self.plan["action_id"],
            plan_sha256=self.plan["plan_sha256"],
            authorization_sha256=self.authorization["authorization_sha256"],
            stack_sha256=self.plan["stack_sha256"],
            catalog_sha256=self.plan["catalog_sha256"],
            session_id=self.plan["session_id"],
            runtime_authority_sha256=self.plan[
                "runtime_authority_sha256"
            ],
            harness_generation_id="8" * 64,
            harness_executable_sha256="9" * 64,
            session_lease=self.lease,
            issued_at=NOW + 1, expires_at=NOW + 121,
        )

    def projection_identity(self) -> dict:
        return native_projection_reconciliation.make_identity(
            original_operation_id=self.plan["action_id"],
            process_identifier=4242, process_start_time_us=123456,
            consumer_executable_sha256="9" * 64,
            session_authority_sha256=self.plan[
                "runtime_authority_sha256"
            ],
            credential_response_sha256="a" * 64,
            credential_reply_sha256="b" * 64,
            observed_at=NOW + 3,
        )

    def projection_journal(
        self, phase: str = "running", *, closure: dict | None = None,
        recovery_plan: dict | None = None,
    ) -> dict:
        value = self.journal("running", ["open:stop-bound-runs"])
        value.update({
            "public_handle": native_codex_ui_handle.public_record(
                self.codex_record()
            ),
            "phase": phase, "projection_identity": self.projection_identity(),
            "projection_closure": closure,
            "projection_recovery_plan": recovery_plan,
        })
        value["journal_sha256"] = manager_module.digest(
            manager_module._body(value)
        )
        return manager_module.validate_journal(value)

    def reconciliation_authorization(self, plan: dict) -> dict:
        body = {
            "authorization_id": "55555555-5555-4555-8555-555555555555",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": "1" * 64,
            "pending_receipt_sha256": "2" * 64,
            "host_release_id": "4" * 64, "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
            "authorized_at": NOW + 10, "expires_at": NOW + 80,
            "status": "authorized",
        }
        return native_projection_reconciliation.validate_authorization(
            {
                "schema": native_projection_reconciliation.AUTHORIZATION_SCHEMA,
                **body,
                "authorization_sha256": (
                    native_projection_reconciliation.sha256(body)
                ),
            },
            plan, now=NOW + 12, expected_host_release_id="4" * 64,
        )

    def identity_recovery_authorization(self, plan: dict) -> dict:
        body = {
            "authorization_id": "55555555-5555-4555-8555-555555555555",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "plan_sha256": plan["plan_sha256"],
            "request_sha256": "1" * 64,
            "pending_receipt_sha256": "2" * 64,
            "host_release_id": "4" * 64, "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
            "authorized_at": NOW + 10, "expires_at": NOW + 80,
            "status": "authorized",
        }
        return native_projection_identity_recovery.validate_authorization(
            {
                "schema": (
                    native_projection_identity_recovery.AUTHORIZATION_SCHEMA
                ),
                **body,
                "authorization_sha256": (
                    native_projection_identity_recovery.sha256(body)
                ),
            },
            plan, now=NOW + 12, expected_host_release_id="4" * 64,
        )

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
                handles = Path(tmp) / "handles"
                handles.mkdir(mode=0o700)
                native_terminal_handle.publish(
                    self.handle_record, root=handles,
                    trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                )
                path = self.write_journal(state, self.journal(phase, steps))
                backend = RecoveryBackend(self.status)
                manager = manager_module.NativeStackSessionManager(
                    backend, state_root=state, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                    terminal_root=handles,
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

    def test_codex_prepare_reply_is_closed_and_evidence_bound(self):
        claim = {"access_expires_at_ms": (NOW + 100) * 1000}
        body = {
            "operation_id": self.plan["action_id"],
            "prepare_sha256": "8" * 64, "expires_at": NOW + 60,
            "runtime_authority_sha256": self.plan[
                "runtime_authority_sha256"
            ],
            "session_lease_sha256": self.lease["lease_sha256"],
            "session_expires_at": self.lease["expires_at"],
        }
        reply = {
            "schema": "secure-sandbox-native-codex-session-prepare-reply-v1",
            "operation_id": body["operation_id"],
            "prepare_sha256": body["prepare_sha256"],
            "expires_at": body["expires_at"],
            "session_lease_sha256": body["session_lease_sha256"],
            "session_expires_at": body["session_expires_at"],
            "evidence_sha256": manager_module.digest(body),
        }
        self.assertEqual(
            manager_module.validate_codex_prepare_reply(
                reply, plan=self.plan, lease=self.lease,
                projection_claim=claim, now=NOW,
            ),
            reply,
        )
        hostile = dict(reply, extra="9" * 64)
        with self.assertRaisesRegex(
            manager_module.NativeStackSessionManagerError, "fields_invalid"
        ):
            manager_module.validate_codex_prepare_reply(
                hostile, plan=self.plan, lease=self.lease,
                projection_claim=claim, now=NOW,
            )
        hostile = dict(reply, evidence_sha256="9" * 64)
        with self.assertRaisesRegex(
            manager_module.NativeStackSessionManagerError,
            "evidence_mismatch",
        ):
            manager_module.validate_codex_prepare_reply(
                hostile, plan=self.plan, lease=self.lease,
                projection_claim=claim, now=NOW,
            )

    def test_projection_termination_ack_is_exact_then_eof(self):
        host, consumer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            manager_module.NativeStackSessionManager._ack_projection_termination(
                host, operation_id=self.plan["action_id"],
                session_authority_sha256=self.plan[
                    "runtime_authority_sha256"
                ],
            )
            payload = consumer.recv(256)
            self.assertEqual(len(payload), 108)
            self.assertEqual(
                payload,
                manager_module.PROJECTION_TERMINATION_MAGIC
                + self.plan["action_id"].encode("ascii")
                + self.plan["runtime_authority_sha256"].encode("ascii"),
            )
            self.assertEqual(consumer.recv(1), b"")
        finally:
            host.close()
            consumer.close()

    def test_projected_journal_cannot_claim_terminal_without_helper_readback(self):
        value = self.projection_journal()
        value["phase"] = "completed"
        value["network_open"] = False
        value["journal_sha256"] = manager_module.digest(
            manager_module._body(value)
        )
        with self.assertRaisesRegex(
            manager_module.NativeStackSessionManagerError,
            "projection_terminalization_missing",
        ):
            manager_module.validate_journal(value)

    def test_lost_ack_persists_closure_and_blocks_until_custody_clears(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        retained = status_for(
            self.stack, activation="active", custody="retained",
            projection_count=0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            path = self.write_journal(state, self.projection_journal())
            backend = RecoveryBackend(ambiguous)
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            with mock.patch.object(manager, "_retire_handle"), \
                    mock.patch.object(manager, "_finalize_handle_retirement"):
                with self.assertRaisesRegex(
                    manager_module.NativeStackSessionManagerError,
                    "recovery_required",
                ):
                    manager.recover()
                observed = manager_module.validate_journal(
                    manager_module.stack_manager.trusted_canonical_document(
                        path, os.geteuid()
                    )
                )
                self.assertIsNotNone(observed["projection_closure"])
                self.assertIsNone(observed["projection_terminalization"])
                self.assertNotIn(observed["phase"], manager_module.TERMINAL_PHASES)

                backend.status_value = retained
                terminalization = manager.finalize_projection(
                    self.plan["action_id"]
                )
                self.assertEqual(terminalization["state"], "helper-cleared")
                observed = manager_module.validate_journal(
                    manager_module.stack_manager.trusted_canonical_document(
                        path, os.geteuid()
                    )
                )
                self.assertEqual(observed["phase"], "fenced")
                self.assertIsNotNone(observed["projection_terminalization"])

    def test_crash_before_projection_identity_persistence_stays_fenced(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            path = self.write_journal(
                state, self.journal("running", ["open:stop-bound-runs"])
            )
            manager = manager_module.NativeStackSessionManager(
                RecoveryBackend(ambiguous), state_root=state,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                host_release_id="4" * 64, now=lambda: NOW + 10,
            )
            with mock.patch.object(manager, "_retire_handle"), \
                    self.assertRaisesRegex(
                        manager_module.NativeStackSessionManagerError,
                        "recovery_required",
                    ):
                manager.recover()
            observed = manager_module.validate_journal(
                manager_module.stack_manager.trusted_canonical_document(
                    path, os.geteuid()
                )
            )
            self.assertNotIn(observed["phase"], manager_module.TERMINAL_PHASES)
            self.assertIsNone(observed["projection_terminalization"])

    def test_crash_window_identity_import_is_distinct_and_never_clears(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        backend = ProjectionRecoveryBackend(ambiguous)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            value = self.journal("recovery-required", [])
            value.update({
                "public_handle": native_codex_ui_handle.public_record(
                    self.codex_record()
                ),
                "stop_reply": backend.recover_stop(
                    self.plan, self.authorization, value["journal_sha256"]
                ),
                "error_code": "native_projection_identity_recovery_required",
            })
            value["journal_sha256"] = manager_module.digest(
                manager_module._body(value)
            )
            path = self.write_journal(
                state, manager_module.validate_journal(value)
            )
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            plan = manager.projection_identity_recovery_plan(
                original_operation_id=self.plan["action_id"],
                recovery_operation_id=(
                    "66666666-6666-4666-8666-666666666666"
                ),
            )
            authorization = self.identity_recovery_authorization(plan)
            with mock.patch.object(
                manager, "_verify_projection_identity_recovery_receipt"
            ):
                reply = manager.recover_projection_identity(
                    plan, authorization
                )
            self.assertEqual(reply["process_identifier"], 4242)
            self.assertEqual(backend.identity_recoveries, 1)
            self.assertEqual(
                backend.status_value["credential_custody"]["state"],
                "ambiguous",
            )
            observed = manager_module.validate_journal(
                manager_module.stack_manager.trusted_canonical_document(
                    path, os.geteuid()
                )
            )
            self.assertEqual(
                observed["projection_identity"]["process_identifier"], 4242
            )
            self.assertEqual(
                observed["projection_identity_recovery_reply"], reply
            )
            self.assertNotIn(observed["phase"], manager_module.TERMINAL_PHASES)
            with mock.patch.object(
                manager, "_verify_projection_identity_recovery_receipt"
            ), self.assertRaisesRegex(
                manager_module.NativeStackSessionManagerError,
                "journal_mismatch",
            ):
                manager.recover_projection_identity(plan, authorization)

    def test_identity_import_rejects_substituted_session_authority(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        backend = ProjectionRecoveryBackend(ambiguous)
        original_recover = backend.recover_projection_identity

        def substituted(*args, **kwargs):
            value = original_recover(*args, **kwargs)
            value["session_authority_sha256"] = "e" * 64
            body = {
                key: item for key, item in value.items()
                if key not in {"schema", "reply_sha256"}
            }
            value["reply_sha256"] = (
                native_projection_identity_recovery.sha256(body)
            )
            return value

        backend.recover_projection_identity = substituted
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            value = self.journal("recovery-required", [])
            value["public_handle"] = native_codex_ui_handle.public_record(
                self.codex_record()
            )
            value["stop_reply"] = backend.recover_stop(
                self.plan, self.authorization, value["journal_sha256"]
            )
            value["journal_sha256"] = manager_module.digest(
                manager_module._body(value)
            )
            self.write_journal(state, manager_module.validate_journal(value))
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            plan = manager.projection_identity_recovery_plan(
                original_operation_id=self.plan["action_id"],
                recovery_operation_id=(
                    "66666666-6666-4666-8666-666666666666"
                ),
            )
            authorization = self.identity_recovery_authorization(plan)
            with mock.patch.object(
                manager, "_verify_projection_identity_recovery_receipt"
            ), self.assertRaisesRegex(
                manager_module.NativeStackSessionManagerError,
                "reply_invalid",
            ):
                manager.recover_projection_identity(plan, authorization)

    def test_projection_reconciliation_is_exact_evidence_bound_and_replay_safe(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        retained = status_for(
            self.stack, activation="active", custody="retained",
            projection_count=0,
        )
        backend = ProjectionRecoveryBackend(ambiguous)
        backend.final_status = retained
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            path = self.write_journal(state, self.projection_journal())
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            plan = manager.projection_recovery_plan(
                original_operation_id=self.plan["action_id"],
                recovery_operation_id=(
                    "66666666-6666-4666-8666-666666666666"
                ),
            )
            self.assertEqual(
                plan["guest_absence_evidence_sha256"], "9" * 64
            )
            authorization = self.reconciliation_authorization(plan)
            with mock.patch.object(
                manager, "_verify_projection_reconciliation_receipt"
            ), mock.patch.object(manager, "_retire_handle"), \
                    mock.patch.object(manager, "_finalize_handle_retirement"):
                reply = manager.reconcile_projection(plan, authorization)
                self.assertEqual(reply["outcome"], "verified")
                self.assertEqual(backend.reconciliations, 1)
                observed = manager_module.validate_journal(
                    manager_module.stack_manager.trusted_canonical_document(
                        path, os.geteuid()
                    )
                )
                self.assertEqual(observed["phase"], "fenced")
                self.assertEqual(
                    observed["projection_reconciliation"], reply
                )
                self.assertIsNotNone(observed["projection_terminalization"])
                with self.assertRaisesRegex(
                    manager_module.NativeStackSessionManagerError,
                    "journal_mismatch",
                ):
                    manager.reconcile_projection(plan, authorization)

    def test_projection_reconciliation_rejects_changed_guest_evidence(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        backend = ProjectionRecoveryBackend(ambiguous)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            self.write_journal(state, self.projection_journal())
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            plan = manager.projection_recovery_plan(
                original_operation_id=self.plan["action_id"],
                recovery_operation_id=(
                    "66666666-6666-4666-8666-666666666666"
                ),
            )
            authorization = self.reconciliation_authorization(plan)
            original_stop = backend.recover_stop

            def substituted_stop(*args, **kwargs):
                value = original_stop(*args, **kwargs)
                value["evidence_sha256"] = "e" * 64
                return value

            backend.recover_stop = substituted_stop
            with mock.patch.object(
                manager, "_verify_projection_reconciliation_receipt"
            ), self.assertRaisesRegex(
                manager_module.NativeStackSessionManagerError,
                "closure_changed",
            ):
                manager.reconcile_projection(plan, authorization)
            self.assertEqual(backend.reconciliations, 0)

    def test_explicit_codex_stop_never_reports_success_for_ambiguous_custody(self):
        ambiguous = status_for(
            self.stack, activation="active", custody="ambiguous",
            projection_count=None,
        )
        backend = ProjectionRecoveryBackend(ambiguous)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            path = self.write_journal(state, self.projection_journal())
            manager = manager_module.NativeStackSessionManager(
                backend, state_root=state, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(), host_release_id="4" * 64,
                now=lambda: NOW + 10,
            )
            with mock.patch.object(
                manager, "_validate_authority",
                return_value=(self.plan, self.authorization),
            ), mock.patch.object(manager, "_retire_handle"), \
                    mock.patch.object(manager, "_finalize_handle_retirement"), \
                    self.assertRaisesRegex(
                        manager_module.NativeStackSessionManagerError,
                        "reconciliation_required",
                    ):
                manager.stop(self.plan, self.authorization)
            observed = manager_module.validate_journal(
                manager_module.stack_manager.trusted_canonical_document(
                    path, os.geteuid()
                )
            )
            self.assertNotIn(observed["phase"], manager_module.TERMINAL_PHASES)
            self.assertIsNotNone(observed["projection_closure"])
            self.assertIsNone(observed["projection_terminalization"])

    def test_terminate_stream_reaps_when_process_group_is_already_absent(self):
        process = mock.Mock(spec=subprocess.Popen)
        process.pid = 1234
        process.poll.return_value = None
        with mock.patch.object(
            manager_module.os, "killpg", side_effect=ProcessLookupError
        ):
            manager_module.NativeStackSessionManager._terminate_stream(process)
        process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
