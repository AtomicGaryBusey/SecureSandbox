#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared import native_projection_reconciliation as reconciliation


NOW = 2_000_000_000


class NativeProjectionReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = reconciliation.make_identity(
            original_operation_id="11111111-1111-4111-8111-111111111111",
            process_identifier=4321,
            process_start_time_us=123456789,
            consumer_executable_sha256="1" * 64,
            session_authority_sha256="2" * 64,
            credential_response_sha256="3" * 64,
            credential_reply_sha256="4" * 64,
            observed_at=NOW,
        )
        self.evidence = reconciliation.make_closure_evidence(
            original_operation_id=self.identity["original_operation_id"],
            guest_absence_evidence_sha256="5" * 64,
            egress_closed_evidence_sha256="6" * 64,
            observed_at=NOW + 1,
        )
        self.plan = reconciliation.make_plan(
            recovery_operation_id="22222222-2222-4222-8222-222222222222",
            original_operation_id=self.identity["original_operation_id"],
            session_id="33333333-3333-4333-8333-333333333333",
            stack_id="openai-daybreak-blue",
            stack_sha256="7" * 64,
            session_authority_sha256=self.identity[
                "session_authority_sha256"
            ],
            process_identifier=self.identity["process_identifier"],
            process_start_time_us=self.identity["process_start_time_us"],
            consumer_executable_sha256=self.identity[
                "consumer_executable_sha256"
            ],
            guest_absence_evidence_sha256=self.evidence[
                "guest_absence_evidence_sha256"
            ],
            egress_closed_evidence_sha256=self.evidence[
                "egress_closed_evidence_sha256"
            ],
            host_release_id="8" * 64,
            created_at=NOW + 2,
        )
        authorization_body = {
            "authorization_id": "44444444-4444-4444-8444-444444444444",
            "recovery_operation_id": self.plan["recovery_operation_id"],
            "original_operation_id": self.plan["original_operation_id"],
            "plan_sha256": self.plan["plan_sha256"],
            "request_sha256": "9" * 64,
            "pending_receipt_sha256": "a" * 64,
            "host_release_id": self.plan["host_release_id"],
            "method": "touch-id", "password_fallback": False,
            "requesting_agent_sha256": "b" * 64,
            "requesting_session_sha256": "c" * 64,
            "authorized_at": NOW + 3, "expires_at": NOW + 100,
            "status": "authorized",
        }
        self.authorization = reconciliation.validate_authorization(
            {
                "schema": reconciliation.AUTHORIZATION_SCHEMA,
                **authorization_body,
                "authorization_sha256": reconciliation.sha256(
                    authorization_body
                ),
            },
            self.plan, now=NOW + 4,
            expected_host_release_id=self.plan["host_release_id"],
        )

    def test_exact_plan_authorization_and_ticket_match_swift_contract(self):
        ticket = reconciliation.make_ticket(
            self.plan, self.authorization,
            ticket_id=self.authorization["authorization_id"], now=NOW + 4,
            expected_host_release_id=self.plan["host_release_id"],
        )
        self.assertEqual(
            set(ticket),
            {
                "schema", "ticket_id", "recovery_operation_id",
                "original_operation_id", "provider", "process_identifier",
                "process_start_time_us", "consumer_executable_sha256",
                "session_authority_sha256", "stack_sha256",
                "recovery_plan_sha256", "guest_absence_evidence_sha256",
                "egress_closed_evidence_sha256", "host_release_id",
                "recovery_request_sha256", "recovery_receipt_sha256",
                "issued_at", "expires_at", "status", "ticket_sha256",
            },
        )
        self.assertEqual(ticket["provider"], "openAIChatGPT")
        self.assertEqual(
            reconciliation.validate_ticket(
                ticket, now=NOW + 4, require_fresh=True
            ),
            ticket,
        )

    def test_substitution_and_replay_authority_are_rejected(self):
        hostile = copy.deepcopy(self.plan)
        hostile["process_start_time_us"] += 1
        with self.assertRaisesRegex(
            reconciliation.NativeProjectionReconciliationError,
            "digest_mismatch",
        ):
            reconciliation.validate_plan(hostile)

        ticket = reconciliation.make_ticket(
            self.plan, self.authorization,
            ticket_id=self.authorization["authorization_id"], now=NOW + 4,
            expected_host_release_id=self.plan["host_release_id"],
        )
        hostile_ticket = dict(ticket, extra="d" * 64)
        with self.assertRaisesRegex(
            reconciliation.NativeProjectionReconciliationError,
            "fields_invalid",
        ):
            reconciliation.validate_ticket(hostile_ticket)
        with self.assertRaisesRegex(
            reconciliation.NativeProjectionReconciliationError,
            "expired",
        ):
            reconciliation.validate_ticket(
                ticket, now=ticket["expires_at"], require_fresh=True
            )

    def test_reply_is_closed_and_bound_to_exact_process_generation(self):
        body = {
            "outcome": "verified",
            "recovery_operation_id": self.plan["recovery_operation_id"],
            "original_operation_id": self.plan["original_operation_id"],
            "process_identifier": self.plan["process_identifier"],
            "process_start_time_us": self.plan["process_start_time_us"],
            "consumer_executable_sha256": self.plan[
                "consumer_executable_sha256"
            ],
            "session_authority_sha256": self.plan[
                "session_authority_sha256"
            ],
            "reconciliation_evidence_sha256": "e" * 64,
        }
        reply = {
            "schema": reconciliation.REPLY_SCHEMA, **body,
            "reply_sha256": reconciliation.sha256(body),
        }
        self.assertEqual(
            reconciliation.validate_reply(reply, plan_value=self.plan), reply
        )
        hostile = dict(reply, process_start_time_us=body["process_start_time_us"] + 1)
        hostile_body = {
            key: hostile[key]
            for key in hostile if key not in {"schema", "reply_sha256"}
        }
        hostile["reply_sha256"] = reconciliation.sha256(hostile_body)
        with self.assertRaisesRegex(
            reconciliation.NativeProjectionReconciliationError, "mismatch"
        ):
            reconciliation.validate_reply(hostile, plan_value=self.plan)


if __name__ == "__main__":
    unittest.main()
