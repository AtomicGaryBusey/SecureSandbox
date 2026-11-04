import copy
import unittest

from shared import native_projection_identity_recovery as recovery


class NativeProjectionIdentityRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.plan = recovery.make_plan(
            recovery_operation_id="00000000-0000-4000-8000-000000000001",
            original_operation_id="00000000-0000-4000-8000-000000000002",
            session_id="00000000-0000-4000-8000-000000000003",
            stack_id="codex-daybreak",
            stack_sha256="1" * 64,
            session_authority_sha256="2" * 64,
            host_release_id="3" * 64,
            created_at=self.now,
        )
        authorization_body = {
            "authorization_id": "00000000-0000-4000-8000-000000000004",
            "recovery_operation_id": self.plan["recovery_operation_id"],
            "original_operation_id": self.plan["original_operation_id"],
            "plan_sha256": self.plan["plan_sha256"],
            "request_sha256": "4" * 64,
            "pending_receipt_sha256": "5" * 64,
            "host_release_id": self.plan["host_release_id"],
            "method": "touch-id",
            "password_fallback": False,
            "requesting_agent_sha256": "6" * 64,
            "requesting_session_sha256": "7" * 64,
            "authorized_at": self.now + 1,
            "expires_at": self.now + 60,
            "status": "authorized",
        }
        self.authorization = {
            "schema": recovery.AUTHORIZATION_SCHEMA,
            **authorization_body,
            "authorization_sha256": recovery.sha256(authorization_body),
        }

    def test_plan_authorization_ticket_and_reply_are_exact(self):
        plan = recovery.validate_plan(
            self.plan, now=self.now, require_fresh=True
        )
        authorization = recovery.validate_authorization(
            self.authorization, plan, now=self.now + 1,
            expected_host_release_id=plan["host_release_id"],
        )
        ticket = recovery.make_ticket(
            plan, authorization,
            ticket_id="00000000-0000-4000-8000-000000000005",
            now=self.now + 1,
            expected_host_release_id=plan["host_release_id"],
        )
        self.assertEqual(
            recovery.validate_ticket(
                ticket, now=self.now + 1, require_fresh=True
            ),
            ticket,
        )
        reply_body = {
            "outcome": "verified",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "process_identifier": 123,
            "process_start_time_us": 456,
            "consumer_executable_sha256": "8" * 64,
            "session_authority_sha256": plan["session_authority_sha256"],
            "identity_evidence_sha256": "9" * 64,
        }
        reply = {
            "schema": recovery.REPLY_SCHEMA,
            **reply_body,
            "reply_sha256": recovery.sha256(reply_body),
        }
        self.assertEqual(
            recovery.validate_reply(reply, plan_value=plan), reply
        )

    def test_unknown_fields_digest_changes_and_wrong_binding_reject(self):
        for field, value in (
            ("unknown", True),
            ("stack_sha256", "a" * 64),
            ("expires_at", self.now + 121),
        ):
            hostile = copy.deepcopy(self.plan)
            hostile[field] = value
            with self.assertRaises(
                recovery.NativeProjectionIdentityRecoveryError
            ):
                recovery.validate_plan(
                    hostile, now=self.now, require_fresh=True
                )

    def test_password_fallback_expiry_and_replay_identity_reject(self):
        hostile = dict(self.authorization)
        hostile["password_fallback"] = True
        with self.assertRaises(recovery.NativeProjectionIdentityRecoveryError):
            recovery.validate_authorization(
                hostile, self.plan, now=self.now + 1,
                expected_host_release_id=self.plan["host_release_id"],
            )
        with self.assertRaises(recovery.NativeProjectionIdentityRecoveryError):
            recovery.validate_authorization(
                self.authorization, self.plan, now=self.now + 61,
                expected_host_release_id=self.plan["host_release_id"],
            )
        hostile_plan = dict(self.plan)
        hostile_plan["recovery_operation_id"] = (
            hostile_plan["original_operation_id"]
        )
        body = {
            key: value for key, value in hostile_plan.items()
            if key not in {"schema", "plan_sha256"}
        }
        hostile_plan["plan_sha256"] = recovery.sha256(body)
        with self.assertRaises(recovery.NativeProjectionIdentityRecoveryError):
            recovery.validate_plan(hostile_plan)

    def test_reply_cannot_substitute_identity_or_add_token(self):
        body = {
            "outcome": "verified",
            "recovery_operation_id": self.plan["recovery_operation_id"],
            "original_operation_id": self.plan["original_operation_id"],
            "process_identifier": 123,
            "process_start_time_us": 456,
            "consumer_executable_sha256": "8" * 64,
            "session_authority_sha256": self.plan[
                "session_authority_sha256"
            ],
            "identity_evidence_sha256": "9" * 64,
        }
        reply = {
            "schema": recovery.REPLY_SCHEMA,
            **body,
            "reply_sha256": recovery.sha256(body),
        }
        for field, value in (
            ("original_operation_id", self.plan["recovery_operation_id"]),
            ("session_authority_sha256", "a" * 64),
            ("token", "secret"),
        ):
            hostile = dict(reply)
            hostile[field] = value
            with self.assertRaises(
                recovery.NativeProjectionIdentityRecoveryError
            ):
                recovery.validate_reply(hostile, plan_value=self.plan)


if __name__ == "__main__":
    unittest.main()
