#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from shared import native_stack_operations as operations


ROOT = Path(__file__).resolve().parent.parent


class NativeStackOperationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(encoding="ascii")
        )["stacks"][0]
        cls.stack["harness"]["generation_id"] = "a" * 64
        cls.stack["account_binding"]["account_subject_sha256"] = "b" * 64
        cls.stack["account_binding"]["workspace_sha256"] = "c" * 64

    def observation(self, state: str, *, extra: dict | None = None) -> dict:
        value = {"state": state, "observed_at": 100, "evidence_sha256": "d" * 64}
        value.update(extra or {})
        return value

    def entitlement(self, state: str, assurance: str = "provider-enforced") -> dict:
        if state != "verified":
            assurance = "unknown"
        return {**self.observation(state), "assurance": assurance}

    def status(self, *, activation: str = "inactive", auth: str = "signed-in") -> dict:
        return operations.make_status(
            stack=self.stack,
            harness=self.observation(
                "admitted",
                extra={"generation_id": "a" * 64, "binding_sha256": "e" * 64},
            ),
            authentication=self.observation(auth),
            credential_custody={
                "state": "retained",
                "observed_at": 100,
                "evidence_sha256": "8" * 64,
                "tombstone_sha256": None,
                "projection_count": 0,
            },
            account_binding=self.observation(
                "bound",
                extra={
                    "account_subject_sha256": "b" * 64,
                    "workspace_sha256": "c" * 64,
                },
            ),
            program_entitlement=self.entitlement("verified", "operator-external"),
            model_entitlement=self.entitlement("verified"),
            network={
                "phase": "closed",
                "grant_sha256": None,
                "expires_at": None,
                "observed_at": 100,
            },
            activation=self.observation(
                activation,
                extra={"receipt_sha256": "f" * 64 if activation == "active" else None},
            ),
            live_run_count=0,
        )

    def test_status_is_self_digested_and_content_free(self) -> None:
        value = self.status()
        self.assertEqual(operations.validate_status(value), value)
        encoded = operations.canonical_bytes(value).decode("ascii")
        for forbidden in (
            "access_token", "refresh_token", "authorization_code", "pkce",
            "email", "credential_path", "provider_response",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_status_rejects_mutation_and_incomplete_admission(self) -> None:
        value = self.status()
        value["live_run_count"] = 1
        with self.assertRaisesRegex(operations.NativeStackOperationError, "digest_mismatch"):
            operations.validate_status(value)
        value = self.status()
        value["harness"]["generation_id"] = None
        with self.assertRaisesRegex(operations.NativeStackOperationError, "admission_incomplete"):
            operations.validate_status(value)

    def test_status_rejects_network_grant_while_closed(self) -> None:
        value = self.status()
        value["network"]["grant_sha256"] = "1" * 64
        with self.assertRaisesRegex(operations.NativeStackOperationError, "closed_has_grant"):
            operations.validate_status(value)

    def test_entitlement_assurance_is_exact_and_state_bound(self) -> None:
        value = self.status()
        self.assertEqual(
            value["program_entitlement"]["assurance"], "operator-external"
        )
        self.assertEqual(
            value["model_entitlement"]["assurance"], "provider-enforced"
        )
        for field in ("program_entitlement", "model_entitlement"):
            changed = copy.deepcopy(value)
            changed[field]["assurance"] = "unknown"
            changed["status_sha256"] = operations.sha256({
                key: changed[key]
                for key in changed if key not in {"schema", "status_sha256"}
            })
            with self.assertRaisesRegex(
                operations.NativeStackOperationError, "verified_assurance_missing"
            ):
                operations.validate_status(changed)
            changed = copy.deepcopy(value)
            changed[field]["state"] = "denied"
            changed["status_sha256"] = operations.sha256({
                key: changed[key]
                for key in changed if key not in {"schema", "status_sha256"}
            })
            with self.assertRaisesRegex(
                operations.NativeStackOperationError, "unverified_assurance_claim"
            ):
                operations.validate_status(changed)

    def test_all_actions_have_exact_phase_and_impact(self) -> None:
        status = self.status()
        for index, action in enumerate(sorted(operations.ACTIONS), start=1):
            kwargs = {}
            if action == "binding-commit":
                kwargs = {
                    "observed_account_subject_sha256": "2" * 64,
                    "observed_workspace_sha256": "3" * 64,
                }
            plan = operations.make_plan(
                stack=self.stack,
                status=status,
                action=action,
                created_at=1000,
                action_id=f"00000000-0000-4000-8000-{index:012x}",
                **kwargs,
            )
            self.assertEqual(plan["requested_network_phase"], operations.ACTION_PHASE[action])
            self.assertEqual(operations.validate_plan(plan, now=1001, require_fresh=True), plan)

    def test_plan_rejects_expiry_phase_and_extra_secret(self) -> None:
        plan = operations.make_plan(
            stack=self.stack,
            status=self.status(),
            action="activate",
            created_at=1000,
            action_id="00000000-0000-4000-8000-000000000001",
        )
        with self.assertRaisesRegex(operations.NativeStackOperationError, "expired"):
            operations.validate_plan(plan, now=1301, require_fresh=True)
        with self.assertRaisesRegex(operations.NativeStackOperationError, "expired"):
            operations.validate_plan(plan, now=1300, require_fresh=True)
        changed = copy.deepcopy(plan)
        changed["requested_network_phase"] = "inference"
        with self.assertRaisesRegex(operations.NativeStackOperationError, "network_phase_invalid"):
            operations.validate_plan(changed)
        changed = copy.deepcopy(plan)
        changed["access_token"] = "secret"
        with self.assertRaisesRegex(operations.NativeStackOperationError, "fields_invalid"):
            operations.validate_plan(changed)

    def test_binding_commit_requires_two_observed_digests(self) -> None:
        with self.assertRaisesRegex(operations.NativeStackOperationError, "observed_binding_incomplete"):
            operations.make_plan(
                stack=self.stack,
                status=self.status(),
                action="binding-commit",
                observed_account_subject_sha256="4" * 64,
                created_at=1000,
                action_id="00000000-0000-4000-8000-000000000001",
            )

    def test_plan_rejects_status_from_another_stack_revision(self) -> None:
        status = self.status()
        changed = copy.deepcopy(self.stack)
        changed["display_name"] = "Another reviewed display name"
        with self.assertRaisesRegex(operations.NativeStackOperationError, "status_mismatch"):
            operations.make_plan(
                stack=changed,
                status=status,
                action="activate",
                created_at=1000,
                action_id="00000000-0000-4000-8000-000000000001",
            )

    def test_receipt_binds_plan_status_and_evidence(self) -> None:
        status = self.status()
        plan = operations.make_plan(
            stack=self.stack,
            status=status,
            action="activate",
            created_at=1000,
            action_id="00000000-0000-4000-8000-000000000001",
        )
        receipt = operations.make_receipt(
            plan=plan,
            status=status,
            result="verified",
            evidence_sha256="5" * 64,
            completed_at=1100,
        )
        self.assertEqual(operations.validate_receipt(receipt), receipt)
        receipt["result"] = "ambiguous"
        with self.assertRaisesRegex(operations.NativeStackOperationError, "digest_mismatch"):
            operations.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
