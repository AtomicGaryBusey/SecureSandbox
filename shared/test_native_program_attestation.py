#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from shared import native_program_attestation as attestation
from shared import native_stack_operations
from shared import native_vendor_stack


ROOT = Path(__file__).resolve().parent.parent


class NativeProgramAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text()
        )["stacks"][0]
        self.stack["harness"]["generation_id"] = "a" * 64
        self.stack["account_binding"]["account_subject_sha256"] = "b" * 64
        self.stack["account_binding"]["workspace_sha256"] = "c" * 64

        def observed(state: str, **extra: object) -> dict:
            return {"state": state, "observed_at": 900,
                    "evidence_sha256": "d" * 64, **extra}

        self.status = native_stack_operations.make_status(
            stack=self.stack,
            harness=observed(
                "admitted", generation_id="a" * 64, binding_sha256="e" * 64),
            authentication=observed("signed-in"),
            credential_custody={
                "state": "retained", "observed_at": 900,
                "evidence_sha256": "1" * 64, "tombstone_sha256": None,
                "projection_count": 0,
            },
            account_binding=observed(
                "bound", account_subject_sha256="b" * 64,
                workspace_sha256="c" * 64),
            program_entitlement=observed("unknown", assurance="unknown"),
            model_entitlement=observed(
                "verified", assurance="provider-enforced"),
            network={"phase": "closed", "grant_sha256": None,
                     "expires_at": None, "observed_at": 900},
            activation=observed("inactive", receipt_sha256=None),
            live_run_count=0,
        )
        self.plan = attestation.make_plan(
            stack=self.stack, catalog_sha256="2" * 64,
            status_value=self.status,
            attestation_id="11111111-1111-4111-8111-111111111111",
            created_at=1_000,
        )

    def test_plan_is_operator_external_and_exactly_bound(self) -> None:
        self.assertEqual(attestation.validate_plan(self.plan), self.plan)
        self.assertEqual(self.plan["assurance"], "operator-external")
        self.assertEqual(
            self.plan["account_subject_sha256"],
            self.stack["account_binding"]["account_subject_sha256"],
        )
        changed = copy.deepcopy(self.plan)
        changed["assurance"] = "provider-enforced"
        body = {key: changed[key] for key in changed if key not in {"schema", "plan_sha256"}}
        changed["plan_sha256"] = attestation.sha256(body)
        with self.assertRaisesRegex(
            attestation.NativeProgramAttestationError, "assurance_invalid"
        ):
            attestation.validate_plan(changed)

    def test_plan_rejects_changed_account_and_live_run(self) -> None:
        changed_stack = copy.deepcopy(self.stack)
        changed_stack["account_binding"]["account_subject_sha256"] = "9" * 64
        with self.assertRaisesRegex(
            attestation.NativeProgramAttestationError, "not_attestable"
        ):
            attestation.make_plan(
                stack=changed_stack, catalog_sha256="2" * 64,
                status_value=self.status,
                attestation_id="11111111-1111-4111-8111-111111111111",
                created_at=1_000,
            )
        changed_status = copy.deepcopy(self.status)
        changed_status["live_run_count"] = 1
        changed_status["status_sha256"] = native_stack_operations.sha256({
            key: changed_status[key]
            for key in changed_status if key not in {"schema", "status_sha256"}
        })
        with self.assertRaisesRegex(
            attestation.NativeProgramAttestationError, "not_attestable"
        ):
            attestation.make_plan(
                stack=self.stack, catalog_sha256="2" * 64,
                status_value=changed_status,
                attestation_id="11111111-1111-4111-8111-111111111111",
                created_at=1_000,
            )

    def test_authorization_is_release_plan_and_time_bound(self) -> None:
        body = {
            "authorization_id": "22222222-2222-4222-8222-222222222222",
            "attestation_id": self.plan["attestation_id"],
            "plan_sha256": self.plan["plan_sha256"],
            "request_sha256": "3" * 64, "host_release_id": "4" * 64,
            "authorized_at": 1_010, "expires_at": 1_100,
            "status": "authorized",
        }
        authorization = {
            "schema": attestation.AUTHORIZATION_SCHEMA, **body,
            "authorization_sha256": attestation.sha256(body),
        }
        self.assertEqual(
            attestation.validate_authorization(
                authorization, self.plan, now=1_020,
                expected_host_release_id="4" * 64),
            authorization,
        )


if __name__ == "__main__":
    unittest.main()
