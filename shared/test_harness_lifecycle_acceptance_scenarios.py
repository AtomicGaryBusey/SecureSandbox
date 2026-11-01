#!/usr/bin/env python3
from __future__ import annotations

import copy
import unittest
import uuid

import harness_generation_store as generation_store
import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_interactive as interactive
import harness_lifecycle_acceptance_scenarios as scenarios


NOW = 2_000_000_000
OPERATOR_UID = 501


class HarnessLifecycleAcceptanceScenarioTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60,
            "expires_at": NOW + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def authorization(self, plan: dict) -> dict:
        value = {
            "schema": generation_store.AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()),
            "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"],
            "operation": plan["operation"],
            "method": "touch-id",
            "password_fallback": False,
            "authorized_at": NOW,
            "expires_at": NOW + 120,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = generation_store.sha256_value(value)
        return value

    def execute(self, campaign: dict, case_id: str) -> tuple[dict, dict]:
        state = scenarios.initial_state(campaign, case_id, now=NOW)
        options = {}
        if case_id in scenarios.TOUCH_ID_CASES:
            plan = interactive.make_plan(
                campaign, case_id, scenarios.OPERATION[case_id],
                state["target_generation_id"], OPERATOR_UID, NOW,
            )
            options = {"plan": plan, "authorization": self.authorization(plan)}
        return state, scenarios.execute_case(
            campaign, case_id, state, now=NOW, **options,
        )

    def test_all_runtime_and_management_cases_are_closed_and_non_authorizing(self):
        campaign = self.campaign()
        for case_id in sorted(scenarios.SCENARIO_CASES):
            with self.subTest(case_id=case_id):
                before, result = self.execute(campaign, case_id)
                case = acceptance.CASE_BY_ID[case_id]
                self.assertEqual(result["outcome"], case.expected)
                self.assertEqual(
                    result["status"],
                    "verified" if case.expected == "passed" else "rejected",
                )
                self.assertEqual(result["before_state_sha256"], before["state_sha256"])
                self.assertEqual(result["candidate_authority"], "none")
                self.assertFalse(result["production_store_access"])
                self.assertFalse(result["lifecycle_mutation_performed"])
                scenarios.validate_state(
                    result["after_state"], campaign, case_id,
                )
                if case.expected == "rejected":
                    self.assertEqual(result["after_state"], before)
                if case.requires_touch_id:
                    self.assertIsNotNone(result["authorization_sha256"])
                else:
                    self.assertIsNone(result["authorization_sha256"])

    def test_expected_runtime_and_management_semantics(self):
        campaign = self.campaign()
        _before, future = self.execute(campaign, "activate-future-session")
        future_state = future["after_state"]
        session = next(iter(future_state["sessions"].values()))
        self.assertEqual(
            session["binding"]["harness_generation_id"],
            future_state["active_generation_id"],
        )

        before, pinned = self.execute(campaign, "preserve-old-session-pinning")
        self.assertEqual(pinned["after_state"], before)
        binding = pinned["evidence"]["binding"]
        self.assertEqual(
            binding["harness_generation_id"], before["predecessor_generation_id"],
        )

        before, legacy = self.execute(campaign, "legacy-session-fails-closed")
        self.assertEqual(legacy["after_state"], before)
        self.assertEqual(legacy["evidence"]["error"], "legacy_session_unbound")

        _before, migrated = self.execute(campaign, "legacy-session-touchid-migration")
        migrated_session = next(iter(migrated["after_state"]["sessions"].values()))
        self.assertEqual(migrated_session["status"], "resumable")
        self.assertIsNotNone(migrated_session["binding"])

        _before, retired = self.execute(campaign, "retire-zero-reference")
        target = retired["after_state"]["target_generation_id"]
        record = next(item for item in retired["after_state"]["generations"]
                      if item["generation_id"] == target)
        self.assertEqual(record["status"], "retired")

        _before, reclaimed = self.execute(campaign, "reclaim-zero-reference")
        target = reclaimed["after_state"]["target_generation_id"]
        record = next(item for item in reclaimed["after_state"]["generations"]
                      if item["generation_id"] == target)
        self.assertFalse(record["release_present"])
        self.assertTrue(record["evidence_retained"])

        _before, revoked = self.execute(campaign, "revoke-generation")
        self.assertEqual(
            revoked["after_state"]["revoked_generation_ids"],
            [revoked["after_state"]["target_generation_id"]],
        )

        _before, contained = self.execute(campaign, "emergency-containment")
        self.assertTrue(contained["after_state"]["containment"])
        self.assertIsNone(contained["after_state"]["active_generation_id"])

    def test_tampered_state_and_wrong_touchid_plan_fail_closed(self):
        campaign = self.campaign()
        state = scenarios.initial_state(campaign, "rollback-explicit", now=NOW)
        tampered = copy.deepcopy(state)
        tampered["target_generation_id"] = tampered["active_generation_id"]
        with self.assertRaisesRegex(scenarios.ScenarioError, "state_invalid"):
            scenarios.execute_case(campaign, "rollback-explicit", tampered, now=NOW)

        wrong = interactive.make_plan(
            campaign, "rollback-explicit", "rollback",
            state["active_generation_id"], OPERATOR_UID, NOW,
        )
        with self.assertRaisesRegex(scenarios.ScenarioError, "plan_binding_invalid"):
            scenarios.execute_case(
                campaign, "rollback-explicit", state, plan=wrong,
                authorization=self.authorization(wrong), now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
