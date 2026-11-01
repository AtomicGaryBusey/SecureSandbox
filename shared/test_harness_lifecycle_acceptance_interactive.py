#!/usr/bin/env python3
from __future__ import annotations

import unittest
import uuid

import harness_generation_store as store
import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_interactive as interactive


NOW = 2_000_000_000


class InteractiveAcceptanceTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()), "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64, "source_commit": "2" * 40,
            "created_at": NOW - 60, "expires_at": NOW + 3600,
            "environment": "disposable-mac", "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    @staticmethod
    def authorization(plan: dict, *, now: int = NOW) -> dict:
        value = {
            "schema": store.AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()), "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"],
            "operation": plan["operation"], "method": "touch-id",
            "password_fallback": False, "authorized_at": now,
            "expires_at": now + 120, "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = store.sha256_value(value)
        return value

    def test_exact_touchid_authorization_is_consumed_without_mutation_authority(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64, 501, NOW,
        )
        result, ledger = interactive.consume(
            plan, plan, self.authorization(plan), interactive.empty_ledger(campaign),
            campaign, NOW,
        )
        self.assertEqual(result["status"], "authorized-for-acceptance-only")
        self.assertFalse(result["production_store_access"])
        self.assertFalse(result["lifecycle_mutation_performed"])
        self.assertEqual(ledger["epoch"], 1)

    def test_replay_is_rejected_by_durable_authorization_digest(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-replay", "authorize", "5" * 64, 501, NOW,
        )
        authorization = self.authorization(plan)
        _, ledger = interactive.consume(
            plan, plan, authorization, interactive.empty_ledger(campaign), campaign, NOW,
        )
        with self.assertRaisesRegex(
                interactive.InteractiveAcceptanceError, "authorization_replayed"):
            interactive.consume(plan, plan, authorization, ledger, campaign, NOW)

    def test_changed_plan_and_wrong_generation_fail_before_consumption(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "5" * 64, 501, NOW,
        )
        changed = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "6" * 64, 501, NOW,
            plan_id=plan["plan_id"], transaction_id=plan["transaction_id"],
        )
        with self.assertRaisesRegex(interactive.InteractiveAcceptanceError, "plan_changed"):
            interactive.consume(
                plan, changed, self.authorization(changed),
                interactive.empty_ledger(campaign), campaign, NOW,
            )

    def test_expired_plan_and_password_fallback_fail_closed(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-expired-plan", "authorize", "5" * 64, 501, NOW,
        )
        with self.assertRaisesRegex(interactive.InteractiveAcceptanceError, "plan_time"):
            interactive.consume(
                plan, plan, self.authorization(plan), interactive.empty_ledger(campaign),
                campaign, NOW + 301,
            )
        authorization = self.authorization(plan)
        authorization["password_fallback"] = True
        authorization["authorization_sha256"] = store.sha256_value(
            {name: item for name, item in authorization.items()
             if name != "authorization_sha256"},
        )
        with self.assertRaisesRegex(
                interactive.InteractiveAcceptanceError, "authorization_invalid"):
            interactive.consume(
                plan, plan, authorization, interactive.empty_ledger(campaign),
                campaign, NOW,
            )

    def test_noninteractive_case_and_production_access_claim_are_rejected(self):
        campaign = self.campaign()
        with self.assertRaisesRegex(interactive.InteractiveAcceptanceError, "case_invalid"):
            interactive.make_plan(
                campaign, "cold-boot-host-readback", "authorize", "5" * 64, 501, NOW,
            )
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64, 501, NOW,
        )
        plan["production_store_access"] = True
        plan["plan_sha256"] = acceptance.digest(
            {name: item for name, item in plan.items() if name != "plan_sha256"},
        )
        with self.assertRaisesRegex(interactive.InteractiveAcceptanceError, "plan_invalid"):
            interactive.validate_plan(plan, campaign, NOW)


if __name__ == "__main__":
    unittest.main()
