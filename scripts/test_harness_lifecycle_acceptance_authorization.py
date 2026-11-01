#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

import harness_generation_store as store
import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_interactive as interactive


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_authorization",
    ROOT / "scripts/harness-lifecycle-acceptance-authorization.py",
)
assert SPEC and SPEC.loader
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
NOW = 2_000_000_000


class AuthorizationConsumerTests(unittest.TestCase):
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
    def authorization(plan: dict) -> dict:
        value = {
            "schema": store.AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()), "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"], "operation": plan["operation"],
            "method": "touch-id", "password_fallback": False,
            "authorized_at": NOW, "expires_at": NOW + 120,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = store.sha256_value(value)
        return value

    def state(self, root: Path, campaign: dict, plan: dict) -> Path:
        state = root / campaign["campaign_id"] / "interactive" / "authorization"
        state.mkdir(mode=0o700, parents=True)
        for parent in (root, root / campaign["campaign_id"], state.parent, state):
            parent.chmod(0o700)
        files = {
            "campaign.json": (campaign, 0o400), "plan.json": (plan, 0o400),
            "ledger.json": (interactive.empty_ledger(campaign), 0o600),
        }
        for name, (value, mode) in files.items():
            path = state / name; path.write_bytes(acceptance.canonical(value)); path.chmod(mode)
        return state

    def test_consumer_atomically_advances_ledger_and_publishes_immutable_result(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        authorization = self.authorization(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            result = driver.consume_request(
                plan, authorization, root=root, uid=os.geteuid(), now=NOW,
            )
            ledger = json.loads((state / "ledger.json").read_text())
            output = state / f"result-{authorization['authorization_sha256']}.json"
            self.assertEqual(ledger["epoch"], 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o400)
            self.assertEqual(result["candidate_authority"], "none")
            self.assertFalse(result["production_store_access"])
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "replayed"):
                driver.consume_request(
                    plan, authorization, root=root, uid=os.geteuid(), now=NOW,
                )

    def test_changed_plan_rejects_without_advancing_ledger(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        changed = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "6" * 64,
            os.geteuid() or 501, NOW,
            plan_id=plan["plan_id"], transaction_id=plan["transaction_id"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            before = (state / "ledger.json").read_bytes()
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "plan_changed"):
                driver.consume_request(
                    changed, self.authorization(changed), root=root,
                    uid=os.geteuid(), now=NOW,
                )
            self.assertEqual((state / "ledger.json").read_bytes(), before)
            self.assertFalse(list(state.glob("result-*.json")))

    def test_transaction_recovery_finishes_ledger_and_result_before_replay_rejects(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-replay", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        authorization = self.authorization(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            prior = interactive.empty_ledger(campaign)
            result, next_ledger = interactive.consume(
                plan, plan, authorization, prior, campaign, NOW,
            )
            journal = {
                "schema":
                    "secure-sandbox-harness-lifecycle-acceptance-authorization-transaction-v1",
                "campaign_id": campaign["campaign_id"],
                "campaign_sha256": campaign["campaign_sha256"],
                "prior_ledger_sha256": prior["ledger_sha256"],
                "next_ledger": next_ledger, "result": result,
            }
            journal["journal_sha256"] = acceptance.digest(journal)
            path = state / "transaction.json"
            path.write_bytes(acceptance.canonical(journal)); path.chmod(0o600)
            driver.recover_transaction(state, campaign, os.geteuid())
            self.assertFalse(path.exists())
            self.assertEqual(
                json.loads((state / "ledger.json").read_text()), next_ledger,
            )
            self.assertTrue(
                (state / f"result-{authorization['authorization_sha256']}.json").is_file(),
            )
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "replayed"):
                driver.consume_request(
                    plan, authorization, root=root, uid=os.geteuid(), now=NOW,
                )

    def test_cli_has_no_state_root_or_campaign_override(self):
        help_text = driver.parser().format_help()
        self.assertNotIn("state-root", help_text)
        self.assertNotIn("campaign", help_text)

    def test_operator_uid_mismatch_rejects_before_state_access(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        with self.assertRaisesRegex(driver.AuthorizationDriverError, "operator_uid_mismatch"):
            driver.consume_request(
                plan, self.authorization(plan), root=Path("/does/not/exist"),
                uid=os.geteuid(), operator_uid=plan["operator_uid"] + 1, now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
