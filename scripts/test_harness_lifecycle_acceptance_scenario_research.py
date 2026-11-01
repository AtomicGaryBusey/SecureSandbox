#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_scenario_research",
    ROOT / "scripts/harness-lifecycle-acceptance-scenario-research.py",
)
research = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(research)

import harness_generation_store as generation_store  # noqa: E402
import harness_lifecycle_acceptance as acceptance  # noqa: E402
import harness_lifecycle_acceptance_interactive as interactive  # noqa: E402
import harness_lifecycle_acceptance_scenarios as scenarios  # noqa: E402


NOW = 2_000_000_000


class ResearchScenarioTests(unittest.TestCase):
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
            "method": "touch-id", "password_fallback": False,
            "authorized_at": NOW, "expires_at": NOW + 120,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = generation_store.sha256_value(value)
        return value

    def prepare_root(self, temporary: str, campaign: dict) -> tuple[Path, Path]:
        root = Path(temporary) / "state"; root.mkdir(mode=0o700)
        campaign_root = root / campaign["campaign_id"]
        campaign_root.mkdir(mode=0o700)
        path = campaign_root / "campaign.json"
        path.write_bytes(acceptance.canonical(campaign)); path.chmod(0o600)
        return root, path

    def test_all_cases_execute_once_and_resume_exact_result(self):
        for case_id in sorted(scenarios.SCENARIO_CASES):
            with self.subTest(case_id=case_id), tempfile.TemporaryDirectory() as temporary:
                campaign = self.campaign()
                root, path = self.prepare_root(temporary, campaign)
                category = acceptance.CASE_BY_ID[case_id].category
                options = {}
                if case_id in scenarios.TOUCH_ID_CASES:
                    state = scenarios.initial_state(campaign, case_id, now=NOW)
                    plan = interactive.make_plan(
                        campaign, case_id, scenarios.OPERATION[case_id],
                        state["target_generation_id"], os.geteuid() or 501, NOW,
                    )
                    options = {
                        "plan": plan, "authorization": self.authorization(plan),
                    }
                first = research.execute(
                    path, case_id, category=category, state_root=root,
                    uid=os.geteuid(), now=NOW, **options,
                )
                second = research.execute(
                    path, case_id, category=category, state_root=root,
                    uid=os.geteuid(), now=NOW + 1, **options,
                )
                self.assertEqual(first, second)
                case_root = root / campaign["campaign_id"] / "scenarios" / case_id
                self.assertEqual((case_root / "result.json").stat().st_mode & 0o777, 0o400)
                self.assertEqual(
                    json.loads((case_root / "result.json").read_text()), first,
                )

    def test_category_and_authorization_policy_fail_closed(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root, path = self.prepare_root(temporary, campaign)
            with self.assertRaisesRegex(
                    research.ResearchScenarioError, "case_invalid"):
                research.execute(
                    path, "activate-future-session", category="management",
                    state_root=root, uid=os.geteuid(), now=NOW,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root, path = self.prepare_root(temporary, campaign)
            with self.assertRaisesRegex(
                    research.ResearchScenarioError, "authorization_required"):
                research.execute(
                    path, "rollback-explicit", category="management",
                    state_root=root, uid=os.geteuid(), now=NOW,
                )

    def test_publish_exact_recovers_completed_link_cleanup(self):
        value = {"schema": "secure-sandbox-test-v1", "status": "verified"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            alias = root / ".record.json.publish-interrupted"
            alias.write_bytes(acceptance.canonical(value)); alias.chmod(0o400)
            destination = root / "record.json"
            os.link(alias, destination)

            research.publish_exact(destination, value, os.geteuid(), 0o400)

            self.assertFalse(alias.exists())
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(
                research.trusted_json(destination, os.geteuid(), 0o400), value,
            )


if __name__ == "__main__":
    unittest.main()
