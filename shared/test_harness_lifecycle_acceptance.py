#!/usr/bin/env python3
from __future__ import annotations

import copy
import unittest
import uuid

import harness_lifecycle_acceptance as acceptance


NOW = 2_000_000_000


class HarnessLifecycleAcceptanceTests(unittest.TestCase):
    def campaign(self):
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

    def observations(self, campaign):
        result = []
        for case in acceptance.CASES:
            for kind in case.evidence_kinds:
                value = {
                    "schema": acceptance.OBSERVATION_SCHEMA,
                    "observation_id": str(uuid.uuid4()),
                    "campaign_id": campaign["campaign_id"],
                    "campaign_sha256": campaign["campaign_sha256"],
                    "case_id": case.case_id,
                    "kind": kind,
                    "collector": "secure-sandbox-disposable-supervisor-v1",
                    "machine_identity_sha256": campaign["machine_identity_sha256"],
                    "source_commit": campaign["source_commit"],
                    "started_at": NOW - 10,
                    "completed_at": NOW - 5,
                    "outcome": case.expected,
                    "subject_sha256": "3" * 64,
                    "detail_sha256": "4" * 64,
                    "detail_size": 100,
                    "candidate_statement_used": False,
                }
                value["observation_sha256"] = acceptance.digest(value)
                result.append(value)
        return result

    def export(self):
        campaign = self.campaign()
        return acceptance.assemble_export(campaign, self.observations(campaign), NOW)

    def redigest_export(self, value):
        value["export_sha256"] = acceptance.digest({
            key: item for key, item in value.items() if key != "export_sha256"
        })

    def test_catalog_covers_complete_destructive_matrix(self):
        ids = set(acceptance.CASE_BY_ID)
        self.assertGreaterEqual(len(ids), 80)
        for required in (
            "bootstrap-clean-install", "reject-bad-signature", "reject-broken-chain",
            "reject-release-rollback", "reject-release-freeze", "reject-release-equivocation",
            "reject-archive-dotdot", "reject-archive-symlink", "reject-archive-archive-bomb",
            "touchid-approve-exact-plan", "touchid-cancel", "touchid-expired-plan",
            "touchid-replay", "touchid-changed-plan", "touchid-wrong-generation",
            "activate-future-session", "preserve-old-session-pinning",
            "legacy-session-fails-closed", "rollback-explicit", "retire-zero-reference",
            "reclaim-zero-reference", "revoke-generation", "emergency-containment",
            "cold-boot-host-readback", "independent-evidence-export",
        ):
            self.assertIn(required, ids)
        transitions = (
            "stage-created", "plan-written", "fenced", "authorized", "release-published",
            "catalog-written", "floor-written", "selector-written", "health-passed",
            "workflow-activated", "workflow-verified", "workflow-committed", "fence-removed",
            "journal-removed",
        )
        for transition in transitions:
            self.assertIn(f"process-loss-{transition}", ids)
            self.assertIn(f"power-loss-{transition}", ids)

    def test_complete_export_yields_only_separate_admission_authority(self):
        value = self.export()
        result = acceptance.verdict(value, NOW)
        self.assertEqual(result["status"], "accepted-for-separate-admission-decision")
        self.assertEqual(result["authority"], "acceptance-evidence-only")
        self.assertEqual(result["case_count"], len(acceptance.CASES))
        self.assertEqual(value["candidate_authority"], "none")

    def test_missing_duplicate_and_reordered_observations_fail_closed(self):
        campaign = self.campaign()
        observations = self.observations(campaign)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "inventory"):
            acceptance.assemble_export(campaign, observations[:-1], NOW)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "duplicate"):
            acceptance.assemble_export(campaign, observations + [observations[0]], NOW)
        value = self.export()
        receipt = value["receipts"][0]
        receipt["observation_sha256"] = list(reversed(receipt["observation_sha256"]))
        receipt["receipt_sha256"] = acceptance.digest({
            key: item for key, item in receipt.items() if key != "receipt_sha256"
        })
        self.redigest_export(value)
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.verdict(value, NOW)

    def test_candidate_statement_mixed_machine_and_source_fail_closed(self):
        for field, replacement, reason in (
            ("candidate_statement_used", True, "binding"),
            ("machine_identity_sha256", "5" * 64, "binding"),
            ("source_commit", "6" * 40, "binding"),
        ):
            with self.subTest(field=field):
                campaign = self.campaign()
                observations = self.observations(campaign)
                observations[0][field] = replacement
                observations[0]["observation_sha256"] = acceptance.digest({
                    key: item for key, item in observations[0].items()
                    if key != "observation_sha256"
                })
                with self.assertRaisesRegex(acceptance.AcceptanceError, reason):
                    acceptance.assemble_export(campaign, observations, NOW)

    def test_wrong_outcome_and_unknown_collector_fail_closed(self):
        campaign = self.campaign()
        for field, replacement in (("outcome", "passed"), ("collector", "candidate-harness")):
            observations = self.observations(campaign)
            target = next(item for item in observations if item["outcome"] == "rejected")
            target[field] = replacement
            target["observation_sha256"] = acceptance.digest({
                key: item for key, item in target.items() if key != "observation_sha256"
            })
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.assemble_export(campaign, observations, NOW)

    def test_production_material_or_non_disposable_campaign_rejects(self):
        for field, replacement in (
            ("production_data_present", True),
            ("production_credentials_present", True),
            ("synthetic_credentials_only", False),
            ("environment", "production-mac"),
        ):
            campaign = self.campaign()
            campaign[field] = replacement
            campaign["campaign_sha256"] = acceptance.digest({
                key: item for key, item in campaign.items() if key != "campaign_sha256"
            })
            with self.assertRaisesRegex(acceptance.AcceptanceError, "policy"):
                acceptance.validate_campaign(campaign, NOW)

    def test_expiry_and_receipt_chain_tampering_reject(self):
        with self.assertRaisesRegex(acceptance.AcceptanceError, "time"):
            acceptance.verdict(self.export(), NOW + 7200)
        value = self.export()
        value["receipts"][1]["previous_receipt_sha256"] = "9" * 64
        value["receipts"][1]["receipt_sha256"] = acceptance.digest({
            key: item for key, item in value["receipts"][1].items() if key != "receipt_sha256"
        })
        self.redigest_export(value)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "binding"):
            acceptance.verdict(value, NOW)

    def test_suite_digest_changes_with_any_contract_change(self):
        current = acceptance.suite_sha256()
        changed = [acceptance.case_record(case) for case in acceptance.CASES]
        changed[0] = copy.deepcopy(changed[0])
        changed[0]["destructive"] = not changed[0]["destructive"]
        self.assertNotEqual(current, acceptance.digest({
            "suite_id": acceptance.SUITE_ID, "cases": changed,
        }))


if __name__ == "__main__":
    unittest.main()
