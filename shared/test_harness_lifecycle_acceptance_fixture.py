#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from pathlib import Path

import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_fixture as fixture


NOW = 2_000_000_000


class HarnessLifecycleAcceptanceFixtureTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60,
            "expires_at": NOW + 86400,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def test_every_durable_checkpoint_stops_and_recovers_fail_closed(self):
        checkpoints = (
            "stage-created", "plan-written", "journal-prepared", "fenced",
            "workflow-authorized", "release-published", "catalog-written",
            "floor-written", "selector-written", "health-passed",
            "workflow-activated", "workflow-verified", "workflow-committed",
            "fence-removed", "journal-removed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = self.campaign()
            for checkpoint in checkpoints:
                with self.subTest(checkpoint=checkpoint):
                    case_id = f"process-loss-{checkpoint}"
                    worker = fixture.RecoveryFixture(
                        root / case_id, campaign, case_id, now=lambda: NOW,
                    )

                    def stop(observed: str, expected: str = checkpoint) -> None:
                        self.assertEqual(observed, expected)
                        raise SystemExit(f"simulated-loss:{observed}")

                    with self.assertRaisesRegex(SystemExit, checkpoint):
                        worker.run(stop)
                    result = worker.recover()
                    self.assertEqual(result["status"], "recovered")
                    self.assertEqual(result["checkpoint"], checkpoint)
                    self.assertEqual(result["candidate_authority"], "none")
                    self.assertFalse(result["production_material_used"])
                    self.assertEqual(result["recovery_sha256"], acceptance.digest({
                        key: value for key, value in result.items()
                        if key != "recovery_sha256"
                    }))

    def test_power_and_process_cases_share_mechanics_but_remain_case_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign()
            worker = fixture.RecoveryFixture(
                Path(temporary) / "power", campaign, "power-loss-fenced", now=lambda: NOW,
            )
            with self.assertRaises(SystemExit):
                worker.run(lambda _checkpoint: (_ for _ in ()).throw(SystemExit("power-loss")))
            result = worker.recover()
            self.assertEqual(result["case_id"], "power-loss-fenced")
            self.assertEqual(result["checkpoint"], "fenced")

    def test_unknown_case_callback_return_and_metadata_tamper_fail_closed(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(fixture.AcceptanceFixtureError, "case_invalid"):
                fixture.RecoveryFixture(root / "bad", campaign, "touchid-cancel")
            worker = fixture.RecoveryFixture(
                root / "return", campaign, "process-loss-stage-created", now=lambda: NOW,
            )
            with self.assertRaisesRegex(fixture.AcceptanceFixtureError, "callback_returned"):
                worker.run(lambda _checkpoint: None)
            metadata = json.loads(worker.metadata_path.read_text())
            metadata["candidate_authority"] = "admission"
            worker.metadata_path.write_bytes(fixture.canonical(metadata))
            with self.assertRaisesRegex(fixture.AcceptanceFixtureError, "metadata_invalid"):
                worker.recover()


if __name__ == "__main__":
    unittest.main()
