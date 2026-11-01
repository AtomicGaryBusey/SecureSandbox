#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_recovery",
    ROOT / "scripts/harness-lifecycle-acceptance-recovery.py",
)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
NOW = 2_000_000_000


class HarnessLifecycleAcceptanceRecoveryTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60, "expires_at": NOW + 3600,
            "environment": "disposable-mac", "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def test_proc_identity_handles_spaces_and_parentheses_in_comm(self):
        fields = ["T", *(["0"] * 18), "4242"]
        raw = "41 (worker ) fixture) " + " ".join(fields)
        with mock.patch.object(recovery.Path, "read_text", return_value=raw):
            self.assertEqual(
                recovery.process_identity(41), {"state": "T", "start_time": 4242},
            )

    def test_bounded_abort_accepts_zombie_as_nonexecuting(self):
        stopped = {
            "campaign_id": str(uuid.uuid4()), "campaign_sha256": "1" * 64,
            "case_id": "power-loss-fenced", "checkpoint": "fenced",
            "checkpoint_sha256": "2" * 64, "worker_pid": 41,
            "worker_start_time": 42, "research_boot_sha256": "3" * 64,
        }
        with mock.patch.object(recovery, "inspect_stopped_worker", return_value=stopped), \
                mock.patch.object(recovery.os, "kill") as kill, \
                mock.patch.object(recovery, "process_identity",
                                  return_value={"state": "Z", "start_time": 42}):
            value = recovery.kill_stopped_worker(
                Path("campaign.json"), "power-loss-fenced", NOW, abort=True,
            )
        kill.assert_called_once_with(41, recovery.signal.SIGKILL)
        self.assertEqual(value["schema"], recovery.ABORT_SCHEMA)
        self.assertEqual(value["status"], "aborted")
        self.assertEqual(
            value["abort_sha256"],
            acceptance.digest({key: item for key, item in value.items()
                               if key != "abort_sha256"}),
        )

    def test_evidentiary_termination_is_process_case_only(self):
        with self.assertRaisesRegex(recovery.AcceptanceFixtureError, "process_case"):
            recovery.terminate_stopped_worker(
                Path("campaign.json"), "power-loss-fenced", NOW,
            )

    def test_boot_readback_is_campaign_and_power_case_bound(self):
        campaign = self.campaign()
        with mock.patch.object(recovery, "trusted_json", return_value=campaign), \
                mock.patch.object(recovery, "boot_sha256", return_value="4" * 64):
            value = recovery.boot_readback(
                Path("campaign.json"), "power-loss-fenced", NOW,
            )
        self.assertEqual(value["campaign_sha256"], campaign["campaign_sha256"])
        self.assertEqual(value["research_boot_sha256"], "4" * 64)
        self.assertEqual(
            value["boot_sha256"],
            acceptance.digest({key: item for key, item in value.items()
                               if key != "boot_sha256"}),
        )

    def test_boot_readback_accepts_suite_bound_cold_boot_case(self):
        campaign = self.campaign()
        with mock.patch.object(recovery, "trusted_json", return_value=campaign), \
                mock.patch.object(recovery, "boot_sha256", return_value="5" * 64):
            value = recovery.boot_readback(
                Path("campaign.json"), "cold-boot-host-readback", NOW,
            )
        self.assertEqual(value["case_id"], "cold-boot-host-readback")
        self.assertEqual(value["research_boot_sha256"], "5" * 64)


if __name__ == "__main__":
    unittest.main()
