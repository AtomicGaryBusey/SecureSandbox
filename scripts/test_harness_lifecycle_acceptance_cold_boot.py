#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance
from harness_runtime_binding import make_binding


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_cold_boot",
    ROOT / "scripts/harness-lifecycle-acceptance-cold-boot.py",
)
assert SPEC and SPEC.loader
cold_boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cold_boot)
NOW = 2_000_000_000


class HarnessLifecycleAcceptanceColdBootTests(unittest.TestCase):
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

    def case(self, case_id: str = "cold-boot-host-readback") -> dict:
        return acceptance.case_record(acceptance.CASE_BY_ID[case_id])

    @staticmethod
    def boot(campaign: dict, case_id: str, identity: str) -> dict:
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-research-boot-v1",
            "status": "verified", "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"], "case_id": case_id,
            "research_boot_sha256": identity, "candidate_authority": "none",
            "production_material_used": False,
        }
        value["boot_sha256"] = acceptance.digest(value)
        return value

    @staticmethod
    def boundary() -> dict:
        return {
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "verified", "active_generation_id": "a" * 64,
            "generation_count": 1, "catalog_sha256": "b" * 64,
            "selector_sha256": "c" * 64, "floor_sha256": "d" * 64,
        }

    def test_acknowledgement_is_exact_and_precedes_mutation(self):
        campaign = self.campaign(); case = self.case()
        with tempfile.TemporaryDirectory() as temporary:
            raw_root = Path(temporary); raw_root.chmod(0o700)
            with mock.patch.object(cold_boot, "preflight", return_value=(campaign, case, {})), \
                    mock.patch.object(cold_boot.SUPERVISOR, "prerequisite"), \
                    mock.patch.object(cold_boot.SUPERVISOR, "acquire_lock") as lock:
                lock.return_value = os.open("/dev/null", os.O_RDONLY)
                with self.assertRaisesRegex(cold_boot.ColdBootError, "acknowledgement"):
                    cold_boot.collect(
                        Path("campaign"), Path("observations"), case["case_id"],
                        raw_root, "wrong", NOW, 501,
                    )
        lock.assert_not_called()

    def test_collect_targets_only_research_and_reserves_evidence_first(self):
        campaign = self.campaign(); case = self.case()
        pre = self.boot(campaign, case["case_id"], "3" * 64)
        post = self.boot(campaign, case["case_id"], "4" * 64)
        boundary = self.boundary()
        binding = make_binding(
            harness_id="claude-code", generation_id="a" * 64,
            manifest_sha256="e" * 64, executable_sha256="f" * 64,
            inventory_sha256="0" * 64, adapter_id="claude-core-v1",
            adapter_sha256="9" * 64,
        )
        record = {
            "generation_id": "a" * 64, "status": "active",
            "manifest_sha256": "e" * 64, "inventory_sha256": "0" * 64,
            "adapter_id": "claude-core-v1", "adapter_sha256": "9" * 64,
            "policy_sha256": "8" * 64,
        }
        status = {
            "schema": "secure-sandbox-harness-generation-status-v1",
            "status": "verified", "admission": "open", "recovery_pending": False,
            "active_generation_id": "a" * 64, "generations": [record],
            "boundary": boundary,
        }
        inventories = [
            {"gateway": "running", "research": "running", "target": "stopped"},
            {"gateway": "running", "research": "stopped", "target": "stopped"},
            {"gateway": "running", "research": "running", "target": "stopped"},
            {"gateway": "running", "research": "running", "target": "stopped"},
        ]
        protected_manifest = {"suite_sha256": "7" * 64, "source_commit": "2" * 40}
        protected_manifest["manifest_sha256"] = acceptance.digest(protected_manifest)
        with tempfile.TemporaryDirectory() as temporary:
            raw_root = Path(temporary); raw_root.chmod(0o700)
            lock_fd = os.open("/dev/null", os.O_RDONLY)

            def command(arguments, **_kwargs):
                self.assertTrue((raw_root / case["case_id"]).is_dir())
                self.assertEqual(arguments[2], cold_boot.SUPERVISOR.RESEARCH_VM)
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")

            with mock.patch.object(
                    cold_boot, "preflight", return_value=(campaign, case, {
                        **protected_manifest,
                    })), \
                    mock.patch.object(cold_boot.SUPERVISOR, "prerequisite"), \
                    mock.patch.object(cold_boot.SUPERVISOR, "acquire_lock", return_value=lock_fd), \
                    mock.patch.object(cold_boot.SUPERVISOR, "require_gui_closed"), \
                    mock.patch.object(cold_boot.SUPERVISOR, "vm_inventory", side_effect=inventories), \
                    mock.patch.object(cold_boot.SUPERVISOR, "remote_json", side_effect=[pre, post]), \
                    mock.patch.object(cold_boot.SUPERVISOR, "command", side_effect=command) as run, \
                    mock.patch.object(cold_boot.SUPERVISOR, "wait_vm_state"), \
                    mock.patch.object(cold_boot.SUPERVISOR, "wait_research_control"), \
                    mock.patch.object(cold_boot, "control", side_effect=[status, boundary, binding]):
                result = cold_boot.collect(
                    Path("campaign"), Path("observations"), case["case_id"],
                    raw_root, cold_boot.ACKNOWLEDGEMENT, NOW, 501,
                )
            self.assertEqual(result["status"], "recorded")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(
                [call.args[0][1] for call in run.call_args_list], ["stop", "start"],
            )
            self.assertEqual(
                {item.name for item in (raw_root / case["case_id"]).iterdir()},
                {"cold-boot-readback.json", "host-release-readback.json"},
            )

    def test_raw_set_rejects_unchanged_boot_identity(self):
        campaign = self.campaign(); case = self.case()
        boot = self.boot(campaign, case["case_id"], "3" * 64)
        inventory = {"gateway": "running", "research": "running", "target": "stopped"}
        value = {
            "schema": cold_boot.COLD_BOOT_SCHEMA, "status": "verified",
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"], "case_id": case["case_id"],
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "observed_at": NOW, "pre_boot": boot, "post_boot": boot,
            "vm_before": inventory, "vm_stopped": {**inventory, "research": "stopped"},
            "vm_restarted": inventory, "vm_after": inventory,
            "gateway_unchanged": True, "target_unchanged": True,
            "candidate_authority": "none", "production_material_used": False,
        }
        value["cold_boot_sha256"] = acceptance.digest(value)
        protected_manifest = {"suite_sha256": "7" * 64, "source_commit": "2" * 40}
        protected_manifest["manifest_sha256"] = acceptance.digest(protected_manifest)
        receipt = cold_boot.receipt(
            campaign, case, "host-release-readback", NOW,
            {"protected_manifest": protected_manifest,
             "protected_manifest_sha256": protected_manifest["manifest_sha256"],
             "protected_suite_sha256": "7" * 64},
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); directory.chmod(0o700)
            cold_boot.SUPERVISOR.write_new(directory / "cold-boot-readback.json", value)
            cold_boot.SUPERVISOR.write_new(directory / "host-release-readback.json", receipt)
            with self.assertRaisesRegex(cold_boot.ColdBootError, "raw_readback"):
                cold_boot.raw_set(campaign, case, directory, NOW)


if __name__ == "__main__":
    unittest.main()
