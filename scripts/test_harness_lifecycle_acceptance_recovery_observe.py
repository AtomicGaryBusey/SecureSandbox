#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_recovery_observe",
    ROOT / "scripts/harness-lifecycle-acceptance-recovery-observe.py",
)
assert SPEC and SPEC.loader
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)
NOW = 2_000_000_000


class RecoveryObservationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.campaign_path = self.root / "campaign.json"
        self.observations = self.root / "observations"
        self.raw = self.root / "raw"
        self.observations.mkdir(mode=0o700)
        self.raw.mkdir(mode=0o700)
        self.campaign = {
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
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        self.campaign_path.write_bytes(acceptance.canonical(self.campaign))
        self.campaign_path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def case(self, case_id: str) -> dict:
        return acceptance.case_record(acceptance.CASE_BY_ID[case_id])

    def checkpoint(self, case: dict) -> dict:
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-checkpoint-v1",
            "status": "recorded", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "source_commit": self.campaign["source_commit"],
            "case_id": case["case_id"],
            "checkpoint": case["procedure"]["interruption_checkpoint"],
            "worker_pid": 41, "worker_start_time": 42,
            "research_boot_sha256": "3" * 64, "observed_at": NOW,
            "candidate_authority": "none", "production_material_used": False,
        }
        value["checkpoint_sha256"] = acceptance.digest(value)
        return value

    def stop(self, checkpoint: dict) -> dict:
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-worker-stop-v1",
            "status": "verified", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": checkpoint["case_id"], "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_pid": checkpoint["worker_pid"],
            "worker_start_time": checkpoint["worker_start_time"],
            "process_state": "T",
            "research_boot_sha256": checkpoint["research_boot_sha256"],
            "candidate_authority": "none", "production_material_used": False,
        }
        value["stop_sha256"] = acceptance.digest(value)
        return value

    def termination(self, checkpoint: dict) -> dict:
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-worker-termination-v1",
            "status": "verified", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": checkpoint["case_id"], "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_pid": checkpoint["worker_pid"],
            "worker_start_time": checkpoint["worker_start_time"],
            "research_boot_sha256": checkpoint["research_boot_sha256"],
            "signal": "SIGKILL", "candidate_authority": "none",
            "production_material_used": False,
        }
        value["termination_sha256"] = acceptance.digest(value)
        return value

    def fault(self, case: dict, checkpoint: dict) -> dict:
        inventory = {"gateway": "running", "research": "running", "target": "running"}
        value = {
            "schema": projection.SUPERVISOR.FAULT_SCHEMA, "status": "verified",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "source_commit": self.campaign["source_commit"],
            "case_id": case["case_id"],
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "interaction": case["procedure"]["interaction"],
            "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_checkpoint": checkpoint, "worker_stop": self.stop(checkpoint),
            "worker_termination": self.termination(checkpoint),
            "vm_before": inventory, "vm_stopped": None, "vm_restarted": None,
            "vm_after": inventory, "candidate_authority": "none",
            "production_material_used": False,
        }
        value["fault_sha256"] = acceptance.digest(value)
        return value

    def boot(self, case: dict, identity: str) -> dict:
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-research-boot-v1",
            "status": "verified", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"], "research_boot_sha256": identity,
            "candidate_authority": "none", "production_material_used": False,
        }
        value["boot_sha256"] = acceptance.digest(value)
        return value

    def recovery(self, case: dict, checkpoint: dict) -> tuple[dict, dict]:
        boundary = {
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "verified", "active_generation_id": "6" * 64,
            "generation_count": 1, "catalog_sha256": "7" * 64,
            "selector_sha256": "8" * 64, "floor_sha256": "9" * 64,
        }
        inner = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-recovery-v1",
            "status": "recovered", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"], "checkpoint": checkpoint["checkpoint"],
            "recovery_result": "restored_predecessor",
            "active_generation_id": "6" * 64,
            "boundary_sha256": acceptance.digest(boundary), "boundary": boundary,
            "candidate_authority": "none", "production_material_used": False,
        }
        inner["recovery_sha256"] = acceptance.digest(inner)
        result = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-recovery-result-v1",
            "status": "recovered", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"], "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"], "recovery": inner,
            "candidate_authority": "none", "production_material_used": False,
        }
        result["result_sha256"] = acceptance.digest(result)
        return result, boundary

    def prepare_process_case(self) -> tuple[dict, dict]:
        case = self.case("process-loss-fenced")
        checkpoint = self.checkpoint(case)
        recovery, boundary = self.recovery(case, checkpoint)
        values = {
            "fault-injection-receipt.json": self.fault(case, checkpoint),
            "recovery-receipt.json": recovery,
            "boundary-readback.json": boundary,
        }
        for name, value in values.items():
            path = self.raw / name
            path.write_bytes(acceptance.canonical(value)); path.chmod(0o600)
        return case, checkpoint

    def prepare_power_case(self) -> tuple[dict, dict]:
        case = self.case("power-loss-fenced")
        checkpoint = self.checkpoint(case)
        running = {"gateway": "running", "research": "running", "target": "running"}
        stopped = {**running, "research": "stopped"}
        fault = {
            "schema": projection.SUPERVISOR.FAULT_SCHEMA, "status": "verified",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "source_commit": self.campaign["source_commit"],
            "case_id": case["case_id"],
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "interaction": case["procedure"]["interaction"],
            "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_checkpoint": checkpoint, "worker_stop": self.stop(checkpoint),
            "worker_termination": None, "vm_before": running,
            "vm_stopped": stopped, "vm_restarted": running, "vm_after": running,
            "candidate_authority": "none", "production_material_used": False,
        }
        fault["fault_sha256"] = acceptance.digest(fault)
        pre_boot = self.boot(case, checkpoint["research_boot_sha256"])
        post_boot = self.boot(case, "5" * 64)
        cold_boot = {
            "schema": projection.SUPERVISOR.COLD_BOOT_SCHEMA, "status": "verified",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "pre_boot": pre_boot, "post_boot": post_boot,
            "vm_stopped": stopped, "vm_restarted": running,
            "gateway_unchanged": True, "target_unchanged": True,
            "candidate_authority": "none", "production_material_used": False,
        }
        cold_boot["cold_boot_sha256"] = acceptance.digest(cold_boot)
        recovery, boundary = self.recovery(case, checkpoint)
        values = {
            "fault-injection-receipt.json": fault,
            "cold-boot-readback.json": cold_boot,
            "recovery-receipt.json": recovery,
            "boundary-readback.json": boundary,
        }
        for name, value in values.items():
            path = self.raw / name
            path.write_bytes(acceptance.canonical(value)); path.chmod(0o600)
        return case, checkpoint

    def patches(self, case: dict):
        return (
            mock.patch.object(projection.SUPERVISOR, "verify_source_checkout"),
            mock.patch.object(
                projection.SUPERVISOR, "current_machine_identity",
                return_value=self.campaign["machine_identity_sha256"],
            ),
            mock.patch.object(
                projection.SUPERVISOR, "next_recovery_case", return_value=case,
            ),
        )

    def test_projects_exact_fixed_authority_observations_and_resumes(self):
        case, _ = self.prepare_process_case()
        source, first, second = self.patches(case)
        with source, first, second:
            result = projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        self.assertEqual(result["recorded_observation_kinds"], case["evidence_kinds"])
        self.assertEqual(result["resumed_observation_kinds"], [])
        self.assertEqual(
            {item.name for item in self.observations.iterdir()},
            {f"{case['case_id']}.{kind}.json" for kind in case["evidence_kinds"]},
        )
        for kind in case["evidence_kinds"]:
            value = json.loads(
                (self.observations / f"{case['case_id']}.{kind}.json").read_bytes(),
            )
            self.assertEqual(
                value["evidence"]["artifacts"][0]["authority"],
                projection.AUTHORITIES[kind],
            )
            acceptance.validate_observation(value, self.campaign, acceptance.CASE_BY_ID[case["case_id"]])

        source, first, second = self.patches(case)
        with source, first, second:
            resumed = projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        self.assertEqual(resumed["recorded_observation_kinds"], [])
        self.assertEqual(resumed["resumed_observation_kinds"], case["evidence_kinds"])

    def test_changed_boundary_rejects_before_any_observation(self):
        case, _ = self.prepare_process_case()
        path = self.raw / "boundary-readback.json"
        value = json.loads(path.read_bytes()); value["status"] = "rejected"
        path.write_bytes(acceptance.canonical(value))
        source, first, second = self.patches(case)
        with source, first, second, self.assertRaisesRegex(
                projection.ProjectionError, "boundary_readback_mismatch"):
            projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        self.assertEqual(list(self.observations.iterdir()), [])

    def test_resume_rejects_changed_supporting_artifact_even_when_self_consistent(self):
        case, _ = self.prepare_process_case()
        source, first, second = self.patches(case)
        with source, first, second:
            projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        path = self.observations / f"{case['case_id']}.recovery-receipt.json"
        value = json.loads(path.read_bytes())
        alternate = b'{"schema":"alternate","status":"verified"}\n'
        support = value["evidence"]["artifacts"][1]
        support["content_base64"] = base64.b64encode(alternate).decode("ascii")
        support["size"] = len(alternate)
        support["sha256"] = hashlib.sha256(alternate).hexdigest()
        value["evidence"].pop("evidence_sha256")
        value["evidence"]["evidence_sha256"] = acceptance.digest(value["evidence"])
        value["evidence_sha256"] = value["evidence"]["evidence_sha256"]
        value.pop("observation_sha256")
        value["observation_sha256"] = acceptance.digest(value)
        path.write_bytes(acceptance.canonical(value))
        source, first, second = self.patches(case)
        with source, first, second, self.assertRaisesRegex(
                projection.ProjectionError, "existing_observation_mismatch"):
            projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )

    def test_power_projection_requires_bound_cold_boot_change(self):
        case, _ = self.prepare_power_case()
        source, first, second = self.patches(case)
        with source, first, second:
            result = projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        self.assertIn("cold-boot-readback", result["recorded_observation_kinds"])
        path = self.observations / f"{case['case_id']}.cold-boot-readback.json"
        self.assertEqual(
            json.loads(path.read_bytes())["evidence"]["artifacts"][0]["authority"],
            "cold-boot-supervisor",
        )

    def test_unexpected_raw_file_and_mismatched_existing_observation_reject(self):
        case, _ = self.prepare_process_case()
        extra = self.raw / "extra.json"; extra.write_bytes(b"{}\n"); extra.chmod(0o600)
        source, first, second = self.patches(case)
        with source, first, second, self.assertRaisesRegex(
                projection.ProjectionError, "raw_inventory"):
            projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )
        extra.unlink()
        destination = self.observations / f"{case['case_id']}.fault-injection-receipt.json"
        destination.write_bytes(b"{}\n"); destination.chmod(0o600)
        source, first, second = self.patches(case)
        with source, first, second, self.assertRaisesRegex(
                projection.ProjectionError, "existing_observation"):
            projection.project(
                self.campaign_path, self.observations, case["case_id"], self.raw, NOW,
            )

    def test_surface_has_no_authority_or_artifact_override(self):
        source = (
            ROOT / "scripts/harness-lifecycle-acceptance-recovery-observe.py"
        ).read_text()
        self.assertNotIn('add_argument("--authority"', source)
        self.assertNotIn('add_argument("--artifact"', source)
        self.assertNotIn('add_argument("--kind"', source)


if __name__ == "__main__":
    unittest.main()
