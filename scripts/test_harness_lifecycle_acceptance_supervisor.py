#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
assert SPEC and SPEC.loader
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)
NOW = 2_000_000_000


class FakeProcess:
    stdout = None
    stderr = None

    def poll(self):
        return 0


class HarnessLifecycleAcceptanceSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.campaign_path = self.root / "campaign.json"
        self.observations = self.root / "observations"
        self.evidence = self.root / "evidence"
        self.observations.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
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
            "research_boot_sha256": "3" * 64,
            "observed_at": NOW, "candidate_authority": "none",
            "production_material_used": False,
        }
        value["checkpoint_sha256"] = acceptance.digest(value)
        return value

    def recovery(self, case: dict) -> dict:
        checkpoint_sha256 = self.checkpoint(case)["checkpoint_sha256"]
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
            "case_id": case["case_id"],
            "checkpoint": case["procedure"]["interruption_checkpoint"],
            "recovery_result": "restored_predecessor",
            "active_generation_id": "6" * 64,
            "boundary_sha256": acceptance.digest(boundary),
            "boundary": boundary, "candidate_authority": "none",
            "production_material_used": False,
        }
        inner["recovery_sha256"] = acceptance.digest(inner)
        value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-recovery-result-v1",
            "status": "recovered", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"],
            "checkpoint": case["procedure"]["interruption_checkpoint"],
            "checkpoint_sha256": checkpoint_sha256, "recovery": inner,
            "candidate_authority": "none", "production_material_used": False,
        }
        value["result_sha256"] = acceptance.digest(value)
        return value

    def stopped(self, checkpoint: dict) -> dict:
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

    def common_patches(self, case: dict, checkpoint: dict):
        lock = os.open(self.root / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        patches = (
            mock.patch.object(supervisor.time, "time", return_value=NOW),
            mock.patch.object(supervisor, "verify_source_checkout"),
            mock.patch.object(supervisor, "current_machine_identity",
                              return_value=self.campaign["machine_identity_sha256"]),
            mock.patch.object(supervisor, "next_recovery_case", return_value=case),
            mock.patch.object(supervisor, "prerequisite"),
            mock.patch.object(supervisor, "require_gui_closed"),
            mock.patch.object(supervisor, "acquire_lock", return_value=lock),
            mock.patch.object(supervisor, "deploy"),
            mock.patch.object(supervisor.subprocess, "Popen", return_value=FakeProcess()),
            mock.patch.object(supervisor, "read_worker_checkpoint", return_value=checkpoint),
            mock.patch.object(supervisor, "terminate_process"),
        )
        return lock, patches

    def test_checkpoint_and_recovery_bind_every_campaign_dimension(self):
        case = self.case("process-loss-fenced")
        checkpoint = self.checkpoint(case)
        supervisor.validate_checkpoint(self.campaign, case, checkpoint)
        recovery = self.recovery(case)
        recovery["checkpoint_sha256"] = checkpoint["checkpoint_sha256"]
        recovery["result_sha256"] = acceptance.digest(
            {key: value for key, value in recovery.items() if key != "result_sha256"},
        )
        _, boundary = supervisor.validate_recovery(
            self.campaign, case, checkpoint, recovery,
        )
        self.assertEqual(boundary["status"], "verified")
        checkpoint["source_commit"] = "9" * 40
        with self.assertRaisesRegex(supervisor.SupervisorError, "binding"):
            supervisor.validate_checkpoint(self.campaign, case, checkpoint)
        recovery["recovery"]["boundary"]["status"] = "rejected"
        with self.assertRaisesRegex(supervisor.SupervisorError, "recovery_invalid"):
            supervisor.validate_recovery(self.campaign, case, checkpoint, recovery)

    def test_machine_and_evidence_preflight_precede_every_mutation(self):
        case = self.case("process-loss-fenced")
        with mock.patch.object(supervisor.time, "time", return_value=NOW), \
                mock.patch.object(supervisor, "verify_source_checkout"), \
                mock.patch.object(supervisor, "current_machine_identity",
                                  return_value="9" * 64), \
                mock.patch.object(supervisor, "next_recovery_case") as next_case:
            with self.assertRaisesRegex(supervisor.SupervisorError, "machine_identity"):
                supervisor.execute(
                    self.campaign_path, self.observations, case["case_id"],
                    self.evidence, "",
                )
            next_case.assert_not_called()

        self.evidence.chmod(0o755)
        with mock.patch.object(supervisor.time, "time", return_value=NOW), \
                mock.patch.object(supervisor, "verify_source_checkout"), \
                mock.patch.object(supervisor, "current_machine_identity",
                                  return_value=self.campaign["machine_identity_sha256"]), \
                mock.patch.object(supervisor, "next_recovery_case", return_value=case), \
                mock.patch.object(supervisor, "deploy") as deploy:
            with self.assertRaisesRegex(supervisor.SupervisorError, "evidence_root"):
                supervisor.execute(
                    self.campaign_path, self.observations, case["case_id"],
                    self.evidence, "",
                )
            deploy.assert_not_called()
        self.evidence.chmod(0o700)

    def test_machine_identity_matches_enrollment_material_projection(self):
        payload = (
            b'"IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"\n'
            b'"IOPlatformSerialNumber" = "SERIAL"\n'
            b'"model" = <"MacFixture1,1">\n'
        )
        expected = hashlib.sha256(
            b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\0SERIAL\0MacFixture1,1",
        ).hexdigest()
        with mock.patch.object(supervisor.platform, "system", return_value="Darwin"), \
                mock.patch.object(supervisor.platform, "machine", return_value="arm64"), \
                mock.patch.object(supervisor, "command",
                                  return_value=mock.Mock(stdout=payload)):
            self.assertEqual(supervisor.current_machine_identity(), expected)

    def test_exact_commit_staging_never_rereads_mutated_campaign_bytes(self):
        stage = self.root / "stage"
        stage.mkdir(mode=0o700)
        self.campaign_path.write_bytes(b"tampered\n")

        def fake_command(argv, **_kwargs):
            payload = b"source\n" if "blob" in argv else b""
            return mock.Mock(stdout=payload, stderr=b"", returncode=0)

        with mock.patch.object(supervisor, "command", side_effect=fake_command):
            supervisor.stage_exact_commit(self.campaign, stage)
        self.assertEqual(
            (stage / "campaign.json").read_bytes(), acceptance.canonical(self.campaign),
        )

    def test_running_checkout_must_equal_campaign_commit_without_replacements(self):
        calls = []

        def exact(argv, **kwargs):
            calls.append((argv, kwargs))
            return mock.Mock(
                stdout=(f"{self.campaign['source_commit']}\n".encode()
                        if "rev-parse" in argv else b""),
                stderr=b"", returncode=0,
            )

        with mock.patch.object(supervisor, "command", side_effect=exact):
            supervisor.verify_source_checkout(self.campaign)
        self.assertEqual(calls[0][0][-2:], ["--verify", "HEAD^{commit}"])
        self.assertIn("GIT_NO_REPLACE_OBJECTS", calls[0][1]["environment"])
        self.assertIn("--exit-code", calls[1][0])

        with mock.patch.object(
            supervisor, "command",
            return_value=mock.Mock(stdout=b"9" * 40 + b"\n", stderr=b"", returncode=0),
        ), self.assertRaisesRegex(supervisor.SupervisorError, "source_checkout"):
            supervisor.verify_source_checkout(self.campaign)

    def test_process_loss_writes_exact_fixed_collector_artifacts(self):
        case = self.case("process-loss-fenced")
        checkpoint = self.checkpoint(case)
        recovery = self.recovery(case)
        termination = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-worker-termination-v1",
            "status": "verified", "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": case["case_id"], "checkpoint": checkpoint["checkpoint"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "worker_pid": checkpoint["worker_pid"],
            "worker_start_time": checkpoint["worker_start_time"],
            "research_boot_sha256": checkpoint["research_boot_sha256"],
            "signal": "SIGKILL", "candidate_authority": "none",
            "production_material_used": False,
        }
        termination["termination_sha256"] = acceptance.digest(termination)
        lock, patches = self.common_patches(case, checkpoint)
        inventory = {"gateway": "running", "research": "running", "target": "running"}

        def remote(_campaign, operation, _case, **_kwargs):
            return {
                "inspect": self.stopped(checkpoint),
                "terminate": termination,
                "recover": recovery,
            }[operation]

        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(supervisor, "remote_json", side_effect=remote))
            stack.enter_context(mock.patch.object(supervisor, "vm_inventory", return_value=inventory))
            result = supervisor.execute(
                self.campaign_path, self.observations, case["case_id"], self.evidence, "",
            )
        self.assertEqual(result["status"], "verified")
        directory = self.evidence / case["case_id"]
        self.assertEqual(
            {item.name for item in directory.iterdir()},
            {"fault-injection-receipt.json", "recovery-receipt.json",
             "boundary-readback.json"},
        )
        fault = json.loads((directory / "fault-injection-receipt.json").read_bytes())
        self.assertEqual(fault["worker_termination"]["signal"], "SIGKILL")
        self.assertEqual(fault["vm_before"], fault["vm_after"])

    def test_power_loss_requires_exact_ack_and_proves_research_only_cold_boot(self):
        case = self.case("power-loss-fenced")
        checkpoint = self.checkpoint(case)
        recovery = self.recovery(case)
        with mock.patch.object(supervisor.time, "time", return_value=NOW), \
                mock.patch.object(supervisor, "verify_source_checkout"), \
                mock.patch.object(supervisor, "current_machine_identity",
                                  return_value=self.campaign["machine_identity_sha256"]), \
                mock.patch.object(supervisor, "next_recovery_case", return_value=case):
            with self.assertRaisesRegex(supervisor.SupervisorError, "acknowledgement"):
                supervisor.execute(
                    self.campaign_path, self.observations, case["case_id"],
                    self.evidence, "wrong",
                )

        lock, patches = self.common_patches(case, checkpoint)
        running = {"gateway": "running", "research": "running", "target": "running"}
        stopped = {**running, "research": "stopped"}
        inventories = iter((running, stopped, running, running))
        preboot = self.boot(case, "3" * 64)
        postboot = self.boot(case, "5" * 64)
        boots = iter((preboot, postboot))

        def remote(_campaign, operation, _case, **_kwargs):
            if operation == "boot-readback":
                return next(boots)
            if operation == "inspect":
                return self.stopped(checkpoint)
            if operation == "recover":
                return recovery
            raise AssertionError(operation)

        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(supervisor, "remote_json", side_effect=remote))
            stack.enter_context(mock.patch.object(supervisor, "vm_inventory", side_effect=inventories))
            stack.enter_context(mock.patch.object(supervisor, "command"))
            stack.enter_context(mock.patch.object(supervisor, "wait_vm_state"))
            stack.enter_context(mock.patch.object(supervisor, "wait_research_control"))
            result = supervisor.execute(
                self.campaign_path, self.observations, case["case_id"], self.evidence,
                supervisor.POWER_ACKNOWLEDGEMENT,
            )
        self.assertEqual(result["status"], "verified")
        cold = self.evidence / case["case_id"] / "cold-boot-readback.json"
        self.assertTrue(cold.is_file())
        with self.assertRaisesRegex(supervisor.SupervisorError, "case_exists"):
            supervisor.output_destination(self.evidence, case["case_id"])

    def test_no_arbitrary_vm_pid_or_checkpoint_surface(self):
        source = (ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py").read_text()
        self.assertIn('RESEARCH_VM = "SecureSandbox-Research"', source)
        self.assertNotIn('add_argument("--vm"', source)
        self.assertNotIn('add_argument("--pid"', source)
        self.assertNotIn('add_argument("--checkpoint"', source)
        self.assertIn(supervisor.POWER_ACKNOWLEDGEMENT, source)
        self.assertEqual(supervisor.LOCK.name, "secure-sandbox-lifecycle.lock")
        self.assertIn('"GIT_NO_REPLACE_OBJECTS": "1"', source)
        self.assertNotIn('GIT), "show"', source)


if __name__ == "__main__":
    unittest.main()
