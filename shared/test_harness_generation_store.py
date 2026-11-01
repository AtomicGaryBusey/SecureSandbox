#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_generation_store as STORE
import harness_lifecycle as LIFECYCLE


def uid4() -> str:
    return str(uuid.uuid4())


class PassingProbe:
    def probe(self, plan, executable):
        assert executable.name == "harness"
        value = {
            "schema": STORE.HEALTH_SCHEMA, "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "generation_id": plan["candidate"]["generation_id"],
            "artifact_sha256": plan["candidate"]["artifact_sha256"],
            "adapter_sha256": plan["candidate"]["adapter_sha256"],
            "health_probe_sha256": plan["candidate"]["health_probe_sha256"],
            "observer": "secure-sandbox-fixed-health-supervisor-v1",
            "synthetic": True, "production_credential_present": False,
            "network_attempts": [], "status": "passed",
        }
        value["health_sha256"] = STORE.sha256_value(value)
        return value


class FailingProbe:
    def probe(self, plan, executable):
        raise RuntimeError("synthetic_health_failure")


class CrashProbe:
    def probe(self, plan, executable):
        raise SystemExit("simulated_process_loss")


class HarnessGenerationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release_root = self.root / "releases-root"
        self.state_root = self.root / "state"
        self.source_root = self.root / "quarantine"
        self.source_root.mkdir(mode=0o700)
        self.now = 2_000_000_000
        self.store = STORE.GenerationStore(
            self.release_root, self.state_root, now=lambda: self.now,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def write_json(self, path: Path, value: dict) -> None:
        path.write_bytes(STORE.canonical_bytes(value))
        path.chmod(0o600)

    def candidate(self, sequence: int, version: str) -> dict[str, Path]:
        directory = self.source_root / f"candidate-{sequence}"
        directory.mkdir(mode=0o700)
        artifact = f"#!/bin/sh\necho harness-{version}\n".encode("ascii")
        artifact_sha = STORE.sha256_bytes(artifact)
        adapter_sha = STORE.sha256_bytes(f"adapter-{version}".encode("ascii"))
        policy_sha = STORE.sha256_bytes(b"policy-v1")
        evidence_sha = STORE.sha256_bytes(f"evidence-{version}".encode("ascii"))
        manifest = {
            "schema": LIFECYCLE.MANIFEST_SCHEMA,
            "adapter_id": "claude-core-v1", "harness_id": "claude-code",
            "vendor_id": "anthropic", "version": version, "platform": "linux-arm64",
            "release_sequence": sequence,
            "artifact": {"filename": "claude", "media_type": "application/octet-stream",
                         "sha256": artifact_sha, "size": len(artifact),
                         "url": f"https://updates.example.com/claude-{version}"},
            "compatibility": {"adapter_sha256": adapter_sha,
                              "controller_schema": "harness-controller-v1"},
            "evidence": [{"kind": "vendor-signature", "media_type": "application/json",
                          "required": True, "sha256": evidence_sha,
                          "subject_sha256": artifact_sha}],
        }
        manifest["generation_id"] = LIFECYCLE.generation_identity(manifest)
        manifest_raw = STORE.canonical_bytes(manifest)
        manifest_sha = STORE.sha256_bytes(manifest_raw)
        verification = {
            "action": "verify", "observed_at": self.now - 30, "receipt_id": uid4(),
            "schema": LIFECYCLE.RECEIPT_SCHEMA,
            "status": "artifact_and_evidence_bindings_verified",
            "artifact_sha256": artifact_sha, "envelope_sha256": "e" * 64,
            "evidence_sha256": [evidence_sha], "generation_id": manifest["generation_id"],
            "manifest_sha256": manifest_sha, "note": "not_admitted_not_executable",
            "policy_sha256": policy_sha,
        }
        adapter = {
            "schema": STORE.ADAPTER_SCHEMA, "adapter_id": "claude-core-v1",
            "adapter_sha256": adapter_sha, "harness_id": "claude-code",
            "executable_name": "harness", "protocol": "secure-sandbox-neutral-harness-v1",
            "policy_sha256": policy_sha, "authority": "none",
            "health_probe_sha256": "9" * 64,
        }
        adapter["projection_sha256"] = STORE.sha256_value(adapter)
        qualification = {
            "schema": STORE.QUALIFICATION_SCHEMA, "qualification_id": uid4(),
            "generation_id": manifest["generation_id"], "artifact_sha256": artifact_sha,
            "manifest_sha256": manifest_sha, "adapter_id": "claude-core-v1",
            "adapter_sha256": adapter_sha, "suite_sha256": "s" * 64,
            "policy_sha256": policy_sha, "observer": "secure-sandbox-disposable-supervisor-v1",
            "observation_set_sha256": "o" * 64, "qualified_at": self.now - 20,
            "expires_at": self.now + 86400, "synthetic": False, "status": "qualified",
            "authority": "qualification-evidence-only",
        }
        # Replace non-hex fixture markers with stable hexadecimal values.
        qualification["suite_sha256"] = "a" * 64
        qualification["observation_set_sha256"] = "b" * 64
        qualification["qualification_sha256"] = STORE.sha256_value(qualification)
        paths = {name: directory / name for name in (
            "artifact", "manifest.json", "verification.json", "qualification.json", "adapter.json")}
        paths["artifact"].write_bytes(artifact); paths["artifact"].chmod(0o600)
        paths["manifest.json"].write_bytes(manifest_raw); paths["manifest.json"].chmod(0o600)
        self.write_json(paths["verification.json"], verification)
        self.write_json(paths["qualification.json"], qualification)
        self.write_json(paths["adapter.json"], adapter)
        return paths

    def plan(self, paths, operation="activate"):
        return self.store.create_plan(
            paths["manifest.json"], paths["artifact"], paths["verification.json"],
            paths["qualification.json"], paths["adapter.json"], operation=operation,
            now=self.now,
        )

    def authorization(self, plan):
        value = {
            "schema": STORE.AUTHORIZATION_SCHEMA, "authorization_id": uid4(),
            "plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"], "operation": plan["operation"],
            "method": "touch-id", "password_fallback": False,
            "authorized_at": self.now, "expires_at": self.now + 120,
            "requesting_agent_sha256": "c" * 64,
            "requesting_session_sha256": "d" * 64,
        }
        value["authorization_sha256"] = STORE.sha256_value(value)
        return value

    def reference(self, generation_id, active=0, resumable=0):
        value = {"schema": STORE.REFERENCE_SCHEMA, "generation_id": generation_id,
                 "active_run_count": active, "resumable_session_count": resumable,
                 "observed_at": self.now,
                 "observer": "secure-sandbox-session-catalog-readback-v1"}
        value["reference_sha256"] = STORE.sha256_value(value)
        path = self.source_root / f"references-{uuid.uuid4()}.json"
        self.write_json(path, value)
        return path

    def activate(self, paths, plan=None, probe=None):
        plan = plan or self.plan(paths)
        return self.store.activate(
            plan, self.authorization(plan), paths["manifest.json"], paths["artifact"],
            paths["verification.json"], paths["qualification.json"], paths["adapter.json"],
            probe or PassingProbe(), runtime_idle=lambda: True, now=self.now,
        )

    def test_activation_publishes_immutable_exact_generation(self):
        paths = self.candidate(1, "2.1.300")
        receipt = self.activate(paths)
        status = self.store.status()
        generation = status["active_generation_id"]
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(status["admission"], "open")
        self.assertEqual(status["highest_release_sequence"], 1)
        release = self.release_root / "releases" / generation
        self.assertEqual(release.stat().st_mode & 0o777, 0o555)
        self.assertEqual((release / "harness").stat().st_mode & 0o777, 0o555)
        self.assertEqual((release / "manifest.json").stat().st_mode & 0o777, 0o444)
        self.assertEqual(status["boundary"]["status"], "verified")
        binding = self.store.runtime_binding()
        self.assertEqual(binding["harness_generation_id"], generation)
        self.assertEqual(binding["harness_id"], "claude-code")
        self.assertEqual(binding["harness_executable_sha256"],
                         STORE.sha256_bytes((release / "harness").read_bytes()))
        self.assertEqual(binding["harness_adapter_id"], "claude-core-v1")

    def test_second_activation_retains_predecessor_and_rollback_keeps_floor(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301"); self.activate(second)
        second_id = self.store.status()["active_generation_id"]
        rollback_plan = self.plan(first, "rollback")
        self.activate(first, rollback_plan)
        status = self.store.status()
        self.assertEqual(status["active_generation_id"], first_id)
        self.assertEqual(status["predecessor_generation_id"], second_id)
        self.assertEqual(status["highest_release_sequence"], 2)

    def test_health_failure_restores_predecessor_and_rejects_candidate(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301")
        with self.assertRaisesRegex(RuntimeError, "synthetic_health_failure"):
            self.activate(second, probe=FailingProbe())
        status = self.store.status()
        self.assertEqual(status["active_generation_id"], first_id)
        rejected = [item for item in status["generations"] if item["status"] == "rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(status["admission"], "open")
        self.assertFalse(status["recovery_pending"])

    def test_process_loss_leaves_fence_and_recovery_restores_exact_predecessor(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301")
        with self.assertRaises(SystemExit):
            self.activate(second, probe=CrashProbe())
        status = self.store.status()
        self.assertEqual(status["admission"], "fenced")
        self.assertTrue(status["recovery_pending"])
        recovered = self.store.recover(now=self.now)
        self.assertEqual(recovered["status"], "restored_predecessor")
        self.assertEqual(self.store.status()["active_generation_id"], first_id)
        self.assertEqual(self.store.status()["admission"], "open")

    def test_recovery_removes_only_exact_interrupted_publication_temporary(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301"); plan = self.plan(second)
        generation = plan["candidate"]["generation_id"]

        def interrupted_publish(*_args, **_kwargs):
            temporary = self.store.releases / f".{generation}.new-{uid4()}"
            temporary.mkdir(mode=0o700)
            STORE.write_new_file(temporary / "harness", b"partial", 0o555)
            raise SystemExit("simulated_sigkill_during_publication")

        with mock.patch.object(self.store, "_publish", side_effect=interrupted_publish):
            with self.assertRaises(SystemExit):
                self.activate(second, plan)
        self.assertTrue(any(item.name.startswith(f".{generation}.new-")
                            for item in self.store.releases.iterdir()))
        recovered = self.store.recover(now=self.now)
        self.assertEqual(recovered["status"], "restored_predecessor")
        self.assertEqual(self.store.status()["active_generation_id"], first_id)
        self.assertFalse(any(item.name.startswith(f".{generation}.new-")
                             for item in self.store.releases.iterdir()))

    def test_recovery_handles_loss_before_workflow_transaction_creation(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301"); plan = self.plan(second)
        with mock.patch.object(
                self.store.workflow, "create",
                side_effect=SystemExit("simulated_sigkill_before_workflow_create")):
            with self.assertRaises(SystemExit):
                self.activate(second, plan)
        recovered = self.store.recover(now=self.now)
        self.assertEqual(recovered["status"], "restored_predecessor")
        self.assertEqual(self.store.status()["active_generation_id"], first_id)
        self.assertEqual(self.store.status()["admission"], "open")

    def test_every_durable_activation_checkpoint_is_fail_closed_and_recoverable(self):
        checkpoints = (
            "journal-prepared", "fenced", "workflow-authorized", "release-published",
            "catalog-written", "floor-written", "selector-written", "health-passed",
            "workflow-activated", "workflow-verified", "workflow-committed",
            "fence-removed", "journal-removed",
        )
        for offset, checkpoint in enumerate(checkpoints, start=10):
            with self.subTest(checkpoint=checkpoint):
                paths = self.candidate(offset, f"2.2.{offset}")

                def interrupt(observed, expected=checkpoint):
                    if observed == expected:
                        raise SystemExit(f"simulated_loss:{expected}")

                self.store.checkpoint = interrupt
                with self.assertRaisesRegex(SystemExit, checkpoint):
                    self.activate(paths)
                self.store.checkpoint = lambda _name: None
                if checkpoint == "journal-removed":
                    status = self.store.status()
                    self.assertFalse(status["recovery_pending"])
                    self.assertEqual(status["admission"], "open")
                else:
                    self.assertEqual(len(list(self.store.journals.iterdir())), 1)
                    recovered = self.store.recover(now=self.now)
                    self.assertIn(recovered["status"], {"restored_predecessor", "committed"})
                    status = self.store.status()
                    self.assertFalse(status["recovery_pending"])
                    self.assertEqual(status["admission"], "open")
                self.assertEqual(self.store.verify_boundary()["status"], "verified")

    def test_synthetic_fixture_report_and_password_fallback_are_rejected(self):
        paths = self.candidate(1, "2.1.300")
        qualification = json.loads(paths["qualification.json"].read_text())
        qualification.update(synthetic=True, authority="none", status="fixture_qualified")
        qualification["qualification_sha256"] = STORE.sha256_value(
            {key: value for key, value in qualification.items() if key != "qualification_sha256"}
        )
        self.write_json(paths["qualification.json"], qualification)
        with self.assertRaisesRegex(STORE.GenerationStoreError, "not_admissible"):
            self.plan(paths)
        paths = self.candidate(2, "2.1.301"); plan = self.plan(paths)
        authorization = self.authorization(plan); authorization["password_fallback"] = True
        authorization["authorization_sha256"] = STORE.sha256_value(
            {key: value for key, value in authorization.items() if key != "authorization_sha256"}
        )
        with self.assertRaisesRegex(STORE.GenerationStoreError, "authorization_binding"):
            self.store.activate(
                plan, authorization, paths["manifest.json"], paths["artifact"],
                paths["verification.json"], paths["qualification.json"], paths["adapter.json"],
                PassingProbe(), runtime_idle=lambda: True, now=self.now,
            )

    def test_plan_rejects_source_state_and_authorization_changes(self):
        paths = self.candidate(1, "2.1.300"); plan = self.plan(paths)
        paths["artifact"].write_bytes(b"substituted"); paths["artifact"].chmod(0o600)
        with self.assertRaises(STORE.GenerationStoreError):
            self.activate(paths, plan)
        paths = self.candidate(2, "2.1.301"); plan = self.plan(paths)
        self.store.prepare()
        selector = json.loads(self.store.selector_path.read_text())
        selector["epoch"] += 1
        STORE.atomic_write(self.store.selector_path, STORE.canonical_bytes(selector))
        with self.assertRaisesRegex(STORE.GenerationStoreError, "state_changed"):
            self.activate(paths, plan)

    def test_active_runtime_tampered_release_and_catalog_fail_closed(self):
        paths = self.candidate(1, "2.1.300"); plan = self.plan(paths)
        def not_idle():
            self.assertTrue(self.store.fence_path.is_file())
            return False
        with self.assertRaisesRegex(STORE.GenerationStoreError, "runtime_not_idle"):
            self.store.activate(
                plan, self.authorization(plan), paths["manifest.json"], paths["artifact"],
                paths["verification.json"], paths["qualification.json"], paths["adapter.json"],
                PassingProbe(), runtime_idle=not_idle, now=self.now,
            )
        self.assertFalse(self.store.fence_path.exists())
        self.activate(paths)
        generation = self.store.status()["active_generation_id"]
        harness = self.release_root / "releases" / generation / "harness"
        harness.chmod(0o755)
        with self.assertRaisesRegex(STORE.GenerationStoreError, "file_untrusted"):
            self.store.status()

    def test_retirement_requires_zero_references_and_never_deletes_release(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301"); self.activate(second)
        third = self.candidate(3, "2.1.302"); self.activate(third)
        referenced = self.reference(first_id, resumable=1)
        with self.assertRaisesRegex(STORE.GenerationStoreError, "still_referenced"):
            self.store.create_management_plan("retire", first_id, "e" * 64,
                                              referenced, now=self.now)
        reference = self.reference(first_id)
        plan = self.store.create_management_plan("retire", first_id, "e" * 64,
                                                 reference, now=self.now)
        receipt = self.store.apply_management_plan(
            plan, self.authorization(plan), reference, runtime_idle=lambda: True, now=self.now,
        )
        self.assertEqual(receipt["status"], "committed")
        record = next(item for item in self.store.status()["generations"]
                      if item["generation_id"] == first_id)
        self.assertEqual(record["status"], "retired")
        self.assertTrue((self.release_root / "releases" / first_id / "harness").is_file())

    def test_revocation_is_monotonic_and_active_revocation_closes_selector(self):
        paths = self.candidate(1, "2.1.300"); self.activate(paths)
        generation = self.store.status()["active_generation_id"]
        reference = self.reference(generation, active=1, resumable=1)
        plan = self.store.create_management_plan("revoke", generation, "f" * 64,
                                                 reference, now=self.now)
        self.store.apply_management_plan(
            plan, self.authorization(plan), reference, runtime_idle=lambda: True, now=self.now,
        )
        status = self.store.status()
        self.assertIsNone(status["active_generation_id"])
        self.assertIn(generation, status["revoked_generation_ids"])
        with self.assertRaisesRegex(STORE.GenerationStoreError, "revoked"):
            self.plan(paths)

    def test_management_process_loss_is_recoverable_and_stays_fenced(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        first_id = self.store.status()["active_generation_id"]
        second = self.candidate(2, "2.1.301"); self.activate(second)
        third = self.candidate(3, "2.1.302"); self.activate(third)
        reference = self.reference(first_id)
        plan = self.store.create_management_plan("retire", first_id, "e" * 64,
                                                 reference, now=self.now)
        original = self.store.workflow.advance

        def crash(transaction_id, target_phase, *args, **kwargs):
            if target_phase == "activated":
                raise SystemExit("simulated_process_loss")
            return original(transaction_id, target_phase, *args, **kwargs)

        with mock.patch.object(self.store.workflow, "advance", side_effect=crash):
            with self.assertRaises(SystemExit):
                self.store.apply_management_plan(
                    plan, self.authorization(plan), reference,
                    runtime_idle=lambda: True, now=self.now,
                )
        self.assertEqual(self.store.status()["admission"], "fenced")
        recovered = self.store.recover(now=self.now)
        self.assertEqual(recovered["status"], "restored_predecessor")
        record = next(item for item in self.store.status()["generations"]
                      if item["generation_id"] == first_id)
        self.assertEqual(record["status"], "retained")

    def test_existing_release_bytes_must_equal_plan_sources(self):
        paths = self.candidate(1, "2.1.300"); plan = self.plan(paths)
        sources = self.store._require_plan_sources(
            plan, paths["manifest.json"], paths["artifact"], paths["verification.json"],
            paths["qualification.json"], paths["adapter.json"], self.now,
        )
        wrong = (b"x" * len(sources[0]), *sources[1:])
        self.store.prepare()
        self.store._publish(plan, *wrong, self.now)
        with self.assertRaisesRegex(STORE.GenerationStoreError, "published_source_mismatch"):
            self.activate(paths, plan)

    def test_postactivation_failure_never_rewinds_irreversible_workflow(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        second = self.candidate(2, "2.1.301"); plan = self.plan(second)
        second_id = plan["candidate"]["generation_id"]
        original = self.store.workflow.advance

        def fail_after_activation(transaction_id, target_phase, *args, **kwargs):
            if target_phase == "verified":
                raise RuntimeError("postactivation_failure")
            return original(transaction_id, target_phase, *args, **kwargs)

        with mock.patch.object(self.store.workflow, "advance", side_effect=fail_after_activation):
            with self.assertRaisesRegex(RuntimeError, "postactivation_failure"):
                self.activate(second, plan)
        status = self.store.status()
        self.assertEqual(status["active_generation_id"], second_id)
        self.assertEqual(status["admission"], "fenced")
        self.assertTrue(status["recovery_pending"])
        recovered = self.store.recover(now=self.now)
        self.assertEqual(recovered["status"], "committed")
        self.assertEqual(self.store.status()["active_generation_id"], second_id)

    def test_retained_generation_requires_explicit_rollback_operation(self):
        first = self.candidate(1, "2.1.300"); self.activate(first)
        second = self.candidate(2, "2.1.301"); self.activate(second)
        with self.assertRaisesRegex(STORE.GenerationStoreError, "requires_rollback"):
            self.plan(first, "activate")


if __name__ == "__main__":
    unittest.main()
