#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(ROOT / "shared"))

import harness_generation_manager as MANAGER
import harness_generation_store as STORE
import harness_lifecycle as LIFECYCLE


def uuid4() -> str:
    return str(uuid.uuid4())


class PassingProbe:
    def probe(self, plan, _executable):
        value = {
            "schema": STORE.HEALTH_SCHEMA, "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "generation_id": plan["candidate"]["generation_id"],
            "artifact_sha256": plan["candidate"]["artifact_sha256"],
            "adapter_sha256": plan["candidate"]["adapter_sha256"],
            "health_probe_sha256": plan["candidate"]["health_probe_sha256"],
            "observer": "secure-sandbox-fixed-health-supervisor-v1", "synthetic": True,
            "production_credential_present": False, "network_attempts": [], "status": "passed",
        }
        value["health_sha256"] = STORE.sha256_value(value)
        return value


class HarnessGenerationManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = 2_000_000_000
        lifecycle = self.root / "lifecycle"
        lifecycle.mkdir(mode=0o700)
        run = self.root / "run"
        run.mkdir(mode=0o700)
        self.active = lifecycle / "active.json"
        self.failure = lifecycle / "failure-latched.json"
        self.markers = (run / "run-id", run / "evidence-run-id")
        self.manager = MANAGER.HarnessGenerationConsumer(
            self.root / "release", self.root / "state", self.root / "staging",
            active_run=self.active, failure_latch=self.failure, run_markers=self.markers,
            now=lambda: self.now, health_probe=PassingProbe(),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def candidate(self, sequence: int, version: str) -> tuple[dict, dict[str, bytes]]:
        artifact = f"#!/bin/sh\necho harness-{version}\n".encode("ascii")
        artifact_sha = hashlib.sha256(artifact).hexdigest()
        adapter_sha = hashlib.sha256(f"adapter-{version}".encode()).hexdigest()
        policy_sha = hashlib.sha256(b"policy-v1").hexdigest()
        evidence_sha = hashlib.sha256(f"evidence-{version}".encode()).hexdigest()
        manifest = {
            "schema": LIFECYCLE.MANIFEST_SCHEMA, "adapter_id": "claude-core-v1",
            "harness_id": "claude-code", "vendor_id": "anthropic", "version": version,
            "platform": "linux-arm64", "release_sequence": sequence,
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
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        verification = {
            "action": "verify", "observed_at": self.now - 30, "receipt_id": uuid4(),
            "schema": LIFECYCLE.RECEIPT_SCHEMA,
            "status": "artifact_and_evidence_bindings_verified", "artifact_sha256": artifact_sha,
            "envelope_sha256": "e" * 64, "evidence_sha256": [evidence_sha],
            "generation_id": manifest["generation_id"], "manifest_sha256": manifest_sha,
            "note": "not_admitted_not_executable", "policy_sha256": policy_sha,
        }
        adapter = {
            "schema": STORE.ADAPTER_SCHEMA, "adapter_id": "claude-core-v1",
            "adapter_sha256": adapter_sha, "harness_id": "claude-code",
            "executable_name": "harness", "protocol": "secure-sandbox-neutral-harness-v1",
            "policy_sha256": policy_sha, "authority": "none", "health_probe_sha256": "9" * 64,
        }
        adapter["projection_sha256"] = STORE.sha256_value(adapter)
        qualification = {
            "schema": STORE.QUALIFICATION_SCHEMA, "qualification_id": uuid4(),
            "generation_id": manifest["generation_id"], "artifact_sha256": artifact_sha,
            "manifest_sha256": manifest_sha, "adapter_id": "claude-core-v1",
            "adapter_sha256": adapter_sha, "suite_sha256": "a" * 64,
            "policy_sha256": policy_sha, "observer": "secure-sandbox-disposable-supervisor-v1",
            "observation_set_sha256": "b" * 64, "qualified_at": self.now - 20,
            "expires_at": self.now + 86400, "synthetic": False, "status": "qualified",
            "authority": "qualification-evidence-only",
        }
        qualification["qualification_sha256"] = STORE.sha256_value(qualification)
        files = {
            "artifact": artifact, "manifest.json": manifest_raw,
            "verification.json": STORE.canonical_bytes(verification),
            "qualification.json": STORE.canonical_bytes(qualification),
            "adapter.json": STORE.canonical_bytes(adapter),
        }
        return manifest, files

    def framed(self, manifest: dict, files: dict[str, bytes], stage_id: str | None = None) -> io.BytesIO:
        header = {
            "schema": MANAGER.SCHEMA, "stage_id": stage_id or uuid4(),
            "generation_id": manifest["generation_id"],
            "files": [{"name": name, "sha256": hashlib.sha256(files[name]).hexdigest(),
                       "size": len(files[name])} for name in MANAGER.SAFE_FILES],
        }
        encoded = MANAGER.canonical(header)
        return io.BytesIO(struct.pack(">I", len(encoded)) + encoded
                          + b"".join(files[name] for name in MANAGER.SAFE_FILES))

    def authorization(self, plan: dict) -> dict:
        value = {
            "schema": STORE.AUTHORIZATION_SCHEMA, "authorization_id": uuid4(),
            "plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"], "operation": plan["operation"],
            "method": "touch-id", "password_fallback": False, "authorized_at": self.now,
            "expires_at": self.now + 120, "requesting_agent_sha256": "c" * 64,
            "requesting_session_sha256": "d" * 64,
        }
        value["authorization_sha256"] = STORE.sha256_value(value)
        return value

    def activate(self, sequence: int = 1, version: str = "2.1.300") -> dict:
        manifest, files = self.candidate(sequence, version)
        wrapper = self.manager.stage_activate(self.framed(manifest, files))
        plan = wrapper["plan"]
        return self.manager.apply({
            "schema": MANAGER.APPLY_SCHEMA, "stage_id": wrapper["stage_id"], "plan": plan,
            "authorization": self.authorization(plan), "resumable_session_count": 0,
        })

    def test_stage_and_apply_bind_exact_reviewed_plan(self):
        receipt = self.activate()
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(self.manager.store.status()["admission"], "open")

    def test_stage_rejects_trailing_data_and_removes_only_its_new_stage(self):
        manifest, files = self.candidate(1, "2.1.300")
        stage_id = uuid4()
        stream = self.framed(manifest, files, stage_id)
        stream.seek(0, io.SEEK_END); stream.write(b"x"); stream.seek(0)
        with self.assertRaisesRegex(MANAGER.ConsumerError, "trailing_data"):
            self.manager.stage_activate(stream)
        self.assertFalse((self.root / "staging" / stage_id).exists())

        collision = uuid4()
        protected = self.root / "staging" / collision
        protected.mkdir(mode=0o700); (protected / "sentinel").write_text("keep")
        with self.assertRaises(FileExistsError):
            self.manager.stage_activate(self.framed(manifest, files, collision))
        self.assertEqual((protected / "sentinel").read_text(), "keep")

    def test_apply_rejects_plan_mutation_and_active_runtime(self):
        manifest, files = self.candidate(1, "2.1.300")
        wrapper = self.manager.stage_activate(self.framed(manifest, files))
        changed = dict(wrapper["plan"]); changed["expires_at"] += 1
        with self.assertRaisesRegex(MANAGER.ConsumerError, "apply_plan_changed"):
            self.manager.apply({"schema": MANAGER.APPLY_SCHEMA, "stage_id": wrapper["stage_id"],
                                "plan": changed, "authorization": {},
                                "resumable_session_count": 0})
        self.markers[0].write_text("active")
        plan = wrapper["plan"]
        with self.assertRaisesRegex(STORE.GenerationStoreError, "runtime_not_idle"):
            self.manager.apply({"schema": MANAGER.APPLY_SCHEMA, "stage_id": wrapper["stage_id"],
                                "plan": plan, "authorization": self.authorization(plan),
                                "resumable_session_count": 0})

    def test_management_rechecks_host_count_and_research_active_run(self):
        self.activate()
        generation = self.manager.store.status()["active_generation_id"]
        self.activate(2, "2.1.301")
        self.activate(3, "2.1.302")
        wrapper = self.manager.plan_management("retire", generation, "f" * 64, 0)
        plan = wrapper["plan"]
        request = {"schema": MANAGER.APPLY_SCHEMA, "stage_id": wrapper["stage_id"],
                   "plan": plan, "authorization": self.authorization(plan),
                   "resumable_session_count": 1}
        with self.assertRaisesRegex(MANAGER.ConsumerError, "management_reference_changed"):
            self.manager.apply(request)

        self.active.write_text(json.dumps({"schema": MANAGER.RUN_LIFECYCLE_SCHEMA,
                                           "harness_generation_id": generation}))
        self.active.chmod(0o644)
        request["resumable_session_count"] = 0
        with self.assertRaisesRegex(MANAGER.ConsumerError, "management_reference_changed"):
            self.manager.apply(request)

    def test_active_run_state_requires_known_schema_and_generation_binding(self):
        self.active.write_text('{}'); self.active.chmod(0o644)
        with self.assertRaisesRegex(MANAGER.ConsumerError, "active_run_state_invalid"):
            self.manager.active_run_count("a" * 64)


if __name__ == "__main__":
    unittest.main()
