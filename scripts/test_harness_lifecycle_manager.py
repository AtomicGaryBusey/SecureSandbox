#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_manager", ROOT / "scripts/harness_lifecycle_manager.py"
)
assert SPEC and SPEC.loader
MANAGER = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MANAGER)


def signed(value: dict, field: str) -> dict:
    value[field] = hashlib.sha256(MANAGER.canonical(value)).hexdigest()
    return value


class HarnessLifecycleHostManagerTests(unittest.TestCase):
    def plan_wrapper(self, operation: str = "activate") -> dict:
        plan = {
            "schema": (MANAGER.ACTIVATION_PLAN_SCHEMA if operation in {"activate", "rollback"}
                       else MANAGER.MANAGEMENT_PLAN_SCHEMA),
            "plan_id":"11111111-1111-4111-8111-111111111111",
            "transaction_id":"22222222-2222-4222-8222-222222222222",
            "operation":operation, "created_at":2_000_000_000, "expires_at":2_000_000_300,
        }
        if operation in {"activate", "rollback"}:
            plan["candidate"] = {"generation_id":"a" * 64}
            reference = None
        else:
            plan["generation_id"] = "a" * 64
            reference = {"schema":"secure-sandbox-harness-session-reference-readback-v1"}
        signed(plan, "plan_sha256")
        wrapper = {"schema":MANAGER.PLAN_WRAPPER_SCHEMA,
                   "stage_id":"33333333-3333-4333-8333-333333333333",
                   "plan":plan, "reference":reference}
        return signed(wrapper, "wrapper_sha256")

    def authorization(self, plan: dict) -> dict:
        value = {"schema":MANAGER.AUTHORIZATION_SCHEMA,
                 "authorization_id":"44444444-4444-4444-8444-444444444444",
                 "plan_id":plan["plan_id"], "plan_sha256":plan["plan_sha256"],
                 "transaction_id":plan["transaction_id"], "operation":plan["operation"],
                 "method":"touch-id", "password_fallback":False,
                 "authorized_at":2_000_000_001, "expires_at":2_000_000_121,
                 "requesting_agent_sha256":"c" * 64, "requesting_session_sha256":"d" * 64}
        return signed(value, "authorization_sha256")

    def test_apply_forwards_exact_plan_then_independently_reads_status_and_boundary(self):
        wrapper = self.plan_wrapper(); calls = []
        outputs = [
            {"schema":"receipt", "status":"committed"},
            {"schema":"status", "admission":"open"},
            {"schema":"boundary", "status":"verified"},
        ]
        def runner(command, **kwargs):
            calls.append((command, kwargs.get("input")))
            value = outputs.pop(0)
            return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")
        manager = MANAGER.HarnessLifecycleManager(Path("/protected/release"), runner)
        result = manager.apply("activate", wrapper, self.authorization(wrapper["plan"]), 501)
        self.assertEqual(result["boundary"]["status"], "verified")
        forwarded = json.loads(calls[0][1])
        self.assertEqual(forwarded["plan"], wrapper["plan"])
        self.assertEqual(forwarded["authorization"]["method"], "touch-id")
        self.assertEqual(calls[1][0][-1], "harness-generation-status")
        self.assertEqual(calls[2][0][-1], "harness-generation-verify-boundary")

    def test_management_counts_only_exact_generation_and_rejects_untrusted_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "session-runs.json"
            def record(generation):
                return {"last_started_at":1, "runs":1, "run_ids":[],
                        "adapter":"anthropic-messages-v1", "model":"model",
                        "model_profile_id":"profile", "model_profile_sha256":"1" * 64,
                        "vendor_id":"vendor", "harness_id":"claude-code",
                        "harness_generation_id":generation, "harness_manifest_sha256":"2" * 64,
                        "harness_executable_sha256":"3" * 64, "harness_inventory_sha256":"4" * 64,
                        "harness_adapter_id":"claude-core-v1", "harness_adapter_sha256":"5" * 64,
                        "harness_binding_sha256":"6" * 64}
            path.write_text(json.dumps({"schema":MANAGER.CATALOG_SCHEMA, "sessions":{
                "11111111-1111-4111-8111-111111111111":record("a" * 64),
                "22222222-2222-4222-8222-222222222222":record("b" * 64),
            }}))
            path.chmod(0o600)
            self.assertEqual(MANAGER.resumable_count("a" * 64, os.getuid(), path), 1)
            path.chmod(0o644)
            with self.assertRaisesRegex(MANAGER.ManagerError, "session_catalog_untrusted"):
                MANAGER.resumable_count("a" * 64, os.getuid(), path)

    def test_plan_or_authorization_mutation_is_rejected_before_transport(self):
        wrapper = self.plan_wrapper(); authorization = self.authorization(wrapper["plan"])
        wrapper["plan"]["expires_at"] += 1
        manager = MANAGER.HarnessLifecycleManager(Path("/protected/release"),
                                                  lambda *_args, **_kwargs: self.fail("transport"))
        with self.assertRaisesRegex(MANAGER.ManagerError, "wrapper_digest_invalid"):
            manager.apply("activate", wrapper, authorization, 501)

    def test_recovery_rereads_exact_journal_before_mutation(self):
        recovery = {"schema":MANAGER.RECOVERY_SCHEMA, "pending":True,
                    "journal_sha256":"a" * 64}
        def runner(command, **_kwargs):
            changed = dict(recovery, journal_sha256="b" * 64)
            return subprocess.CompletedProcess(command, 0, json.dumps(changed).encode(), b"")
        manager = MANAGER.HarnessLifecycleManager(Path("/protected/release"), runner)
        with self.assertRaisesRegex(MANAGER.ManagerError, "recovery_state_changed"):
            manager.recover(recovery)


if __name__ == "__main__":
    unittest.main()
