#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProtectedHarnessLifecycleAuthorizationConsumerDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = (ROOT / "docs/PROTECTED_HARNESS_LIFECYCLE_AUTHORIZATION_CONSUMER_DESIGN.md").read_text()
        cls.evidence = (ROOT / "docs/PROTECTED_HARNESS_LIFECYCLE_AUTHORIZATION_CONSUMER_ACCEPTANCE_EVIDENCE.md").read_text()
        cls.research = (ROOT / "research/harness_generation_manager.py").read_text()
        cls.host = (ROOT / "scripts/harness_lifecycle_manager.py").read_text()
        cls.broker = (ROOT / "scripts/operator-authorization.py").read_text()
        cls.control = (ROOT / "scripts/privileged_control.py").read_text()
        cls.installer = (ROOT / "scripts/install-harness-lifecycle-consumer.sh").read_text()
        cls.rollback = (ROOT / "research/rollback-harness-lifecycle-consumer.sh").read_text()

    def test_candidate_transport_and_mutation_surface_are_fixed(self):
        self.assertIn('SAFE_FILES = ("artifact", "manifest.json", "verification.json", "qualification.json", "adapter.json")', self.research)
        for operation in ("stage-activate", "prepare-rollback", "plan-management",
                          "apply", "recovery-status", "recover"):
            self.assertIn(operation, self.control)
        pipe_surface = self.control[
            self.control.index("PIPE_OPERATIONS"):
            self.control.index("STREAM_OPERATIONS")
        ]
        self.assertNotIn("selector", pipe_surface)

    def test_touchid_has_no_password_or_caller_receipt_fallback(self):
        for operation in ("activate", "rollback", "retire", "revoke", "recover"):
            self.assertIn(f'"harness-generation-{operation}"', self.broker)
        self.assertIn('"method":"touch-id", "password_fallback":False', self.broker)
        self.assertIn('authorization_method != "touch-id"', self.broker)
        self.assertIn("harness_authorization_missing", self.broker)

    def test_independent_reference_and_boundary_readback_remain_required(self):
        self.assertIn("resumable_count(plan[\"generation_id\"]", self.host)
        self.assertIn('"harness-generation-verify-boundary"', self.host)
        self.assertIn("management_reference_changed", self.research)
        self.assertIn("recovery_state_changed", self.host)

    def test_deployment_is_run_idle_and_rollback_preserves_published_data(self):
        for marker in ("run-id", "evidence-run-id", "active.json", "failure-latched.json"):
            self.assertIn(marker, self.installer)
            self.assertIn(marker, self.rollback)
        self.assertIn("Refusing to remove lifecycle consumer with a published generation", self.rollback)
        self.assertNotIn("secure-sandbox-harnesses/releases", self.rollback)

    def test_fresh_install_initializes_store_before_read_only_inspection(self):
        manager_call = (
            '/usr/local/libexec/secure-sandbox/harness-generation-manager.py '
            'initialize-empty-store'
        )
        inspector_call = (
            '/usr/local/libexec/secure-sandbox/harness-generation.py status'
        )
        recovery_call = (
            '/usr/local/libexec/secure-sandbox/harness-generation-manager.py '
            'recovery-status'
        )
        self.assertIn(manager_call, self.installer)
        self.assertIn(inspector_call, self.installer)
        self.assertIn(recovery_call, self.installer)
        self.assertLess(self.installer.index(manager_call),
                        self.installer.index(inspector_call))
        self.assertLess(self.installer.index(inspector_call),
                        self.installer.index(recovery_call))
        self.assertIn('"pending":False', self.installer)
        self.assertIn('prior_count == 0 || prior_count == ${#destinations[@]}',
                      self.installer)
        self.assertNotIn('"initialize-empty-store"', self.control)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / "secure-sandbox"
            shared = installed / "shared"
            shared.mkdir(parents=True)
            shutil.copy2(ROOT / "research/harness_generation_manager.py",
                         installed / "harness-generation-manager.py")
            shutil.copy2(ROOT / "scripts/harness-generation.py",
                         installed / "harness-generation.py")
            for name in (
                "harness_generation_store.py", "harness_runtime_binding.py",
                "privileged_workflow.py",
            ):
                shutil.copy2(ROOT / "shared" / name, shared / name)
            release = root / "releases-root"
            state = root / "state-root"
            stage = state / "staging"
            release.mkdir(mode=0o755)
            state.mkdir(mode=0o700)
            recovery = subprocess.run(
                [
                    "python3", str(installed / "harness-generation-manager.py"),
                    "--release-root", str(release), "--state-root", str(state),
                    "--stage-root", str(stage), "initialize-empty-store",
                ],
                text=True, capture_output=True, check=True,
            )
            initialized = json.loads(recovery.stdout)
            self.assertEqual(initialized["schema"],
                             "secure-sandbox-harness-consumer-initialization-v1")
            self.assertEqual(initialized["status"], "initialized")
            self.assertEqual(initialized["boundary"]["generation_count"], 0)
            inspection = subprocess.run(
                [
                    "python3", str(installed / "harness-generation.py"),
                    "--release-root", str(release), "--state-root", str(state),
                    "status",
                ],
                text=True, capture_output=True, check=True,
            )
            status = json.loads(inspection.stdout)
            self.assertEqual(status["schema"],
                             "secure-sandbox-harness-generation-status-v1")
            self.assertEqual(status["status"], "verified")
            self.assertEqual(status["generations"], [])
            self.assertEqual(status["boundary"]["generation_count"], 0)

            repeated = subprocess.run(
                [
                    "python3", str(installed / "harness-generation-manager.py"),
                    "--release-root", str(release), "--state-root", str(state),
                    "--stage-root", str(stage), "initialize-empty-store",
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("initial_store_not_empty", repeated.stderr)

    def test_documentation_keeps_live_admission_as_a_separate_gate(self):
        self.assertIn("No vendor generation or", self.evidence)
        self.assertIn("has not deployed the new Host or Research payloads live", self.design)
        self.assertIn("Disposable-Mac\nHarness Lifecycle Acceptance DDD", self.design)


if __name__ == "__main__":
    unittest.main()
