#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class PrivilegedWorkflowDDDTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_design_and_reviewed_deployment_exist(self):
        design = self.text("docs/PRIVILEGED_WORKFLOW_TRANSACTION_ENGINE_DESIGN.md")
        for phrase in ("Append-only event chain", "Lost-response recovery", "Authorization boundary",
                       "Irreversible activation", "Mixed-state rejection", "Expiry and rollback"):
            self.assertIn(phrase, design)
        deploy = self.text("scripts/deploy-privileged-workflow-transaction-engine-ddd.sh")
        self.assertIn("install-privileged-workflow-engine.sh", deploy)
        self.assertIn("verify-boundaries.sh", deploy)

    def test_live_verifier_passes_for_every_role(self):
        verifier = ROOT / "scripts/privileged_workflow_live_verifier.py"
        for role in ("gateway", "research", "target"):
            with tempfile.TemporaryDirectory() as temporary:
                environment = os.environ.copy()
                environment["PYTHONPATH"] = str(ROOT)
                completed = subprocess.run(
                    ["python3", str(verifier), role, "--state-parent", temporary],
                    env=environment, text=True, capture_output=True, timeout=10, check=True,
                )
            self.assertIn('"status":"verified"', completed.stdout)
            self.assertEqual(completed.stderr, "")

    def test_engine_is_part_of_policy_and_boundary_measurements(self):
        for relative in ("scripts/update-policy-hash.sh", "scripts/verify-boundaries.sh"):
            self.assertIn("privileged_workflow.py", self.text(relative))


if __name__ == "__main__":
    unittest.main()
