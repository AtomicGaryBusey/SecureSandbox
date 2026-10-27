#!/usr/bin/env python3

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class TransactionalPublisherCrashRecoveryTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_design_inventory_and_live_ddd_are_present(self):
        design = self.text("docs/TRANSACTIONAL_PUBLISHER_CRASH_RECOVERY_DESIGN.md")
        for boundary in ("Source acquisition", "Dependency orchestration", "CodeGraph indexing",
                         "Evidence and finding receipts", "Gateway telemetry", "Guest policy deployment"):
            self.assertIn(boundary, design)
        deploy = self.text("scripts/deploy-transactional-publisher-crash-recovery-ddd.sh")
        self.assertIn("deploy-run-leases.sh", deploy)
        self.assertIn("transactional_publisher_live_verifier.py", deploy)
        self.assertIn("verify-boundaries.sh", deploy)

    def test_content_free_live_verifier_passes_both_roles(self):
        environment = os.environ.copy()
        environment.update({
            "PYTHONPATH": f"{ROOT / 'gateway'}:{ROOT / 'research'}:{ROOT}",
            "SECURE_SANDBOX_MODULE_ROOT": "/nonexistent",
            "SECURE_SANDBOX_LIVE_TMP_ROOT": "/tmp",
        })
        script = ROOT / "scripts/transactional_publisher_live_verifier.py"
        for role in ("gateway", "research"):
            completed = subprocess.run(
                ["python3", str(script), role], env=environment,
                text=True, capture_output=True, check=True, timeout=10,
            )
            self.assertEqual(
                completed.stdout.strip(),
                f'{{"role":"{role}","schema":"secure-sandbox-transactional-publisher-live-verification-v1","status":"verified"}}',
            )
            self.assertEqual(completed.stderr, "")

    def test_affected_runtime_files_share_transactional_deployment(self):
        deploy = self.text("scripts/deploy-run-leases.sh")
        gateway_install = self.text("scripts/install-run-leases-gateway.sh")
        gateway_rollback = self.text("gateway/rollback-run-leases-gateway.sh")
        research_install = self.text("scripts/install-run-leases-research.sh")
        research_rollback = self.text("research/rollback-run-leases-research.sh")
        for name in ("telemetry_receiver.py", "update_client_fingerprints.py"):
            self.assertIn(name, deploy)
            self.assertIn(name, gateway_install)
            self.assertIn(name, gateway_rollback)
        for name in ("conversation_shipper.py", "source_importer.py", "codegraph_indexer.py"):
            self.assertIn(name, deploy)
            self.assertIn(name, research_install)
            self.assertIn(name, research_rollback)


if __name__ == "__main__":
    unittest.main()
