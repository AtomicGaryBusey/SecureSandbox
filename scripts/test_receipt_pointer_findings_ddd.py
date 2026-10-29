#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ReceiptPointerFindingsDDDTests(unittest.TestCase):
    def text(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_deployment_is_idle_gated_tested_live_verified_and_boundary_closed(self):
        deploy = self.text("scripts/deploy-receipt-pointer-findings-ddd.sh")
        ordered = [
            "run lifecycle-idle", "python3 -m unittest", "deploy-evidence-receipts.sh",
            "install-receipt-pointer-findings-live-verifier.sh", "verify-boundaries.sh",
        ]
        positions = [deploy.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_live_verifier_uses_uuid_pointer_and_fixed_field_diagnostic(self):
        verifier = self.text("scripts/verify-receipt-pointer-findings-live.py")
        self.assertIn('(\"class\", \"source_id\", \"receipt_id\")', verifier)
        self.assertIn("load_projection_by_id", verifier)
        self.assertIn("receipt_projection_mismatch_receipt_sha256", verifier)
        self.assertNotIn('projection["receipt_id"]}', verifier)

    def test_guest_wrapper_refuses_active_agent_lifecycle(self):
        wrapper = self.text("scripts/install-receipt-pointer-findings-live-verifier.sh")
        self.assertIn("agent_lifecycle_not_idle", wrapper)
        self.assertIn("pgrep -x claude", wrapper)
        self.assertIn("PYTHONPATH=/usr/local/libexec/secure-sandbox", wrapper)


if __name__ == "__main__":
    unittest.main()
