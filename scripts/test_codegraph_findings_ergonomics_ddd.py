#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class CodeGraphFindingsErgonomicsDDDTests(unittest.TestCase):
    def text(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_deployment_is_idle_gated_tested_live_verified_and_boundary_closed(self):
        deploy = self.text("scripts/deploy-codegraph-findings-ergonomics.sh")
        ordered = [
            "run lifecycle-idle", "python3 -m unittest", "deploy-codegraph-adapter.sh",
            "deploy-findings-adjudication.sh", "verify-codegraph-findings-live.sh",
            "verify-boundaries.sh",
        ]
        positions = [deploy.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('[[ "$#" -eq 6 ]]', deploy)

    def test_live_verifier_runs_real_analysis_then_resolves_pointer(self):
        verifier = self.text("scripts/verify-codegraph-findings-ergonomics-live.py")
        self.assertIn("analyze_reachability(", verifier)
        self.assertIn('result.get("finding_evidence_pointer")', verifier)
        self.assertIn('(\"class\", \"source_id\", \"analysis_id\")', verifier)
        self.assertIn("analysis_projection_mismatch_codegraph_index_sha256", verifier)
        self.assertIn("analysis_projection_fields_mismatch", verifier)

    def test_guest_verifier_refuses_active_lifecycle_and_uses_root_control_path(self):
        installer = self.text("scripts/install-codegraph-findings-live-verifier.sh")
        self.assertIn("agent_lifecycle_not_idle", installer)
        self.assertIn("pgrep -x claude", installer)
        self.assertIn("PYTHONPATH=/usr/local/libexec/secure-sandbox", installer)
        self.assertNotIn("runuser -u agent", installer)

    def test_design_documents_exact_shapes_and_presentation_only_grouping(self):
        design = self.text("docs/CODEGRAPH_FINDINGS_ERGONOMICS_DESIGN.md")
        self.assertIn("preferred pointer: `class`, `source_id`, `analysis_id`", design)
        self.assertIn("analysis_projection_mismatch_<field>", design)
        self.assertIn("presentation-only", design)
        self.assertIn("never accepted as protocol", design)


if __name__ == "__main__":
    unittest.main()
