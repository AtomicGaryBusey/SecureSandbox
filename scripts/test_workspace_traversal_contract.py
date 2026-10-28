#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = "/home/agent/research-workspace"
INSTALLERS = (
    "scripts/apply-approved-claude-policy.sh",
    "scripts/install-artifact-collector.sh",
    "scripts/install-codegraph-adapter.sh",
    "scripts/install-corpus-intelligence.sh",
    "scripts/install-dependency-orchestration.sh",
    "scripts/install-disposable-execution-research.sh",
    "scripts/install-source-integrity.sh",
    "scripts/install-source-research.sh",
)


class WorkspaceTraversalContractTests(unittest.TestCase):
    def test_every_workspace_consumer_reasserts_group_traversal(self):
        expected = f"install -d -o agent -g agent -m 750 {WORKSPACE}"
        for relative in INSTALLERS:
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                if relative.endswith("install-disposable-execution-research.sh"):
                    self.assertIn(f"chmod 750 {WORKSPACE}", text)
                else:
                    self.assertIn(expected, text)

    def test_no_installer_restricts_workspace_root_to_owner_only(self):
        unsafe = re.compile(
            r"(?:install -d -o agent -g agent -m|chmod) 700 "
            + re.escape(WORKSPACE) + r"(?:\s|$)",
        )
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")):
            if unsafe.search(path.read_text(encoding="utf-8")):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_live_boundary_checks_real_broker_identities(self):
        verifier = (ROOT / "scripts/verify-boundaries.sh").read_text(encoding="utf-8")
        self.assertIn(WORKSPACE, verifier)
        self.assertIn("agent:agent:750", verifier)
        for identity in ("corpus-broker", "execution-broker", "findings-broker"):
            self.assertIn(
                f"sudo -u {identity} test -r {WORKSPACE}/repos/INDEX.json",
                verifier,
            )


if __name__ == "__main__":
    unittest.main()
