#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class HarnessBoundSessionsDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = (ROOT / "scripts/claude-run-controller.sh").read_text()
        cls.gateway = (ROOT / "gateway/run_lease.py").read_text()
        cls.watchdog = (ROOT / "research/run_lease_watchdog.py").read_text()
        cls.supervisor = (ROOT / "research/run_lease_process.py").read_text()
        cls.migration = (ROOT / "scripts/harness-session-migration.py").read_text()
        cls.launcher = (ROOT / "research/research-claude.proposed").read_text()

    def test_controller_binds_new_and_resumed_sessions_to_exact_generation(self):
        self.assertIn("harness-active-runtime", self.controller)
        self.assertIn("harness-generation-runtime", self.controller)
        self.assertIn("session_harness_generation", self.controller)
        self.assertIn("secure-sandbox-session-runs-v4", self.controller)
        self.assertIn("session_harness_legacy_unbound", self.controller)

    def test_gateway_research_and_process_schemas_carry_binding(self):
        self.assertIn("secure-sandbox-run-lease-v2", self.gateway)
        self.assertIn("secure-sandbox-research-run-lease-v2", self.watchdog)
        self.assertIn("secure-sandbox-run-process-v2", self.supervisor)
        for source in (self.gateway, self.watchdog):
            self.assertIn("harness_binding_sha256", source)
        self.assertIn("from_container(seed) != from_container(lease)", self.supervisor)

    def test_agent_cannot_choose_the_executable(self):
        self.assertNotIn("/usr/local/bin/claude", self.launcher)
        self.assertNotIn("/usr/local/bin/claude", self.supervisor)
        self.assertIn("executable_for_binding", self.supervisor)
        self.assertIn("HARNESS_RELEASE_ROOT", self.supervisor)

    def test_legacy_migration_is_explicit_touchid_only_and_noninferential(self):
        self.assertIn('value["method"] != "touch-id"', self.migration)
        self.assertIn('value["password_fallback"] is not False', self.migration)
        self.assertIn("legacy_executable_binding_mismatch", self.migration)
        self.assertNotIn("active_generation_id", self.migration)
        self.assertNotIn("predecessor_generation_id", self.migration)
        self.assertNotIn('sub.add_parser("apply")', self.migration)

    def test_deployment_requires_a_verified_active_runtime_first(self):
        deploy = (ROOT / "scripts/deploy-run-leases.sh").read_text()
        self.assertIn("run harness-active-runtime >/dev/null", deploy)
        self.assertIn("shared/harness_runtime_binding.py", deploy)


if __name__ == "__main__":
    unittest.main()
