#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ParallelsLifecycleResilienceDDDTests(unittest.TestCase):
    def text(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_design_records_readback_and_operator_safety_contract(self):
        design = self.text("docs/PARALLELS_LIFECYCLE_RESILIENCE_DESIGN.md")
        for required in (
            "independent `prlctl`", "lost_response",
            "Parallels Desktop GUI", "all three observed VM states",
            "complete live",
        ):
            self.assertIn(required, design)

    def test_labctl_routes_start_stop_and_status_to_one_controller(self):
        labctl = self.text("scripts/labctl")
        invocation = 'exec /usr/bin/python3 "$root_dir/scripts/parallels-lifecycle.py"'
        self.assertEqual(labctl.count(invocation), 3)
        self.assertNotIn('"$prlctl" start SecureSandbox-Gateway', labctl)

    def test_live_ddd_requires_closed_gui_and_exact_readbacks(self):
        deploy = self.text("scripts/deploy-parallels-lifecycle-resilience-ddd.sh")
        self.assertIn("pgrep -x prl_client_app", deploy)
        self.assertIn("scripts/labctl status", deploy)
        self.assertEqual(deploy.count("scripts/labctl stop"), 2)
        self.assertEqual(deploy.count("scripts/labctl start"), 2)
        self.assertIn('all(.action_outcomes[]; .result == \\"already_satisfied\\")', deploy)
        self.assertIn("scripts/verify-boundaries.sh", deploy)
        self.assertIn("performing read-only state recovery", deploy)
        self.assertNotIn("--kill", deploy)

    def test_lifecycle_controller_has_bounded_commands_and_nonblocking_lock(self):
        controller = self.text("scripts/parallels-lifecycle.py")
        self.assertIn("timeout=", controller)
        self.assertIn("MAX_OUTPUT = 64 * 1024", controller)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", controller)
        self.assertIn("O_NOFOLLOW", controller)
        self.assertIn("RUNTIME_DIR = Path(tempfile.gettempdir())", controller)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", controller)
        self.assertIn('"--timeout-seconds", str(CONTROL_MUTATION_TIMEOUT)', controller)
        self.assertIn('state not in ("running", "stopped")', controller)

    def test_time_sync_bounds_ssh_and_protected_control_calls(self):
        sync = self.text("scripts/sync-lab-time.sh")
        self.assertIn("ServerAliveInterval=5", sync)
        self.assertIn("ServerAliveCountMax=1", sync)
        self.assertIn("--timeout-seconds 15", sync)


if __name__ == "__main__":
    unittest.main()
