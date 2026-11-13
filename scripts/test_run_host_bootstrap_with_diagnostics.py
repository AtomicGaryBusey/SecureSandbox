#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run-host-bootstrap-with-diagnostics.sh"


class BootstrapDiagnosticRunnerTests(unittest.TestCase):
    def make_fixture(self, root: Path, *, exit_status: int = 0) -> tuple[Path, Path]:
        scripts = root / "scripts"
        scripts.mkdir()
        runner = scripts / RUNNER.name
        shutil.copy2(RUNNER, runner)
        deploy = scripts / "deploy-host-controller.py"
        deploy.write_text(
            textwrap.dedent(
                f"""\
                import sys
                print("fixture stdout", flush=True)
                print("fixture stderr", file=sys.stderr, flush=True)
                raise SystemExit({exit_status})
                """
            )
        )
        diagnostic_root = root / "SecureSandbox-Native-Host-Transfer"
        diagnostic_root.mkdir(mode=0o700)
        subprocess.run(
            ["git", "init", "--quiet", str(root)], check=True
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Fixture"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "checkout", "-q", "-b", "public-release"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "add", "scripts"], check=True
        )
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        (root / ".git/info/exclude").write_text(
            "SecureSandbox-Native-Host-Transfer/\n"
        )
        return runner, diagnostic_root

    def run_fixture(self, runner: Path, diagnostic_root: Path) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "HOME": str(diagnostic_root.parent),
        }
        return subprocess.run(
            [str(runner)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )

    def test_log_captures_lifecycle_output_and_success_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner, diagnostic_root = self.make_fixture(root)
            result = self.run_fixture(runner, diagnostic_root)

            self.assertEqual(result.returncode, 0, result.stderr)
            logs = list(diagnostic_root.glob("bootstrap-authorization.*"))
            self.assertEqual(len(logs), 1)
            self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode), 0o600)
            content = logs[0].read_text()
            for marker in (
                "event=launcher-start",
                "event=command-start",
                "fixture stdout",
                "fixture stderr",
                "event=command-exit status=0",
                "event=launcher-exit status=0 reason=command-return",
            ):
                self.assertIn(marker, content)

    def test_nonzero_command_status_is_logged_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner, diagnostic_root = self.make_fixture(root, exit_status=17)
            result = self.run_fixture(runner, diagnostic_root)

            self.assertEqual(result.returncode, 17)
            content = next(diagnostic_root.glob("bootstrap-authorization.*")).read_text()
            self.assertIn("event=command-exit status=17", content)
            self.assertIn(
                "event=launcher-exit status=17 reason=command-return", content
            )

    def test_insecure_diagnostic_root_is_rejected_without_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner, diagnostic_root = self.make_fixture(root)
            diagnostic_root.chmod(0o755)
            result = self.run_fixture(runner, diagnostic_root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("diagnostic root mode must be 700", result.stderr)
            self.assertEqual(list(diagnostic_root.iterdir()), [])

    def test_dirty_source_checkout_is_rejected_with_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner, diagnostic_root = self.make_fixture(root)
            (root / "scripts/deploy-host-controller.py").write_text(
                'print("changed")\n'
            )
            result = self.run_fixture(runner, diagnostic_root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source checkout must be clean", result.stderr)
            logs = list(diagnostic_root.glob("bootstrap-authorization.*"))
            self.assertEqual(len(logs), 1)
            content = logs[0].read_text()
            self.assertIn(
                "event=preflight-rejected reason=source-checkout-dirty",
                content,
            )
            self.assertIn("event=launcher-exit status=1 reason=preflight", content)

    def test_wrong_source_branch_is_rejected_with_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner, diagnostic_root = self.make_fixture(root)
            subprocess.run(
                ["git", "-C", str(root), "checkout", "-q", "-b", "other"],
                check=True,
            )
            result = self.run_fixture(runner, diagnostic_root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source branch must be public-release", result.stderr)
            content = next(diagnostic_root.glob("bootstrap-authorization.*")).read_text()
            self.assertIn(
                "event=preflight-rejected reason=source-branch-invalid branch=other",
                content,
            )
            self.assertIn("event=launcher-exit status=1 reason=preflight", content)


if __name__ == "__main__":
    unittest.main()
