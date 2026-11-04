#!/usr/bin/env python3

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from research import native_lifecycle_fence
from scripts import native_deployment_fence_bootstrap as bootstrap
from shared import native_deployment, native_deployment_lifecycle


class NativeDeploymentFenceBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.install = self.root / "install"
        self.lifecycle = self.root / "lifecycle"
        self.egress = self.root / "egress"
        for path in (self.install, self.lifecycle, self.egress):
            path.mkdir(mode=0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.payload_catalog = self.root / "payload-catalog.json"
        self.installed_catalog = self.root / "installed-catalog.json"
        self.catalog_value = {"schema": "test-native-catalog-v1", "stacks": []}
        raw = native_deployment.canonical(self.catalog_value)
        self.payload_catalog.write_bytes(raw)
        self.payload_catalog.chmod(0o600)
        self.installed_catalog.write_bytes(raw)
        self.installed_catalog.chmod(0o644)
        self.catalog_sha256 = native_deployment.digest(self.catalog_value)
        self.previous = "a" * 64
        self.plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()), host_release_id="1" * 64,
            catalog_sha256=self.catalog_sha256,
            gateway_package_sha256="2" * 64,
            research_package_sha256="3" * 64,
            previous_gateway_package_sha256="4" * 64,
            previous_research_package_sha256=self.previous,
            created_at=1000, expires_at=1100)
        self.generation = "legacy"
        self.observed_release = {"package_sha256": self.previous}
        self.active_grant = self.root / "active.json"
        self.pending = self.install / "pending.json"
        self.sessions = (self.root / "sessions",)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runner(self, command, *, accepted={0}):
        command = list(command)
        if command[:2] == ["/usr/bin/pgrep", "-u"]:
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[:3] == ["/usr/bin/systemctl", "show",
                           "native-harness-supervisor.service"]:
            raw = (
                b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                b"MainPID=0\nUnitFileState=disabled\n")
            return subprocess.CompletedProcess(command, 0, raw, b"")
        if command[:3] == ["/usr/bin/systemctl", "show",
                           "secure-sandbox-native-egress-watchdog.service"]:
            raw = (
                b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                b"MainPID=0\nUnitFileState=\n")
            return subprocess.CompletedProcess(command, 0, raw, b"")
        if command[:3] == ["/usr/bin/systemctl", "is-active",
                           "secure-sandbox-native-egress-watchdog.service"]:
            return subprocess.CompletedProcess(command, 0, b"active\n", b"")
        raise AssertionError(command)

    @staticmethod
    def closed_observer(_role: str) -> dict:
        return {
            "schema": "secure-sandbox-native-closed-state-v1",
            "live_policy_sha256": "5" * 64,
            "persistent_policy_sha256": "6" * 64,
            "service": "inactive", "state": "closed",
        }

    def absent_runner(self, command, *, accepted={0}):
        command = list(command)
        if command[:2] == ["/usr/bin/pgrep", "-u"]:
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[:2] == ["/usr/bin/systemctl", "show"]:
            raw = (
                b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                b"MainPID=0\nUnitFileState=\n")
            return subprocess.CompletedProcess(command, 0, raw, b"")
        raise AssertionError(command)

    def execute(self, action: str, request: dict, *, now: int,
                crash=lambda _phase: None, closed_observer=None) -> dict:
        def lookup(name: str):
            if self.generation == "absent":
                raise KeyError(name)
            return SimpleNamespace(pw_uid=99999)

        return bootstrap.execute(
            action, request, deployment=native_deployment,
            lifecycle=native_deployment_lifecycle,
            fence=native_lifecycle_fence, release=SimpleNamespace(),
            release_observer=lambda: (
                self.generation, self.observed_release),
            payload_catalog=self.payload_catalog,
            installed_catalog=self.installed_catalog,
            install_lock=self.install / "install.lock",
            lifecycle_root=self.lifecycle,
            egress_lock=self.egress / ".lock",
            pending=self.pending, active_grant=self.active_grant,
            session_roots=self.sessions, runner=self.runner,
            closed_observer=(self.closed_observer if closed_observer is None
                             else closed_observer),
            user_lookup=lookup,
            trusted_uid=self.uid, trusted_gid=self.gid, now=now,
            crash_hook=crash)

    def test_legacy_acquire_replays_after_expiry(self) -> None:
        request = native_deployment.make_fence_request(self.plan)
        first = self.execute("acquire", request, now=1001)
        self.assertEqual(first["state"], "fenced")
        self.assertEqual(self.execute("acquire", request, now=1200), first)

    def test_new_expired_acquire_rejects(self) -> None:
        acquire = native_deployment.make_fence_request(self.plan)
        with self.assertRaisesRegex(
            native_deployment_lifecycle.NativeDeploymentLifecycleError,
            "fence_rejected",
        ):
            self.execute("acquire", acquire, now=1200)
        self.assertFalse(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())

    def test_closed_observer_runs_under_egress_barrier(self) -> None:
        observed = {"locked": False}

        def observer(role: str) -> dict:
            descriptor = os.open(self.egress / ".lock", os.O_RDWR)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    observed["locked"] = True
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
            return self.closed_observer(role)

        self.execute(
            "acquire", native_deployment.make_fence_request(self.plan),
            now=1001, closed_observer=observer)
        self.assertTrue(observed["locked"])

    def test_stale_predecessor_and_protected_generation_reject(self) -> None:
        request = native_deployment.make_fence_request(self.plan)
        self.observed_release = {"package_sha256": "f" * 64}
        with self.assertRaisesRegex(
            bootstrap.NativeDeploymentFenceBootstrapError,
            "predecessor_mismatch",
        ):
            self.execute("acquire", request, now=1001)
        self.generation = "protected"
        self.observed_release = {"package_sha256": self.previous}
        with self.assertRaisesRegex(
            bootstrap.NativeDeploymentFenceBootstrapError,
            "generation_forbidden",
        ):
            self.execute("acquire", request, now=1001)

    def test_active_or_mixed_state_leaves_no_fence(self) -> None:
        request = native_deployment.make_fence_request(self.plan)
        self.active_grant.write_text("ambiguous", encoding="ascii")
        with self.assertRaisesRegex(
            bootstrap.NativeDeploymentFenceBootstrapError, "active_state",
        ):
            self.execute("acquire", request, now=1001)
        self.assertFalse(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())

    def test_absent_predecessor_is_exact(self) -> None:
        self.generation = "absent"
        self.observed_release = None
        self.runner = self.absent_runner
        self.plan = native_deployment.make_plan(
            deployment_id=self.plan["deployment_id"],
            host_release_id=self.plan["host_release_id"],
            catalog_sha256=self.plan["catalog_sha256"],
            gateway_package_sha256=self.plan["gateway_package_sha256"],
            research_package_sha256=self.plan["research_package_sha256"],
            previous_gateway_package_sha256=None,
            previous_research_package_sha256=None,
            created_at=1000, expires_at=1100)
        reply = self.execute(
            "acquire", native_deployment.make_fence_request(self.plan),
            now=1001)
        self.assertEqual(reply["state"], "fenced")

    def test_rollback_release_is_terminal_first_and_replayable(self) -> None:
        self.execute(
            "acquire", native_deployment.make_fence_request(self.plan),
            now=1001)
        request = native_deployment.make_release_request(self.plan)

        def crash(phase: str) -> None:
            if phase == "terminal-published":
                raise RuntimeError("injected")

        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.execute("release", request, now=1200, crash=crash)
        self.assertTrue(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())
        released = self.execute("release", request, now=1201)
        self.assertEqual(released["state"], "released")
        self.assertFalse(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())
        self.assertEqual(self.execute("release", request, now=1202), released)

    def test_bootstrap_release_rejects_protected_candidate(self) -> None:
        self.execute(
            "acquire", native_deployment.make_fence_request(self.plan),
            now=1001)
        self.generation = "protected"
        self.observed_release = {
            "package_sha256": self.plan["research_package_sha256"]}
        with self.assertRaisesRegex(
            bootstrap.NativeDeploymentFenceBootstrapError,
            "generation_forbidden",
        ):
            self.execute(
                "release", native_deployment.make_release_request(self.plan),
                now=1200)
        self.assertTrue(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())

    def test_changed_catalog_cannot_acquire(self) -> None:
        self.payload_catalog.write_bytes(native_deployment.canonical({
            "schema": "test-native-catalog-v1", "stacks": ["changed"]}))
        with self.assertRaisesRegex(
            bootstrap.NativeDeploymentFenceBootstrapError,
            "catalog_mismatch",
        ):
            self.execute(
                "acquire", native_deployment.make_fence_request(self.plan),
                now=1001)
        self.assertFalse(
            (self.lifecycle / native_lifecycle_fence.FENCE_NAME).exists())

    def test_wrappers_are_fixed_root_only_and_syntax_valid(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for name, action in (
            ("install-native-deployment-fence-bootstrap.sh", "acquire"),
            ("install-native-deployment-fence-bootstrap-release.sh", "release"),
        ):
            path = root / "scripts" / name
            result = subprocess.run(
                ["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                f"native_deployment_fence_bootstrap.py {action}", text)
            self.assertNotIn("eval", text)

    def test_actual_payload_closure_loads_in_isolated_python(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        payload = self.root / "isolated-payload"
        payload.mkdir(mode=0o700)
        sources = {
            "native_guest_control.py": "shared/native_guest_control.py",
            "native_egress.py": "shared/native_egress.py",
            "native_vendor_stack.py": "shared/native_vendor_stack.py",
            "harness_runtime_binding.py":
                "shared/harness_runtime_binding.py",
            "native_stack_runtime_binding.py":
                "shared/native_stack_runtime_binding.py",
            "model_stack_runtime_binding.py":
                "shared/model_stack_runtime_binding.py",
            "session_context_binding.py":
                "shared/session_context_binding.py",
            "runtime_authority.py": "shared/runtime_authority.py",
        }
        for name, relative in sources.items():
            target = payload / name
            shutil.copyfile(repository / relative, target)
            target.chmod(0o600)
        code = (
            "import pathlib,runpy,sys;"
            "m=runpy.run_path(sys.argv[1]);"
            "o=m['load_closed_observer'](pathlib.Path(sys.argv[2]),"
            "trusted_uid=int(sys.argv[3]),trusted_gid=int(sys.argv[4]));"
            "assert callable(o);print('verified')"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", code,
             str(repository / "scripts/native_deployment_fence_bootstrap.py"),
             str(payload), str(self.uid), str(self.gid)],
            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "verified\n")


if __name__ == "__main__":
    unittest.main()
