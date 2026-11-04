#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from research import native_lifecycle_fence
from shared import native_deployment, native_deployment_lifecycle


class NativeDeploymentLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "lifecycle"
        self.root.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.catalog = "1" * 64
        self.plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()), host_release_id="2" * 64,
            catalog_sha256=self.catalog,
            gateway_package_sha256="3" * 64,
            research_package_sha256="4" * 64,
            previous_gateway_package_sha256="5" * 64,
            previous_research_package_sha256="6" * 64,
            previous_gateway_status_sha256="7" * 64,
            previous_research_status_sha256="8" * 64,
            created_at=1000, expires_at=1100)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _acquire(self, request: dict, *, now: int) -> dict:
        with native_lifecycle_fence.locked(
            root=self.root, trusted_uid=self.uid,
            trusted_gid=self.gid,
        ) as descriptor:
            return native_deployment_lifecycle.acquire_locked(
                request, descriptor, catalog_sha256=self.catalog,
                live_run_count=0, deployment=native_deployment,
                fence=native_lifecycle_fence, trusted_uid=self.uid,
                trusted_gid=self.gid, now=now)

    def _release(self, request: dict, *, now: int,
                 crash=lambda _phase: None) -> dict:
        with native_lifecycle_fence.locked(
            root=self.root, trusted_uid=self.uid,
            trusted_gid=self.gid,
        ) as descriptor:
            return native_deployment_lifecycle.release_locked(
                request, descriptor, catalog_sha256=self.catalog,
                live_run_count=0, deployment=native_deployment,
                fence=native_lifecycle_fence, trusted_uid=self.uid,
                trusted_gid=self.gid, now=now, crash_hook=crash)

    def test_exact_active_acquire_replays_after_plan_expiry(self) -> None:
        request = native_deployment.make_fence_request(self.plan)
        first = self._acquire(request, now=1001)
        self.assertEqual(self._acquire(request, now=1200), first)

    def test_expired_new_acquire_fails_without_fence(self) -> None:
        request = native_deployment.make_fence_request(self.plan)
        with self.assertRaisesRegex(
            native_deployment_lifecycle.NativeDeploymentLifecycleError,
            "fence_rejected",
        ):
            self._acquire(request, now=1200)
        self.assertFalse((self.root / native_lifecycle_fence.FENCE_NAME).exists())

    def test_release_terminal_precedes_unlink_and_replays(self) -> None:
        self._acquire(native_deployment.make_fence_request(self.plan), now=1001)
        request = native_deployment.make_release_request(self.plan)

        def crash(phase: str) -> None:
            if phase == "terminal-published":
                raise RuntimeError("injected")

        with self.assertRaisesRegex(RuntimeError, "injected"):
            self._release(request, now=1002, crash=crash)
        self.assertTrue((self.root / native_lifecycle_fence.FENCE_NAME).exists())
        terminal = self.root / (
            f"deployment-fence.{self.plan['deployment_id']}.released.json")
        before = terminal.read_bytes()
        released = self._release(request, now=1200)
        self.assertFalse((self.root / native_lifecycle_fence.FENCE_NAME).exists())
        self.assertEqual(terminal.read_bytes(), before)
        self.assertEqual(self._release(request, now=1300), released)

    def test_terminal_tamper_blocks_replay(self) -> None:
        self._acquire(native_deployment.make_fence_request(self.plan), now=1001)
        request = native_deployment.make_release_request(self.plan)
        self._release(request, now=1002)
        terminal = self.root / (
            f"deployment-fence.{self.plan['deployment_id']}.released.json")
        value = json.loads(terminal.read_bytes())
        value["release_evidence_sha256"] = "f" * 64
        terminal.chmod(0o600)
        terminal.write_bytes(native_deployment.canonical(value))
        with self.assertRaisesRegex(
            native_deployment_lifecycle.NativeDeploymentLifecycleError,
            "terminal_invalid",
        ):
            self._release(request, now=1300)

    def test_terminal_link_crash_is_recovered_exactly(self) -> None:
        self._acquire(native_deployment.make_fence_request(self.plan), now=1001)
        request = native_deployment.make_release_request(self.plan)

        def crash(phase: str) -> None:
            if phase == "terminal-linked":
                raise RuntimeError("link-crash")

        with self.assertRaisesRegex(RuntimeError, "link-crash"):
            self._release(request, now=1002, crash=crash)
        name = (
            f"deployment-fence.{self.plan['deployment_id']}.released.json")
        pending = self.root / f".{name}.pending"
        terminal = self.root / name
        self.assertEqual(pending.stat().st_ino, terminal.stat().st_ino)
        self.assertEqual(terminal.stat().st_nlink, 2)
        released = self._release(request, now=1003)
        self.assertEqual(released["state"], "released")
        self.assertFalse(pending.exists())
        self.assertEqual(terminal.stat().st_nlink, 1)

    def test_delayed_acquire_cannot_refence_released_deployment(self) -> None:
        acquire = native_deployment.make_fence_request(self.plan)
        self._acquire(acquire, now=1001)
        self._release(
            native_deployment.make_release_request(self.plan), now=1002)
        with self.assertRaisesRegex(
            native_deployment_lifecycle.NativeDeploymentLifecycleError,
            "already_released",
        ):
            self._acquire(acquire, now=1003)
        self.assertFalse((self.root / native_lifecycle_fence.FENCE_NAME).exists())


if __name__ == "__main__":
    unittest.main()
