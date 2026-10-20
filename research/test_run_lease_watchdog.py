#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease_watchdog as watchdog


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.run_id = str(uuid.uuid4()); self.lease_id = str(uuid.uuid4())
        self.run_file = self.root / "run-id"; self.lease_file = self.root / "run-lease.json"
        self.process_file = self.root / "run-process.json"
        self.lock_file = self.root / "run-lease.lock"
        self.run_file.write_text(self.run_id + "\n")
        self.patches = [
            mock.patch.object(watchdog, "RUN_DIRECTORY", self.root),
            mock.patch.object(watchdog, "RUN_ID_FILE", self.run_file),
            mock.patch.object(watchdog, "LEASE_FILE", self.lease_file),
            mock.patch.object(watchdog, "PROCESS_FILE", self.process_file),
            mock.patch.object(watchdog, "LOCK_FILE", self.lock_file),
            mock.patch("run_lease_watchdog.os.chown"),
            mock.patch("run_lease_watchdog.pwd.getpwnam", return_value=type("User", (), {"pw_uid": os.getuid()})()),
        ]
        for patch in self.patches: patch.start()

    def tearDown(self):
        mock.patch.stopall(); self.temp.cleanup()

    def test_arm_is_root_owned_mode_600_and_bound_to_marker(self):
        value = watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertEqual(value["run_id"], self.run_id)
        self.assertEqual(self.lease_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.process_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.process_file.read_text())["ready"], False)
        watchdog.os.chown.assert_any_call(self.process_file.with_name(
            f".{self.process_file.name}.{os.getpid()}.new"), 0, 0)

    def test_arm_rejects_marker_mismatch_and_existing_lease(self):
        with self.assertRaises(PermissionError):
            watchdog.arm(str(uuid.uuid4()), self.lease_id, int(__import__("time").time()) + 60)
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with self.assertRaises(FileExistsError):
            watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)

    def test_disarm_requires_matching_run(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        lease = {"run_id": self.run_id, "lease_id": self.lease_id}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease), \
                mock.patch("run_lease_watchdog.registered_targets", return_value=({42}, {43})) as registered, \
                mock.patch("run_lease_watchdog.supervisor_processes", return_value={44}), \
                mock.patch("run_lease_watchdog.terminate", return_value=True) as terminate:
            with self.assertRaises(PermissionError): watchdog.disarm(str(uuid.uuid4()))
            watchdog.disarm(self.run_id)
        registered.assert_called_once_with(self.run_id, self.lease_id, os.getuid())
        terminate.assert_called_once_with({42}, {43, 44}, os.getuid())
        self.assertFalse(self.lease_file.exists())

    def test_disarm_retains_enforcement_state_until_uid_is_quiescent(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        lease = {"run_id": self.run_id, "lease_id": self.lease_id}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease), \
                mock.patch("run_lease_watchdog.registered_targets", return_value=(set(), set())), \
                mock.patch("run_lease_watchdog.supervisor_processes", return_value={44}), \
                mock.patch("run_lease_watchdog.terminate", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "agent processes remain"):
                watchdog.disarm(self.run_id)
        self.assertTrue(self.lease_file.exists())
        self.assertTrue(self.process_file.exists())

    def test_renew_requires_same_identity_and_increasing_expiry(self):
        initial = int(__import__("time").time()) + 60
        watchdog.arm(self.run_id, self.lease_id, initial)
        lease = {"schema": watchdog.SCHEMA, "run_id": self.run_id, "lease_id": self.lease_id, "expires_at": initial}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease):
            renewed = watchdog.renew(self.run_id, self.lease_id, initial + 60)
        self.assertEqual(renewed["expires_at"], initial + 60)

    def test_expire_shortens_only_matching_run(self):
        initial = int(__import__("time").time()) + 60
        watchdog.arm(self.run_id, self.lease_id, initial)
        lease = {"schema": watchdog.SCHEMA, "run_id": self.run_id, "lease_id": self.lease_id, "expires_at": initial}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease):
            with self.assertRaises(PermissionError): watchdog.expire(str(uuid.uuid4()))
            expired = watchdog.expire(self.run_id)
        self.assertLess(expired["expires_at"], initial)

    def test_invalid_registration_cannot_disable_agent_process_fallback(self):
        self.process_file.write_text("not json\n")
        self.process_file.chmod(0o600)
        self.assertEqual(
            watchdog.registered_targets(self.run_id, self.lease_id, os.getuid()),
            (set(), set()),
        )
        with mock.patch("run_lease_watchdog.process_ids_for_uid", side_effect=[{4242}, set()]), \
                mock.patch("run_lease_watchdog.os.kill") as kill, \
                mock.patch("run_lease_watchdog.time.monotonic", side_effect=[0, 6, 6, 9]):
            self.assertTrue(watchdog.terminate(set(), set(), os.getuid()))
        kill.assert_any_call(4242, __import__("signal").SIGKILL)


if __name__ == "__main__": unittest.main()

