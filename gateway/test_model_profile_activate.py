#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import model_profile_activate as activation


class GatewayAdmissionFenceTests(unittest.TestCase):
    activation_id = "12345678-1234-4123-8123-123456789abc"
    plan_sha256 = "a" * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fence_path = self.root / "model-profile.pending"
        self.lock_path = self.root / "counters" / ".lock"
        self.leases = self.root / "leases"
        self.leases.mkdir()
        self.patches = [
            mock.patch.object(activation, "FENCE", self.fence_path),
            mock.patch.object(activation, "LEASE_LOCK", self.lock_path),
            mock.patch.object(activation, "LEASES", self.leases),
            mock.patch("model_profile_activate.os.chown"),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        mock.patch.stopall()
        self.temp.cleanup()

    def test_fence_is_exact_idempotent_and_durable_until_exact_unfence(self):
        expected = activation.fence(self.activation_id, self.plan_sha256)
        self.assertEqual(activation.fence(self.activation_id, self.plan_sha256), expected)
        self.assertEqual(json.loads(self.fence_path.read_text()), expected)
        self.assertEqual(self.fence_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(RuntimeError, "fence_conflict"):
            activation.fence(self.activation_id, "b" * 64)
        with self.assertRaisesRegex(RuntimeError, "fence_mismatch"):
            activation.unfence("22222222-2222-4222-8222-222222222222")
        self.assertEqual(activation.unfence(self.activation_id)["status"], "open")
        self.assertFalse(self.fence_path.exists())
        self.assertEqual(activation.unfence(self.activation_id)["status"], "open")

    def test_fence_refuses_an_active_lease(self):
        (self.leases / "active.json").write_text("{}\n")
        with self.assertRaisesRegex(RuntimeError, "active_lease"):
            activation.fence(self.activation_id, self.plan_sha256)
        self.assertFalse(self.fence_path.exists())

    def test_helpers_cannot_contaminate_the_json_result_channel(self):
        completed = mock.Mock(returncode=0)
        with mock.patch.object(activation.subprocess, "run", return_value=completed) as run:
            self.assertIs(
                activation.quiet_run(["helper"], check=True, timeout=1), completed
            )
        self.assertIs(run.call_args.kwargs["stdout"], activation.subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], activation.subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
