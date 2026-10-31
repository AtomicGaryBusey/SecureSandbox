#!/usr/bin/env python3

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import model_profile_activate as activation


class ResearchAdmissionFenceTests(unittest.TestCase):
    activation_id = "12345678-1234-4123-8123-123456789abc"
    plan_sha256 = "a" * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fence_path = self.root / "model-profile.pending"
        self.lock_path = self.root / "run-lease.lock"
        self.patches = [
            mock.patch.object(activation, "FENCE", self.fence_path),
            mock.patch.object(activation, "LEASE_LOCK", self.lock_path),
            mock.patch.object(activation, "LIFECYCLE", self.root / "active.json"),
            mock.patch.object(activation, "FAILURE", self.root / "failure.json"),
            mock.patch.object(activation, "RUN_ID", self.root / "run-id"),
            mock.patch.object(activation, "EVIDENCE_RUN_ID", self.root / "evidence-run-id"),
            mock.patch("model_profile_activate.os.chown"),
            mock.patch("model_profile_activate.subprocess.run",
                       return_value=mock.Mock(returncode=1)),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        mock.patch.stopall()
        self.temp.cleanup()

    def test_fence_is_exact_and_blocks_until_exact_unfence(self):
        expected = activation.fence(self.activation_id, self.plan_sha256)
        self.assertEqual(json.loads(self.fence_path.read_text()), expected)
        self.assertEqual(activation.fence(self.activation_id, self.plan_sha256), expected)
        with self.assertRaisesRegex(RuntimeError, "fence_conflict"):
            activation.fence(self.activation_id, "b" * 64)
        self.assertEqual(activation.unfence(self.activation_id)["status"], "open")
        self.assertFalse(self.fence_path.exists())

    def test_fence_refuses_active_research_lifecycle(self):
        activation.LIFECYCLE.write_text("{}\n")
        with self.assertRaisesRegex(RuntimeError, "not_idle"):
            activation.fence(self.activation_id, self.plan_sha256)
        self.assertFalse(self.fence_path.exists())

    def test_status_reports_explicit_legacy_unbound_without_inference(self):
        missing = self.root / "missing-active.json"
        self.assertEqual(activation.status(missing, __import__("os").getuid()), {
            "schema":"secure-sandbox-active-model-profile-v1",
            "state":"legacy_unbound", "status":"verified",
        })


if __name__ == "__main__":
    unittest.main()
