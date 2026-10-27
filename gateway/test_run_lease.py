#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease


class LeaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        for name in ("leases", "counters", "summaries"):
            (root / name).mkdir()
        self.profiles = root / "profiles.json"
        self.broker = root / "broker.json"
        self.policy = root / "policy.sha256"
        self.profiles.write_text(json.dumps({
            "schema": run_lease.PROFILE_SCHEMA,
            "model": "abliterated-model-large-v2",
            "input_microusd_per_million_tokens": 5_000_000,
            "output_microusd_per_million_tokens": 5_000_000,
            "profiles": {"test": {
                "duration_seconds": 100, "maximum_total_seconds": 200,
                "max_requests": 2, "max_input_tokens": 20,
                "max_output_tokens": 10, "max_cost_microusd": 150,
            }},
        }))
        self.identity = "a" * 64
        self.policy_hash = "b" * 64
        self.broker.write_text(json.dumps({"allowed_client_sha256": [self.identity]}))
        self.policy.write_text(self.policy_hash + "\n")
        self.store = run_lease.LeaseStore(root, self.profiles, self.broker, self.policy)
        self.run_id = str(uuid.uuid4())
        self.emit = mock.patch("run_lease.emit").start()

    def tearDown(self):
        mock.patch.stopall()
        self.temp.cleanup()

    def issue(self):
        return self.store.issue(self.run_id, "test", now=1000)

    def test_issue_binds_identity_model_policy_and_limits(self):
        lease = self.issue()
        self.assertEqual(lease["relay_sha256"], self.identity)
        self.assertEqual(lease["policy_sha256"], self.policy_hash)
        self.assertEqual(lease["expires_at"], 1100)
        self.assertEqual(lease["limits"]["max_requests"], 2)

    def test_same_run_issue_is_idempotent_only_for_exact_active_context(self):
        lease = self.issue()
        self.assertEqual(self.store.issue(self.run_id, "test", now=1001), lease)
        self.policy.write_text("d" * 64 + "\n")
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.store.issue(self.run_id, "test", now=1002)

    def test_same_run_issue_rejects_profile_or_expired_context(self):
        self.issue()
        profiles = json.loads(self.profiles.read_text())
        profiles["profiles"]["other"] = dict(profiles["profiles"]["test"])
        self.profiles.write_text(json.dumps(profiles))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.store.issue(self.run_id, "other", now=1001)
        with self.assertRaises(FileExistsError):
            self.store.issue(self.run_id, "test", now=1100)

    def test_pending_install_blocks_new_and_existing_paid_call_authority(self):
        pending = Path(self.temp.name) / "install.pending"
        pending.write_text("pending\n")
        with mock.patch.object(run_lease, "INSTALL_PENDING", pending):
            with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_deployment_incomplete"):
                self.issue()
        self.issue()
        with mock.patch.object(run_lease, "INSTALL_PENDING", pending):
            with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_deployment_incomplete"):
                self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1001)

    def test_reservation_is_durable_and_settlement_refunds_only_unused_output(self):
        self.issue()
        reservation_id = str(uuid.uuid4())
        first = self.store.reserve(
            self.run_id, self.identity, "abliterated-model-large-v2", 10, 5,
            reservation_id, now=1001,
        )
        self.assertEqual(first["cumulative"]["cost_microusd"], 75)
        settled = self.store.settle(self.run_id, reservation_id, 1, now=1002)
        self.assertEqual(settled["released"]["output_tokens"], 4)
        self.assertEqual(settled["cumulative"]["output_tokens"], 1)
        self.assertEqual(settled["cumulative"]["cost_microusd"], 55)
        self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1002)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_requests_exhausted"):
            self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1003)
        counter = json.loads((self.store.counters / f"{self.run_id}.json").read_text())
        self.assertEqual(counter["requests"], 2)

    def test_settlement_is_one_time_and_cannot_exceed_reservation(self):
        self.issue()
        reservation_id = str(uuid.uuid4())
        self.store.reserve(
            self.run_id, self.identity, "abliterated-model-large-v2", 1, 5,
            reservation_id, now=1001,
        )
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_settlement_exceeds_reservation"):
            self.store.settle(self.run_id, reservation_id, 6, now=1002)
        counter = json.loads((self.store.counters / f"{self.run_id}.json").read_text())
        self.assertEqual(counter["output_tokens"], 5)
        self.store.settle(self.run_id, reservation_id, 2, now=1003)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reservation_not_found"):
            self.store.settle(self.run_id, reservation_id, 1, now=1004)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reservation_replayed"):
            self.store.reserve(
                self.run_id, self.identity, "abliterated-model-large-v2", 1, 1,
                reservation_id, now=1004,
            )

    def test_unsettled_reservation_remains_fully_charged_on_finalize(self):
        self.issue()
        self.store.reserve(
            self.run_id, self.identity, "abliterated-model-large-v2", 1, 5,
            str(uuid.uuid4()), now=1001,
        )
        summary = self.store.finalize(self.run_id, "operator_closed", now=1002)
        self.assertEqual(summary["final_counters"]["output_tokens"], 5)
        self.assertEqual(len(summary["final_counters"]["reservations"]), 1)

    def test_mismatch_and_expiry_fail_closed_without_increment(self):
        self.issue()
        for identity, model, now, code in (
            ("c" * 64, "abliterated-model-large-v2", 1001, "lease_relay_mismatch"),
            (self.identity, "other", 1001, "lease_model_mismatch"),
            (self.identity, "abliterated-model-large-v2", 1100, "lease_expired"),
        ):
            with self.assertRaisesRegex(run_lease.LeaseDenied, code):
                self.store.reserve(self.run_id, identity, model, 1, 1, now=now)
        counter = json.loads((self.store.counters / f"{self.run_id}.json").read_text())
        self.assertEqual(counter["requests"], 0)

    def test_policy_change_invalidates_active_lease(self):
        self.issue()
        self.policy.write_text("d" * 64 + "\n")
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_policy_mismatch"):
            self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1001)

    def test_renewal_cannot_cross_profile_maximum(self):
        self.issue()
        renewed = self.store.renew(self.run_id, 60, now=1001)
        self.assertEqual(renewed["expires_at"], 1160)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_renewal_limit_exceeded"):
            self.store.renew(self.run_id, 60, now=1002)

    def test_final_summary_closes_lease_and_is_idempotent(self):
        lease = self.issue()
        summary = self.store.finalize(self.run_id, "completed", now=1002)
        self.assertEqual(summary["lease"]["lease_id"], lease["lease_id"])
        self.assertEqual(self.store.finalize(self.run_id, "completed", now=1003), summary)
        self.assertEqual(os.stat(self.store.summaries / f"{self.run_id}.json").st_mode & 0o777, 0o444)
        self.assertFalse((self.store.leases / f"{self.run_id}.json").exists())
        self.assertFalse((self.store.counters / f"{self.run_id}.json").exists())
        self.assertEqual(self.store.status(self.run_id)["summary"], summary)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_closed"):
            self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1004)

    def test_recovery_finalizes_expired_lease(self):
        self.issue()
        self.assertEqual(self.store.recover(now=1100), [self.run_id])
        summary = json.loads((self.store.summaries / f"{self.run_id}.json").read_text())
        self.assertEqual(summary["reason"], "expired")

    def test_issue_never_creates_entry_beyond_state_limit(self):
        with mock.patch.object(run_lease, "MAX_LEASES", 1):
            self.issue()
            second_run = str(uuid.uuid4())
            with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_state_limit_exceeded"):
                self.store.issue(second_run, "test", now=1001)
            self.assertFalse((self.store.leases / f"{second_run}.json").exists())

    def test_corrupt_state_is_a_structured_denial(self):
        self.issue()
        path = self.store.leases / f"{self.run_id}.json"
        lease = json.loads(path.read_text()); del lease["pricing"]
        path.write_text(json.dumps(lease))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_state_invalid"):
            self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1001)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_state_invalid"):
            self.store.renew(self.run_id, 60, now=1001)


if __name__ == "__main__":
    unittest.main()
