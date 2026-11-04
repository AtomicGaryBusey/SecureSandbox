#!/usr/bin/env python3

import json
import os
import copy
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease
from shared.harness_runtime_binding import make_binding


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
            "adapter": "anthropic-messages-v1",
            "profile_id": "abliterated-glm",
            "profile_sha256": "c" * 64,
            "vendor_id": "abliteration",
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
        self.broker.write_text(json.dumps({
            "adapter": "anthropic-messages-v1",
            "allowed_client_sha256": [self.identity],
            "allowed_models": ["abliterated-model-large-v2"],
            "mode": "production",
            "profile_id": "abliterated-glm",
            "profile_sha256": "c" * 64,
            "vendor_id": "abliteration",
        }))
        self.policy.write_text(self.policy_hash + "\n")
        self.store = run_lease.LeaseStore(root, self.profiles, self.broker, self.policy)
        self.run_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.session_policy = {
            "schema": run_lease.SESSION_POLICY_SCHEMA,
            "source_id": None,
            "source_manifest_sha256": None,
            "persona_sha256": "3" * 64,
            "tool_catalog_sha256": "4" * 64,
            "extension_set_sha256": "5" * 64,
        }
        self.harness = make_binding(
            harness_id="claude-code", generation_id="d" * 64,
            manifest_sha256="e" * 64, executable_sha256="f" * 64,
            inventory_sha256="1" * 64, adapter_id="claude-core-v1",
            adapter_sha256="2" * 64,
        )
        self.emit = mock.patch("run_lease.emit").start()

    def tearDown(self):
        mock.patch.stopall()
        self.temp.cleanup()

    def issue(
        self,
        *,
        run_id=None,
        profile="test",
        session_id=None,
        policy=None,
        harness=None,
        now=1000,
    ):
        return self.store.issue(
            run_id or self.run_id,
            profile,
            session_id or self.session_id,
            policy or self.session_policy,
            harness or self.harness,
            now=now,
        )

    def test_issue_binds_identity_model_policy_and_limits(self):
        lease = self.issue()
        transport = lease["brokered_transport"]
        authority = lease["runtime_authority"]
        brokered = authority["model_stack_binding"]["authority"]
        self.assertEqual(transport["relay_sha256"], self.identity)
        self.assertEqual(transport["policy_sha256"], self.policy_hash)
        self.assertEqual(brokered["adapter"], "anthropic-messages-v1")
        self.assertEqual(brokered["profile_id"], "abliterated-glm")
        self.assertEqual(brokered["profile_sha256"], "c" * 64)
        self.assertEqual(brokered["provider_mode"], "production")
        self.assertEqual(brokered["vendor_id"], "abliteration")
        self.assertEqual(
            authority["harness_binding"]["harness_generation_id"], "d" * 64
        )
        self.assertEqual(lease["expires_at"], 1100)
        self.assertEqual(lease["limits"]["max_requests"], 2)

    def test_same_run_issue_is_idempotent_only_for_exact_active_context(self):
        lease = self.issue()
        self.assertEqual(self.issue(now=1001), lease)
        self.policy.write_text("d" * 64 + "\n")
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.issue(now=1002)

    def test_same_run_cannot_be_rebound_to_another_harness_generation(self):
        self.issue()
        changed = make_binding(
            harness_id="claude-code", generation_id="3" * 64,
            manifest_sha256="4" * 64, executable_sha256="5" * 64,
            inventory_sha256="6" * 64, adapter_id="claude-core-v1",
            adapter_sha256="7" * 64,
        )
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.issue(harness=changed, now=1001)

    def test_same_run_cannot_be_rebound_to_another_session_policy(self):
        self.issue()
        changed = copy.deepcopy(self.session_policy)
        changed["persona_sha256"] = "9" * 64
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.issue(policy=changed, now=1001)

    def test_same_run_issue_rejects_profile_or_expired_context(self):
        self.issue()
        profiles = json.loads(self.profiles.read_text())
        profiles["profiles"]["other"] = dict(profiles["profiles"]["test"])
        self.profiles.write_text(json.dumps(profiles))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_reuse_mismatch"):
            self.issue(profile="other", now=1001)
        with self.assertRaises(FileExistsError):
            self.issue(now=1100)

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

    def test_model_profile_fence_blocks_new_lease_admission(self):
        fence = Path(self.temp.name) / "model-profile.pending"
        fence.write_text("{}\n")
        with mock.patch.object(run_lease, "MODEL_PROFILE_FENCE", fence):
            with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_deployment_incomplete"):
                self.issue()
        self.assertFalse((self.store.leases / f"{self.run_id}.json").exists())

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

    def test_model_profile_change_invalidates_active_lease(self):
        self.issue()
        broker = json.loads(self.broker.read_text())
        broker["profile_sha256"] = "d" * 64
        self.broker.write_text(json.dumps(broker))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_model_profile_mismatch"):
            self.store.reserve(self.run_id, self.identity, "abliterated-model-large-v2", 1, 1, now=1001)

    def test_provider_mode_change_invalidates_reserve_and_renew(self):
        self.issue()
        broker = json.loads(self.broker.read_text())
        broker["mode"] = "mock"
        self.broker.write_text(json.dumps(broker))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_model_profile_mismatch"):
            self.store.reserve(
                self.run_id,
                self.identity,
                "abliterated-model-large-v2",
                1,
                1,
                now=1001,
            )
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_model_profile_mismatch"):
            self.store.renew(self.run_id, 60, now=1001)

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
                self.issue(run_id=second_run, now=1001)
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

    def test_nested_authority_tampering_is_a_structured_denial(self):
        self.issue()
        path = self.store.leases / f"{self.run_id}.json"
        lease = json.loads(path.read_text())
        lease["runtime_authority"]["session_context_binding"]["persona_sha256"] = (
            "9" * 64
        )
        path.write_text(json.dumps(lease))
        with self.assertRaisesRegex(run_lease.LeaseDenied, "lease_state_invalid"):
            self.store.reserve(
                self.run_id,
                self.identity,
                "abliterated-model-large-v2",
                1,
                1,
                now=1001,
            )

    def test_issue_payload_is_exact_canonical_and_bounded(self):
        value = {
            "schema": run_lease.ISSUE_SCHEMA,
            "session_id": self.session_id,
            "session_policy": self.session_policy,
            "harness_binding": self.harness,
        }
        raw = run_lease.canonical_json_line(value)
        self.assertEqual(run_lease.parse_issue_payload(raw), value)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "noncanonical"):
            run_lease.parse_issue_payload(b" " + raw)
        with self.assertRaisesRegex(run_lease.LeaseDenied, "payload_invalid"):
            run_lease.parse_issue_payload(
                run_lease.canonical_json_line({**value, "fallback": "native"})
            )
        with self.assertRaisesRegex(run_lease.LeaseDenied, "size_invalid"):
            run_lease.parse_issue_payload(b"x" * (run_lease.MAX_ISSUE_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
