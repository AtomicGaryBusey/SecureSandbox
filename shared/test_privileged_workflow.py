#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from shared import privileged_workflow as workflow


class PrivilegedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.store = workflow.WorkflowStore(self.root, "test-rotation")
        self.transaction_id = str(uuid.uuid4())
        self.identities = {"host_release": "a" * 64, "research_release": "b" * 64}
        self.now = 2_000_000_000
        self.expiry = self.now + 600

    def tearDown(self):
        self.temporary.cleanup()

    def action(self) -> str:
        return str(uuid.uuid4())

    def create(self):
        with self.store.locked():
            return self.store.create(self.transaction_id, self.action(), self.identities, self.expiry, now=self.now)

    def authorize(self):
        return self.store.advance(self.transaction_id, "authorized", self.action(), self.identities,
                                  authorization_sha256="c" * 64,
                                  authorization_expires_at=self.now + 300, now=self.now + 1)

    def test_complete_monotonic_workflow_and_append_only_history(self):
        self.create()
        with self.store.locked():
            self.authorize()
            self.store.advance(self.transaction_id, "activated", self.action(), self.identities,
                               evidence_sha256="d" * 64, now=self.now + 2)
            self.store.advance(self.transaction_id, "verified", self.action(), self.identities,
                               evidence_sha256="e" * 64, now=self.now + 3)
            result = self.store.advance(self.transaction_id, "committed", self.action(), self.identities,
                                        evidence_sha256="f" * 64, now=self.now + 4)
            history = self.store.event_history(self.transaction_id, self.identities)
        self.assertEqual(result["phase"], "committed")
        self.assertEqual([event["phase"] for event in history], list(workflow.PHASES))
        self.assertEqual(len({event["event_sha256"] for event in history}), 5)

    def test_lost_response_after_event_append_repairs_head_and_is_idempotent(self):
        self.create()
        action = self.action()
        original = workflow.atomic_write
        def lose_head(path, data, mode=0o600):
            if path.name == "head.json":
                raise OSError("simulated process loss")
            return original(path, data, mode)
        with self.store.locked(), mock.patch.object(workflow, "atomic_write", side_effect=lose_head):
            with self.assertRaises(OSError):
                self.store.advance(self.transaction_id, "authorized", action, self.identities,
                                   authorization_sha256="c" * 64,
                                   authorization_expires_at=self.now + 300, now=self.now + 1)
        with self.store.locked():
            recovered = self.store.advance(self.transaction_id, "authorized", action, self.identities,
                                           authorization_sha256="c" * 64,
                                           authorization_expires_at=self.now + 300, now=self.now + 1)
            history = self.store.event_history(self.transaction_id, self.identities)
        self.assertEqual(recovered["phase"], "authorized")
        self.assertEqual(len(history), 2)

    def test_exact_component_identity_binding_rejects_mixed_state(self):
        self.create()
        changed = dict(self.identities); changed["research_release"] = "0" * 64
        with self.store.locked():
            with self.assertRaisesRegex(workflow.WorkflowError, "component_identity_mismatch"):
                self.store.inspect(self.transaction_id, changed)
            with self.assertRaisesRegex(workflow.WorkflowError, "component_identity_mismatch"):
                self.store.advance(self.transaction_id, "authorized", self.action(), changed,
                                   authorization_sha256="c" * 64,
                                   authorization_expires_at=self.now + 300, now=self.now + 1)

    def test_expiry_and_rollback_are_pre_activation_only(self):
        self.create()
        with self.store.locked():
            expired = self.store.advance(self.transaction_id, "expired", self.action(), self.identities,
                                         now=self.expiry + 1)
        self.assertEqual(expired["phase"], "expired")
        second = str(uuid.uuid4())
        with self.store.locked():
            self.store.create(second, self.action(), self.identities, self.expiry, now=self.now)
            rolled_back = self.store.advance(second, "rolled_back", self.action(), self.identities,
                                             evidence_sha256="d" * 64, now=self.now + 1)
        self.assertEqual(rolled_back["phase"], "rolled_back")

    def test_expired_authorization_cannot_activate_and_active_cannot_rollback(self):
        self.create()
        with self.store.locked():
            self.authorize()
            with self.assertRaisesRegex(workflow.WorkflowError, "authorization_expired"):
                self.store.advance(self.transaction_id, "activated", self.action(), self.identities,
                                   evidence_sha256="d" * 64, now=self.now + 301)
            self.store.advance(self.transaction_id, "activated", self.action(), self.identities,
                               evidence_sha256="d" * 64, now=self.now + 2)
            with self.assertRaisesRegex(workflow.WorkflowError, "phase_transition_invalid"):
                self.store.advance(self.transaction_id, "rolled_back", self.action(), self.identities,
                                   evidence_sha256="e" * 64, now=self.now + 3)

    def test_action_id_is_exactly_idempotent(self):
        self.create(); action = self.action()
        with self.store.locked():
            first = self.store.advance(self.transaction_id, "authorized", action, self.identities,
                                       authorization_sha256="c" * 64,
                                       authorization_expires_at=self.now + 300, now=self.now + 1)
            repeated = self.store.advance(self.transaction_id, "authorized", action, self.identities,
                                          authorization_sha256="c" * 64,
                                          authorization_expires_at=self.now + 300, now=self.now + 2)
            with self.assertRaisesRegex(workflow.WorkflowError, "action_id_conflict"):
                self.store.advance(self.transaction_id, "authorized", action, self.identities,
                                   authorization_sha256="e" * 64,
                                   authorization_expires_at=self.now + 300, now=self.now + 2)
        self.assertEqual(first, repeated)

    def test_substituted_event_and_ambiguous_successor_fail_closed(self):
        self.create()
        transaction = self.root / "transactions" / self.transaction_id
        event = next((transaction / "events").iterdir())
        value = json.loads(event.read_text())
        value["component_identities"]["host_release"] = "0" * 64
        event.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        with self.store.locked():
            with self.assertRaisesRegex(workflow.WorkflowError, "event_hash_mismatch"):
                self.store.inspect(self.transaction_id)

    def test_symlink_and_world_writable_state_are_rejected(self):
        self.store.prepare()
        os.chmod(self.root, 0o777)
        with self.assertRaisesRegex(workflow.WorkflowError, "state_directory_untrusted"):
            self.store.prepare()

    def test_mutation_without_store_lock_is_rejected(self):
        self.store.prepare()
        with self.assertRaisesRegex(workflow.WorkflowError, "workflow_lock_required"):
            self.store.create(self.transaction_id, self.action(), self.identities,
                              self.expiry, now=self.now)

    def test_incomplete_unpublished_create_is_cleaned_before_recovery(self):
        self.store.prepare()
        temporary = self.store.transactions / f".new-{self.transaction_id}-{uuid.uuid4()}"
        temporary.mkdir(mode=0o700)
        (temporary / "events").mkdir(mode=0o700)
        self.store.prepare()
        self.assertFalse(temporary.exists())

    def test_two_workflow_families_reuse_the_same_contract(self):
        first = workflow.WorkflowStore(self.root / "one", "pki-rotation")
        second = workflow.WorkflowStore(self.root / "two", "host-release")
        for store in (first, second):
            with store.locked():
                result = store.create(str(uuid.uuid4()), self.action(), self.identities,
                                      self.expiry, now=self.now)
            self.assertEqual(result["phase"], "prepared")


if __name__ == "__main__":
    unittest.main()
