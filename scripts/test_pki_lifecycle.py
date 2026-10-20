#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import pki_lifecycle


def manifest(generation_id: str | None = None, expiry: int = 2_000_000_000) -> dict:
    generation_id = generation_id or str(uuid.uuid4())
    identities = {}
    for index, name in enumerate(pki_lifecycle.IDENTITIES):
        identities[name] = {
            "fingerprint_sha256": hashlib.sha256(f"cert-{index}".encode()).hexdigest(),
            "spki_sha256": hashlib.sha256(f"key-{index}".encode()).hexdigest(),
            "serial_hex": f"{index + 1:02x}",
            "not_before": min(1_899_999_000, expiry - 1_000),
            "not_after": expiry + index,
        }
    value = {
        "schema": 2,
        "generation_id": generation_id,
        "created_at": 1_900_000_000,
        "minimum_not_after": expiry,
        "identities": identities,
    }
    value["manifest_sha256"] = pki_lifecycle.sha256_bytes(pki_lifecycle.canonical_bytes(value))
    return value


class ManifestTests(unittest.TestCase):
    def test_manifest_is_hash_bound_and_exact(self):
        value = manifest()
        self.assertIs(pki_lifecycle.validate_manifest(value), value)
        value["identities"]["server"]["not_after"] += 1
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "manifest_hash_mismatch"):
            pki_lifecycle.validate_manifest(value)

    def test_minimum_expiry_and_identity_set_are_enforced(self):
        value = manifest()
        value["minimum_not_after"] += 1
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "minimum_expiry_mismatch"):
            pki_lifecycle.validate_manifest(value)
        value = manifest()
        del value["identities"]["conversation"]
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "identity_set_invalid"):
            pki_lifecycle.validate_manifest(value)

    def test_expiry_evidence_has_fixed_content_free_fields(self):
        value = manifest(expiry=1_000_700)
        event = pki_lifecycle.expiry_event(value, now=1_000_000)
        self.assertEqual(event, {
            "event": "pki_expiry_status",
            "generation_id": value["generation_id"],
            "minimum_not_after": 1_000_700,
            "remaining_seconds": 700,
            "status": "critical",
        })
        self.assertNotIn("identities", event)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.store = pki_lifecycle.TransactionStore(self.root)
        self.generation = str(uuid.uuid4())
        self.digest = "a" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def test_phase_progression_is_monotonic_and_idempotent(self):
        with self.store.locked():
            created = self.store.create(self.generation, self.digest)
            self.assertEqual(created["phase"], "prepared")
            advanced = self.store.advance(self.generation, "prepared", "research_dual_trust")
            self.assertEqual(advanced["phase"], "research_dual_trust")
            repeated = self.store.advance(self.generation, "prepared", "research_dual_trust")
            self.assertEqual(repeated["phase"], "research_dual_trust")
            with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "phase_transition_invalid"):
                self.store.advance(self.generation, "research_dual_trust", "research_new_clients")

    def test_transaction_file_is_exact_mode_and_hash_bound(self):
        with self.store.locked():
            self.store.create(self.generation, self.digest)
        path = self.store.path(self.generation)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        value = json.loads(path.read_text())
        value["manifest_sha256"] = "b" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "transaction_hash_mismatch"):
            self.store.load(self.generation)

    def test_symlink_transaction_is_rejected(self):
        self.store.prepare()
        target = self.root / "outside"
        target.write_text("{}")
        os.symlink(target, self.store.path(self.generation))
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "untrusted_file"):
            self.store.load(self.generation)

    def test_entry_bounds_are_enforced_before_create(self):
        self.store.prepare()
        for index in range(pki_lifecycle.MAX_TRANSACTIONS):
            (self.store.transactions / f"placeholder-{index}").write_text("x")
        with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "transaction_limit_exceeded"):
            self.store.create(self.generation, self.digest)

    def test_restrictive_umask_does_not_change_modes(self):
        prior = os.umask(0o777)
        try:
            with self.store.locked():
                self.store.create(self.generation, self.digest)
        finally:
            os.umask(prior)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.path(self.generation).stat().st_mode & 0o777, 0o600)

    def test_changed_file_during_read_is_rejected(self):
        path = Path(self.temporary.name) / "manifest.json"
        path.write_text("{}")
        original = os.fstat
        def changed(fd):
            info = original(fd)
            return mock.Mock(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size + 1)
        with mock.patch("pki_lifecycle.os.fstat", side_effect=changed):
            with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "file_changed_during_read"):
                pki_lifecycle.load_json(path)

    def test_pruning_removes_only_old_committed_inactive_generations(self):
        generations = [str(uuid.uuid4()) for _ in range(4)]
        with self.store.locked():
            for index, generation in enumerate(generations):
                (self.store.generations / generation).mkdir()
                self.store.create(generation, self.digest)
                if index != 3:
                    for expected, target in zip(pki_lifecycle.PHASES, pki_lifecycle.PHASES[1:]):
                        self.store.advance(generation, expected, target)
            removed = self.store.prune_committed(generations[2], keep=2)
        self.assertEqual(set(removed), set(generations[:2]))
        self.assertTrue((self.store.generations / generations[2]).exists())
        self.assertTrue((self.store.generations / generations[3]).exists())


if __name__ == "__main__":
    unittest.main()
