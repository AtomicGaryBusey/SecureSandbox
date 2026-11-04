#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from research import native_claude_login_replay as replay


def operation(number: int) -> str:
    return str(uuid.UUID(int=number, version=4))


class NativeClaudeLoginReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.handles = base / "handles"
        self.proofs = base / "proofs"
        self.handles.mkdir(mode=0o700)
        self.proofs.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def claim(self, number: int) -> str:
        operation_id = operation(number)
        replay.claim_handle(
            operation_id=operation_id, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256="3" * 64,
            catalog_sha256="4" * 64, root=self.handles,
            trusted_uid=self.uid, trusted_gid=self.gid)
        return operation_id

    def finalize(self, operation_id: str) -> None:
        replay.finalize_handle(
            operation_id=operation_id, plan_sha256="1" * 64,
            authorization_sha256="2" * 64, stack_sha256="3" * 64,
            result_evidence_sha256="5" * 64, root=self.handles,
            trusted_uid=self.uid, trusted_gid=self.gid, now=1_800_000_000)

    def compact(self, number: int, **options: object) -> dict[str, object]:
        return replay.compact(
            operation_id=operation(number), plan_sha256="6" * 64,
            authorization_sha256="7" * 64, binding_key=b"k" * 32,
            root=self.handles, proof_root=self.proofs,
            trusted_uid=self.uid, trusted_gid=self.gid,
            now=lambda: 1_800_000_001, **options)

    def test_compaction_is_canonical_monotonic_keyed_and_replay_denying(self) -> None:
        operation_id = self.claim(1)
        self.finalize(operation_id)
        receipt = self.compact(100)
        self.assertEqual(receipt["false_positive_semantics"], "denial-only")
        self.assertEqual(receipt["removed_handle_count"], 1)
        self.assertFalse((self.handles / f"{operation_id}.json").exists())
        floor_raw = (self.handles / replay.FLOOR_NAME).read_bytes()
        floor = json.loads(floor_raw)
        self.assertEqual(floor_raw, replay.canonical(floor))
        self.assertEqual(floor["bit_count"], replay.FLOOR_BITS)
        self.assertEqual(floor["hash_count"], replay.FLOOR_HASH_COUNT)
        self.assertEqual(floor["compaction_count"], 1)
        self.assertEqual(floor["inserted_handle_count"], 1)
        self.assertEqual(len(receipt["evidence_sha256"]), 64)
        with self.assertRaisesRegex(
            replay.NativeClaudeReplayError, "floor_match_denied"
        ):
            self.claim(1)

    def test_only_finalized_consumed_handles_are_compacted(self) -> None:
        claimed = self.claim(2)
        finalized_with_proof = self.claim(3)
        self.finalize(finalized_with_proof)
        proof = self.proofs / f"{finalized_with_proof}.json"
        proof.write_bytes(b"{}\n")
        proof.chmod(0o600)
        with self.assertRaisesRegex(
            replay.NativeClaudeReplayError, "nothing_to_compact"
        ):
            self.compact(101)
        self.assertTrue((self.handles / f"{claimed}.json").exists())
        self.assertTrue((self.handles / f"{finalized_with_proof}.json").exists())

    def test_crash_after_floor_readback_retries_without_advancing_chain(self) -> None:
        operation_id = self.claim(4)
        self.finalize(operation_id)

        def crash(phase: str) -> None:
            if phase == "floor-published":
                raise RuntimeError("simulated-crash")

        with self.assertRaisesRegex(RuntimeError, "simulated-crash"):
            self.compact(102, checkpoint=crash)
        before = json.loads((self.handles / replay.FLOOR_NAME).read_bytes())
        self.assertTrue((self.handles / f"{operation_id}.json").exists())
        recovered = self.compact(103)
        after = json.loads((self.handles / replay.FLOOR_NAME).read_bytes())
        self.assertEqual(before, after)
        self.assertEqual(after["compaction_count"], 1)
        self.assertEqual(recovered["removed_handle_count"], 1)

    def test_crash_with_durable_pending_floor_is_idempotently_recovered(self) -> None:
        operation_id = self.claim(8)
        self.finalize(operation_id)

        def crash(phase: str) -> None:
            if phase == "floor-pending":
                raise RuntimeError("simulated-pending-crash")

        with self.assertRaisesRegex(RuntimeError, "pending-crash"):
            self.compact(107, checkpoint=crash)
        self.assertTrue((self.handles / replay.PENDING_FLOOR_NAME).exists())
        recovered = self.compact(108)
        floor = json.loads((self.handles / replay.FLOOR_NAME).read_bytes())
        self.assertFalse((self.handles / replay.PENDING_FLOOR_NAME).exists())
        self.assertFalse((self.handles / f"{operation_id}.json").exists())
        self.assertEqual(floor["compaction_count"], 1)
        self.assertEqual(recovered["removed_handle_count"], 1)

    def test_pending_handle_finalization_is_recovered_without_deletion(self) -> None:
        operation_id = self.claim(9)

        def crash(phase: str) -> None:
            if phase == "handle-finalization-pending":
                raise RuntimeError("simulated-handle-crash")

        with self.assertRaisesRegex(RuntimeError, "handle-crash"):
            replay.finalize_handle(
                operation_id=operation_id, plan_sha256="1" * 64,
                authorization_sha256="2" * 64, stack_sha256="3" * 64,
                result_evidence_sha256="5" * 64, root=self.handles,
                trusted_uid=self.uid, trusted_gid=self.gid,
                now=1_800_000_000, checkpoint=crash)
        pending = self.handles / f".pending-{operation_id}.json"
        self.assertTrue(pending.exists())
        self.claim(10)
        self.assertFalse(pending.exists())
        recovered = json.loads(
            (self.handles / f"{operation_id}.json").read_bytes())
        self.assertEqual(recovered["state"], "finalized")
        self.assertEqual(recovered["finalized_evidence_sha256"], "5" * 64)

    def test_false_positive_is_explicit_denial_only(self) -> None:
        first = self.claim(5)
        self.finalize(first)
        self.compact(104)
        with mock.patch.object(replay, "_bloom_contains", return_value=True):
            with self.assertRaisesRegex(
                replay.NativeClaudeReplayError, "floor_match_denied"
            ):
                self.claim(6)

    def test_compaction_limit_and_saturation_fail_closed(self) -> None:
        operation_id = self.claim(7)
        self.finalize(operation_id)
        with mock.patch.object(replay, "MAX_COMPACTIONS", 0):
            with self.assertRaisesRegex(
                replay.NativeClaudeReplayError, "compaction_limit"
            ):
                self.compact(105)
        self.assertTrue((self.handles / f"{operation_id}.json").exists())
        with mock.patch.object(replay, "MAX_SET_BITS", 0):
            with self.assertRaisesRegex(
                replay.NativeClaudeReplayError, "floor_saturated"
            ):
                self.compact(106)
        self.assertTrue((self.handles / f"{operation_id}.json").exists())


if __name__ == "__main__":
    unittest.main()
