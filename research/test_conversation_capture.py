import io
import json
import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(__file__))
import conversation_capture as capture


class ConversationFramingTests(unittest.TestCase):
    def opened(self, root: Path):
        user = SimpleNamespace(pw_uid=os.getuid())
        with mock.patch.object(capture, "JOURNAL_ROOT", os.path.realpath(root)), \
                mock.patch("conversation_capture.pwd.getpwnam", return_value=user):
            result = []
            for path, handle, info in capture.secure_journals():
                with handle:
                    result.append((path, handle.read(), info))
            return result

    def test_journal_identity_does_not_alias_reused_inode_at_new_path(self):
        info = SimpleNamespace(st_dev=8, st_ino=42)
        first = capture.journal_identity("/journals/first.jsonl", info)
        second = capture.journal_identity("/journals/second.jsonl", info)
        self.assertNotEqual(first, second)

    def test_defers_partial_trailing_record(self):
        complete = json.dumps({"type": "user", "text": "complete"}).encode() + b"\n"
        partial = b'{"type":"assistant","text":"still writing"'
        handle = io.BytesIO(complete + partial)
        records, consumed, corruptions = capture.read_complete_records(handle)
        self.assertEqual(records, complete)
        self.assertEqual(consumed, len(complete))
        self.assertEqual(corruptions, [])

    def test_defers_partial_record_without_newline(self):
        self.assertEqual(capture.read_complete_records(io.BytesIO(b'{"type":"assistant"')), (b"", 0, []))

    def test_preserves_malformed_completed_record_in_json_wrapper(self):
        records, consumed, corruptions = capture.read_complete_records(io.BytesIO(b"not-json\n"))
        wrapper = json.loads(records)
        self.assertEqual(base64.b64decode(wrapper["raw_base64"]), b"not-json")
        self.assertEqual(wrapper["raw_sha256"], corruptions[0]["raw_sha256"])
        self.assertEqual(consumed, len(b"not-json\n"))

    def test_rejects_oversized_unterminated_record(self):
        with self.assertRaisesRegex(RuntimeError, "exceeds capture limit"):
            capture.read_complete_records(io.BytesIO(b"x" * (capture.MAX_CHUNK + 1)))

    def test_descriptor_walk_reads_nested_regular_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); nested = root / "project"; nested.mkdir()
            journal = nested / "session.jsonl"; journal.write_bytes(b'{"type":"user"}\n')
            opened = self.opened(root)
            self.assertEqual([(Path(path).name, content) for path, content, _ in opened],
                             [("session.jsonl", b'{"type":"user"}\n')])

    def test_descriptor_walk_rejects_final_and_ancestor_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory); secret = Path(outside) / "secret.jsonl"
            secret.write_bytes(b"secret\n")
            (root / "final.jsonl").symlink_to(secret)
            (root / "ancestor").symlink_to(Path(outside), target_is_directory=True)
            self.assertEqual(self.opened(root), [])

    def test_root_open_rejects_symlink_in_prefix_component(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            base = Path(os.path.realpath(directory))
            real_root = Path(outside) / "projects"
            real_root.mkdir()
            (real_root / "session.jsonl").write_bytes(b"secret\n")
            (base / ".claude").symlink_to(Path(outside), target_is_directory=True)
            user = SimpleNamespace(pw_uid=os.getuid())
            with mock.patch.object(capture, "JOURNAL_ROOT", str(base / ".claude" / "projects")), \
                    mock.patch("conversation_capture.pwd.getpwnam", return_value=user):
                with self.assertRaises(OSError):
                    list(capture.secure_journals())

    def test_descriptor_walk_rejects_hardlinks_and_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"alias\n")
            os.link(source, root / "alias.jsonl")
            os.mkfifo(root / "pipe.jsonl")
            self.assertEqual(self.opened(root), [])

    def test_open_descriptor_stays_bound_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory); journal = root / "session.jsonl"
            journal.write_bytes(b"journal\n")
            secret = Path(outside) / "secret.jsonl"; secret.write_bytes(b"secret\n")
            user = SimpleNamespace(pw_uid=os.getuid())
            with mock.patch.object(capture, "JOURNAL_ROOT", os.path.realpath(root)), \
                    mock.patch("conversation_capture.pwd.getpwnam", return_value=user):
                journals = capture.secure_journals()
                _, handle, _ = next(journals)
                journal.rename(root / "old")
                journal.symlink_to(secret)
                try:
                    self.assertEqual(handle.read(), b"journal\n")
                finally:
                    handle.close(); journals.close()

    def test_idle_scan_never_advances_offsets(self):
        state = {"offsets": {"existing": 7}}
        with mock.patch.object(capture, "current_run", return_value=""), \
                mock.patch.object(capture, "secure_journals") as journals:
            self.assertFalse(capture.scan("age1test", state))
        journals.assert_not_called()
        self.assertEqual(state, {"offsets": {"existing": 7}})

    def test_finalize_wraps_unterminated_tail_and_receipts_exact_offset(self):
        run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            lock_path = root / "capture.lock"
            receipt_dir = root / "receipts"
            outbox = root / "outbox"; outbox.mkdir()
            journal = root / "session.jsonl"
            baseline = b'{"type":"user"}\n'
            tail = b'{"type":"assistant","partial":true}'
            journal.write_bytes(baseline)
            user = SimpleNamespace(pw_uid=os.getuid())
            patches = (
                mock.patch.object(capture, "JOURNAL_ROOT", os.path.realpath(root)),
                mock.patch.object(capture, "STATE", str(state_path)),
                mock.patch.object(capture, "LOCK", str(lock_path)),
                mock.patch.object(capture, "RECEIPT_DIR", str(receipt_dir)),
                mock.patch.object(capture, "OUTBOX", str(outbox)),
                mock.patch("conversation_capture.pwd.getpwnam", return_value=user),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                capture.prepare(run_id)
                with journal.open("ab") as handle:
                    handle.write(tail)
                encrypted = []
                def fake_encrypt(_recipient, _run, _source, sequence, _previous, records):
                    encrypted.append(records)
                    digest = (f"{sequence:x}" * 64)[:64]
                    temporary = outbox / f".{run_id}-{sequence:012d}.pending"
                    final = outbox / f"{run_id}-{sequence:012d}-{digest}.age"
                    temporary.write_bytes(b"ciphertext")
                    return digest, str(temporary), str(final)
                with mock.patch.object(capture, "encrypt_chunk", side_effect=fake_encrypt):
                    receipt = capture.finalize("age1test", run_id)
            self.assertEqual(receipt["journals"][0]["snapshot_size"], len(baseline + tail))
            self.assertEqual(receipt["journals"][0]["final_offset"], len(baseline + tail))
            wrapped = json.loads(encrypted[0])
            self.assertEqual(base64.b64decode(wrapped["raw_base64"]), tail)
            self.assertTrue((receipt_dir / f"{run_id}.json").is_file())

    def test_finalize_fails_if_prepared_journal_disappears(self):
        run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); journal = root / "session.jsonl"
            journal.write_bytes(b'{"type":"user"}\n')
            state = root / "state.json"; lock = root / "capture.lock"
            receipts = root / "receipts"; outbox = root / "outbox"; outbox.mkdir()
            user = SimpleNamespace(pw_uid=os.getuid())
            with mock.patch.object(capture, "JOURNAL_ROOT", os.path.realpath(root)), \
                    mock.patch.object(capture, "STATE", str(state)), \
                    mock.patch.object(capture, "LOCK", str(lock)), \
                    mock.patch.object(capture, "RECEIPT_DIR", str(receipts)), \
                    mock.patch.object(capture, "OUTBOX", str(outbox)), \
                    mock.patch("conversation_capture.pwd.getpwnam", return_value=user):
                capture.prepare(run_id)
                journal.unlink()
                with self.assertRaisesRegex(RuntimeError, "disappeared"):
                    capture.finalize("age1test", run_id)

    def test_finalize_encryption_failure_cannot_mint_receipt(self):
        run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); journal = root / "session.jsonl"
            journal.write_bytes(b'{"type":"user"}\n')
            state = root / "state.json"; lock = root / "capture.lock"
            receipts = root / "receipts"; outbox = root / "outbox"; outbox.mkdir()
            user = SimpleNamespace(pw_uid=os.getuid())
            with mock.patch.object(capture, "JOURNAL_ROOT", os.path.realpath(root)), \
                    mock.patch.object(capture, "STATE", str(state)), \
                    mock.patch.object(capture, "LOCK", str(lock)), \
                    mock.patch.object(capture, "RECEIPT_DIR", str(receipts)), \
                    mock.patch.object(capture, "OUTBOX", str(outbox)), \
                    mock.patch("conversation_capture.pwd.getpwnam", return_value=user):
                capture.prepare(run_id)
                with journal.open("ab") as handle:
                    handle.write(b'{"type":"assistant"}\n')
                with mock.patch.object(capture, "encrypt_chunk", side_effect=RuntimeError("encrypt failed")):
                    with self.assertRaisesRegex(RuntimeError, "encrypt failed"):
                        capture.finalize("age1test", run_id)
            self.assertFalse((receipts / f"{run_id}.json").exists())

    def test_pending_ciphertext_recovery_advances_state_before_publication(self):
        run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); outbox = root / "outbox"; outbox.mkdir()
            state_path = root / "state.json"
            identity = "1:2:/journal"
            state = {"offsets":{identity:0}, "runs":{run_id:{
                "sequence":0,"previous":"","chunks":[]}}}
            temporary = outbox / f".{run_id}-000000000000.pending"
            temporary.write_bytes(b"ciphertext")
            digest = __import__("hashlib").sha256(b"ciphertext").hexdigest()
            pending = {"schema":"secure-sandbox-capture-chunk-transaction-v1",
                       "run_id":run_id,"sequence":0,"previous_cipher_sha256":"",
                       "source":"/journal","journal_identity":identity,
                       "start_offset":0,"end_offset":7,"records_sha256":"a" * 64,
                       "cipher_sha256":digest,"temporary":str(temporary),
                       "final":str(outbox / f"{run_id}-000000000000-{digest}.age")}
            with mock.patch.object(capture, "STATE", str(state_path)), \
                    mock.patch.object(capture, "OUTBOX", str(outbox)):
                capture.atomic_json(capture.pending_chunk_path(), pending)
                capture.reconcile_pending(state)
            persisted = json.loads(state_path.read_text())
            self.assertEqual(persisted["runs"][run_id]["sequence"], 1)
            self.assertEqual(persisted["offsets"][identity], 7)
            self.assertFalse((root / "pending-chunk.json").exists())
            self.assertTrue(Path(pending["final"]).exists())

    def test_lifecycle_cli_reserves_stdout_for_one_json_document(self):
        run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        stdout = io.StringIO(); stderr = io.StringIO()
        def finalizer(_recipient, _run_id):
            capture.emit_event({"event":"chunk"})
            return {"schema":"secure-sandbox-capture-final-v1","run_id":run_id}
        with mock.patch.object(sys, "argv", ["capture", "--recipient-file", "unused", "--finalize", run_id]), \
                mock.patch("builtins.open", mock.mock_open(read_data="age1test\n")), \
                mock.patch.object(capture, "finalize", side_effect=finalizer), \
                mock.patch.object(capture.os, "makedirs"), redirect_stdout(stdout), redirect_stderr(stderr):
            capture.main()
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(stdout.getvalue())["run_id"], run_id)
        self.assertEqual(json.loads(stderr.getvalue())["event"], "chunk")


if __name__ == "__main__":
    unittest.main()
