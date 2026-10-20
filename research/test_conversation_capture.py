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


if __name__ == "__main__":
    unittest.main()
