#!/usr/bin/env python3

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import conversation_receiver


def chunk_name(body: bytes) -> str:
    return "11111111-1111-4111-8111-111111111111-202610270800-" + hashlib.sha256(body).hexdigest() + ".age"


class ConversationReceiverTests(unittest.TestCase):
    def test_publish_is_no_overwrite_and_idempotent(self):
        body = b"encrypted"
        name = chunk_name(body)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            conversation_receiver.publish_chunk(name, body, hashlib.sha256(body).hexdigest())
            self.assertEqual((Path(directory) / name).read_bytes(), body)
            self.assertFalse((Path(directory) / (name + ".new")).exists())
            with self.assertRaises(conversation_receiver.AlreadyStored):
                conversation_receiver.publish_chunk(name, body, hashlib.sha256(body).hexdigest())
            self.assertEqual((Path(directory) / name).read_bytes(), body)

    def test_complete_stale_temporary_converges(self):
        body = b"encrypted"
        name = chunk_name(body)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            (Path(directory) / (name + ".new")).write_bytes(body)
            conversation_receiver.publish_chunk(name, body, hashlib.sha256(body).hexdigest())
            self.assertEqual((Path(directory) / name).read_bytes(), body)
            self.assertFalse((Path(directory) / (name + ".new")).exists())

    def test_crash_after_link_converges_without_wedging_spool(self):
        body = b"encrypted"
        name = chunk_name(body)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            temporary = Path(directory) / (name + ".new")
            final = Path(directory) / name
            temporary.write_bytes(body)
            os.link(temporary, final)
            self.assertEqual(temporary.stat().st_nlink, 2)
            with self.assertRaises(conversation_receiver.AlreadyStored):
                conversation_receiver.publish_chunk(
                    name, body, hashlib.sha256(body).hexdigest(),
                )
            self.assertFalse(temporary.exists())
            self.assertEqual(final.stat().st_nlink, 1)
            self.assertEqual(conversation_receiver.spool_usage(), (1, len(body)))

    def test_reused_complete_temporary_is_fsynced_before_link(self):
        body = b"encrypted"
        name = chunk_name(body)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory), \
             mock.patch.object(conversation_receiver.os, "fsync", wraps=os.fsync) as synced:
            (Path(directory) / (name + ".new")).write_bytes(body)
            conversation_receiver.publish_chunk(name, body, hashlib.sha256(body).hexdigest())
            self.assertGreaterEqual(synced.call_count, 3)

    def test_partial_stale_temporary_is_replaced(self):
        body = b"encrypted"
        name = chunk_name(body)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            (Path(directory) / (name + ".new")).write_bytes(b"partial")
            conversation_receiver.publish_chunk(name, body, hashlib.sha256(body).hexdigest())
            self.assertEqual((Path(directory) / name).read_bytes(), body)

    def test_entry_limit_bounds_scan(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory), \
             mock.patch.object(conversation_receiver, "MAX_SPOOL_ENTRIES", 2):
            for index in range(3):
                body = str(index).encode()
                (Path(directory) / chunk_name(body)).write_bytes(body)
            with self.assertRaises(conversation_receiver.SpoolFull):
                conversation_receiver.spool_usage()

    def test_untrusted_directory_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            (Path(directory) / "unexpected").write_bytes(b"x")
            with self.assertRaises(ValueError):
                conversation_receiver.spool_usage()

    def test_full_write_retries_short_writes(self):
        body = b"abcdef"
        writes = []

        def short_write(_descriptor, value):
            data = bytes(value[:2])
            writes.append(data)
            return len(data)

        with mock.patch.object(conversation_receiver.os, "write", side_effect=short_write):
            conversation_receiver.write_all(7, body)
        self.assertEqual(b"".join(writes), body)

    def test_symlinked_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, \
             tempfile.TemporaryDirectory() as outside, \
             mock.patch.object(conversation_receiver, "SPOOL", directory):
            body = b"encrypted"
            target = Path(outside) / "target"
            target.write_bytes(body)
            os.symlink(target, Path(directory) / chunk_name(body))
            with self.assertRaises(ValueError):
                conversation_receiver.spool_usage()


if __name__ == "__main__":
    unittest.main()
