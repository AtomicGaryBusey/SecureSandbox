#!/usr/bin/env python3

import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("conversation_shipper.py")
SPEC = importlib.util.spec_from_file_location("conversation_shipper", MODULE_PATH)
shipper = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(shipper)


class Response:
    status = 201

    def read(self, _limit):
        return b""


class Connection:
    def request(self, *_args, **_kwargs):
        pass

    def getresponse(self):
        return Response()

    def close(self):
        pass


class ConversationShipperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shipper.OUTBOX = str(self.root / "outbox")
        shipper.QUARANTINE = str(self.root / "quarantine")
        Path(shipper.OUTBOX).mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def chunk(self, body: bytes) -> Path:
        digest = hashlib.sha256(body).hexdigest()
        name = f"artifact-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee-000000000001-{digest}.age"
        path = Path(shipper.OUTBOX) / name
        path.write_bytes(body)
        return path

    def test_exact_transport_maximum_is_sent(self):
        path = self.chunk(b"x" * shipper.MAX_CHUNK_BYTES)
        with mock.patch.object(shipper, "Connection", return_value=Connection()), \
             mock.patch.object(shipper.os, "fsync", wraps=os.fsync) as synced:
            shipper.send(str(path))
        self.assertFalse(path.exists())
        self.assertGreaterEqual(synced.call_count, 1)

    def test_transport_maximum_plus_one_is_permanent(self):
        path = self.chunk(b"x" * (shipper.MAX_CHUNK_BYTES + 1))
        with self.assertRaises(shipper.PermanentChunkError):
            shipper.send(str(path))
        quarantined = shipper.quarantine(str(path))
        self.assertTrue(Path(quarantined).is_file())
        self.assertFalse(path.exists())

    def test_hash_mismatch_is_quarantined_without_removing_later_chunk(self):
        first = self.chunk(b"invalid")
        bad_name = first.with_name(first.name[:-68] + "0" * 64 + ".age")
        first.rename(bad_name)
        later = self.chunk(b"later-valid")
        with self.assertRaises(shipper.PermanentChunkError):
            shipper.send(str(bad_name))
        shipper.quarantine(str(bad_name))
        self.assertTrue(later.exists())
        self.assertFalse(bad_name.exists())


if __name__ == "__main__":
    unittest.main()
