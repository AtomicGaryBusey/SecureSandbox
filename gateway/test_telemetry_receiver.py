#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import telemetry_receiver


class NormalizeTests(unittest.TestCase):
    @mock.patch("time.gmtime")
    @mock.patch("time.strftime", return_value="2026-10-15T08:00:00Z")
    def test_server_supplies_time_and_defaults(self, _strftime, _gmtime):
        result = telemetry_receiver.normalize({"EventType": "heartbeat"})
        self.assertEqual(result["TimeGenerated"], "2026-10-15T08:00:00Z")
        self.assertEqual(result["DestinationPort"], 0)
        self.assertEqual(result["Message"], "")

    def test_rejects_missing_event_type(self):
        with self.assertRaises(ValueError):
            telemetry_receiver.normalize({})

    def test_rejects_wrong_integer_type(self):
        with self.assertRaises(ValueError):
            telemetry_receiver.normalize(
                {"EventType": "request_complete", "Status": "200"}
            )

    def test_truncates_strings(self):
        result = telemetry_receiver.normalize(
            {"EventType": "notice", "Message": "x" * 2000}
        )
        self.assertEqual(len(result["Message"]), telemetry_receiver.STRING_LIMIT)

    def test_append_and_rotation_fsync_the_spool_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "current.jsonl"
            lock = Path(directory) / ".spool.lock"
            spool.write_bytes(b"old\n")
            with mock.patch.object(telemetry_receiver, "SPOOL", str(spool)), \
                 mock.patch.object(telemetry_receiver, "SPOOL_LOCK", str(lock)), \
                 mock.patch.object(telemetry_receiver, "MAX_FILE", 1), \
                 mock.patch.object(telemetry_receiver.os, "fsync", wraps=os.fsync) as synced:
                telemetry_receiver.append_events([{"EventType": "test"}])
            self.assertEqual((Path(str(spool) + ".1")).read_bytes(), b"old\n")
            self.assertEqual(json.loads(spool.read_text()), {"EventType": "test"})
            self.assertGreaterEqual(synced.call_count, 2)


if __name__ == "__main__":
    unittest.main()
