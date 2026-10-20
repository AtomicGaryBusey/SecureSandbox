#!/usr/bin/env python3

import unittest
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


if __name__ == "__main__":
    unittest.main()
