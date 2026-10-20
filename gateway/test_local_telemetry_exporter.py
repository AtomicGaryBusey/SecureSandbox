#!/usr/bin/env python3

import json
import unittest
from unittest import mock

import local_telemetry_exporter


class GatewayNormalizationTests(unittest.TestCase):
    @mock.patch("local_telemetry_exporter.open", side_effect=OSError)
    def test_pki_evidence_is_bounded_and_content_free(self, _open):
        generation = "00000000-0000-4000-8000-000000000001"
        result = local_telemetry_exporter.from_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-pki",
            "MESSAGE": json.dumps({
                "event": "pki_expiry_status", "generation_id": generation,
                "minimum_not_after": 123456, "remaining_seconds": 654321,
                "status": "warning", "certificate": "must not escape",
            }),
        })
        self.assertEqual(result["RequestId"], generation)
        self.assertEqual(result["Message"], "warning")
        self.assertNotIn("must not escape", json.dumps(result))

    def test_malformed_pki_evidence_is_rejected(self):
        self.assertIsNone(local_telemetry_exporter.from_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-pki",
            "MESSAGE": '{"event":"pki_expiry_status","generation_id":"bad"}',
        }))

    @mock.patch("local_telemetry_exporter.open", side_effect=OSError)
    def test_broker_metadata_excludes_payloads(self, _open):
        value = {
            "event": "request_complete",
            "request_id": "abc",
            "request_bytes": 10,
            "response_bytes": 20,
            "status": 200,
            "run_id": "00000000-0000-4000-8000-000000000001",
            "prompt": "do not retain",
        }
        result = local_telemetry_exporter.from_journal(
            {"_SYSTEMD_UNIT": "model-broker.service", "MESSAGE": json.dumps(value)}
        )
        self.assertEqual(result["RequestId"], "abc")
        self.assertEqual(result["RunId"], value["run_id"])
        self.assertNotIn("do not retain", json.dumps(result))

    def test_unrelated_message_is_ignored(self):
        self.assertIsNone(local_telemetry_exporter.from_journal({"MESSAGE": "hello"}))

    @mock.patch("local_telemetry_exporter.open", side_effect=OSError)
    def test_lease_lifecycle_is_content_free(self, _open):
        value = {
            "event": "lease_issued", "run_id": "00000000-0000-4000-8000-000000000001",
            "lease_id": "00000000-0000-4000-8000-000000000002", "profile": "short",
            "expires_at": 1234, "prompt": "must not escape",
        }
        result = local_telemetry_exporter.from_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-lease", "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["RequestId"], value["lease_id"])
        self.assertEqual(result["Message"], "")
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("local_telemetry_exporter.open", side_effect=OSError)
    def test_archive_lifecycle_retains_only_cipher_metadata(self, _open):
        name = "00000000-0000-4000-8000-000000000001-000000000000-" + "b" * 64 + ".age"
        result = local_telemetry_exporter.from_journal({
            "_SYSTEMD_UNIT": "conversation-azure-shipper.service",
            "MESSAGE": json.dumps({"event":"conversation_blob_uploaded","name":name,"bytes":714,"response":"must not escape"}),
        })
        self.assertEqual(result["RunId"], "00000000-0000-4000-8000-000000000001")
        self.assertEqual(result["RequestId"], "b" * 64)
        self.assertNotIn("must not escape", json.dumps(result))

    def test_repeated_identical_inbound_drops_are_throttled(self):
        throttle = local_telemetry_exporter.InboundDropThrottle(interval=300)
        event = {
            "EventType": "firewall_inbound_drop",
            "Destination": "10.0.0.255",
            "DestinationPort": 17500,
        }
        self.assertTrue(throttle.allow(event, 1000.0))
        self.assertFalse(throttle.allow(event, 1100.0))
        self.assertTrue(throttle.allow(event, 1300.0))
        self.assertTrue(throttle.allow({"EventType": "request_denied"}, 1100.0))


if __name__ == "__main__":
    unittest.main()
