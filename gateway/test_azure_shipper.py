import json
import os
import tempfile
import unittest

import azure_shipper


class AzureShipperTests(unittest.TestCase):
    def test_config_rejects_unpinned_or_unexpected_endpoint(self):
        value = {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "ingestion_endpoint": "https://example.com",
            "dcr_immutable_id": "dcr-abc",
            "stream_name": "Custom-SecureSandbox_CL",
            "token_ipv4": ["1.1.1.1"],
            "ingestion_ipv4": ["8.8.8.8"],
        }
        with self.assertRaises(ValueError):
            azure_shipper.validate_config(value)
        value["ingestion_endpoint"] = "https://test.ingest.monitor.azure.com"
        value["token_ipv4"] = ["127.0.0.1"]
        with self.assertRaises(ValueError):
            azure_shipper.validate_config(value)

    def test_batch_cursor_advances_only_over_complete_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            old_spool = azure_shipper.SPOOL
            azure_shipper.SPOOL = os.path.join(directory, "current.jsonl")
            try:
                first = {"EventType": "heartbeat", "VmId": "gateway"}
                second = {"EventType": "request_denied", "VmId": "research"}
                with open(azure_shipper.SPOOL, "wb") as handle:
                    handle.write(json.dumps(first).encode() + b"\n")
                    handle.write(json.dumps(second).encode() + b"\n")
                events, identity, position, _ = azure_shipper.next_batch({})
                self.assertEqual(events, [first, second])
                self.assertTrue(identity)
                self.assertEqual(position, os.path.getsize(azure_shipper.SPOOL))
                events, _, _, _ = azure_shipper.next_batch({identity: position})
                self.assertEqual(events, [])
            finally:
                azure_shipper.SPOOL = old_spool


if __name__ == "__main__":
    unittest.main()
