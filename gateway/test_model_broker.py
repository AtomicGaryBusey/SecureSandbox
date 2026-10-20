#!/usr/bin/env python3

import socket
import unittest
import uuid
from unittest import mock

import model_broker


class AddressPolicyTests(unittest.TestCase):
    def test_rejects_private_address(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))]
        with mock.patch("socket.getaddrinfo", return_value=answer):
            with self.assertRaises(ValueError):
                model_broker.validate_global_addresses("example.test", 443)

    def test_rejects_metadata_address(self):
        answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        ]
        with mock.patch("socket.getaddrinfo", return_value=answer):
            with self.assertRaises(ValueError):
                model_broker.validate_global_addresses("example.test", 443)

    def test_rejects_mixed_public_and_private_answers(self):
        answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=answer):
            with self.assertRaises(ValueError):
                model_broker.validate_global_addresses("example.test", 443)

    def test_accepts_public_ipv4(self):
        answer = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        with mock.patch("socket.getaddrinfo", return_value=answer):
            self.assertEqual(
                model_broker.validate_global_addresses("example.test", 443),
                ["93.184.216.34"],
            )


class RequestPolicyTests(unittest.TestCase):
    def test_rejects_server_side_web_search_type(self):
        payload = {"tools": [{"type": "web_search_20250305", "name": "search"}]}
        self.assertTrue(model_broker.contains_forbidden_remote_tool(payload))

    def test_rejects_any_noncustom_server_tool_type(self):
        payload = {"tools": [{"type": "code_execution_20250522", "name": "runner"}]}
        self.assertTrue(model_broker.contains_forbidden_remote_tool(payload))

    def test_rejects_server_side_web_fetch_name(self):
        payload = {"tools": [{"name": "web_fetch", "input_schema": {}}]}
        self.assertTrue(model_broker.contains_forbidden_remote_tool(payload))

    def test_allows_claude_code_local_tool(self):
        payload = {"tools": [{"name": "Bash", "input_schema": {"type": "object"}}]}
        self.assertFalse(model_broker.contains_forbidden_remote_tool(payload))

    def test_rejects_image_content(self):
        payload = {"messages": [{"content": [{"type": "image"}]}]}
        self.assertTrue(model_broker.contains_image_input(payload))


class CorrelationHeaderTests(unittest.TestCase):
    def test_accepts_canonical_uuid4_and_named_run_markers(self):
        value = str(uuid.uuid4())
        self.assertEqual(model_broker.canonical_request_id(value), value)
        self.assertEqual(model_broker.canonical_run_id(value), value)
        self.assertEqual(model_broker.canonical_run_id("preflight"), "preflight")
        self.assertEqual(model_broker.canonical_run_id("boundary-test"), "boundary-test")

    def test_rejects_missing_or_untrusted_correlation_values(self):
        for value in (None, "", "not-a-uuid", str(uuid.uuid1())):
            with self.assertRaises(ValueError):
                model_broker.canonical_request_id(value)
        with self.assertRaises(ValueError):
            model_broker.canonical_run_id("attacker-chosen-label")


if __name__ == "__main__":
    unittest.main()
