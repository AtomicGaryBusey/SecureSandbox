#!/usr/bin/env python3

import json
import socket
import sys
import types
import unittest
import urllib.parse
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


class UsageSettlementParsingTests(unittest.TestCase):
    def test_extracts_nonstreaming_output_usage(self):
        response = json.dumps(
            {"usage": {"input_tokens": 12, "output_tokens": 7}}
        ).encode()
        self.assertEqual(
            model_broker.response_output_tokens(response, "application/json"), 7
        )

    def test_extracts_final_cumulative_usage_across_split_sse_chunks(self):
        parser = model_broker.StreamingUsage()
        wire = (
            b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":12,"output_tokens":1}}}\n\n'
            b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9}}\n\n'
        )
        parser.feed(wire[:47])
        parser.feed(wire[47:])
        self.assertEqual(parser.finish(), 9)

    def test_rejects_missing_negative_and_boolean_usage(self):
        for value in (
            {},
            {"usage": {"output_tokens": -1}},
            {"usage": {"output_tokens": True}},
        ):
            self.assertIsNone(model_broker.usage_output_tokens(value))


class GoogleOAuthTests(unittest.TestCase):
    def setUp(self):
        model_broker.GOOGLE_TOKEN_CACHE.update(
            access_token="", expires_at=0, profile_sha256=""
        )

    def test_exchanges_signed_assertion_at_fixed_pinned_origin_and_caches_token(self):
        credential = json.dumps({
            "type": "service_account",
            "client_email": "sandbox@example.test",
            "private_key": "reviewed-test-key",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        calls = []

        class Key:
            @staticmethod
            def sign(signing_input, _padding, _hash):
                calls.append(("signed", signing_input.count(b".")))
                return b"signature"

        hashes = types.SimpleNamespace(SHA256=lambda: "sha256")
        serialization = types.SimpleNamespace(
            load_pem_private_key=lambda raw, password: Key()
        )
        padding = types.SimpleNamespace(PKCS1v15=lambda: "pkcs1v15")
        cryptography = types.ModuleType("cryptography")
        hazmat = types.ModuleType("cryptography.hazmat")
        primitives = types.ModuleType("cryptography.hazmat.primitives")
        asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
        primitives.hashes = hashes
        primitives.serialization = serialization
        asymmetric.padding = padding
        crypto_modules = {
            "cryptography": cryptography,
            "cryptography.hazmat": hazmat,
            "cryptography.hazmat.primitives": primitives,
            "cryptography.hazmat.primitives.asymmetric": asymmetric,
        }

        class Response:
            status = 200

            @staticmethod
            def read(_limit):
                return b'{"access_token":"bounded-token","expires_in":3600}'

        class Connection:
            def __init__(self, host, address, port, timeout):
                calls.append((host, address, port, timeout))

            def request(self, method, path, body, headers):
                values = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
                self.assertion = values["assertion"][0]
                calls.append((method, path, headers["Host"], self.assertion.count(".")))

            @staticmethod
            def getresponse():
                return Response()

            @staticmethod
            def close():
                return None

        config = {
            "oauth_ipv4": ["8.8.8.8"],
            "profile_sha256": "a" * 64,
            "upstream_timeout_seconds": 12,
        }
        with mock.patch.dict(sys.modules, crypto_modules), \
             mock.patch.object(model_broker, "FixedAddressHTTPSConnection", Connection), \
             mock.patch.object(model_broker.time, "time", return_value=2_000_000_000):
            self.assertEqual(model_broker.google_access_token(credential, config), "bounded-token")
            self.assertEqual(model_broker.google_access_token("not-json", config), "bounded-token")
        self.assertEqual(calls, [
            ("signed", 1),
            ("oauth2.googleapis.com", "8.8.8.8", 443, 12.0),
            ("POST", "/token", "oauth2.googleapis.com", 2),
        ])

    def test_rejects_unreviewed_token_origin(self):
        credential = json.dumps({
            "type": "service_account",
            "client_email": "sandbox@example.test",
            "private_key": "unused",
            "token_uri": "https://attacker.example/token",
        })
        with self.assertRaisesRegex(ValueError, "credential is invalid"):
            model_broker.google_access_token(credential, {
                "oauth_ipv4": ["8.8.8.8"],
                "profile_sha256": "b" * 64,
                "upstream_timeout_seconds": 12,
            })


if __name__ == "__main__":
    unittest.main()
