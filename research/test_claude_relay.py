#!/usr/bin/env python3

import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import claude_relay


class SafeRequestPathTests(unittest.TestCase):
    def test_strips_query_parameters(self):
        self.assertEqual(
            claude_relay.safe_request_path("/api/example?token=must-not-log"),
            "/api/example",
        )

    def test_bounds_logged_path(self):
        self.assertEqual(len(claude_relay.safe_request_path("/" + "a" * 500)), 256)

    def test_query_diagnostics_keep_only_bounded_keys(self):
        self.assertEqual(
            claude_relay.safe_query_keys("/v1/messages?beta=secret&flag=yes&beta=other"),
            ["beta", "flag"],
        )
        self.assertNotIn("secret", repr(claude_relay.safe_query_keys("/?token=secret")))


class CanonicalApiPathTests(unittest.TestCase):
    def test_accepts_approved_paths_without_query(self):
        for path in claude_relay.ALLOWED_PATHS:
            self.assertEqual(claude_relay.canonical_api_path(path), path)

    def test_strips_exact_beta_true_marker(self):
        for path in claude_relay.ALLOWED_PATHS:
            self.assertEqual(
                claude_relay.canonical_api_path(path + "?beta=true"), path
            )

    def test_rejects_every_other_query_form(self):
        for query in (
            "beta=false",
            "beta=true&other=1",
            "other=1&beta=true",
            "beta=True",
            "beta=true&",
            "beta%3Dtrue",
        ):
            self.assertIsNone(
                claude_relay.canonical_api_path("/v1/messages?" + query)
            )

    def test_rejects_unapproved_path_and_fragment(self):
        self.assertIsNone(claude_relay.canonical_api_path("/v1/models?beta=true"))
        self.assertIsNone(claude_relay.canonical_api_path("/v1/messages#fragment"))


class RunIdTests(unittest.TestCase):
    def test_reads_only_valid_root_marker_values(self):
        with TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"
            with mock.patch.object(claude_relay, "RUN_ID_FILE", str(marker)):
                self.assertEqual(claude_relay.current_run_id(), "preflight")
                value = str(uuid.uuid4())
                marker.write_text(value + "\n", encoding="ascii")
                self.assertEqual(claude_relay.current_run_id(), value)
                marker.write_text("attacker-label\n", encoding="ascii")
                self.assertEqual(claude_relay.current_run_id(), "preflight")


if __name__ == "__main__":
    unittest.main()
