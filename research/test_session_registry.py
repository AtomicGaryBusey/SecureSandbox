#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import session_registry


class SessionRegistryTests(unittest.TestCase):
    def test_discovers_only_workspace_cli_sessions_in_owned_regular_files(self):
        accepted = "11111111-1111-4111-8111-111111111111"
        ignored = "22222222-2222-4222-8222-222222222222"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "session.jsonl"
            records = [
                {"sessionId": accepted, "cwd": session_registry.WORKSPACE, "entrypoint": "cli", "timestamp": "2000-01-01T00:01:00Z"},
                {"sessionId": accepted, "cwd": session_registry.WORKSPACE, "entrypoint": "cli", "timestamp": "2000-01-01T00:00:00Z"},
                {"sessionId": ignored, "cwd": "/tmp", "entrypoint": "cli", "timestamp": "2000-01-01T00:00:00Z"},
                {"sessionId": ignored, "cwd": session_registry.WORKSPACE, "entrypoint": "other", "timestamp": "2000-01-01T00:00:00Z"},
            ]
            journal.write_text("".join(json.dumps(record) + "\n" for record in records))
            (root / "journal-link.jsonl").symlink_to(journal)
            with mock.patch.object(session_registry, "JOURNAL_ROOT", root), mock.patch(
                "session_registry.pwd.getpwnam",
                return_value=SimpleNamespace(pw_uid=os.getuid()),
            ):
                self.assertEqual(
                    session_registry.discover(),
                    {accepted: datetime(2000, 1, 1, 0, 0, tzinfo=timezone.utc)},
                )

    def test_registry_write_is_sorted_atomic_and_world_read_only(self):
        first = "11111111-1111-4111-8111-111111111111"
        second = "22222222-2222-4222-8222-222222222222"
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "sessions.txt"
            with mock.patch.object(session_registry, "REGISTRY", registry):
                session_registry.write_registry(
                    {
                        first: datetime(2000, 1, 1, 0, 2, tzinfo=timezone.utc),
                        second: datetime(2000, 1, 1, 0, 1, tzinfo=timezone.utc),
                    }
                )
            self.assertEqual(
                registry.read_text(encoding="ascii"),
                second + "\t2000-01-01T00:01:00Z\n" + first + "\t2000-01-01T00:02:00Z\n",
            )
            self.assertEqual(registry.stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
