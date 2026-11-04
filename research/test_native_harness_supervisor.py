#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from research import native_harness_supervisor as supervisor
from shared import native_egress
from shared.test_native_egress import NOW, inference_grant


class NativeHarnessSupervisorTests(unittest.TestCase):
    def test_grant_bytes_and_identity_come_from_same_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "native-egress"
            root.mkdir(mode=0o700)
            grant_path = root / "active.json"
            grant = inference_grant()
            grant_path.write_bytes(native_egress.canonical_bytes(grant))
            grant_path.chmod(0o640)
            observed, identity = supervisor.observed_grant(
                grant_path,
                gid=os.getgid(),
                now=NOW,
                expected_uid=os.geteuid(),
            )
            self.assertEqual(observed, grant["grant_sha256"])
            self.assertEqual(identity[0:2], (
                grant_path.stat().st_dev, grant_path.stat().st_ino
            ))
            self.assertEqual(identity[2], grant_path.stat().st_size)

    def test_monitor_exits_cleanly_only_on_explicit_stop(self) -> None:
        calls = 0

        def stopping() -> bool:
            nonlocal calls
            calls += 1
            return calls > 2

        with mock.patch.object(
            supervisor,
            "observed_grant",
            return_value=("a" * 64, (1, 2, 3, 4)),
        ) as observed:
            supervisor.monitor(
                Path("/grant"), gid=42, now=lambda: 1, sleep=lambda _value: None,
                stopping=stopping,
            )
        self.assertEqual(observed.call_count, 3)

    def test_monitor_fails_on_replacement_even_with_same_digest(self) -> None:
        with mock.patch.object(
            supervisor,
            "observed_grant",
            side_effect=[
                ("a" * 64, (1, 2, 3, 4)),
                ("a" * 64, (1, 9, 3, 4)),
            ],
        ):
            with self.assertRaisesRegex(
                supervisor.NativeHarnessSupervisorError, "grant_changed"
            ):
                supervisor.monitor(
                    Path("/grant"), gid=42, now=lambda: 1,
                    sleep=lambda _value: None, stopping=lambda: False,
                )

    def test_monitor_fails_closed_when_grant_disappears(self) -> None:
        with mock.patch.object(
            supervisor,
            "observed_grant",
            side_effect=[("a" * 64, (1, 2, 3, 4)), FileNotFoundError()],
        ):
            with self.assertRaisesRegex(
                supervisor.NativeHarnessSupervisorError, "grant_lost"
            ):
                supervisor.monitor(
                    Path("/grant"), gid=42, now=lambda: 1,
                    sleep=lambda _value: None, stopping=lambda: False,
                )


if __name__ == "__main__":
    unittest.main()
