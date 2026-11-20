#!/usr/bin/env python3
"""Tests for the bounded visible acceptance ceremony runner."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name(
    "harness-lifecycle-acceptance-ceremony-burst.py"
)
SPEC = importlib.util.spec_from_file_location("ceremony_burst", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BURST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BURST
SPEC.loader.exec_module(BURST)


class FakeStdout:
    def __init__(self, value: bytes):
        self.value = io.BytesIO(value)

    def read(self, size: int = -1) -> bytes:
        return self.value.read(size)


class FakeProcess:
    def __init__(self, value: bytes, returncode: int = 0):
        self.stdout = FakeStdout(value)
        self.returncode = returncode
        self.terminated = False

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True


class CeremonyBurstTests(unittest.TestCase):
    def next_value(self, case_id: str = "reject-stale-metadata",
                   driver: str = "host-provenance-fixture",
                   category: str = "provenance", **changes):
        value = {
            "status": "pending",
            "case": {
                "case_id": case_id, "category": category,
                "destructive": False, "requires_touch_id": False,
                "requires_reboot": False,
                "procedure": {"driver": driver, "interaction": "none"},
            },
        }
        value["case"].update(changes)
        return value

    def completed(self, value: dict) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            [], 0, json.dumps(value).encode(), b"",
        )

    def test_eligible_case_accepts_only_fixed_noninteractive_drivers(self):
        self.assertEqual(
            BURST.eligible_case(self.next_value()),
            ("reject-stale-metadata", "harness-lifecycle-acceptance-provenance.py"),
        )
        self.assertIsNone(BURST.eligible_case(self.next_value(
            driver="research-qualification-fixture", category="qualification",
        )))
        for field in ("destructive", "requires_touch_id", "requires_reboot"):
            value = self.next_value(**{field: True})
            with self.assertRaisesRegex(
                    BURST.CeremonyBurstError, "next_case_not_burst_eligible"):
                BURST.eligible_case(value)
        value = self.next_value()
        value["case"]["procedure"]["interaction"] = "touch-id"
        with self.assertRaisesRegex(
                BURST.CeremonyBurstError, "next_case_not_burst_eligible"):
            BURST.eligible_case(value)

    def test_query_next_uses_protected_cli_and_closed_environment(self):
        value = self.next_value()
        runner = mock.Mock(return_value=self.completed(value))
        release = Path("/protected/release")
        observed = BURST.query_next(
            release, Path("/campaign"), Path("/observations"), runner=runner,
        )
        self.assertEqual(observed, value)
        args, kwargs = runner.call_args
        self.assertEqual(args[0][0:3], ["/usr/bin/python3", "-I", str(
            release / "scripts/harness-lifecycle-acceptance.py")])
        self.assertEqual(kwargs["cwd"], Path("/"))
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"], BURST.clean_environment())

    def test_run_driver_is_one_sudo_process_and_private_exclusive_log(self):
        result = {
            "status": "recorded", "case_id": "reject-stale-metadata",
            "authority": "acceptance-evidence-only", "record_sha256": "a" * 64,
        }
        raw = BURST.canonical(result)
        process = FakeProcess(raw)
        popen = mock.Mock(return_value=process)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                BURST.sys, "stdout", mock.Mock(buffer=io.BytesIO())):
            log = Path(temporary) / "case.log"
            observed = BURST.run_driver(
                ["/usr/bin/sudo", "--", "/usr/bin/true"], log,
                "reject-stale-metadata", popen=popen,
            )
            self.assertEqual(observed, result)
            self.assertEqual(log.read_bytes(), raw)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            command = popen.call_args.args[0]
            self.assertEqual(command[:2], ["/usr/bin/sudo", "--"])
            self.assertNotIn("-v", command)
            self.assertNotIn("-s", command)
            with self.assertRaises(FileExistsError):
                BURST.run_driver(command, log, "reject-stale-metadata", popen=popen)

    def test_run_driver_retains_rejection_and_never_retries(self):
        raw = b'{"status":"rejected","error":"fixture_failed"}\n'
        popen = mock.Mock(return_value=FakeProcess(raw, returncode=1))
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                BURST.sys, "stdout", mock.Mock(buffer=io.BytesIO())):
            log = Path(temporary) / "case.log"
            with self.assertRaisesRegex(
                    BURST.CeremonyBurstError, "driver_rejected"):
                BURST.run_driver(
                    ["/usr/bin/sudo", "--", "/usr/bin/false"], log,
                    "reject-stale-metadata", popen=popen,
                )
            self.assertEqual(log.read_bytes(), raw)
            popen.assert_called_once()

    def test_execute_revalidates_next_between_distinct_sudo_processes(self):
        first = self.next_value()
        second = self.next_value(
            case_id="reject-release-rollback",
            driver="host-archive-fixture", category="archive",
        )
        boundary = self.next_value(
            case_id="qualify-runtime-isolation",
            driver="research-qualification-fixture", category="qualification",
        )
        sequence = iter([first, second, second, boundary, boundary])
        run_driver = mock.Mock(side_effect=[
            {"record_sha256": "1" * 64}, {"record_sha256": "2" * 64},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            campaign_root = home / "Library/Application Support/SecureSandbox/harness-acceptance"
            observations = campaign_root / "observations"
            handoff = home / "SecureSandbox-Acceptance-Handoff"
            observations.mkdir(parents=True, mode=0o700)
            handoff.mkdir(mode=0o700)
            campaign_root.chmod(0o700)
            observations.chmod(0o700)
            handoff.chmod(0o700)
            campaign = campaign_root / "campaign.json"
            campaign.write_text(json.dumps({
                "source_commit": "a" * 40,
                "campaign_id": "12345678-1234-4123-8123-123456789abc",
            }))
            campaign.chmod(0o600)
            account = mock.Mock(pw_dir=str(home))
            with mock.patch.object(BURST.os, "getuid", return_value=os.getuid()), \
                    mock.patch.object(BURST.os, "geteuid", return_value=501), \
                    mock.patch.object(BURST.os, "isatty", return_value=True), \
                    mock.patch.object(BURST.pwd, "getpwuid", return_value=account), \
                    mock.patch.object(BURST, "protected_release",
                                      return_value=Path("/protected/release")), \
                    mock.patch.object(BURST, "query_next",
                                      side_effect=lambda *a, **k: next(sequence)) as query, \
                    mock.patch.object(BURST, "run_driver", run_driver), \
                    mock.patch.object(BURST, "emit"):
                result = BURST.execute()
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["completed_cases"], [
            "reject-stale-metadata", "reject-release-rollback",
        ])
        self.assertEqual(result["next_case"], "qualify-runtime-isolation")
        self.assertEqual(query.call_count, 5)
        self.assertEqual(run_driver.call_count, 2)
        first_command = run_driver.call_args_list[0].args[0]
        second_command = run_driver.call_args_list[1].args[0]
        self.assertEqual(first_command[:2], ["/usr/bin/sudo", "--"])
        self.assertEqual(second_command[:2], ["/usr/bin/sudo", "--"])
        first_case = first_command[first_command.index("--case") + 1]
        second_case = second_command[second_command.index("--case") + 1]
        self.assertNotEqual(first_case, second_case)

    def test_execute_stops_if_protected_next_does_not_advance(self):
        value = self.next_value()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            campaign_root = home / "Library/Application Support/SecureSandbox/harness-acceptance"
            observations = campaign_root / "observations"
            handoff = home / "SecureSandbox-Acceptance-Handoff"
            observations.mkdir(parents=True, mode=0o700)
            handoff.mkdir(mode=0o700)
            campaign_root.chmod(0o700)
            observations.chmod(0o700)
            handoff.chmod(0o700)
            campaign = campaign_root / "campaign.json"
            campaign.write_text(json.dumps({
                "source_commit": "a" * 40,
                "campaign_id": "12345678-1234-4123-8123-123456789abc",
            }))
            campaign.chmod(0o600)
            account = mock.Mock(pw_dir=str(home))
            with mock.patch.object(BURST.os, "getuid", return_value=os.getuid()), \
                    mock.patch.object(BURST.os, "geteuid", return_value=501), \
                    mock.patch.object(BURST.os, "isatty", return_value=True), \
                    mock.patch.object(BURST.pwd, "getpwuid", return_value=account), \
                    mock.patch.object(BURST, "protected_release",
                                      return_value=Path("/protected/release")), \
                    mock.patch.object(BURST, "query_next", return_value=value), \
                    mock.patch.object(BURST, "run_driver",
                                      return_value={"record_sha256": "1" * 64}), \
                    mock.patch.object(BURST, "emit"):
                with self.assertRaisesRegex(
                        BURST.CeremonyBurstError, "next_case_did_not_advance"):
                    BURST.execute()

    def test_main_emits_one_terminal_record_without_status_collision(self):
        result = {
            "status": "stopped", "completed_cases": ["one"],
            "next_case": "qualify-runtime-isolation",
            "reason": "next_driver_not_burst_eligible",
        }
        with mock.patch.object(BURST, "execute", return_value=result), \
                mock.patch.object(BURST, "emit") as emit:
            self.assertEqual(BURST.main([]), 0)
        emit.assert_called_once_with(
            "stopped", "result", completed_cases=["one"],
            next_case="qualify-runtime-isolation",
            reason="next_driver_not_burst_eligible",
        )


if __name__ == "__main__":
    unittest.main()
