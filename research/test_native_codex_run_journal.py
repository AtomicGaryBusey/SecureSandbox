#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from research import native_codex_run_journal as journal
from research.test_native_codex_session_controller import authority, session_lease
from shared import native_stack_session


class NativeCodexRunJournalTests(unittest.TestCase):
    def test_valid_alternate_grant_cannot_drift_within_run_chain(self) -> None:
        runtime = authority()
        original = session_lease(runtime, issued_at=100)
        changed = native_stack_session.make_session_lease(
            lease_profile_id=original["lease_profile_id"],
            session_id=original["session_id"],
            runtime_authority_sha256=original["runtime_authority_sha256"],
            grant_id="55555555-5555-4555-8555-555555555555",
            grant_sha256="5" * 64,
            issued_at=original["issued_at"], expires_at=original["expires_at"])
        session_id = runtime["session_context_binding"]["session_id"]
        unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            common = dict(
                transition_operation_id="11111111-1111-4111-8111-111111111111",
                authority=runtime, scope_unit=unit,
                boot_id_sha256="1" * 64,
                executable_sha256=runtime["harness_binding"][
                    "harness_executable_sha256"],
                lease_started_at=original["issued_at"],
                lease_expires_at=original["expires_at"],
                root=root, trusted_uid=uid, trusted_gid=gid)
            journal.append_event(
                phase="prepared", process_id=None,
                process_start_time_ticks=None, observed_at=100,
                exit_code=None, absence_evidence_sha256=None,
                session_lease=original, **common)
            with self.assertRaisesRegex(
                journal.NativeCodexRunJournalError, "authority_drift"
            ):
                journal.append_event(
                    phase="active", process_id=1234,
                    process_start_time_ticks=5678, observed_at=101,
                    exit_code=None, absence_evidence_sha256=None,
                    session_lease=changed, **common)

    def test_exact_authority_process_lease_and_terminal_summary_chain(self) -> None:
        runtime = authority()
        lease = session_lease(runtime, issued_at=100)
        session_id = runtime["session_context_binding"]["session_id"]
        unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            common = dict(
                transition_operation_id="11111111-1111-4111-8111-111111111111",
                authority=runtime, scope_unit=unit,
                boot_id_sha256="1" * 64,
                executable_sha256=runtime["harness_binding"]["harness_executable_sha256"],
                session_lease=lease,
                lease_started_at=lease["issued_at"],
                lease_expires_at=lease["expires_at"],
                root=root, trusted_uid=uid, trusted_gid=gid)
            prepared = journal.append_event(
                phase="prepared", process_id=None,
                process_start_time_ticks=None, observed_at=100,
                exit_code=None, absence_evidence_sha256=None, **common)
            active = journal.append_event(
                phase="active", process_id=1234,
                process_start_time_ticks=5678, observed_at=101,
                exit_code=None, absence_evidence_sha256=None, **common)
            terminal = journal.append_event(
                phase="terminal", process_id=1234,
                process_start_time_ticks=5678, observed_at=102,
                exit_code=0, absence_evidence_sha256="2" * 64, **common)
            self.assertEqual(active["prior_event_sha256"], prepared["event_sha256"])
            self.assertEqual(terminal["prior_event_sha256"], active["event_sha256"])
            observed = journal.latest(
                session_id, root=root, trusted_uid=uid, trusted_gid=gid)
            self.assertEqual(observed, terminal)
            self.assertEqual(observed["runtime_authority"], runtime)
            self.assertEqual(observed["session_lease"], lease)
            self.assertEqual(observed["lease_sha256"], lease["lease_sha256"])
            self.assertEqual(observed["lease_expires_at"], lease["expires_at"])
            self.assertEqual(
                journal.append_event(
                    phase="terminal", process_id=1234,
                    process_start_time_ticks=5678, observed_at=102,
                    exit_code=0, absence_evidence_sha256="2" * 64, **common),
                terminal,
            )
            with self.assertRaisesRegex(
                journal.NativeCodexRunJournalError, "replay_conflict"
            ):
                journal.append_event(
                    phase="terminal", process_id=1234,
                    process_start_time_ticks=5678, observed_at=103,
                    exit_code=0, absence_evidence_sha256="2" * 64, **common)

    def test_absence_proof_rejects_live_scope_process_and_session_state(self) -> None:
        session_id = "11111111-1111-4111-8111-111111111111"
        unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            states = root / "states"
            proc.mkdir()
            states.mkdir()

            def inactive(*_args, **_kwargs):
                return subprocess.CompletedProcess(
                    [], 0,
                    b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nControlGroup=\n",
                    b"",
                )

            evidence = journal.prove_absence(
                session_id=session_id, scope_unit=unit, process_id=None,
                process_start_time_ticks=None, egress_evidence_sha256="3" * 64,
                session_state_root=states, proc_root=proc, runner=inactive)
            self.assertEqual(len(evidence), 64)

            session = states / session_id
            session.mkdir()
            with self.assertRaisesRegex(
                journal.NativeCodexRunJournalError, "session_state_live"
            ):
                journal.prove_absence(
                    session_id=session_id, scope_unit=unit, process_id=None,
                    process_start_time_ticks=None,
                    egress_evidence_sha256="3" * 64,
                    session_state_root=states, proc_root=proc, runner=inactive)

            def active(*_args, **_kwargs):
                return subprocess.CompletedProcess(
                    [], 0,
                    b"LoadState=loaded\nActiveState=active\nSubState=running\nControlGroup=/system.slice/"
                    + unit.encode("ascii") + b"\n",
                    b"",
                )

            with self.assertRaisesRegex(
                journal.NativeCodexRunJournalError, "scope_ambiguous"
            ):
                journal.prove_absence(
                    session_id=session_id, scope_unit=unit, process_id=None,
                    process_start_time_ticks=None,
                    egress_evidence_sha256="3" * 64,
                    session_state_root=states, proc_root=proc, runner=active)


if __name__ == "__main__":
    unittest.main()
