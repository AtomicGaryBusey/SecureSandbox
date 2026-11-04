#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from research import native_codex_run_journal as journal
from research.test_native_codex_session_controller import authority


class NativeCodexRunJournalTests(unittest.TestCase):
    def test_exact_authority_process_lease_and_terminal_summary_chain(self) -> None:
        runtime = authority()
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
                lease_started_at=100, lease_expires_at=200,
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
            self.assertEqual(observed["lease_expires_at"], 200)
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
