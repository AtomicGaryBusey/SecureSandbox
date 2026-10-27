#!/usr/bin/env python3

import json
import os
import tempfile
import stat
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease_watchdog as watchdog


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.run_id = str(uuid.uuid4()); self.lease_id = str(uuid.uuid4())
        self.run_file = self.root / "run-id"; self.lease_file = self.root / "run-lease.json"
        self.evidence_file = self.root / "evidence-run-id"
        self.process_file = self.root / "run-process.json"
        self.lock_file = self.root / "run-lease.lock"
        self.close_lock_file = self.root / "run-close.lock"
        self.lifecycle_dir = self.root / "lifecycle"
        self.lifecycle_file = self.lifecycle_dir / "active.json"
        self.failure_file = self.lifecycle_dir / "failure-latched.json"
        self.approval_fence = self.lifecycle_dir / "execution-approval-migration-fence.json"
        self.acceptance_permit = self.lifecycle_dir / "execution-approval-acceptance-permit.json"
        self.completed = self.lifecycle_dir / "completed"
        self.receipts = self.lifecycle_dir / "capture-receipts"
        self.proc = self.root / "proc"; self.proc.mkdir()
        self.patches = [
            mock.patch.object(watchdog, "RUN_DIRECTORY", self.root),
            mock.patch.object(watchdog, "RUN_ID_FILE", self.run_file),
            mock.patch.object(watchdog, "EVIDENCE_RUN_ID_FILE", self.evidence_file),
            mock.patch.object(watchdog, "LEASE_FILE", self.lease_file),
            mock.patch.object(watchdog, "PROCESS_FILE", self.process_file),
            mock.patch.object(watchdog, "LOCK_FILE", self.lock_file),
            mock.patch.object(watchdog, "CLOSE_LOCK_FILE", self.close_lock_file),
            mock.patch.object(watchdog, "LIFECYCLE_DIRECTORY", self.lifecycle_dir),
            mock.patch.object(watchdog, "LIFECYCLE_FILE", self.lifecycle_file),
            mock.patch.object(watchdog, "FAILURE_FILE", self.failure_file),
            mock.patch.object(watchdog, "EXECUTION_APPROVAL_MIGRATION_FENCE", self.approval_fence),
            mock.patch.object(watchdog, "EXECUTION_APPROVAL_ACCEPTANCE_PERMIT", self.acceptance_permit),
            mock.patch.object(watchdog, "COMPLETED_DIRECTORY", self.completed),
            mock.patch.object(watchdog, "CAPTURE_RECEIPTS", self.receipts),
            mock.patch.object(watchdog, "PROC", self.proc),
            mock.patch.object(watchdog, "TRUSTED_UID", os.getuid()),
            mock.patch("run_lease_watchdog.os.chown"),
            mock.patch("run_lease_watchdog.os.fchown"),
            mock.patch("run_lease_watchdog.pwd.getpwnam", return_value=type("User", (), {"pw_uid": os.getuid()})()),
            mock.patch("run_lease_watchdog.stop_agent_user_manager"),
            mock.patch("run_lease_watchdog.capture_operation", return_value={"run_id":self.run_id,"final_sequence":0}),
        ]
        for patch in self.patches: patch.start()

    def tearDown(self):
        mock.patch.stopall(); self.temp.cleanup()

    def test_arm_publishes_admission_last_with_durable_active_lifecycle(self):
        value = watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertEqual(value["run_id"], self.run_id)
        self.assertEqual(self.lease_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.process_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.process_file.read_text())["ready"], False)
        self.assertEqual(self.run_file.read_text().strip(), self.run_id)
        lifecycle = json.loads(self.lifecycle_file.read_text())
        self.assertEqual(lifecycle["phase"], "active")
        self.assertEqual(lifecycle["unit"], watchdog.unit_name(self.run_id))
        watchdog.os.chown.assert_any_call(self.process_file.with_name(
            f".{self.process_file.name}.{os.getpid()}.new"), 0, 0)

    def test_arm_rejects_existing_lifecycle_and_preexisting_agent_processes(self):
        with mock.patch("run_lease_watchdog.process_ids_for_uid_strict", return_value={44}):
            with self.assertRaisesRegex(RuntimeError, "before run arm"):
                watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with self.assertRaises(FileExistsError):
            watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)

    def test_arm_refuses_an_incomplete_policy_install(self):
        pending = self.root / "install.pending"; pending.write_text("pending\n")
        with mock.patch.object(watchdog, "INSTALL_PENDING", pending):
            with self.assertRaises(FileExistsError):
                watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertFalse(self.run_file.exists())

    def test_arm_refuses_execution_approval_migration_fence(self):
        self.lifecycle_dir.mkdir(parents=True)
        self.approval_fence.write_text("{}\n", encoding="ascii")
        with self.assertRaisesRegex(PermissionError, "migration has closed Research admission"):
            watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertFalse(self.run_file.exists())

    def test_fence_admits_and_consumes_only_exact_bounded_acceptance_context(self):
        self.lifecycle_dir.mkdir(parents=True)
        self.approval_fence.write_text("{}\n", encoding="ascii")
        session_id = str(uuid.uuid4())
        now = int(__import__("time").time())
        permit = {
            "schema":"secure-sandbox-execution-approval-acceptance-permit-v1",
            "status":"ready", "transaction_id":str(uuid.uuid4()),
            "generation_id":str(uuid.uuid4()), "generation_epoch":1,
            "run_id":self.run_id, "session_id":session_id,
            "source_id":str(uuid.uuid4()), "code_sha256":"a" * 64,
            "fixture_manifest_sha256":"b" * 64, "timeout_seconds":5,
            "runtime_image_id":"sha256:" + "c" * 64, "expires_at":now + 120,
            "acceptance_attempt_id":str(uuid.uuid4()), "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "acceptance_binding_sha256":"d" * 64,
        }
        watchdog.atomic_json(self.acceptance_permit, permit)
        watchdog.arm(self.run_id, self.lease_id, now + 60, session_id)
        self.assertEqual(json.loads(self.acceptance_permit.read_text())["status"], "consumed")
        lifecycle = json.loads(self.lifecycle_file.read_text())
        self.assertEqual(lifecycle["execution_approval_acceptance"]["source_id"], permit["source_id"])

    def test_acceptance_permit_is_not_consumed_before_arm_preconditions_pass(self):
        self.lifecycle_dir.mkdir(parents=True)
        self.approval_fence.write_text("{}\n", encoding="ascii")
        now = int(__import__("time").time())
        permit = {
            "schema":"secure-sandbox-execution-approval-acceptance-permit-v1",
            "status":"ready", "transaction_id":str(uuid.uuid4()),
            "generation_id":str(uuid.uuid4()), "generation_epoch":1,
            "run_id":self.run_id, "session_id":str(uuid.uuid4()),
            "source_id":str(uuid.uuid4()), "code_sha256":"a" * 64,
            "fixture_manifest_sha256":"b" * 64, "timeout_seconds":5,
            "runtime_image_id":"sha256:" + "c" * 64, "expires_at":now + 120,
            "acceptance_attempt_id":str(uuid.uuid4()), "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "acceptance_binding_sha256":"d" * 64,
        }
        watchdog.atomic_json(self.acceptance_permit, permit)
        pending = self.root / "install.pending"
        pending.write_text("pending\n", encoding="ascii")
        with mock.patch.object(watchdog, "INSTALL_PENDING", pending), \
                self.assertRaisesRegex(FileExistsError, "already armed"):
            watchdog.arm(self.run_id, self.lease_id, now + 60, permit["session_id"])
        self.assertEqual(json.loads(self.acceptance_permit.read_text()), permit)

    def test_arm_transition_failure_is_durably_latched_without_admission(self):
        with mock.patch("run_lease_watchdog.capture_operation", side_effect=RuntimeError("capture failed")):
            with self.assertRaisesRegex(RuntimeError, "capture failed"):
                watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertFalse(self.run_file.exists())
        self.assertEqual(json.loads(self.lifecycle_file.read_text())["phase"], "failure_latched")
        self.assertTrue(self.failure_file.exists())

    def test_close_revokes_admission_kills_cgroup_and_retains_state_for_commit(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with mock.patch("run_lease_watchdog.kill_run_cgroup") as kill, \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            state = watchdog.close(self.run_id)
        kill.assert_called_once_with(watchdog.unit_name(self.run_id))
        self.assertEqual(state["phase"], "local_closed")
        self.assertFalse(self.run_file.exists())
        self.assertTrue(self.lease_file.exists())

    def test_active_snapshot_requires_matching_lifecycle_and_admission(self):
        lease = watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        self.assertEqual(watchdog.validated_snapshot(lease)["phase"], "active")
        self.run_file.unlink()
        with self.assertRaisesRegex(RuntimeError, "admission marker"):
            watchdog.validated_snapshot(lease)
        self.run_file.write_text(self.run_id + "\n", encoding="ascii")
        self.run_file.chmod(0o644)
        state = json.loads(self.lifecycle_file.read_text()); state["lease_id"] = str(uuid.uuid4())
        watchdog.atomic_json(self.lifecycle_file, state, 0o644)
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            watchdog.validated_snapshot(lease)

    def test_close_accepts_root_recorded_empty_scope_after_unit_unloads(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        registration = json.loads(self.process_file.read_text())
        registration.update({"ready":True,"scope_empty":True,"scope_pid":99,
                             "exit_status":0,"exited_at":1})
        watchdog.atomic_json(self.process_file, registration)
        with mock.patch("run_lease_watchdog.kill_run_cgroup", side_effect=RuntimeError("unit gone")), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            state = watchdog.close(self.run_id)
        self.assertEqual(state["phase"], "local_closed")

    def test_claimed_but_unready_supervisor_is_not_an_empty_scope_receipt(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        registration = json.loads(self.process_file.read_text())
        registration.update({"supervisor_pid":99,"supervisor_start_time":100})
        watchdog.atomic_json(self.process_file, registration)
        state = json.loads(self.lifecycle_file.read_text())
        self.assertFalse(watchdog.recorded_scope_empty(state))
        registration["scope_empty"] = True
        watchdog.atomic_json(self.process_file, registration)
        self.assertTrue(watchdog.recorded_scope_empty(state))

    def test_close_releases_lifecycle_lock_while_waiting_for_supervisor_receipt(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        registration = json.loads(self.process_file.read_text())
        registration.update({"ready":True,"scope_pid":99})
        watchdog.atomic_json(self.process_file, registration)
        def vanish_and_publish(_unit):
            descriptor = os.open(self.lock_file, os.O_RDWR)
            try:
                __import__("fcntl").flock(descriptor, __import__("fcntl").LOCK_EX | __import__("fcntl").LOCK_NB)
                current = json.loads(self.process_file.read_text())
                current.update({"scope_empty":True,"exit_status":0,"exited_at":1})
                watchdog.atomic_json(self.process_file, current)
            finally:
                os.close(descriptor)
            raise RuntimeError("scope unloaded")
        with mock.patch("run_lease_watchdog.kill_run_cgroup", side_effect=vanish_and_publish), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            self.assertEqual(watchdog.close(self.run_id)["phase"], "local_closed")

    def test_close_failure_latches_and_never_restores_admission(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        registration = json.loads(self.process_file.read_text())
        registration["ready"] = True
        registration["scope_pid"] = 99
        watchdog.atomic_json(self.process_file, registration)
        with mock.patch("run_lease_watchdog.kill_run_cgroup", side_effect=RuntimeError("failed")), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            with self.assertRaisesRegex(RuntimeError, "not proven"):
                watchdog.close(self.run_id)
        self.assertFalse(self.run_file.exists())
        self.assertTrue(self.failure_file.exists())
        self.assertEqual(json.loads(self.lifecycle_file.read_text())["phase"], "failure_latched")

    def test_renew_requires_same_identity_and_increasing_expiry(self):
        initial = int(__import__("time").time()) + 60
        watchdog.arm(self.run_id, self.lease_id, initial)
        lease = {"schema": watchdog.SCHEMA, "run_id": self.run_id, "lease_id": self.lease_id, "expires_at": initial}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease):
            renewed = watchdog.renew(self.run_id, self.lease_id, initial + 60)
        self.assertEqual(renewed["expires_at"], initial + 60)

    def test_expire_shortens_only_matching_run(self):
        initial = int(__import__("time").time()) + 60
        watchdog.arm(self.run_id, self.lease_id, initial)
        lease = {"schema": watchdog.SCHEMA, "run_id": self.run_id, "lease_id": self.lease_id, "expires_at": initial}
        with mock.patch("run_lease_watchdog.load_lease", return_value=lease):
            with self.assertRaises(PermissionError): watchdog.expire(str(uuid.uuid4()))
            expired = watchdog.expire(self.run_id)
        self.assertLess(expired["expires_at"], initial)

    def test_emergency_uid_fallback_repeats_until_quiescent(self):
        with mock.patch("run_lease_watchdog.process_ids_for_uid_strict", side_effect=[{4242}, set()]), \
                mock.patch("run_lease_watchdog.os.kill") as kill, \
                mock.patch("run_lease_watchdog.time.monotonic", side_effect=[0, 1]):
            watchdog.kill_agent_uid(os.getuid())
        kill.assert_any_call(4242, __import__("signal").SIGKILL)

    def test_agent_user_manager_is_stopped_and_failure_state_cleared(self):
        self.patches[-2].stop()
        completed = __import__("subprocess").CompletedProcess
        with mock.patch("run_lease_watchdog.subprocess.run", side_effect=[
                completed([], 0, "", ""), completed([], 3, "", ""),
                completed([], 1, "", ""), completed([], 1, "", ""),
        ]) as run:
            watchdog.stop_agent_user_manager(1001)
        unit = f"user@{1001}.service"
        self.assertEqual(
            [call.args[0][1:3] for call in run.call_args_list],
            [["stop", unit], ["is-active", "--quiet"],
             ["reset-failed", unit], ["is-failed", "--quiet"]],
        )

    def test_agent_user_manager_remaining_failed_is_not_hidden(self):
        self.patches[-2].stop()
        completed = __import__("subprocess").CompletedProcess
        with mock.patch("run_lease_watchdog.subprocess.run", side_effect=[
                completed([], 0, "", ""), completed([], 3, "", ""),
                completed([], 1, "", ""), completed([], 0, "", ""),
        ]):
            with self.assertRaisesRegex(RuntimeError, "could not be cleared"):
                watchdog.stop_agent_user_manager(1001)

    def test_agent_user_manager_stop_failure_is_not_hidden(self):
        self.patches[-2].stop()
        completed = __import__("subprocess").CompletedProcess
        with mock.patch("run_lease_watchdog.subprocess.run",
                        return_value=completed([], 1, "", "")):
            with self.assertRaisesRegex(RuntimeError, "did not stop cleanly"):
                watchdog.stop_agent_user_manager(1001)

    def test_emergency_failure_preserves_known_run_identity(self):
        self.lifecycle_dir.mkdir(parents=True)
        state = {"schema":watchdog.LIFECYCLE_SCHEMA,"run_id":self.run_id,
                 "lease_id":self.lease_id,"phase":"closing","unit":watchdog.unit_name(self.run_id)}
        watchdog.atomic_json(self.lifecycle_file, state, 0o644)
        with mock.patch("run_lease_watchdog.close", side_effect=RuntimeError("capture failed")), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            with self.assertRaisesRegex(RuntimeError, "capture failed"):
                watchdog.emergency()
        self.assertEqual(json.loads(self.failure_file.read_text())["run_id"], self.run_id)
        self.assertEqual(json.loads(self.lifecycle_file.read_text())["run_id"], self.run_id)

    def test_process_inventory_uses_kernel_reported_uid_not_proc_directory_owner(self):
        process = self.proc / "4242"; process.mkdir()
        process.joinpath("status").write_text(
            "Name:\ttest\nState:\tS (sleeping)\nUid:\t1234\t1234\t1234\t1234\n",
            encoding="ascii",
        )
        self.assertEqual(watchdog.process_ids_for_uid_strict(1234), {4242})
        self.assertEqual(watchdog.process_ids_for_uid_strict(4321), set())

    def test_watchdog_waits_only_until_commit_then_can_monitor_again(self):
        lease = {"run_id":self.run_id,"lease_id":self.lease_id,"expires_at":0}
        self.lifecycle_dir.mkdir(parents=True)
        state = {"schema":watchdog.LIFECYCLE_SCHEMA,"run_id":self.run_id,
                 "lease_id":self.lease_id,"phase":"active"}
        self.lifecycle_file.write_text(json.dumps(state), encoding="ascii")
        def finish_commit(_seconds):
            self.lifecycle_file.unlink(missing_ok=True)
        with mock.patch("run_lease_watchdog.load_lease", side_effect=[lease, KeyboardInterrupt]), \
                mock.patch("run_lease_watchdog.lifecycle", side_effect=[state, FileNotFoundError, KeyboardInterrupt]), \
                mock.patch("run_lease_watchdog.validated_snapshot", return_value=state), \
                mock.patch("run_lease_watchdog.close", return_value={"phase":"local_closed"}), \
                mock.patch("run_lease_watchdog.time.sleep", side_effect=finish_commit) as sleep:
            with self.assertRaises(KeyboardInterrupt):
                watchdog.watch()
        sleep.assert_any_call(0.5)

    def test_reboot_preserves_local_closed_state_without_recreating_a_failure_latch(self):
        self.lifecycle_dir.mkdir(parents=True)
        state = {"schema":watchdog.LIFECYCLE_SCHEMA,"run_id":self.run_id,
                 "lease_id":self.lease_id,"phase":"local_closed"}
        watchdog.atomic_json(self.lifecycle_file, state, 0o644)
        with mock.patch("run_lease_watchdog.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                watchdog.watch()
        self.assertEqual(json.loads(self.lifecycle_file.read_text())["phase"], "local_closed")
        self.assertFalse(self.failure_file.exists())

    def test_reboot_without_volatile_lease_resumes_active_state_through_close(self):
        self.lifecycle_dir.mkdir(parents=True)
        state = {"schema":watchdog.LIFECYCLE_SCHEMA,"run_id":self.run_id,
                 "lease_id":self.lease_id,"phase":"active","unit":watchdog.unit_name(self.run_id)}
        watchdog.atomic_json(self.lifecycle_file, state, 0o644)
        with mock.patch("run_lease_watchdog.close", return_value={"phase":"local_closed"}) as close, \
                mock.patch("run_lease_watchdog.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                watchdog.watch()
        close.assert_called_once_with(self.run_id)

    def test_malformed_volatile_lease_closes_capture_then_preserves_corruption_latch(self):
        self.lifecycle_dir.mkdir(parents=True)
        state = {"schema":watchdog.LIFECYCLE_SCHEMA,"run_id":self.run_id,
                 "lease_id":self.lease_id,"phase":"active","unit":watchdog.unit_name(self.run_id)}
        watchdog.atomic_json(self.lifecycle_file, state, 0o644)
        self.run_file.write_text(self.run_id + "\n"); self.run_file.chmod(0o644)
        self.lease_file.write_text("{not-json\n"); self.lease_file.chmod(0o600)
        with mock.patch("run_lease_watchdog.close", return_value={"phase":"local_closed"}) as close, \
                mock.patch("run_lease_watchdog.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                watchdog.watch()
        close.assert_called_once_with(self.run_id)
        self.assertEqual(json.loads(self.failure_file.read_text())["operation"], "watch_state")
        self.assertFalse(self.run_file.exists())

    def test_commit_requires_capture_receipt_and_zero_agent_processes(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with mock.patch("run_lease_watchdog.kill_run_cgroup"), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            watchdog.close(self.run_id)
        self.receipts.mkdir(parents=True, exist_ok=True)
        receipt = {"schema":"secure-sandbox-capture-final-v1","run_id":self.run_id,
                   "final_sequence":0,"final_cipher_sha256":"","chunks":[],
                   "journals":[],"prepared_offsets":{}}
        watchdog.atomic_json(self.receipts / f"{self.run_id}.json", receipt)
        completed = watchdog.commit(self.run_id, "a" * 64)
        self.assertEqual(completed["phase"], "committed")
        self.assertFalse(self.lifecycle_file.exists())
        self.assertTrue((self.completed / f"{self.run_id}.json").exists())

    def test_commit_rechecks_cgroup_quiescence(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with mock.patch("run_lease_watchdog.kill_run_cgroup"), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            watchdog.close(self.run_id)
        with mock.patch("run_lease_watchdog.scope_is_empty", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "cgroup"):
                watchdog.commit(self.run_id, "c" * 64)

    def test_commit_rejects_receipt_without_terminal_offset_proof(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        with mock.patch("run_lease_watchdog.kill_run_cgroup"), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            watchdog.close(self.run_id)
        self.receipts.mkdir(parents=True, exist_ok=True)
        watchdog.atomic_json(self.receipts / f"{self.run_id}.json",
                             {"schema":"secure-sandbox-capture-final-v1","run_id":self.run_id,
                              "final_sequence":0,"final_cipher_sha256":"","chunks":[],
                              "journals":[{"identity":"journal","snapshot_size":2,
                                           "final_offset":1}],"prepared_offsets":{}})
        with self.assertRaisesRegex(RuntimeError, "terminal offsets"):
            watchdog.commit(self.run_id, "d" * 64)

    def test_successful_identity_bound_commit_archives_and_clears_failure_latch(self):
        watchdog.arm(self.run_id, self.lease_id, int(__import__("time").time()) + 60)
        watchdog.latch_failure(self.run_id, "test", RuntimeError("boom"))
        with mock.patch("run_lease_watchdog.kill_run_cgroup"), \
                mock.patch("run_lease_watchdog.kill_agent_uid"):
            watchdog.close(self.run_id)
        self.receipts.mkdir(parents=True, exist_ok=True)
        watchdog.atomic_json(self.receipts / f"{self.run_id}.json",
                             {"schema":"secure-sandbox-capture-final-v1","run_id":self.run_id,
                              "final_sequence":0,"final_cipher_sha256":"","chunks":[],
                              "journals":[],"prepared_offsets":{}})
        watchdog.commit(self.run_id, "b" * 64)
        self.assertFalse(self.failure_file.exists())

    def test_capture_cli_protocol_accepts_one_stdout_document_and_ignores_events(self):
        self.patches[-1].stop()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "capture"
            script.write_text("#!/bin/sh\nprintf '%s\\n' '{\"event\":\"chunk\"}' >&2\nprintf '%s\\n' '{\"run_id\":\"%s\",\"final_sequence\":1}'\n" % ("%s", "%s", self.run_id), encoding="utf-8")
            script.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            recipient = Path(directory) / "recipient"; recipient.write_text("age1test\n")
            with mock.patch.object(watchdog, "CAPTURE", str(script)), \
                    mock.patch.object(watchdog, "CAPTURE_RECIPIENT", str(recipient)):
                self.assertEqual(watchdog.capture_operation("finalize", self.run_id)["final_sequence"], 1)


if __name__ == "__main__": unittest.main()

