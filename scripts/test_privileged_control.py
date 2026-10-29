import hashlib
import importlib.util
import io
import json
import os
import re
import signal
import subprocess
import struct
import sys
import tarfile
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("privileged_control", ROOT / "scripts/privileged_control.py")
assert SPEC and SPEC.loader
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
OPERATION_SPEC = importlib.util.spec_from_file_location(
    "privileged_control_operation", ROOT / "scripts/privileged-control-operation.py"
)
assert OPERATION_SPEC and OPERATION_SPEC.loader
OPERATION = importlib.util.module_from_spec(OPERATION_SPEC)
OPERATION_SPEC.loader.exec_module(OPERATION)


class RequestTests(unittest.TestCase):
    def test_memory_proposal_metadata_preserves_origin_and_checks_digest(self):
        proposal_id = "11111111-1111-4111-8111-111111111111"
        request = {"category": "project_context", "title": "Review this",
                   "proposal": "Untrusted text", "rationale": "Untrusted reason",
                   "evidence_refs": []}
        digest = hashlib.sha256(json.dumps(request, separators=(",", ":"),
                                           sort_keys=True).encode()).hexdigest()
        record = {**request, "schema": "secure-sandbox-memory-proposal-v1",
                  "proposal_id": proposal_id,
                  "run_id": "22222222-2222-4222-8222-222222222222",
                  "created_at": "2026-10-29T00:00:00Z", "content_sha256": digest,
                  "authority": "untrusted_proposal", "status": "pending_operator_review"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"{proposal_id}.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            selected = CONTROL.memory_proposal_metadata(path, os.getuid())
            self.assertEqual(selected["run_id"], record["run_id"])
            self.assertEqual(selected["content_sha256"], digest)
            self.assertNotIn("proposal", selected)
            for changed in ({**record, "run_id": "other"},
                            {**record, "proposal": "changed"},
                            {**record, "authority": "operator_adjudication"}):
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(CONTROL.ControlFailure, "untrusted"):
                    CONTROL.memory_proposal_metadata(path, os.getuid())

    def test_poweroff_is_exact_and_role_bound(self):
        command, validator, roles = CONTROL.OPERATIONS["poweroff"]
        self.assertEqual(command, ["/usr/bin/systemctl", "poweroff"])
        self.assertTrue(validator([]))
        self.assertFalse(validator(["now"]))
        self.assertEqual(roles, {"gateway", "research", "target"})

    def test_round_trip_and_trailing_input_rejected(self):
        stream = io.BytesIO()
        CONTROL.write_request(stream, {"kind": "run", "operation": "pki-verify", "args": []})
        request, payload = CONTROL.read_request(io.BytesIO(stream.getvalue()))
        self.assertEqual(request["operation"], "pki-verify")
        self.assertEqual(payload, b"")
        with self.assertRaisesRegex(CONTROL.ControlFailure, "trailing_input"):
            CONTROL.read_request(io.BytesIO(stream.getvalue() + b"x"))

    def test_oversized_and_truncated_requests_fail_closed(self):
        with self.assertRaisesRegex(CONTROL.ControlFailure, "header_size_invalid"):
            CONTROL.read_request(io.BytesIO(struct.pack(">I", CONTROL.MAX_HEADER + 1)))
        with self.assertRaisesRegex(CONTROL.ControlFailure, "request_truncated"):
            CONTROL.read_request(io.BytesIO(struct.pack(">I", 8) + b"{}"))

    def test_client_deadline_kills_ssh_process_group_and_reports_ambiguity_id(self):
        request_id = "11111111-1111-4111-8111-111111111111"

        class Sink:
            def __init__(self):
                self.data = bytearray()
                self.closed = False

            def write(self, data):
                self.data.extend(data)
                return len(data)

            def close(self):
                self.closed = True

        class HungProcess:
            pid = 12345
            returncode = None
            stdin = Sink()
            wait_calls = 0
            timeouts = []

            def wait(self, timeout=None):
                self.wait_calls += 1
                self.timeouts.append(timeout)
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(["ssh"], timeout)
                self.returncode = -signal.SIGKILL
                return self.returncode

            def poll(self):
                return self.returncode

        process = HungProcess()
        arguments = SimpleNamespace(
            request_id=request_id, command="run", arguments=[], name="control-status",
            ssh_config="/trusted/config", host="sandbox-gateway-control",
            timeout_seconds=7,
        )
        stderr = io.StringIO()
        with (mock.patch.object(CONTROL.subprocess, "Popen", return_value=process),
              mock.patch.object(CONTROL.os, "killpg") as killpg,
              mock.patch.object(CONTROL.time, "sleep"),
              mock.patch.object(CONTROL.sys, "stderr", stderr)):
            self.assertEqual(CONTROL.client_main(arguments), 124)
        self.assertEqual(
            killpg.call_args_list,
            [mock.call(process.pid, signal.SIGTERM), mock.call(process.pid, signal.SIGKILL)],
        )
        self.assertEqual(process.timeouts[0], 7)
        self.assertTrue(process.stdin.closed)
        self.assertGreater(len(process.stdin.data), 4)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["request_id"], request_id)
        self.assertEqual(failure["error"], "client_deadline_exceeded")

    def test_client_rejects_out_of_range_deadline_before_ssh(self):
        arguments = SimpleNamespace(timeout_seconds=0)
        with self.assertRaisesRegex(CONTROL.ControlFailure, "client_timeout_invalid"):
            CONTROL.client_main(arguments)


class BundleTests(unittest.TestCase):
    def _archive(self, members):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for info, data in members:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return output.getvalue()

    def test_verified_regular_file_extracts(self):
        data = b"#!/bin/bash\nexit 0\n"
        info = tarfile.TarInfo("files/install-ok.sh")
        info.size = len(data)
        manifest = [{"path": "install-ok.sh", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o755}]
        with tempfile.TemporaryDirectory() as temporary:
            CONTROL.extract_bundle(self._archive([(info, data)]), manifest, Path(temporary))
            installed = Path(temporary, "install-ok.sh")
            self.assertEqual(installed.read_bytes(), data)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)

    def test_symlink_traversal_duplicate_and_digest_mismatch_rejected(self):
        data = b"x"
        manifest = [{"path": "install-x.sh", "size": 1, "sha256": hashlib.sha256(data).hexdigest(), "mode": 0o755}]
        link = tarfile.TarInfo("files/install-x.sh")
        link.type = tarfile.SYMTYPE
        link.linkname = "/bin/sh"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_member_invalid"):
                CONTROL.extract_bundle(self._archive([(link, None)]), manifest, Path(temporary))
        traversal = tarfile.TarInfo("files/../install-x.sh")
        traversal.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_member_invalid"):
                CONTROL.extract_bundle(self._archive([(traversal, data)]), manifest, Path(temporary))
        first = tarfile.TarInfo("files/install-x.sh")
        first.size = 1
        second = tarfile.TarInfo("files/install-x.sh")
        second.size = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_inventory_mismatch"):
                CONTROL.extract_bundle(self._archive([(first, data), (second, data)]), manifest, Path(temporary))
        wrong = tarfile.TarInfo("files/install-x.sh")
        wrong.size = 1
        bad_manifest = [{**manifest[0], "sha256": "0" * 64}]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "bundle_digest_mismatch"):
                CONTROL.extract_bundle(self._archive([(wrong, data)]), bad_manifest, Path(temporary))

    def test_source_mutation_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "a")
            other = Path(temporary, "b")
            source.write_bytes(b"x")
            os.link(source, other)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "source_not_regular"):
                CONTROL.build_bundle([str(source)])

    def test_private_tmp_is_sticky_but_staging_parent_and_secrets_remain_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary, "staging")
            stage = parent / "research-request"
            parent.mkdir(mode=0o700)
            stage.mkdir(mode=0o700)
            secret = stage / "secret"
            secret.write_bytes(b"secret")
            secret.chmod(0o600)

            CONTROL.prepare_private_tmp(stage)

            self.assertEqual(parent.stat().st_mode & 0o7777, 0o700)
            self.assertEqual(stage.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)


class DispatchTests(unittest.TestCase):
    def request(self, value, payload=b""):
        value = {**value, "request_id": str(uuid.uuid4())}
        stream = io.BytesIO()
        CONTROL.write_request(stream, value, payload)
        stream.seek(0)
        return stream

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_role_and_argument_validation_precede_execution(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "operation_not_allowed_for_role"):
                CONTROL.dispatch("target", self.request({"kind": "run", "operation": "pki-verify", "args": []}), Path(temporary))
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "lease-status", "args": ["bad;id"]}), Path(temporary))
        run.assert_not_called()

    def test_watchdog_expiry_uses_decimal_epoch_contract(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        session_id = "33333333-3333-4333-8333-333333333333"
        validator = CONTROL.OPERATIONS["watchdog-arm"][1]
        self.assertTrue(validator([run_id, lease_id, "1760000000", session_id]))
        self.assertFalse(validator([run_id, lease_id, "2026-10-21T00:00:00Z", session_id]))

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_request_id_is_at_most_once(self, run):
        run.return_value.returncode = 0
        request_id = str(uuid.uuid4())
        value = {"kind": "run", "operation": "lease-status", "args": ["run-1"], "request_id": request_id}
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            first = io.BytesIO()
            CONTROL.write_request(first, value)
            first.seek(0)
            self.assertEqual(CONTROL.dispatch("gateway", first, state), 0)
            replay = io.BytesIO()
            CONTROL.write_request(replay, value)
            replay.seek(0)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "request_replayed"):
                CONTROL.dispatch("gateway", replay, state)
            receipt = json.loads((state / "receipts" / f"{request_id}.json").read_text())
            self.assertEqual((receipt["state"], receipt["status"]), ("completed", 0))
            events = [json.loads(line) for line in (state / "audit.jsonl").read_text().splitlines()]
            self.assertTrue(all(event["request_id"] == request_id for event in events))
            self.assertTrue(all("args" not in event for event in events))
        run.assert_called_once()

    def test_receipt_archival_is_lossless_and_preserves_replay_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_ids = [str(uuid.uuid4()) for _ in range(3)]
            for index, request_id in enumerate(request_ids):
                path = receipts / f"{request_id}.json"
                path.write_bytes(CONTROL.canonical_json({
                    "request_id":request_id,
                    "request_sha256":hashlib.sha256(str(index).encode()).hexdigest(),
                    "schema":"secure-sandbox-privileged-control-receipt-v1",
                    "state":"completed",
                    "status":0,
                }) + b"\n")
                path.chmod(0o600)
                os.utime(path, ns=(index + 1, index + 1))

            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["archived"], 2)
            self.assertEqual(len(list(receipts.iterdir())), 1)
            archive = state / "receipt-archive"
            self.assertEqual(len(list(archive.iterdir())), 2)
            for archived in archive.iterdir():
                original_id = request_ids.index(archived.stem)
                expected = CONTROL.canonical_json({
                    "request_id": archived.stem,
                    "request_sha256": hashlib.sha256(str(original_id).encode()).hexdigest(),
                    "schema": "secure-sandbox-privileged-control-receipt-v1",
                    "state": "completed",
                    "status": 0,
                }) + b"\n"
                self.assertEqual(archived.read_bytes(), expected)

            replayed = next(path.stem for path in archive.iterdir())
            with self.assertRaisesRegex(CONTROL.ControlFailure, "request_replayed"):
                CONTROL.reserve_request(state, {"request_id":replayed})

    def test_receipt_archival_rejects_dangling_destination_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            archive = state / "receipt-archive"
            receipts.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            request_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
            for index, request_id in enumerate(request_ids):
                path = receipts / f"{request_id}.json"
                path.write_bytes(CONTROL.canonical_json({
                    "request_id": request_id,
                    "request_sha256": "a" * 64,
                    "schema": "secure-sandbox-privileged-control-receipt-v1",
                    "state": "completed",
                    "status": 0,
                }) + b"\n")
                path.chmod(0o600)
                os.utime(path, ns=(index + 1, index + 1))
            (archive / f"{request_ids[0]}.json").symlink_to("missing")
            with self.assertRaisesRegex(CONTROL.ControlFailure, "archive_collision"):
                CONTROL.archive_control_receipts(state, keep=1)
            self.assertTrue((receipts / f"{request_ids[0]}.json").exists())

    def test_receipt_ledger_lock_serializes_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            request_id = str(uuid.uuid4())
            entered = threading.Event()
            finished = threading.Event()

            def reserve():
                entered.set()
                CONTROL.reserve_request(state, {"request_id": request_id})
                finished.set()

            with CONTROL.receipt_ledger_lock(state):
                worker = threading.Thread(target=reserve)
                worker.start()
                self.assertTrue(entered.wait(1))
                self.assertFalse(finished.wait(0.1))
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertTrue(finished.is_set())

    def test_receipt_archival_keeps_in_progress_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            path = receipts / f"{request_id}.json"
            path.write_bytes(CONTROL.canonical_json({
                "request_id":request_id,
                "request_sha256":"a" * 64,
                "schema":"secure-sandbox-privileged-control-receipt-v1",
                "state":"started",
            }) + b"\n")
            path.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["archived"], 0)
            self.assertTrue(path.exists())

    def test_receipt_archival_recovers_exact_durable_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            digest = "a" * 64
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": digest,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n")
            staged_bytes = CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": digest,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "completed", "status": 0,
            }) + b"\n"
            staged.write_bytes(staged_bytes)
            canonical.chmod(0o600)
            staged.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["recovered_completions"], 1)
            self.assertEqual(canonical.read_bytes(), staged_bytes)
            self.assertFalse(staged.exists())

    def test_receipt_archival_rejects_mismatched_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "a" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n")
            staged.write_bytes(CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "b" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "completed", "status": 0,
            }) + b"\n")
            canonical.chmod(0o600)
            staged.chmod(0o600)
            with self.assertRaisesRegex(
                CONTROL.ControlFailure, "completion_recovery_invalid"
            ):
                CONTROL.archive_control_receipts(state, keep=1)
            self.assertTrue(canonical.exists())
            self.assertTrue(staged.exists())

    def test_receipt_archival_losslessly_quarantines_empty_completion_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            receipts = state / "receipts"
            receipts.mkdir(mode=0o700)
            request_id = str(uuid.uuid4())
            canonical = receipts / f"{request_id}.json"
            staged = receipts / f".{request_id}.json.complete"
            canonical_bytes = CONTROL.canonical_json({
                "request_id": request_id, "request_sha256": "a" * 64,
                "schema": "secure-sandbox-privileged-control-receipt-v1",
                "state": "started",
            }) + b"\n"
            canonical.write_bytes(canonical_bytes)
            staged.write_bytes(b"")
            canonical.chmod(0o600)
            staged.chmod(0o600)
            result = CONTROL.archive_control_receipts(state, keep=1)
            self.assertEqual(result["quarantined_empty_completion_stages"], 1)
            self.assertEqual(canonical.read_bytes(), canonical_bytes)
            self.assertFalse(staged.exists())
            quarantined = (
                state / "receipt-recovery" /
                f"{request_id}.empty-completion-stage"
            )
            self.assertTrue(quarantined.exists())
            self.assertEqual(quarantined.read_bytes(), b"")

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_role_bound_policy_and_backup_prefixes(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "policy-hash", "args": ["research"]}), state)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "arguments_invalid"):
                CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "rollback-run-leases-gateway", "args": ["run-leases-research-20261020T120000Z-1"]}), state)
        run.assert_not_called()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_started_audit_is_durable_before_execution(self, run):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            CONTROL, "audit_event", side_effect=[CONTROL.ControlFailure("audit unavailable"), None]
        ):
            with self.assertRaisesRegex(CONTROL.ControlFailure, "audit unavailable"):
                CONTROL.dispatch(
                    "gateway",
                    self.request({"kind": "run", "operation": "lease-status", "args": ["run-1"]}),
                    Path(temporary),
                )
        run.assert_not_called()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_runtime_exec_uses_argv_and_clean_environment(self, run):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as temporary:
            result = CONTROL.dispatch("gateway", self.request({"kind": "run", "operation": "lease-status", "args": ["run-1"]}), Path(temporary))
        self.assertEqual(result, 0)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/local/libexec/secure-sandbox/run_lease.py", "status", "run-1"])
        self.assertNotIn("SHELL", run.call_args.kwargs["env"])

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_pipe_operation_is_role_bound_and_content_bound(self, run):
        payload = b"framed source archive"
        request = {
            "kind": "pipe",
            "operation": "source-import-stage",
            "args": [],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(CONTROL.dispatch("research", self.request(request, payload), Path(temporary)), 0)
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/local/sbin/secure-sandbox-source-import", "stage"],
        )
        self.assertEqual(run.call_args.kwargs["input"], payload)

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "payload_digest_mismatch"):
                CONTROL.dispatch(
                    "research",
                    self.request({**request, "payload_sha256": "0" * 64}, payload),
                    Path(temporary),
                )
        self.assertEqual(run.call_count, 1)

    def test_deploy_rejects_non_installer_before_fork(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CONTROL.ControlFailure, "installer_invalid"):
                CONTROL.dispatch(
                    "gateway",
                    self.request({"kind": "deploy", "installer": "shell.py", "args": [], "files": []}),
                    Path(temporary),
                )


class EntryTests(unittest.TestCase):
    def test_entry_rejects_every_command_except_request(self):
        path = ROOT / "scripts/privileged_control_entry.py"
        spec = importlib.util.spec_from_file_location("privileged_control_entry", path)
        assert spec and spec.loader
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "sh"}, clear=True):
            self.assertEqual(entry.main(), 64)
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "request", "LD_PRELOAD": "/evil"}, clear=True), mock.patch.object(entry.os, "execve", side_effect=RuntimeError) as execute:
            with self.assertRaises(RuntimeError):
                entry.main()
        self.assertEqual(execute.call_args.args[0], "/usr/bin/sudo")
        self.assertNotIn("LD_PRELOAD", execute.call_args.args[2])


class SelfCheckTests(unittest.TestCase):
    @mock.patch.object(CONTROL.subprocess, "run")
    def test_effective_sudo_policy_asks_sudo_after_invalidating_credentials(self, run):
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=0)]
        self.assertTrue(CONTROL._labadmin_passwordless_sudo_present())
        self.assertEqual(run.call_args_list[0].args[0][-2:], ["/usr/bin/sudo", "-k"])
        self.assertEqual(run.call_args_list[1].args[0][-3:], ["/usr/bin/sudo", "-n", "-l"])

        run.reset_mock()
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=1)]
        self.assertFalse(CONTROL._labadmin_passwordless_sudo_present())

        run.reset_mock()
        run.side_effect = [mock.Mock(returncode=0), mock.Mock(returncode=2)]
        with self.assertRaisesRegex(CONTROL.ControlFailure, "labadmin_sudo_policy_unavailable"):
            CONTROL._labadmin_passwordless_sudo_present()

    @mock.patch.object(CONTROL.subprocess, "run")
    def test_lifecycle_idle_requires_no_markers_and_exact_pgrep_no_match(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary, "marker")
            run.return_value = mock.Mock(returncode=1)
            self.assertTrue(CONTROL.lifecycle_idle((marker,)))
            run.return_value = mock.Mock(returncode=0)
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            run.return_value = mock.Mock(returncode=2)
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            marker.write_text("active\n", encoding="ascii")
            run.reset_mock()
            self.assertFalse(CONTROL.lifecycle_idle((marker,)))
            run.assert_not_called()

    def test_self_check_file_is_content_bound_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "policy"
            path.write_bytes(b"policy\n")
            path.chmod(0o644)
            expected = hashlib.sha256(b"policy\n").hexdigest()
            result = CONTROL._self_check_file(
                path, 0o644, path.stat().st_uid, path.stat().st_gid
            )
            self.assertEqual(result["sha256"], expected)
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    link, 0o644, path.stat().st_uid, path.stat().st_gid
                )

    def test_self_check_file_rejects_wrong_mode_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "policy"
            linked = root / "linked"
            path.write_bytes(b"policy\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    path, 0o644, path.stat().st_uid, path.stat().st_gid
                )
            os.link(path, linked)
            with self.assertRaisesRegex(CONTROL.ControlFailure, "control_file_untrusted"):
                CONTROL._self_check_file(
                    path, 0o600, path.stat().st_uid, path.stat().st_gid
                )


class RepositoryMigrationTests(unittest.TestCase):
    def test_clean_bootstrap_installers_preserve_fail_closed_boundaries(self):
        research = (ROOT / "scripts/install-research-auditd.sh").read_text(encoding="utf-8")
        target = (ROOT / "scripts/install-target-rootless-docker-provisioning.sh").read_text(encoding="utf-8")
        docker = (ROOT / "scripts/install-rootless-docker.sh").read_text(encoding="utf-8")
        principals = (ROOT / "scripts/install-research-service-principals.sh").read_text(encoding="utf-8")

        self.assertIn('== research', research)
        self.assertIn('== target', target)
        for text in (research, target):
            self.assertIn('/sys/class/net/*/address', text)
            self.assertIn('runtime_interface=', text)
            self.assertIn('ip address flush dev "$runtime_interface"', text)
            self.assertIn('ip link set dev "$runtime_interface" down', text)
            self.assertIn('nft -f /etc/nftables.conf', text)
            self.assertIn('table inet secure_sandbox_maintenance', text)
            self.assertIn('policy drop;', text)
            self.assertIn('ip daddr 10.211.55.1 udp dport 53 accept', text)
            self.assertNotIn('\nnft flush ruleset\n', text)
            self.assertNotIn('nft -f /etc/nftables.conf || true', text)
            self.assertIn('! ip -4 route show default | grep -q .', text)
        self.assertLess(research.index('nft -f "$maintenance_policy"'), research.index('apt-get'))
        self.assertLess(target.index('nft -f "$maintenance_policy"'), target.index('/bin/bash "$installer"'))
        self.assertEqual(docker.count('apt-get update --error-on=any'), 2)
        self.assertIn('nft list table inet secure_sandbox_maintenance', docker)
        self.assertNotIn('nft flush ruleset', docker)
        self.assertNotIn('APT::Sandbox::User=root', docker)
        self.assertIn('execution-broker', principals)
        self.assertIn('This installer is restricted to Research.', principals)

    def test_first_source_integrity_generation_has_reversible_absence_records(self):
        installer = (ROOT / "scripts/install-source-integrity.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "research/rollback_source_integrity.sh").read_text(encoding="utf-8")
        for name in ("managed-settings.json", "research-claude"):
            self.assertIn(name, installer)
            self.assertIn(name, rollback)
        self.assertIn(': > "$backup/$name.absent"', installer)
        self.assertIn('rm -f -- "$destination"', rollback)

    def test_large_claude_binary_is_reassembled_without_raising_control_limits(self):
        installer = (ROOT / "scripts/install-claude-code.sh").read_text(encoding="utf-8")
        self.assertIn('part.00', installer)
        self.assertIn('part.01', installer)
        self.assertIn('part.02', installer)
        self.assertIn('cat "${parts[@]}" > "$assembled_claude"', installer)
        self.assertIn('ae2295ae2da156936bf5831ab01971ce924d0c9a0af174e28d96fffa8d5fa0a6', installer)
        self.assertEqual(CONTROL.MAX_FILE, 128 * 1024 * 1024)
        self.assertEqual(CONTROL.MAX_PAYLOAD, 256 * 1024 * 1024)

    def test_runtime_callers_do_not_execute_the_mutable_workspace_client(self):
        offenders = []
        paths = sorted((ROOT / "scripts").glob("*.sh")) + [
            ROOT / "scripts/labctl",
            ROOT / "scripts/verify-privileged-control-live.py",
        ]
        forbidden = (
            '$root_dir/scripts/privileged_control.py" client',
            'control_client="$root_dir/scripts/privileged_control.py"',
            'CLIENT = ROOT / "scripts/privileged_control.py"',
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            if any(value in text for value in forbidden):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

        source_references = {
            path.name
            for path in (ROOT / "scripts").iterdir()
            if path.is_file() and not path.name.startswith("test_")
            and "scripts/privileged_control.py" in path.read_text(encoding="utf-8")
        }
        self.assertEqual(
            source_references,
            {
                "build-autoinstall-seed.sh",
                "deploy-foundation.sh",
                "deploy-legacy-preservation.sh",
                "host-controller-release.py",
                "legacy-vm-preservation.py",
                "plan-legacy-vm-preservation.py",
                "privileged-control-operation.py",
                "verify-autoinstall-seed.py",
                "verify-boundaries.sh",
                "verify-privileged-control-live.py",
            },
        )
        foundation = (ROOT / "scripts/deploy-foundation.sh").read_text(encoding="utf-8")
        self.assertIn(
            "control_client=/usr/local/libexec/secure-sandbox-host/current/control_client",
            foundation,
        )
        self.assertIn(
            '--file "$root_dir/scripts/privileged_control.py"',
            foundation,
        )
        self.assertNotIn(
            '$root_dir/scripts/privileged_control.py" client',
            foundation,
        )

    def test_protected_client_callers_use_the_protected_ssh_config(self):
        protected_client = "/usr/local/libexec/secure-sandbox-host/current/control_client"
        protected_config = "/usr/local/libexec/secure-sandbox-host/current/ssh_config"
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if protected_client in text and protected_config not in text:
                offenders.append(path.name)
        live = (ROOT / "scripts/verify-privileged-control-live.py").read_text(encoding="utf-8")
        if protected_client not in live or protected_config not in live:
            offenders.append("verify-privileged-control-live.py")
        self.assertEqual(offenders, [])

    def test_no_automated_guest_admin_password_delivery_remains(self):
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if "sudo -S" in text or any(
                value in text for value in (
                    "SecureSandbox-Gateway/password",
                    "SecureSandbox-Research/password",
                    "SecureSandbox-Target/password",
                )
            ):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_labadmin_has_no_passwordless_automation_grants_or_callers(self):
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            text = path.read_text(encoding="utf-8")
            if "labadmin ALL=(root) NOPASSWD:" in text or re.search(
                r"sudo -n (?:/usr/local/sbin/secure-sandbox-source-import|"
                r"/usr/local/libexec/secure-sandbox/(?:dependency_orchestrator|codegraph_indexer)\.py)",
                text,
            ):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

        labctl = (ROOT / "scripts/labctl").read_text(encoding="utf-8")
        for operation in (
            "source-import-stage", "source-import-publish", "dependency-plan",
            "dependency-status", "dependency-apply", "dependency-list", "source-list",
        ):
            self.assertIn(operation, labctl)
            self.assertIn(f'"{operation}"', (ROOT / "scripts/privileged_control.py").read_text(encoding="utf-8"))
        self.assertNotIn('cat /home/agent/research-workspace/repos/INDEX.json', labctl)
        self.assertNotIn('cat /home/agent/research-workspace/dependency-bundles/INDEX.json', labctl)

    def test_privileged_control_install_reload_is_fail_closed_when_ssh_is_active(self):
        installer = (ROOT / "scripts/install-privileged-control.sh").read_text(encoding="utf-8")
        self.assertIn('ssh_state="$(systemctl is-active ssh.service 2>/dev/null)"', installer)
        self.assertIn('0:active)', installer)
        self.assertIn('3:inactive)', installer)
        self.assertIn('ssh_service_state_invalid:', installer)
        self.assertIn('ssh_service_not_active_after_reload', installer)
        self.assertIn('0:reloading) sleep 0.1', installer)
        self.assertIn('ssh_service_reload_timeout', installer)
        self.assertIn('systemctl reload ssh.service', installer)
        self.assertNotIn('systemctl reload ssh.service >/dev/null 2>&1 || true', installer)
        self.assertLess(
            installer.index('systemctl reload ssh.service'),
            installer.index('echo "privileged-control:installed:$role"'),
        )

    def test_no_host_copy_targets_guest_tmp(self):
        offenders = []
        pattern = re.compile(r"sandbox-(?:gateway|research-admin|target-admin):/tmp")
        for path in sorted((ROOT / "scripts").glob("*.sh")) + [ROOT / "scripts/labctl"]:
            if pattern.search(path.read_text(encoding="utf-8")):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

    def test_control_deploy_uses_only_protected_client_and_authenticated_deployments(self):
        operation = (ROOT / "scripts/privileged-control-operation.py").read_text(encoding="utf-8")
        self.assertFalse((ROOT / "scripts/deploy-privileged-control.sh").exists())
        self.assertIn('/usr/local/libexec/secure-sandbox-host/current/control_client', operation)
        self.assertIn('LAUNCHER.acquire_lock', operation)
        self.assertIn('MANAGER.active_markers', operation)
        self.assertIn('DEFERRED_SIGNALS', operation)
        self.assertIn('signal.pthread_sigmask', operation)
        self.assertIn('start_new_session=True', operation)
        self.assertIn('"verify", "--json"', operation)
        self.assertIn('"run", "lifecycle-idle"', operation)
        self.assertIn('deploy_role("sandbox-gateway-control", "gateway"', operation)
        self.assertIn('deploy_role("sandbox-research-control", "research"', operation)
        self.assertIn('deploy_role("sandbox-target-control", "target"', operation)
        self.assertLess(
            operation.index('deploy_role("sandbox-research-control", "research"'),
            operation.index('"run", "lifecycle-idle"'),
        )
        self.assertLess(
            operation.index('"run", "lifecycle-idle"'),
            operation.index('deploy_role("sandbox-gateway-control", "gateway"'),
        )
        self.assertIn('"install-approved-claude-policy.sh"', operation)
        self.assertIn('verify-privileged-control-live.py', operation)
        self.assertNotRegex(operation, r'sandbox-(?:gateway|research-admin|target-admin).*sudo')

    @mock.patch.object(OPERATION, "run_command")
    @mock.patch.object(OPERATION.MANAGER, "active_markers")
    @mock.patch.object(OPERATION.LAUNCHER, "release_lock")
    @mock.patch.object(OPERATION.LAUNCHER, "acquire_lock")
    def test_control_deployment_holds_launch_lock_and_rejects_active_marker(
        self, acquire, release, active_markers, run
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "coordination.lock"
            acquire.return_value = lock
            active_markers.return_value = ["live"]
            self.assertEqual(OPERATION.deploy(root), 1)
            run.assert_not_called()
            release.assert_called_once_with(lock)

    def test_control_deployment_defers_first_termination_signal(self):
        deferred = OPERATION.DeferredSignals()
        deferred.handle(signal.SIGTERM, None)
        deferred.handle(signal.SIGINT, None)
        self.assertEqual(deferred.received, signal.SIGTERM)
        self.assertEqual(OPERATION.interrupted_status(deferred), 128 + signal.SIGTERM)

    @mock.patch.object(OPERATION, "run_command")
    def test_postactivation_host_verifier_requires_exact_floor_denial(self, run):
        denied = {
            "error":"execution_approval_floor_invalid",
            "schema":"secure-sandbox-host-controller-release-v1",
            "status":"rejected",
        }
        run.side_effect = [
            mock.Mock(
                returncode=1, stdout=json.dumps(denied) + "\n", stderr=""
            ),
            mock.Mock(returncode=0, stdout='{"status":"verified"}\n', stderr=""),
        ]
        result = OPERATION.verify_host_controller_release(
            OPERATION.DeferredSignals()
        )
        self.assertEqual(result.returncode, 0)
        fallback = run.call_args_list[1].args[0]
        self.assertIn("verify-postactivation-host-release", fallback)

    @mock.patch.object(OPERATION, "run_command")
    def test_unrelated_host_verifier_failure_does_not_fallback(self, run):
        rejected = {
            "error":"active_release_source_mismatch",
            "schema":"secure-sandbox-host-controller-release-v1",
            "status":"rejected",
        }
        run.return_value = mock.Mock(
            returncode=1, stdout=json.dumps(rejected) + "\n", stderr=""
        )
        with self.assertRaisesRegex(
            RuntimeError, "host_controller_release_verify_failed:1"
        ):
            OPERATION.verify_host_controller_release(
                OPERATION.DeferredSignals()
            )
        run.assert_called_once()

    def test_control_deployment_waits_for_child_after_termination_signal(self):
        with OPERATION.DeferredSignals() as deferred:
            timer = threading.Timer(0.05, os.kill, args=(os.getpid(), signal.SIGTERM))
            timer.start()
            try:
                result = OPERATION.run_command(
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(0.15); print('child-complete')",
                    ],
                    deferred,
                )
            finally:
                timer.join()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "child-complete")
        self.assertEqual(deferred.received, signal.SIGTERM)

    @mock.patch.object(OPERATION, "protected_regular_file", return_value=True)
    @mock.patch.object(OPERATION.MANAGER, "active_markers", return_value=[])
    @mock.patch.object(OPERATION.LAUNCHER, "release_lock")
    @mock.patch.object(OPERATION.LAUNCHER, "acquire_lock")
    def test_control_deployment_propagates_signal_received_during_final_verifier(
        self, acquire, release, _active_markers, _protected_file
    ):
        acquire.return_value = Path("coordination.lock")
        outputs = iter(
            (
                "{}\n",
                "privileged-control:installed:research\n",
                "",
                "privileged-control:installed:gateway\n",
                "privileged-control:installed:target\n",
                "claude-policy:installed; run the post-install safety audit before use\n",
                '{"status":"verified"}\n',
            )
        )

        def run_and_interrupt_final(command, deferred):
            output = next(outputs)
            if command[-1].endswith("verify-privileged-control-live.py"):
                deferred.handle(signal.SIGTERM, None)
            return mock.Mock(returncode=0, stdout=output, stderr="")

        with mock.patch.object(OPERATION, "run_command", side_effect=run_and_interrupt_final):
            self.assertEqual(OPERATION.deploy(Path("state")), 128 + signal.SIGTERM)
        release.assert_called_once_with(Path("coordination.lock"))


if __name__ == "__main__":
    unittest.main()
