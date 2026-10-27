#!/usr/bin/env python3

import base64
import contextlib
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import execution_approval_transition as transition


class ExecutionApprovalTransitionTests(unittest.TestCase):
    def test_trusted_directory_binds_exact_owner_group_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trusted"
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            owner = path.stat().st_uid
            group = path.stat().st_gid
            transition.trusted_existing_directory(path, 0o700, owner, group)
            with self.assertRaisesRegex(transition.TransitionError, "state_directory_untrusted"):
                transition.trusted_existing_directory(path, 0o750, owner, group)
            with self.assertRaisesRegex(transition.TransitionError, "state_directory_untrusted"):
                transition.trusted_existing_directory(path, 0o700, owner + 1, group)
            with self.assertRaisesRegex(transition.TransitionError, "state_directory_untrusted"):
                transition.trusted_existing_directory(path, 0o700, owner, group + 1)

    def test_preactivation_release_rebinding_history_is_continuous_and_current(self):
        journal = {
            "host_release_id":"c" * 64,
            "research_release_id":"d" * 64,
            "preactivation_release_rebindings":[{
                "from_host_release_id":"a" * 64,
                "to_host_release_id":"c" * 64,
                "from_research_release_id":"b" * 64,
                "to_research_release_id":"d" * 64,
                "prior_journal_sha256":"e" * 64,
                "rebound_at":100,
            }],
        }
        self.assertEqual(len(transition.preactivation_release_rebindings(journal)), 1)
        changed = json.loads(json.dumps(journal))
        changed["preactivation_release_rebindings"][0]["to_research_release_id"] = "f" * 64
        with self.assertRaisesRegex(transition.TransitionError, "release_rebinding_invalid"):
            transition.preactivation_release_rebindings(changed)

    def record(self, phase="prepared"):
        spki = transition.SPKI_PREFIX + b"\x04" + b"\x01" * 64
        value = {
            "schema":"secure-sandbox-execution-approval-transition-v2",
            "phase":phase,
            "transaction_id":"11111111-1111-4111-8111-111111111111",
            "generation_id":"22222222-2222-4222-8222-222222222222",
            "generation_epoch":3,
            "algorithm":transition.ALGORITHM,
            "public_key_spki_der_b64":base64.b64encode(spki).decode("ascii"),
            "public_key_sha256":hashlib.sha256(spki).hexdigest(),
            "host_release_id":"a" * 64,
            "research_release_id":"b" * 64,
            "operator_uid":501,
            "previous_generation_id":None,
            "previous_generation_epoch":None,
            "expected_prior_phase":"none" if phase == "prepared" else {
                "fenced":"prepared", "active":"fenced", "acceptance":"active",
                "committed":"acceptance",
            }[phase],
            "recorded_at":2_000_000_000,
        }
        if phase == "acceptance":
            value.update({
                "run_id":"33333333-3333-4333-8333-333333333333",
                "session_id":"44444444-4444-4444-8444-444444444444",
                "source_id":"55555555-5555-4555-8555-555555555555",
                "code_sha256":"c" * 64,
                "fixture_manifest_sha256":"d" * 64,
                "timeout_seconds":5,
                "runtime_image_id":"sha256:" + "e" * 64,
                "expires_at":2_000_003_600,
                "acceptance_attempt_id":"66666666-6666-4666-8666-666666666666",
                "acceptance_attempt_number":1,
                "previous_acceptance_binding_sha256":None,
            })
            binding = transition.acceptance_binding(value)
            value["host_acceptance_authorization"] = {
                "schema":"secure-sandbox-execution-approval-acceptance-authorization-v1",
                "status":"authorized", "transaction_id":value["transaction_id"],
                "generation_id":value["generation_id"],
                "generation_epoch":value["generation_epoch"],
                "algorithm":value["algorithm"],
                "public_key_sha256":value["public_key_sha256"],
                "operator_uid":value["operator_uid"],
                "previous_generation_id":value["previous_generation_id"],
                "previous_generation_epoch":value["previous_generation_epoch"],
                "acceptance_attempt_id":value["acceptance_attempt_id"],
                "acceptance_attempt_number":1,
                "previous_acceptance_binding_sha256":None,
                "acceptance_binding_sha256":binding,
                "host_release_id":value["host_release_id"],
                "research_release_id":value["research_release_id"],
                "authorized_at":2_000_000_000,
            }
        return value

    def test_record_is_exact_and_content_bound(self):
        value = self.record()
        self.assertEqual(transition.validate_record(value), value)
        with self.assertRaisesRegex(transition.TransitionError, "transition_record_invalid"):
            transition.validate_record({**value, "algorithm":"ssh-ed25519"})
        with self.assertRaisesRegex(transition.TransitionError, "transition_record_invalid"):
            transition.validate_record({**value, "extra":True})
        changed = dict(value)
        changed["public_key_sha256"] = "b" * 64
        with self.assertRaisesRegex(transition.TransitionError, "transition_record_invalid"):
            transition.validate_record(changed)

    def test_prepare_writes_a_durable_bound_journal_without_changing_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record_path = root / "record.json"
            record_path.write_bytes(transition.canonical(self.record()))
            written = []
            with mock.patch.object(transition, "STATE_ROOT", root / "state"), \
                    mock.patch.object(transition, "JOURNAL", root / "state/journal.json"), \
                    mock.patch.object(transition, "FLOOR", root / "state/minimum-floor.json"), \
                    mock.patch.object(transition, "ADMISSION_FENCE", root / "lifecycle/fence.json"), \
                    mock.patch.object(transition, "protected_directory"), \
                    mock.patch.object(transition, "trusted_existing_directory"), \
                    mock.patch.object(transition, "current_config", return_value={
                        "schema":"secure-sandbox-execution-broker-v2",
                        "token":"x" * 64,
                        "runtime_image_id":"sha256:" + "1" * 64,
                    }), \
                    mock.patch.object(transition, "release_identity", return_value="b" * 64), \
                    mock.patch.object(transition, "atomic", side_effect=lambda path, value, mode=0o600: written.append((path, value, mode))), \
                    mock.patch.object(transition, "write_config") as write_config, \
                    mock.patch.object(transition.os, "geteuid", return_value=0):
                result = transition.apply(record_path)
            self.assertEqual(result["status"], "prepared")
            self.assertEqual(written[0][1]["transaction_id"], self.record()["transaction_id"])
            self.assertIsNone(written[0][1]["prior_record_sha256"])
            write_config.assert_not_called()

    def test_prepared_release_repair_is_bounded_hash_linked_and_preserves_old_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            receipts = state / "phase-receipts"
            lifecycle = root / "lifecycle"
            state.mkdir()
            receipts.mkdir()
            lifecycle.mkdir()
            old_record = self.record("prepared")
            old_journal = {
                "schema":"secure-sandbox-execution-approval-transition-journal-v2",
                **{name:old_record[name] for name in old_record if name != "schema"},
                "prior_record_sha256":None,
                "acceptance_binding_sha256":None,
            }
            journal_path = state / "journal.json"
            journal_path.write_bytes(transition.canonical(old_journal))
            journal_path.chmod(0o600)
            old_receipt = transition.phase_receipt(old_record, old_journal)
            old_receipt_path = receipts / f"{old_record['transaction_id']}.prepared.json"
            old_receipt_path.write_bytes(transition.canonical(old_receipt))
            old_receipt_path.chmod(0o600)
            repaired = {
                **old_record,
                "host_release_id":"c" * 64,
                "research_release_id":"d" * 64,
                "expected_prior_phase":"prepared",
                "recorded_at":2_000_000_100,
            }
            record_path = root / "record.json"
            record_path.write_bytes(transition.canonical(repaired))
            def read_test_json(path, schema, _mode, maximum=16384):
                value = json.loads(path.read_bytes())
                self.assertEqual(value["schema"], schema)
                self.assertLessEqual(len(path.read_bytes()), maximum)
                return value
            with mock.patch.object(transition, "STATE_ROOT", state), \
                    mock.patch.object(transition, "JOURNAL", journal_path), \
                    mock.patch.object(transition, "PHASE_RECEIPTS", receipts), \
                    mock.patch.object(transition, "FLOOR", state / "missing-floor"), \
                    mock.patch.object(transition, "ADMISSION_FENCE", lifecycle / "fence"), \
                    mock.patch.object(transition, "protected_directory"), \
                    mock.patch.object(transition, "trusted_existing_directory"), \
                    mock.patch.object(transition, "read_json", side_effect=read_test_json), \
                    mock.patch.object(transition, "release_identity", return_value="d" * 64), \
                    mock.patch.object(transition, "current_config", return_value={
                        "schema":"secure-sandbox-execution-broker-v2",
                        "token":"x" * 64,
                        "runtime_image_id":"sha256:" + "1" * 64,
                    }), \
                    mock.patch.object(transition.os, "geteuid", return_value=0):
                result = transition.apply(record_path)
                repeated = transition.apply(record_path)
            self.assertEqual(result, repeated)
            self.assertTrue(old_receipt_path.exists())
            repaired_receipt = receipts / (
                f"{old_record['transaction_id']}.prepared-rebind-1.json"
            )
            self.assertTrue(repaired_receipt.exists())
            journal = json.loads(journal_path.read_bytes())
            self.assertEqual(journal["host_release_id"], "c" * 64)
            self.assertEqual(journal["research_release_id"], "d" * 64)
            self.assertEqual(journal["preactivation_release_rebindings"], [{
                "from_host_release_id":"a" * 64,
                "to_host_release_id":"c" * 64,
                "from_research_release_id":"b" * 64,
                "to_research_release_id":"d" * 64,
                "prior_journal_sha256":hashlib.sha256(
                    transition.canonical(old_journal)
                ).hexdigest(),
                "rebound_at":2_000_000_100,
            }])

    def test_quiescence_rejects_pending_operator_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("pending", "claims", "responses"):
                (root / name).mkdir()
            (root / "pending/request.json").write_text("{}")
            with mock.patch.object(transition, "QUIESCENCE_MARKERS", (root / "absent",)), \
                    mock.patch.object(transition, "APPROVAL_ROOT", root), \
                    mock.patch.object(transition, "trusted_existing_directory") as trusted, \
                    mock.patch.object(transition.pwd, "getpwnam", return_value=mock.Mock(pw_uid=501)), \
                    mock.patch.object(transition.grp, "getgrnam", return_value=mock.Mock(gr_gid=502)), \
                    mock.patch.object(transition.subprocess, "run", return_value=mock.Mock(returncode=1)):
                with self.assertRaisesRegex(transition.TransitionError, "execution_approvals_not_quiescent"):
                    transition.assert_quiescent()
            trusted.assert_called_once_with(root / "pending", 0o700, 501, 502)

    def test_forward_rotation_archives_committed_prior_without_null_dereference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            journal_path.write_text("present")
            record = self.record()
            record.update({
                "generation_id":"33333333-3333-4333-8333-333333333333",
                "generation_epoch":4,
                "previous_generation_id":"22222222-2222-4222-8222-222222222222",
                "previous_generation_epoch":3,
                "expected_prior_phase":"committed",
            })
            record_path = root / "record.json"
            record_path.write_bytes(transition.canonical(record))
            prior = {**self.record("committed"),
                     "schema":"secure-sandbox-execution-approval-transition-journal-v2",
                     "prior_record_sha256":None}
            with mock.patch.object(transition, "STATE_ROOT", root / "state"), \
                    mock.patch.object(transition, "JOURNAL", journal_path), \
                    mock.patch.object(transition, "HISTORY", root / "history"), \
                    mock.patch.object(transition, "FLOOR", root / "missing-floor"), \
                    mock.patch.object(transition, "ADMISSION_FENCE", root / "lifecycle/fence"), \
                    mock.patch.object(transition, "protected_directory"), \
                    mock.patch.object(transition, "trusted_existing_directory"), \
                    mock.patch.object(transition, "read_json", return_value=prior), \
                    mock.patch.object(transition, "release_identity", return_value="b" * 64), \
                    mock.patch.object(transition, "current_config", return_value={
                        "schema":"secure-sandbox-execution-broker-v2", "token":"x" * 64,
                        "runtime_image_id":"sha256:" + "1" * 64,
                    }), \
                    mock.patch.object(transition, "atomic"), \
                    mock.patch.object(transition.os, "geteuid", return_value=0):
                result = transition.apply(record_path)
            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["previous_generation_id"], prior["generation_id"])

    def test_identical_lost_response_redelivery_is_idempotent_for_every_phase(self):
        for phase in transition.PHASES:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                record = self.record(phase)
                record_path = root / "record.json"
                record_path.write_bytes(transition.canonical(record))
                journal = {
                    "schema":"secure-sandbox-execution-approval-transition-journal-v2",
                    **{name:record[name] for name in record if name != "schema"},
                    "prior_record_sha256":None if phase == "prepared" else "c" * 64,
                    "acceptance_binding_sha256":None,
                }
                receipt = {
                    "schema":"secure-sandbox-execution-approval-transition-receipt-v2",
                    "outcome":"succeeded", "phase":phase,
                    "transaction_id":record["transaction_id"],
                }
                def read(path, _schema, _mode, maximum=16384):
                    return journal if path == root / "journal.json" else receipt
                with mock.patch.object(transition, "STATE_ROOT", root), \
                        mock.patch.object(transition, "JOURNAL", root / "journal.json"), \
                        mock.patch.object(transition, "PHASE_RECEIPTS", root / "phase-receipts"), \
                        mock.patch.object(transition, "FLOOR", root / "missing-floor"), \
                        mock.patch.object(transition, "ADMISSION_FENCE", root / "lifecycle/fence"), \
                        mock.patch.object(Path, "exists", autospec=True,
                                          side_effect=lambda path: path == root / "journal.json"), \
                        mock.patch.object(transition, "protected_directory"), \
                        mock.patch.object(transition, "trusted_existing_directory"), \
                        mock.patch.object(transition, "read_json", side_effect=read), \
                        mock.patch.object(transition, "release_identity", return_value="b" * 64), \
                        mock.patch.object(transition, "admission_lock",
                                          return_value=contextlib.nullcontext()), \
                        mock.patch.object(transition, "reconcile_acceptance_permit"), \
                        mock.patch.object(transition, "reconcile_committed_admission"), \
                        mock.patch.object(transition, "atomic") as atomic, \
                        mock.patch.object(transition.os, "geteuid", return_value=0):
                    result = transition.apply(record_path)
                self.assertEqual(result["status"], phase)
                self.assertEqual(atomic.call_count, 1)
                self.assertIn("phase-receipts", str(atomic.call_args.args[0]))

    def test_fence_is_written_under_admission_lock_before_broker_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            journal_path.write_text("present")
            record = self.record("fenced")
            record_path = root / "record.json"
            record_path.write_bytes(transition.canonical(record))
            prior = {**self.record("prepared"),
                     "schema":"secure-sandbox-execution-approval-transition-journal-v2",
                     "prior_record_sha256":None}
            events = []
            def atomic(path, value, mode=0o600):
                events.append("fence" if path == root / "lifecycle/fence" else "journal")
            def run(command, **_kwargs):
                events.append("stop" if "stop" in command else "inactive")
                return mock.Mock(returncode=3 if "is-active" in command else 0)
            with mock.patch.object(transition, "STATE_ROOT", root / "state"), \
                    mock.patch.object(transition, "JOURNAL", journal_path), \
                    mock.patch.object(transition, "FLOOR", root / "missing-floor"), \
                    mock.patch.object(transition, "ADMISSION_FENCE", root / "lifecycle/fence"), \
                    mock.patch.object(transition, "protected_directory"), \
                    mock.patch.object(transition, "trusted_existing_directory"), \
                    mock.patch.object(transition, "read_json", return_value=prior), \
                    mock.patch.object(transition, "release_identity", return_value="b" * 64), \
                    mock.patch.object(transition, "current_config", return_value={
                        "schema":"secure-sandbox-execution-broker-v2", "token":"x" * 64,
                        "runtime_image_id":"sha256:" + "1" * 64,
                    }), \
                    mock.patch.object(transition, "admission_lock", return_value=contextlib.nullcontext()), \
                    mock.patch.object(transition, "assert_quiescent", side_effect=lambda: events.append("quiescent")), \
                    mock.patch.object(transition, "atomic", side_effect=atomic), \
                    mock.patch.object(transition, "write_config", side_effect=lambda _value: events.append("config")), \
                    mock.patch.object(transition.subprocess, "run", side_effect=run), \
                    mock.patch.object(transition.os, "geteuid", return_value=0):
                transition.apply(record_path)
            self.assertLess(events.index("quiescent"), events.index("fence"))
            self.assertLess(events.index("fence"), events.index("stop"))

    def test_failed_or_expired_acceptance_can_advance_by_one_cas_bound_attempt(self):
        prior = {
            **self.record("acceptance"),
            "schema":"secure-sandbox-execution-approval-transition-journal-v2",
            "prior_record_sha256":"1" * 64,
            "acceptance_binding_sha256":"2" * 64,
        }
        retry = self.record("acceptance")
        retry.update({
            "expected_prior_phase":"acceptance",
            "acceptance_attempt_id":"77777777-7777-4777-8777-777777777777",
            "acceptance_attempt_number":2,
            "previous_acceptance_binding_sha256":prior["acceptance_binding_sha256"],
            "run_id":"88888888-8888-4888-8888-888888888888",
            "session_id":"99999999-9999-4999-8999-999999999999",
        })
        retry["host_acceptance_authorization"].update({
            "acceptance_attempt_id":retry["acceptance_attempt_id"],
            "acceptance_attempt_number":2,
            "previous_acceptance_binding_sha256":prior["acceptance_binding_sha256"],
        })
        retry["host_acceptance_authorization"]["acceptance_binding_sha256"] = \
            transition.acceptance_binding(retry)
        existing = {
            "schema":"secure-sandbox-execution-approval-acceptance-permit-v1",
            "status":"consumed",
            **{name:prior[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "run_id", "session_id",
                "source_id", "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
                "runtime_image_id", "expires_at", "acceptance_attempt_id",
                "acceptance_attempt_number", "previous_acceptance_binding_sha256",
            )},
            "acceptance_binding_sha256":prior["acceptance_binding_sha256"],
            "consumed_at":2_000_000_001,
        }
        written = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(transition, "ACCEPTANCE_PERMIT", root / "permit.json"), \
                    mock.patch.object(transition, "ACCEPTANCE_HISTORY", root / "history"), \
                    mock.patch.object(transition, "assert_quiescent") as quiescent, \
                    mock.patch.object(transition, "receipt_is_successful_acceptance",
                                      return_value=False), \
                    mock.patch.object(transition, "read_json", return_value=existing), \
                    mock.patch.object(transition, "protected_directory"), \
                    mock.patch.object(transition, "atomic",
                                      side_effect=lambda path, value, mode=0o600:
                                      written.append((path, value))):
                transition.prepare_acceptance_retry(retry, prior)
        quiescent.assert_called_once()
        self.assertEqual([item[0].name for item in written], [
            f"{retry['transaction_id']}.1.journal.json",
            f"{retry['transaction_id']}.1.permit.json",
        ])

    def test_acceptance_retry_rejects_skips_and_any_successful_prior_evidence(self):
        prior = {
            **self.record("acceptance"),
            "schema":"secure-sandbox-execution-approval-transition-journal-v2",
            "prior_record_sha256":"1" * 64,
            "acceptance_binding_sha256":"2" * 64,
        }
        retry = self.record("acceptance")
        retry.update({
            "acceptance_attempt_id":"77777777-7777-4777-8777-777777777777",
            "acceptance_attempt_number":3,
            "previous_acceptance_binding_sha256":prior["acceptance_binding_sha256"],
        })
        with self.assertRaisesRegex(transition.TransitionError, "acceptance_retry_sequence_invalid"):
            transition.prepare_acceptance_retry(retry, prior)
        retry["acceptance_attempt_number"] = 2
        with mock.patch.object(transition, "assert_quiescent"), \
                mock.patch.object(transition, "receipt_is_successful_acceptance",
                                  return_value=True), \
                mock.patch.object(transition, "reconcile_acceptance_attempt") as reconcile, \
                self.assertRaisesRegex(transition.TransitionError, "acceptance_already_succeeded"):
            transition.prepare_acceptance_retry(retry, prior)
        reconcile.assert_called_once_with(prior)

    def test_durable_success_receipt_reconciles_claimed_attempt_without_reexecution(self):
        record = self.record("acceptance")
        binding = transition.acceptance_binding(record)
        marker = {
            "schema":"secure-sandbox-execution-approval-acceptance-attempt-v2",
            "status":"claimed",
            **{name:record[name] for name in (
                "transaction_id", "generation_id", "generation_epoch", "run_id", "session_id",
                "source_id", "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
                "runtime_image_id", "expires_at", "acceptance_attempt_id",
                "acceptance_attempt_number", "previous_acceptance_binding_sha256",
            )},
            "acceptance_binding_sha256":binding,
            "claimed_at":2_000_000_001,
        }
        evidence = {
            "source_id":record["source_id"], "run_id":record["run_id"],
            "session_id":record["session_id"], "code_sha256":record["code_sha256"],
            "fixture_manifest_sha256":record["fixture_manifest_sha256"],
            "timeout_seconds":record["timeout_seconds"],
            "image_digest":record["runtime_image_id"],
            "approval_key_generation_id":record["generation_id"],
            "approval_key_generation_epoch":record["generation_epoch"],
            "approval_public_key_sha256":record["public_key_sha256"],
            "approval_signature_algorithm":record["algorithm"],
            "exit_code":0, "timed_out":False, "output_limit_exceeded":False,
            "stdout_truncated":False, "stderr_truncated":False,
            "approval_id":"77777777-7777-4777-8777-777777777777",
            "approval_attestation_sha256":"8" * 64,
        }
        receipt = {
            "schema":"secure-sandbox-evidence-receipt-v4",
            "receipt_id":"99999999-9999-4999-8999-999999999999",
            "producer":"execution-broker", "instrument":"run_python_fixture",
            "evidence":evidence,
        }
        content = json.dumps(
            receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        receipt["content_sha256"] = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consumed = root / "approvals/consumed"
            receipts = root / "receipts"
            consumed.mkdir(parents=True)
            receipts.mkdir()
            marker_path = consumed / f"acceptance-{record['acceptance_attempt_id']}.json"
            marker_path.write_bytes(transition.canonical(marker))
            marker_path.chmod(0o600)
            receipt_path = receipts / f"{receipt['receipt_id']}.json"
            receipt_path.write_bytes(json.dumps(
                receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8") + b"\n")
            receipt_path.chmod(0o640)
            identity = mock.Mock(pw_uid=os.geteuid())
            with mock.patch.object(transition, "APPROVAL_ROOT", root / "approvals"), \
                    mock.patch.object(transition, "EVIDENCE_RECEIPTS", receipts), \
                    mock.patch.object(transition.pwd, "getpwnam", return_value=identity):
                reconciled, matches = transition.reconcile_acceptance_attempt(record)
                again, repeated_matches = transition.reconcile_acceptance_attempt(record)
        self.assertEqual(reconciled["status"], "succeeded")
        self.assertEqual(reconciled["research_receipt_id"], receipt["receipt_id"])
        self.assertEqual(reconciled["research_receipt_sha256"], receipt["content_sha256"])
        self.assertEqual(again, reconciled)
        self.assertEqual(len(matches), 1)
        self.assertEqual(repeated_matches, matches)

if __name__ == "__main__":
    unittest.main()
