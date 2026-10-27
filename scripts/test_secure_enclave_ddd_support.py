#!/usr/bin/env python3

import importlib.util
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name("secure_enclave_ddd_support.py")
SPEC = importlib.util.spec_from_file_location("secure_enclave_ddd_support", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SUPPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPORT)


class PreActivationRepairTests(unittest.TestCase):
    HOST = "1" * 64
    NEW_HOST = "2" * 64
    RESEARCH = "3" * 64
    NEW_RESEARCH = "4" * 64

    def required(self, source_host: str, live_host: str, source_research: str) -> bool:
        return SUPPORT.preactivation_repair_required(
            self.HOST, source_host, live_host, self.RESEARCH, source_research
        )

    def test_neither_measurement_changed(self):
        self.assertFalse(self.required(self.HOST, self.HOST, self.RESEARCH))

    def test_host_only_source_measurement_changed(self):
        self.assertTrue(self.required(self.NEW_HOST, self.HOST, self.RESEARCH))

    def test_research_only_measurement_changed(self):
        self.assertTrue(self.required(self.HOST, self.HOST, self.NEW_RESEARCH))

    def test_both_measurements_changed(self):
        self.assertTrue(self.required(self.NEW_HOST, self.HOST, self.NEW_RESEARCH))

    def test_live_host_selector_drift_also_requires_repair(self):
        self.assertTrue(self.required(self.HOST, self.NEW_HOST, self.RESEARCH))

    def test_invalid_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "source_host_release_id_invalid"):
            self.required("not-a-digest", self.HOST, self.RESEARCH)

    def test_selector_restore_not_needed_when_checkpoint_is_live(self):
        self.assertFalse(SUPPORT.selector_restore_required(
            self.HOST, self.HOST, self.HOST, self.NEW_HOST
        ))

    def test_exact_deployed_repair_is_reused_when_checkpoint_is_previous(self):
        self.assertTrue(SUPPORT.reusable_deployed_host(
            self.HOST, self.NEW_HOST, self.NEW_HOST, self.HOST
        ))
        self.assertFalse(SUPPORT.selector_restore_required(
            self.HOST, self.NEW_HOST, self.NEW_HOST, self.HOST
        ))

    def test_selector_restore_needed_after_two_unrebound_deployments(self):
        self.assertTrue(SUPPORT.selector_restore_required(
            self.HOST, self.NEW_HOST, "5" * 64, "6" * 64
        ))

    def test_crash_after_deploy_before_reauthorization_reuses_release(self):
        self.assertTrue(SUPPORT.reusable_deployed_host(
            self.HOST, "6" * 64, "6" * 64, self.HOST
        ))

    def test_crash_after_reauthorization_before_checkpoint_reuses_release(self):
        # The root pending state may already bind the live release.  Reusing
        # it makes the key preparation request safely idempotent.
        self.assertTrue(SUPPORT.reusable_deployed_host(
            self.HOST, "6" * 64, "6" * 64, self.HOST
        ))

    def test_source_change_after_crash_requires_restore(self):
        self.assertTrue(SUPPORT.selector_restore_required(
            self.HOST, "7" * 64, "6" * 64, self.HOST
        ))

    def test_live_source_without_checkpoint_selector_requires_restore(self):
        self.assertTrue(SUPPORT.selector_restore_required(
            self.HOST, "6" * 64, "6" * 64, "7" * 64
        ))


class ProtectedSelectorIdentityTests(unittest.TestCase):
    CURRENT = "1" * 64
    PREVIOUS = "2" * 64
    CAPABILITY = b"secure-sandbox-execution-approval-v2"

    def setUp(self):
        self.current = Path("/protected/releases") / self.CURRENT
        self.previous = Path("/protected/releases") / self.PREVIOUS
        self.manager = SimpleNamespace(
            EXECUTION_APPROVAL_V2_CAPABILITY=self.CAPABILITY,
            enforce_execution_approval_floor=mock.Mock(),
            verified_release=mock.Mock(side_effect=[
                (self.current, {"release_id":self.CURRENT}),
                (self.previous, {"release_id":self.PREVIOUS}),
            ]),
            read_regular=mock.Mock(return_value=b"prefix" + self.CAPABILITY),
        )
        self.identity = {
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_epoch":1,
            "generation_id":"12345678-1234-4123-8123-123456789abc",
            "public_key_sha256":"3" * 64,
        }

    def selectors(self):
        completed = SimpleNamespace(stdout=json.dumps(self.identity))
        with mock.patch.object(
            SUPPORT, "host_release_manager", return_value=self.manager
        ), mock.patch.object(SUPPORT.subprocess, "run", return_value=completed):
            return SUPPORT.protected_selector_identities(
                Path("/repo"), Path("/protected")
            )

    def test_v2_selectors_and_active_hardware_identity_are_accepted(self):
        self.assertEqual(self.selectors(), {
            "current":self.CURRENT, "previous":self.PREVIOUS,
        })
        self.assertEqual(self.manager.verified_release.call_count, 2)
        self.assertIsNotNone(self.manager.enforce_execution_approval_floor)

    def test_legacy_previous_selector_is_rejected(self):
        self.manager.read_regular.side_effect = [
            b"prefix" + self.CAPABILITY,
            b"legacy-software-broker",
        ]
        with self.assertRaisesRegex(
            RuntimeError, "previous_selector_below_execution_approval_floor"
        ):
            self.selectors()

    def test_inactive_live_broker_is_rejected(self):
        self.identity["status"] = "prepared"
        with self.assertRaisesRegex(
            RuntimeError, "active_execution_approval_identity_invalid"
        ):
            self.selectors()

    def test_wrong_algorithm_is_rejected(self):
        self.identity["algorithm"] = "software-fallback"
        with self.assertRaisesRegex(
            RuntimeError, "active_execution_approval_identity_invalid"
        ):
            self.selectors()

    def test_malformed_public_key_digest_is_rejected(self):
        self.identity["public_key_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(
            RuntimeError, "active_execution_approval_identity_invalid"
        ):
            self.selectors()

    def test_boolean_generation_epoch_is_rejected(self):
        self.identity["generation_epoch"] = True
        with self.assertRaisesRegex(
            RuntimeError, "active_execution_approval_identity_invalid"
        ):
            self.selectors()

    def test_live_broker_query_failure_propagates(self):
        with mock.patch.object(
            SUPPORT, "host_release_manager", return_value=self.manager
        ), mock.patch.object(
            SUPPORT.subprocess, "run",
            side_effect=subprocess.CalledProcessError(1, ["broker"]),
        ), self.assertRaises(subprocess.CalledProcessError):
            SUPPORT.protected_selector_identities(
                Path("/repo"), Path("/protected")
            )


class BridgeArchiveTests(unittest.TestCase):
    TRANSACTION = "12345678-1234-4123-8123-123456789abc"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.private = Path(self.temporary.name) / ".private"
        self.history = self.private / "secure-enclave-execution-approval-ddd-history"
        self.state_dir = self.private / "secure-enclave-execution-approval-ddd"
        for path in (self.private, self.history, self.state_dir):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        self.archive = self.history / f"{self.TRANSACTION}.bridge"
        self.value = {
            "schema":"secure-sandbox-secure-enclave-ddd-checkpoint-v1",
            "stage":"bridge_committed",
            "prepared":{"transaction_id":self.TRANSACTION},
        }
        self.write_state(self.state_dir, self.value)

    def tearDown(self):
        self.temporary.cleanup()

    def write_state(self, directory: Path, value: dict) -> None:
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        state = directory / "state.json"
        state.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
        state.chmod(0o600)

    def test_archive_fsyncs_destination_then_source_parent(self):
        calls = []
        with mock.patch.object(SUPPORT, "fsync_directory", side_effect=calls.append):
            result = SUPPORT.archive_bridge_checkpoint(
                self.state_dir, self.archive, os.geteuid()
            )
        self.assertEqual(calls, [self.history, self.private])
        self.assertFalse(self.state_dir.exists())
        self.assertTrue(self.archive.is_dir())
        self.assertIsNone(result["recovered_duplicate"])

    def test_restart_after_fixed_release_or_handoff_keeps_bridge_source_usable(self):
        # Before the rename the bridge checkpoint remains intact and a retry
        # can safely skip an already-installed exact source release.
        raw, value = SUPPORT.bridge_checkpoint(self.state_dir, os.geteuid())
        self.assertTrue(raw)
        self.assertEqual(value["stage"], "bridge_committed")

    def test_fault_after_each_rename_durability_boundary_is_restart_safe(self):
        for boundary in ("rename", "destination_fsync", "source_fsync"):
            with self.subTest(boundary=boundary):
                if not self.state_dir.exists():
                    shutil.copytree(self.archive, self.state_dir)
                    self.state_dir.chmod(0o700)
                if self.archive.exists():
                    shutil.rmtree(self.archive)
                with self.assertRaisesRegex(RuntimeError, f"injected_after_{boundary}"):
                    SUPPORT.archive_bridge_checkpoint(
                        self.state_dir, self.archive, os.geteuid(), fault_after=boundary
                    )
                self.assertFalse(self.state_dir.exists())
                self.assertTrue(self.archive.is_dir())

    def test_resurrected_source_is_preserved_as_duplicate_and_does_not_strand_retry(self):
        shutil.copytree(self.state_dir, self.archive)
        result = SUPPORT.archive_bridge_checkpoint(
            self.state_dir, self.archive, os.geteuid()
        )
        self.assertFalse(self.state_dir.exists())
        duplicate = Path(result["recovered_duplicate"])
        self.assertTrue(duplicate.is_dir())
        self.assertEqual(
            (duplicate / "state.json").read_bytes(),
            (self.archive / "state.json").read_bytes(),
        )

    def test_resurrected_conflicting_source_fails_closed(self):
        shutil.copytree(self.state_dir, self.archive)
        conflicting = dict(self.value)
        conflicting["bridge_committed_at"] = 99
        self.write_state(self.archive, conflicting)
        with self.assertRaisesRegex(RuntimeError, "bridge_archive_conflict"):
            SUPPORT.archive_bridge_checkpoint(
                self.state_dir, self.archive, os.geteuid()
            )
        self.assertTrue(self.state_dir.is_dir())


class CheckpointHostReleaseVerificationTests(unittest.TestCase):
    RELEASE = "1" * 64
    PUBLIC_KEY = "2" * 64
    UI_BUNDLE = "3" * 64
    GENERATION = "12345678-1234-4123-8123-123456789abc"

    def setUp(self):
        self.manager = SimpleNamespace(
            LAUNCHER_SOURCE=Path("scripts/secure-sandbox-claude"),
            enforce_execution_approval_floor=lambda _broker, _uid=0: None,
            verified_release=mock.Mock(return_value=(
                Path("/protected/releases") / self.RELEASE,
                {"payloads":{"authorization_ui_bundle":self.UI_BUNDLE}},
            )),
            read_regular=mock.Mock(return_value=b"exact-launcher"),
            sha256_bytes=lambda value: hashlib.sha256(value).hexdigest(),
        )
        self.launcher = mock.Mock()
        self.launcher.stat.return_value = SimpleNamespace(
            st_uid=0, st_mode=stat.S_IFREG | 0o755
        )
        self.identity = {
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_id":self.GENERATION,
            "generation_epoch":1,
            "public_key_sha256":self.PUBLIC_KEY,
        }

    def verify(self):
        completed = SimpleNamespace(stdout=json.dumps(self.identity))
        with mock.patch.object(
            SUPPORT, "host_release_manager", return_value=self.manager
        ), mock.patch.object(SUPPORT.subprocess, "run", return_value=completed):
            return SUPPORT.verify_checkpoint_host_release(
                Path("/repo"), Path("/protected"), self.launcher,
                self.RELEASE, self.GENERATION, 1, self.PUBLIC_KEY,
                self.UI_BUNDLE,
            )

    def test_exact_immutable_checkpoint_and_active_identity_are_accepted(self):
        result = self.verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["release_id"], self.RELEASE)
        self.assertEqual(result["public_key_sha256"], self.PUBLIC_KEY)

    def test_active_key_substitution_fails_closed(self):
        self.identity["public_key_sha256"] = "4" * 64
        with self.assertRaisesRegex(
            RuntimeError, "checkpoint_execution_approval_identity_mismatch"
        ):
            self.verify()

    def test_checkpoint_ui_substitution_fails_closed(self):
        self.manager.verified_release.return_value = (
            Path("/protected/releases") / self.RELEASE,
            {"payloads":{"authorization_ui_bundle":"5" * 64}},
        )
        with self.assertRaisesRegex(RuntimeError, "checkpoint_ui_bundle_mismatch"):
            self.verify()

    def test_checkpoint_selector_substitution_fails_closed(self):
        self.manager.verified_release.return_value = (
            Path("/protected/releases") / ("6" * 64),
            {"payloads":{"authorization_ui_bundle":self.UI_BUNDLE}},
        )
        with self.assertRaisesRegex(RuntimeError, "checkpoint_host_release_mismatch"):
            self.verify()

    def test_generic_installed_successor_verifies_manifest_and_active_identity(self):
        completed = SimpleNamespace(stdout=json.dumps(self.identity))
        with mock.patch.object(
            SUPPORT, "host_release_manager", return_value=self.manager
        ), mock.patch.object(SUPPORT.subprocess, "run", return_value=completed):
            result = SUPPORT.verify_installed_host_release(
                Path("/repo"), Path("/protected"), self.launcher,
                self.RELEASE, self.GENERATION, 1, self.PUBLIC_KEY,
            )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(
            result["payloads"]["authorization_ui_bundle"], self.UI_BUNDLE
        )

    def test_generic_installed_successor_substitution_fails_closed(self):
        completed = SimpleNamespace(stdout=json.dumps(self.identity))
        self.manager.verified_release.return_value = (
            Path("/protected/releases") / ("6" * 64),
            {"payloads":{"authorization_ui_bundle":self.UI_BUNDLE}},
        )
        with mock.patch.object(
            SUPPORT, "host_release_manager", return_value=self.manager
        ), mock.patch.object(SUPPORT.subprocess, "run", return_value=completed), \
                self.assertRaisesRegex(
                    RuntimeError, "installed_host_release_mismatch"
                ):
            SUPPORT.verify_installed_host_release(
                Path("/repo"), Path("/protected"), self.launcher,
                self.RELEASE, self.GENERATION, 1, self.PUBLIC_KEY,
            )


class ResumeAcceptanceCrashOrderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (Path(__file__).with_name(
            "resume-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")

    def function(self, name: str, next_name: str) -> str:
        start = self.text.index(f"{name}() {{")
        end = self.text.index(f"{next_name}() {{", start)
        return self.text[start:end]

    def test_cold_boot_starts_stopped_stack_before_boundary_verification(self):
        start = self.text.index('case "$gateway_state:$research_state:$target_state"')
        boundary = self.text.index(
            'scripts/verify-boundaries.sh | tee "$temporary/pre-resume-boundary.log"'
        )
        self.assertLess(start, boundary)
        cold_start = self.text[start:boundary]
        self.assertIn("stopped:stopped:stopped)", cold_start)
        self.assertIn("scripts/labctl start", cold_start)

    def test_cold_boot_restores_exact_agents_and_requires_closed_gui_first(self):
        agent = self.text.index("agent_matches() {")
        key_load = self.text.index("scripts/labctl key-load", agent)
        gui = self.text.index("/usr/bin/pgrep -x prl_client_app", key_load)
        lifecycle = self.text.index(
            'case "$gateway_state:$research_state:$target_state"', gui
        )
        self.assertLess(agent, key_load)
        self.assertLess(key_load, gui)
        self.assertLess(gui, lifecycle)
        restore = self.text[agent:gui]
        self.assertIn("/usr/bin/ssh-keygen", restore)
        self.assertIn("/usr/bin/ssh-add", restore)
        self.assertIn("cold_boot_ssh_identity_restore_failed", restore)

    def test_running_stack_is_reused_and_mixed_state_fails_closed(self):
        start = self.text.index('case "$gateway_state:$research_state:$target_state"')
        boundary = self.text.index(
            'scripts/verify-boundaries.sh | tee "$temporary/pre-resume-boundary.log"'
        )
        readback = self.text[start:boundary]
        self.assertIn("running:running:running)", readback)
        self.assertIn("without retrying lifecycle startup", readback)
        self.assertIn("mixed_or_unknown_vm_state", readback)
        self.assertLess(readback.index("scripts/labctl start"), len(readback))

    def test_draft_is_durable_before_remote_lease_and_reuses_fixed_run_id(self):
        persist = self.function(
            "persist_initial_acceptance_draft", "replace_unissued_acceptance_plan"
        )
        materialize = self.function(
            "materialize_acceptance_draft", "persist_initial_acceptance_draft"
        )
        self.assertLess(
            persist.index(".planned_acceptance_retry_draft=$draft"),
            persist.index('durable_replace "$state_tmp" "$state"'),
        )
        self.assertIn('run_id="$(jq -er .run_id <<<"$draft")"', materialize)
        self.assertIn('issue_gateway_lease "$run_id"', materialize)
        self.assertIn("del(.planned_acceptance_retry_draft", materialize)

    def test_expired_draft_lease_is_zero_use_checked_and_reidentified(self):
        materialize = self.function(
            "materialize_acceptance_draft", "persist_initial_acceptance_draft"
        )
        self.assertIn('status="$(gateway_control lease-status "$run_id")"', materialize)
        self.assertIn('.summary.reason == "expired"', materialize)
        self.assertIn('.counters.requests == 0', materialize)
        self.assertIn('.counters.input_tokens == 0', materialize)
        self.assertIn('.counters.output_tokens == 0', materialize)
        self.assertIn('.counters.cost_microusd == 0', materialize)
        self.assertIn('.acceptance_attempt_id=$acceptance_attempt_id', materialize)
        self.assertIn('materialize_acceptance_draft\n    return', materialize)

    def test_host_authorization_is_checkpointed_before_research_cas(self):
        main = self.text[self.text.index("while true; do"):]
        self.assertLess(
            main.index('persist_host_authorization "$acceptance_core" "$host_authorization"'),
            main.index('research_acceptance="$(deploy_transition'),
        )
        self.assertIn(".planned_acceptance_host_authorization", main)

    def test_host_binding_uses_exact_newline_terminated_canonical_vector(self):
        core = {
            "acceptance_attempt_id":"11111111-1111-4111-8111-111111111111",
            "acceptance_attempt_number":3,
            "code_sha256":"a" * 64,
            "expires_at":2_000_003_600,
            "fixture_manifest_sha256":"b" * 64,
            "generation_epoch":1,
            "generation_id":"22222222-2222-4222-8222-222222222222",
            "previous_acceptance_binding_sha256":"c" * 64,
            "run_id":"33333333-3333-4333-8333-333333333333",
            "runtime_image_id":"sha256:" + "d" * 64,
            "session_id":"44444444-4444-4444-8444-444444444444",
            "source_id":"55555555-5555-4555-8555-555555555555",
            "timeout_seconds":5,
            "transaction_id":"66666666-6666-4666-8666-666666666666",
        }
        compact = json.dumps(core, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        expected = hashlib.sha256(compact + b"\n").hexdigest()
        self.assertNotEqual(expected, hashlib.sha256(compact).hexdigest())
        start = self.text.index("persist_host_authorization() {")
        persist = self.text[start:self.text.index("\nset +e", start)]
        self.assertIn("printf '%s\\n'", persist)

    def test_expired_host_authorized_attempt_reaches_research_before_advancing(self):
        main = self.text[self.text.index("while true; do"):]
        research = main.index('research_acceptance="$(deploy_transition')
        checkpoint = main.index(".acceptance_record=$record")
        expired = main.index('if [[ "$(date +%s)" -ge "$expires_at" ]]', checkpoint)
        advance = main.index('exec "$root_dir/scripts/resume-secure-enclave-execution-approval-ddd.sh"', expired)
        self.assertLess(research, checkpoint)
        self.assertLess(checkpoint, expired)
        self.assertLess(expired, advance)

    def test_only_not_issued_expired_plan_gets_replacement_ids(self):
        main = self.text[self.text.index("while true; do"):]
        status = main.index("== not_issued_expired")
        replacement = main.index('replace_unissued_acceptance_plan "$acceptance_core" expired')
        self.assertLess(status, replacement)
        self.assertNotIn("replace_unissued_acceptance_plan", main[:status])

    def test_retry_binds_cross_checked_live_runtime_not_stale_checkpoint_runtime(self):
        resolver = self.function(
            "verified_live_runtime_image", "issue_gateway_lease"
        )
        self.assertIn("sandbox-research-control", resolver)
        self.assertIn("sandbox-target-control", resolver)
        self.assertIn("audit-execution-runtime-identity.sh", resolver)
        self.assertIn('[[ "$research_image" == "$target_image" ]]', resolver)
        persist = self.function(
            "persist_initial_acceptance_draft", "replace_unissued_acceptance_plan"
        )
        self.assertIn('local prepared="$1" runtime_image_id="$2"', persist)
        self.assertIn('--arg runtime_image_id "$runtime_image_id"', persist)
        self.assertNotIn(".acceptance_record.runtime_image_id", persist)

    def test_retry_record_rebinds_every_exact_execution_field(self):
        main = self.text[self.text.index('jq -nS --argjson prior'):]
        for field in (
            "source_id", "code_sha256", "fixture_manifest_sha256",
            "timeout_seconds", "runtime_image_id",
        ):
            self.assertIn(f".{field}=$core.{field}", main)

    def test_predecessor_evidence_is_archived_before_acceptance_verification(self):
        archive = self.text.index("archive_predecessor_acceptance_evidence\n")
        verify = self.text.index(
            'verify_acceptance > "$temporary/research-evidence.json"', archive
        )
        self.assertLess(archive, verify)
        function = self.function(
            "archive_predecessor_acceptance_evidence", "gateway_control"
        )
        self.assertIn("install-acceptance-evidence-archive.sh", function)
        self.assertIn(".current_transaction_id == $transaction", function)


class FinalizeBridgeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (Path(__file__).with_name(
            "finalize-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")
        cls.helper = (Path(__file__).with_name(
            "commit-secure-enclave-bridge-successor.sh"
        )).read_text(encoding="utf-8")
        cls.validator = (Path(__file__).with_name(
            "validate_secure_enclave_finalization.py"
        )).read_text(encoding="utf-8")

    def test_only_bridge_mode_accepts_the_two_exact_predecessor_failures(self):
        self.assertIn('if [[ "$bridge_to_rotation" == true', self.text)
        self.assertIn('"$boundary_status" -eq 0', self.text)
        self.assertIn('"$(grep -c \'^FAIL  \'', self.text)
        self.assertIn(
            "FAIL  Host Claude controller is an immutable release matching approved source",
            self.text,
        )
        self.assertIn(
            "FAIL  Evidence receipts are producer-minted and hidden from the agent",
            self.text,
        )
        self.assertIn('BOUNDARY VERIFICATION FAILED: 2 check(s)', self.text)
        self.assertIn('verify-checkpoint-host-release', self.text)
        self.assertIn('verify-checkpoint-research-boundary.sh', self.text)
        self.assertIn('unexpected_finalize_boundary_failure', self.text)

    def test_bridge_evidence_binds_the_checkpoint_verifier_digest(self):
        self.assertIn('checkpoint_host_verification_sha256', self.text)
        self.assertIn('checkpoint_host_verification:$checkpoint_host_verification', self.text)
        self.assertIn('checkpoint_research_verification_sha256', self.text)
        self.assertIn('checkpoint_research_verification:$checkpoint_research_verification', self.text)
        self.assertIn('bridge_predecessor_exception:$bridge', self.text)

    def test_host_correlation_is_durable_but_negative_gate_is_fresh(self):
        self.assertIn(
            '.host_acceptance_verifier != null',
            self.text,
        )
        self.assertIn(
            '.host_acceptance_verifier=$verifier',
            self.text,
        )
        self.assertIn('finalize_verifier_checkpoint_invalid', self.validator)
        self.assertIn('validate_secure_enclave_finalization.py verifier', self.text)
        self.assertIn('finalize_negative_gate_result_invalid', self.validator)
        self.assertIn('validate_secure_enclave_finalization.py negative', self.text)

    def test_accidental_second_signature_approval_is_distinguished(self):
        self.assertIn(
            'second_signature_was_approved_expected_operator_cancellation',
            self.text,
        )
        self.assertIn('second_sign_unexpected_stdout', self.text)
        self.assertIn('validate_secure_enclave_finalization.py cancellation', self.text)

    def test_bridge_checkpoint_is_cross_bound_to_protected_verifier(self):
        self.assertIn(
            '.prepared.transaction_id == $transaction_id', self.text
        )
        self.assertIn(
            '.prepared.host_release_id == $host_release_id', self.text
        )
        self.assertIn(
            '.prepared.research_release_id == $research_release_id', self.text
        )
        self.assertIn('bridge_checkpoint_verifier_identity_mismatch', self.text)
        self.assertIn(
            '--expected-release-id "$(jq -er .host_release_id <<<"$verifier")"',
            self.text,
        )

    def test_bridge_predecessor_is_checkpointed_before_successor_deployment(self):
        state_update = self.text.index('.bridge_exception=$bridge_exception')
        checkpoint = self.text.index(
            'durable_replace "$state_tmp" "$state"', state_update
        )
        delegation = self.text.index(
            'exec "$root_dir/scripts/commit-secure-enclave-bridge-successor.sh"',
            checkpoint,
        )
        self.assertLess(checkpoint, delegation)
        self.assertNotIn("expected_source_release_id", self.text)
        self.assertIn("expected_source_release_id", self.helper)

    def test_bridge_helper_recovers_selector_advance_before_checkpoint(self):
        self.assertIn(
            'elif [[ "$current_release" == "$source_release" ]]', self.helper
        )
        self.assertIn(
            "Recover the already-deployed exact Host successor", self.helper
        )
        initial_recovery = self.helper[
            self.helper.index(
                "Recover the already-deployed exact Host successor"
            ):self.helper.index(
                "bridge_successor_deployment_invalid"
            )
        ]
        self.assertIn("launcher_sha256:.launcher_sha256", initial_recovery)
        self.assertIn("payloads:.payloads", initial_recovery)
        successor_checkpoint = self.helper.index(
            '.bridge_successor_deployment=$deployment'
        )
        host_commit = self.helper.index(
            'BRIDGE COMMIT 1/2  Commit the successor-validated Host authority'
        )
        self.assertLess(successor_checkpoint, host_commit)


class InitialDeploymentAcceptanceCrashOrderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (Path(__file__).with_name(
            "deploy-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")

    def function(self, name: str, next_name: str) -> str:
        start = self.text.index(f"{name}() {{")
        end = self.text.index(f"{next_name}() {{", start)
        return self.text[start:end]

    def test_draft_precedes_remote_lease_and_lease_defines_expiry(self):
        main = self.text[self.text.index("acceptance_code='"):]
        creation = main[main.index('acceptance_draft="$(jq -ncS'):]
        self.assertLess(
            creation.index(".planned_acceptance_draft=$draft"),
            creation.index("materialize_initial_acceptance_draft"),
        )
        materialize = self.function(
            "materialize_initial_acceptance_draft",
            "persist_initial_host_authorization",
        )
        self.assertIn('run_id="$(jq -er .run_id <<<"$draft")"', materialize)
        self.assertIn('issue_acceptance_gateway_lease "$run_id"', materialize)
        self.assertIn('acceptance_expires_at="$(jq -er .expires_at', materialize)

    def test_abandoned_draft_requires_zero_use_and_new_identities(self):
        finalizer = self.function(
            "finalize_draft_gateway_lease",
            "materialize_initial_acceptance_draft",
        )
        self.assertIn('.summary.reason == "expired"', finalizer)
        self.assertIn('.counters.requests == 0', finalizer)
        self.assertIn('.counters.input_tokens == 0', finalizer)
        self.assertIn('.counters.output_tokens == 0', finalizer)
        self.assertIn('.counters.cost_microusd == 0', finalizer)
        materialize = self.function(
            "materialize_initial_acceptance_draft",
            "persist_initial_host_authorization",
        )
        self.assertGreaterEqual(materialize.count("uuidgen"), 3)
        main = self.text[self.text.index("acceptance_code='"):]
        expired = main.index("== not_issued_expired")
        replacement = main[expired:main.index("persist_initial_host_authorization", expired)]
        self.assertGreaterEqual(replacement.count("uuidgen"), 3)

    def test_exact_host_authorization_is_durable_before_research_cas(self):
        persist = self.function(
            "persist_initial_host_authorization", "make_record"
        )
        self.assertIn("printf '%s\\n'", persist)
        self.assertIn(".acceptance_binding_sha256 == $binding", persist)
        main = self.text[self.text.index("acceptance_code='"):]
        self.assertLess(
            main.index('persist_initial_host_authorization "$acceptance_core"'),
            main.index('research_acceptance="$(deploy_transition'),
        )

    def test_deployed_target_runtime_is_checkpointed_and_drives_acceptance(self):
        deployment = self.text.index(
            'disposable_deployment="$(scripts/deploy-disposable-execution.sh)"'
        )
        extraction = self.text.index('deployed_runtime_image="$(printf', deployment)
        checkpoint = self.text.index(
            'deployed_runtime_image:$deployed_runtime_image', extraction
        )
        acceptance = self.text.index(
            'acceptance_runtime_image="$(jq -er .deployed_runtime_image', checkpoint
        )
        self.assertLess(deployment, extraction)
        self.assertLess(extraction, checkpoint)
        self.assertLess(checkpoint, acceptance)


class RotationRuntimeBindingTests(unittest.TestCase):
    def test_rotation_does_not_pin_a_prior_runtime_digest(self):
        text = (Path(__file__).with_name(
            "rotate-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")
        self.assertNotIn("acceptance_runtime_image=sha256:", text)
        self.assertNotIn("--acceptance-runtime-image", text)

    def test_runtime_auditor_emits_no_token(self):
        text = (Path(__file__).with_name(
            "audit-execution-runtime-identity.sh"
        )).read_text(encoding="utf-8")
        self.assertIn('keys | sort', text)
        self.assertIn('runtime_image_id:.runtime_image_id', text)
        self.assertIn('runtime_image_id:.image_id', text)
        self.assertNotIn('token:.token', text)

    def test_acceptance_evidence_archiver_is_bounded_and_history_bound(self):
        text = (Path(__file__).with_name(
            "archive_execution_approval_acceptance_evidence.py"
        )).read_text(encoding="utf-8")
        self.assertIn("MAX_ARCHIVED = 64", text)
        self.assertIn('journal.get("phase") != "committed"', text)
        self.assertIn('receipt.get("journal_sha256") == journal.get("prior_record_sha256")', text)
        self.assertIn("acceptance_evidence_history_mismatch", text)
        self.assertIn("acceptance_evidence_archive_conflict", text)
        self.assertIn("acceptance_evidence_archive_limit_exceeded", text)
        self.assertIn("os.replace(singleton, target)", text)
        self.assertIn("fsync_directory(archive)", text)
        self.assertIn("fsync_directory(state_root)", text)

    def test_initial_generation_skips_predecessor_archive_repair(self):
        text = (Path(__file__).with_name(
            "resume-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")
        self.assertIn(
            '.prepared.previous_generation_id != null\n'
            '    and .prepared.previous_generation_epoch != null', text,
        )
        self.assertIn(
            '.prepared.previous_generation_id == null\n'
            '    and .prepared.previous_generation_epoch == null', text,
        )
        self.assertIn("acceptance_predecessor_identity_invalid", text)

    def test_bridge_predecessor_digest_is_loaded_from_private_local_config(self):
        concrete = "45126" + "d1c0133ded3a29315ff70fb8b733e947cfd07c4184680c3ea4a1e87df33"
        for name in (
            "resume-secure-enclave-execution-approval-ddd.sh",
            "finalize-secure-enclave-execution-approval-ddd.sh",
            "commit-secure-enclave-bridge-successor.sh",
        ):
            with self.subTest(name=name):
                text = Path(__file__).with_name(name).read_text(encoding="utf-8")
                self.assertIn("local-config-field", text)
                self.assertIn("legacy_launchservices_ui_bundle_sha256", text)
                self.assertNotIn(concrete, text)


class DeploymentRestartSafetyTests(unittest.TestCase):
    def test_reboot_instruction_requires_gui_quit_and_verified_vm_shutdown(self):
        text = (Path(__file__).with_name(
            "deploy-secure-enclave-execution-approval-ddd.sh"
        )).read_text(encoding="utf-8")
        self.assertIn("quit the Parallels Desktop GUI", text)
        self.assertIn("keep it closed", text)
        self.assertIn("printf '  cd %q\\n' \"$root_dir\"", text)
        self.assertIn("./scripts/labctl stop", text)
        self.assertIn("gateway, research, and target all stopped", text)


if __name__ == "__main__":
    unittest.main()
