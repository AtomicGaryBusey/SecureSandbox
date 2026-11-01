#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DisposableMacHarnessLifecycleAcceptanceDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_DESIGN.md").read_text()
        cls.evidence = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_EVIDENCE.md").read_text()
        cls.contract = (ROOT / "shared/harness_lifecycle_acceptance.py").read_text()
        cls.store = (ROOT / "shared/harness_generation_store.py").read_text()
        cls.cli = (ROOT / "scripts/harness-lifecycle-acceptance.py").read_text()
        cls.observer = (ROOT / "scripts/harness-lifecycle-acceptance-observe.py").read_text()
        cls.bootstrap = (ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py").read_text()
        cls.enrollment = (ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py").read_text()
        cls.recovery_cli = (ROOT / "scripts/harness-lifecycle-acceptance-recovery.py").read_text()
        cls.recovery_supervisor = (ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py").read_text()
        cls.recovery_projector = (ROOT / "scripts/harness-lifecycle-acceptance-recovery-observe.py").read_text()
        cls.recovery_installer = (ROOT / "scripts/install-harness-lifecycle-acceptance-recovery.sh").read_text()
        cls.recovery_fixture = (ROOT / "shared/harness_lifecycle_acceptance_fixture.py").read_text()
        cls.bridge = (ROOT / "scripts/control-center-api.py").read_text()
        cls.harness_models = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Models/HarnessModels.swift").read_text()
        cls.harness_client = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Services/CatalogClient.swift").read_text()
        cls.harness_view = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Views/HarnessSettingsView.swift").read_text()

    def test_status_is_honest_about_pending_physical_acceptance(self):
        for phrase in (
            "Physical disposable-Mac execution remains pending",
            "No live acceptance verdict exists yet",
            "must not be relabeled as physical",
        ):
            self.assertIn(phrase, self.design + self.evidence)

    def test_incomplete_driver_inventory_blocks_campaign_initialization(self):
        for phrase in (
            "DRIVER_ENTRYPOINTS", "require_driver_readiness(driver_root)",
            "acceptance_driver_inventory_incomplete",
            '"campaign_initialization_allowed": ready',
        ):
            self.assertIn(phrase, self.contract + self.cli)
        for driver in (
            "clean-machine-bootstrap", "host-provenance-fixture",
            "host-archive-fixture", "research-qualification-fixture",
            "touchid-authorization-fixture", "bound-session-runtime-fixture",
            "protected-management-fixture", "research-recovery-fixture",
            "cold-boot-readback-fixture", "independent-export-fixture",
        ):
            self.assertIn(f'"{driver}"', self.contract)

    def test_campaign_has_no_admission_or_candidate_authority(self):
        for phrase in (
            '"authority": "acceptance-evidence-only"',
            '"candidate_authority": "none"',
            '"production_material_used": False',
            '"candidate_statement_used"] is not False',
        ):
            self.assertIn(phrase, self.contract)

    def test_cli_has_only_evidence_operations(self):
        for command in ("catalog", "readiness", "initialize", "verify-campaign", "status", "next",
                        "assemble", "verify-export"):
            self.assertIn(f'"{command}"', self.cli)
        for forbidden in ('add_parser("activate")', 'add_parser("rollback")',
                          'add_parser("revoke")', 'add_parser("poweroff")'):
            self.assertNotIn(forbidden, self.cli)
        self.assertNotIn("--outcome", self.observer)
        self.assertNotIn('add_argument("--collector"', self.observer)
        self.assertIn("source_status = primary.get", self.observer)
        self.assertIn("COLLECTOR_PRIMARY_AUTHORITY", self.observer)
        self.assertIn("EVIDENCE_KIND_COLLECTOR", self.observer)

    def test_enrollment_does_not_read_or_export_secret_values(self):
        self.assertIn("PROVIDER_ENVIRONMENT", self.enrollment)
        self.assertIn("op-service-account-agents", self.enrollment)
        self.assertNotIn("op-agents read", self.enrollment)
        self.assertIn("hashlib.sha256(material).hexdigest()", self.enrollment)

    def test_bootstrap_driver_is_read_only_exact_source_and_fixed_authority(self):
        for phrase in (
            "SUPERVISOR.verify_source_checkout(campaign)",
            "SUPERVISOR.current_machine_identity()",
            "ACCEPTANCE_CLI.next_case(campaign, observations)",
            "reserve_case(raw_root, case_id)",
            "HOST_RELEASE.verify(",
            'control("harness-generation-verify-boundary")',
            "ENROLLER.keychain_absent(runner)",
            'prefix="secure-sandbox-bootstrap-projection."',
            '"candidate_authority": "none"',
            '"production_material_used": False',
            "O_EXCL | os.O_NOFOLLOW",
        ):
            self.assertIn(phrase, self.bootstrap)
        for forbidden in (
            'add_argument("--authority"', 'add_argument("--artifact"',
            'add_argument("--kind"', 'add_argument("--outcome"',
            'add_argument("--install"', 'add_argument("--authorize"',
        ):
            self.assertNotIn(forbidden, self.bootstrap)

    def test_journal_precedes_fence_and_checkpoints_are_not_runtime_inputs(self):
        journal = self.store.index('journal["phase"] = "fenced"')
        fence = self.store.index('self._write_fence(plan)', journal - 1200)
        prepared = self.store.rindex('atomic_write(journal_path, canonical_bytes(journal))',
                                     journal - 1200, fence)
        self.assertLess(prepared, fence)
        self.assertNotIn("--checkpoint", self.store)
        self.assertNotIn("os.environ", self.store)
        for checkpoint in (
            "journal-prepared", "fenced", "workflow-authorized", "release-published",
            "catalog-written", "floor-written", "selector-written", "health-passed",
            "workflow-activated", "workflow-verified", "workflow-committed",
            "fence-removed", "journal-removed",
        ):
            self.assertIn(f'self.checkpoint("{checkpoint}")', self.store)

    def test_control_center_status_is_read_only_and_zero_authority(self):
        self.assertIn('subparsers.add_parser("harness-acceptance-status")', self.bridge)
        self.assertIn('"authority": "none"', self.bridge)
        self.assertIn("struct HarnessAcceptanceAvailability", self.harness_models)
        self.assertIn("func harnessAcceptanceStatus()", self.harness_client)
        self.assertIn('value.authority == "none"', self.harness_client)
        self.assertIn("Disposable-Mac lifecycle acceptance — read-only", self.harness_view)
        self.assertIn("Interruption checkpoint", self.harness_view)
        self.assertIn("Procedure digest", self.harness_view)
        self.assertIn("cannot enroll a Mac, run a case, create or edit evidence", self.harness_view)
        for forbidden in ("Run Acceptance", "Record Observation", "Accept Harness"):
            self.assertNotIn(forbidden, self.harness_view)

    def test_recovery_driver_is_disposable_only_and_externally_interruptible(self):
        self.assertIn("store_module.GenerationStore", self.recovery_fixture)
        self.assertIn('parent / "recovery-fixtures"', self.recovery_cli)
        self.assertIn("signal.SIGSTOP", self.recovery_cli)
        self.assertIn("os._exit(125)", self.recovery_cli)
        self.assertIn('case.category != "recovery"', self.recovery_cli)
        self.assertNotIn('add_argument("--checkpoint"', self.recovery_cli)
        for source in (self.recovery_cli, self.recovery_fixture):
            self.assertIn('"candidate_authority": "none"', source)
            self.assertIn('"production_material_used": False', source)
            self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", source)

    def test_host_recovery_supervisor_is_exact_commit_machine_and_case_bound(self):
        for phrase in (
            "current_machine_identity() != campaign",
            'record.get("case_id") != requested',
            'record.get("category") != "recovery"',
            'record["procedure"].get("driver") != "research-recovery-fixture"',
            'GIT), "cat-file", "blob", f"{commit}:{source}"',
            '"GIT_NO_REPLACE_OBJECTS": "1"',
            '"supervisor_source_checkout_mismatch"',
            '"diff", "--quiet", "--exit-code", campaign["source_commit"]',
            'RESEARCH_VM = "SecureSandbox-Research"',
            'POWER_ACKNOWLEDGEMENT = "HARD POWER ONLY THE DISPOSABLE RESEARCH VM"',
            'LOCK = Path(tempfile.gettempdir()) / "secure-sandbox-lifecycle.lock"',
            'require_gui_closed()',
            'remote_json(campaign, "abort", case_id)',
        ):
            self.assertIn(phrase, self.recovery_supervisor)
        for forbidden in ('add_argument("--vm"', 'add_argument("--pid"',
                          'add_argument("--checkpoint"'):
            self.assertNotIn(forbidden, self.recovery_supervisor)

    def test_recovery_evidence_is_reserved_before_remote_mutation(self):
        destination = self.recovery_supervisor.index(
            "destination = output_destination(evidence_root, case_id)")
        deployment = self.recovery_supervisor.index("deploy(campaign, destination)")
        worker = self.recovery_supervisor.index("worker = subprocess.Popen", deployment)
        self.assertLess(destination, deployment)
        self.assertLess(deployment, worker)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW", self.recovery_supervisor)
        self.assertIn("os.fsync(directory)", self.recovery_supervisor)

    def test_recovery_installer_is_root_owned_and_collision_closed(self):
        for phrase in (
            '"$(id -u)" -eq 0',
            'cmp -s "$source" "$release/$name"',
            'cmp -s /tmp/campaign.json "$campaign/campaign.json"',
            'stat -c %U:%G:%a "$release"',
            'stat -c %U:%G:%a "$campaign"',
            'value.get("authority") == "acceptance-evidence-only"',
        ):
            self.assertIn(phrase, self.recovery_installer)

    def test_recovery_projection_revalidates_fixed_raw_evidence_without_overrides(self):
        for phrase in (
            "validate_fault(campaign, case, fault)",
            "validate_recovery(",
            "validate_cold_boot(",
            "verify_source_checkout(campaign)",
            'prefix="secure-sandbox-recovery-projection."',
            "existing_observation(",
            "O_EXCL | os.O_NOFOLLOW",
            '"candidate_authority": "none"',
            '"production_material_used": False',
        ):
            self.assertIn(phrase, self.recovery_projector)
        for forbidden in ('add_argument("--authority"', 'add_argument("--artifact"',
                          'add_argument("--kind"', 'add_argument("--outcome"'):
            self.assertNotIn(forbidden, self.recovery_projector)
        self.assertIn('"worker_checkpoint": checkpoint', self.recovery_supervisor)


if __name__ == "__main__":
    unittest.main()
