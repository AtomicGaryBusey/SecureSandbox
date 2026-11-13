#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DisposableMacHarnessLifecycleAcceptanceDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract_module = load(
            "disposable_acceptance_contract",
            ROOT / "shared/harness_lifecycle_acceptance.py",
        )
        cls.design = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_DESIGN.md").read_text()
        cls.evidence = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_EVIDENCE.md").read_text()
        cls.operator_queue = (
            ROOT / "docs/DISPOSABLE_MAC_OPERATOR_CEREMONY_QUEUE.md"
        ).read_text()
        cls.contract = (ROOT / "shared/harness_lifecycle_acceptance.py").read_text()
        cls.lifecycle = (ROOT / "shared/harness_lifecycle.py").read_text()
        cls.store = (ROOT / "shared/harness_generation_store.py").read_text()
        cls.cli = (ROOT / "scripts/harness-lifecycle-acceptance.py").read_text()
        cls.observer = (ROOT / "scripts/harness-lifecycle-acceptance-observe.py").read_text()
        cls.bootstrap = (ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py").read_text()
        cls.morning_preflight = (
            ROOT / "scripts/harness-lifecycle-acceptance-morning-preflight.py"
        ).read_text()
        cls.bootstrap_diagnostics = (
            ROOT / "scripts/run-host-bootstrap-with-diagnostics.sh"
        ).read_text()
        cls.provenance = (ROOT / "scripts/harness-lifecycle-acceptance-provenance.py").read_text()
        cls.host_installer = (ROOT / "scripts/install-harness-lifecycle-acceptance-host.sh").read_text()
        cls.provenance_fixture = (ROOT / "shared/harness_lifecycle_provenance_fixture.py").read_text()
        cls.archive = (ROOT / "scripts/harness-lifecycle-acceptance-archive.py").read_text()
        cls.archive_preflight = (ROOT / "shared/harness_archive_preflight.py").read_text()
        cls.archive_fixture = (ROOT / "shared/harness_lifecycle_archive_fixture.py").read_text()
        cls.authorization = (ROOT / "scripts/harness-lifecycle-acceptance-authorization.py").read_text()
        cls.authorization_projector = (ROOT / "scripts/harness-lifecycle-acceptance-authorization-observe.py").read_text()
        cls.qualification = (ROOT / "scripts/harness-lifecycle-acceptance-qualification.py").read_text()
        cls.qualification_supervisor = (ROOT / "scripts/harness-lifecycle-acceptance-qualification-supervisor.py").read_text()
        cls.scenario_supervisor = (
            ROOT / "scripts/harness-lifecycle-acceptance-scenario-supervisor.py"
        ).read_text()
        cls.qualification_projector = (ROOT / "scripts/harness-lifecycle-acceptance-qualification-observe.py").read_text()
        cls.qualification_installer = (ROOT / "scripts/install-harness-lifecycle-acceptance-qualification.sh").read_text()
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
            "DRIVER_ENTRYPOINTS", "require_driver_readiness(",
            "verify_protected_driver(", "PROTECTED_DRIVER_MANIFEST_SCHEMA",
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

    def test_all_host_scans_share_one_provider_path_inventory(self):
        for source in (
            self.bootstrap, self.qualification_supervisor,
            self.scenario_supervisor,
        ):
            self.assertIn("ENROLLER.PROVIDER_HOME_PATHS", source)
        for marker in (
            '".config/gcloud/credentials.db"',
            '".azure/msal_token_cache.json"',
        ):
            self.assertIn(marker, self.enrollment)

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

    def test_morning_gate_cannot_invoke_operator_authorization_or_mutation(self):
        for phrase in (
            'PUBLIC_BRANCH = "public-release"',
            'AUTHORIZED_REMOTES = (',
            '"https://github.com/AtomicGaryBusey/SecureSandbox.git"',
            'cwd=Path("/")',
            '"GIT_TERMINAL_PROMPT": "0"',
            'ENROLLER.keychain_absent(runner)',
            'trusted_bootstrap_hierarchy(runner=probe_runner)',
            '"bootstrap_trust_root": bootstrap_trust_root',
            'preflight_bootstrap_trust_root_invalid',
            'SUPERVISOR.require_gui_closed()',
            'vm_states = SUPERVISOR.vm_inventory(allow_all_absent=installed_count == 0)',
            '"touch_id_authorization_ready": False',
            '"next_authorization": "none" if protected_ready else "root-password"',
            '"bootstrap-root-owned-exact-commit-host-installer"',
        ):
            self.assertIn(phrase, self.morning_preflight)
        for forbidden in (
            "sudo", "operator-authorization", "authorization_broker",
            "prlctl start", "prlctl stop", "subprocess.Popen",
        ):
            self.assertNotIn(forbidden, self.morning_preflight)

    def test_operator_handoff_is_collision_closed_and_queries_next_before_auth(self):
        for phrase in (
            "set -o noclobber",
            'test ! -e "$handoff_root"',
            '/usr/bin/install -d -m 700 "$handoff_root"',
            '/usr/bin/python3 -I scripts/enroll-disposable-mac-harness-lifecycle.py',
            '--enrollment "$handoff_root/enrollment.json"',
            'test ! -e "$campaign_root"',
            '--output "$campaign_root/campaign.json"',
            '/usr/bin/python3 -I scripts/harness-lifecycle-acceptance-morning-preflight.py',
            '--expect-next-action bootstrap-root-owned-exact-commit-host-installer',
            '--output "$handoff_root/preflight-before-install.json"',
            '--expect-next-action initialize-exact-commit-campaign',
            '--output "$handoff_root/preflight-after-install.json"',
            '--source-commit-from-receipt "$handoff_root/preflight-before-install.json"',
            '--source-commit-from-receipt "$handoff_root/preflight-after-install.json"',
            '/usr/bin/python3 -I scripts/harness-lifecycle-acceptance.py initialize',
            '/usr/bin/python3 -I scripts/harness-lifecycle-acceptance.py next',
            '/usr/bin/install -d -m 700 "$campaign_root"',
            '/usr/bin/sudo -- /usr/bin/env -i',
            'bootstrap_base=/private/var/db/secure-sandbox-harness-acceptance-bootstrap',
            'secure-sandbox-harness-acceptance-bootstrap',
            '"$bootstrap_checkout/scripts/install-harness-lifecycle-acceptance-host.sh"',
            'test "$bootstrap_commit" = "$source_commit"',
            'report ten available drivers',
            'Do not use `sudo` for enrollment or preflight.',
            "partial layout, overwrite evidence",
        ):
            self.assertIn(phrase, self.operator_queue)
        self.assertIn(
            '/usr/bin/sudo -- /usr/bin/env -i \\\n'
            '     PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \\\n'
            '     /bin/bash -- \\\n',
            self.operator_queue,
        )

    def test_product_bootstrap_attempts_have_durable_private_diagnostics(self):
        for phrase in (
            "scripts/run-host-bootstrap-with-diagnostics.sh",
            "mode-`0600` log for every attempt",
            "password input to the log",
            "scrollback is not",
        ):
            self.assertIn(
                phrase,
                self.operator_queue + self.design + self.evidence,
            )
        for phrase in (
            "umask 077",
            "diagnostic root mode must be 700",
            "diagnostic root must not have an extended ACL",
            "source checkout must be clean",
            'exec 3>>"$diagnostic_log"',
            "/usr/bin/tee -a /dev/fd/3",
            "sync_log_and_parent",
            "os.fsync(3)",
            "event launcher-start",
            "event source-verified",
            "event preflight-rejected",
            "event command-start",
            "event command-exit",
            'pipeline_statuses=("${pipestatus[@]}")',
            "tee_status=${pipeline_statuses[2]}",
            "event diagnostic-copy-exit",
            "event launcher-exit",
            "event signal-received",
            "--requesting-agent Codex",
            "--requesting-session DISPOSABLE_MAC_ACCEPTANCE",
        ):
            self.assertIn(phrase, self.bootstrap_diagnostics)

    def test_provenance_core_is_exact_source_fixed_case_and_non_admitting(self):
        for phrase in (
            "ACCEPTANCE_CLI.verify_protected_driver(",
            "PROTECTED_INSTALL_ROOT",
            "fixed_raw_root(campaign[\"campaign_id\"])",
            "output_mode=0o444",
            "SUPERVISOR.current_machine_identity()",
            "ACCEPTANCE_CLI.next_case(",
            "directory_uid=operator_uid",
            'case.get("procedure", {}).get("driver") != "host-provenance-fixture"',
            "reserve_case(raw_root, case_id)",
            'prefix="secure-sandbox-provenance-fixture."',
            '"candidate_authority": "none"',
            '"production_material_used": False',
            "O_EXCL | os.O_NOFOLLOW",
        ):
            self.assertIn(phrase, self.provenance + self.provenance_fixture)
        for case in (
            "reject-redirect", "reject-oversized-artifact",
            "reject-artifact-substitution", "reject-bad-signature",
            "reject-unknown-signer", "reject-revoked-signer",
            "reject-expired-signer", "reject-broken-chain",
            "reject-stale-metadata", "reject-future-metadata",
            "reject-release-rollback", "reject-release-freeze",
            "accept-release-fast-forward", "reject-release-equivocation",
            "reject-inconsistent-provenance",
        ):
            self.assertIn(f'"{case}"', self.provenance_fixture)
        for forbidden in (
            'add_argument("--outcome"', 'add_argument("--authority"',
            'add_argument("--kind"', 'add_argument("--generation"',
        ):
            self.assertNotIn(forbidden, self.provenance)

    def test_host_installer_is_exact_commit_root_owned_and_collision_closed(self):
        for phrase in (
            '"$(id -u)" -eq 0',
            'bootstrap_base=/private/var/db/secure-sandbox-harness-acceptance-bootstrap',
            '/ /private /private/var /private/var/db "$bootstrap_base"',
            'secure-sandbox-harness-acceptance-bootstrap',
            'Protected installer must run from the root-owned bootstrap checkout.',
            'source.resolve(strict=True) != expected',
            'GIT_NO_REPLACE_OBJECTS=1',
            'https://github.com/AtomicGaryBusey/SecureSandbox.git',
            'GIT_CONFIG_NOSYSTEM=1',
            'GIT_CONFIG_GLOBAL=/dev/null',
            'GIT_TERMINAL_PROMPT=0',
            'trusted_git ls-remote --exit-code',
            '[[ "$remote_tip" == "$source_commit"$\'\\t\'"$public_ref" ]]',
            'init --quiet --bare --template=',
            '"$public_ref:refs/heads/accepted"',
            '"refs/heads/accepted^{commit}"',
            'ls-tree "$source_commit"',
            'cat-file blob "$object_id"',
            'No Git',
            'operator-writable',
            '/usr/local/libexec/secure-sandbox-harness-acceptance',
            '/var/db/SecureSandbox/harness-lifecycle-acceptance',
            'PROTECTED_DRIVER_MANIFEST_SCHEMA',
            '"manifest_sha256"',
            '/bin/mkdir -m 700 "$lock"',
            '[[ ! -e "$release" && ! -L "$release" ]]',
            'chown root:wheel "$temporary/manifest.json"',
            'chmod 444 "$temporary/manifest.json"',
            'find "$temporary" -type d -exec chmod 555',
            '"research-qualification-fixture",',
            'module.verify_protected_driver(',
            'echo "harness-lifecycle-acceptance-host:installed:$source_commit"',
        ):
            self.assertIn(phrase, self.host_installer)
        for forbidden in (
            'git -C "$repo"',
            'status --porcelain',
            'core.fsmonitor',
            '/usr/bin/python3 - ',
            'bootstrap_base=/usr/local/libexec/secure-sandbox-harness-acceptance-bootstrap',
        ):
            self.assertNotIn(forbidden, self.host_installer)
        self.assertEqual(self.host_installer.count('/usr/bin/python3 -I -'), 4)

        verifier_start = self.host_installer.index("<<'PY'\n", self.host_installer.index(
            "expected_installer=",
        )) + len("<<'PY'\n")
        verifier_end = self.host_installer.index("\nPY\ngit=/usr/bin/git", verifier_start)
        compile(
            self.host_installer[verifier_start:verifier_end],
            "bootstrap-path-verifier", "exec",
        )
        self.assertIn(
            'scripts/harness-lifecycle-acceptance-archive.py',
            self.host_installer,
        )
        self.assertIn(
            '"touchid-authorization-fixture",', self.host_installer,
        )
        for required in (
            'scripts/harness-lifecycle-acceptance-bootstrap.py',
            'scripts/host-controller-release.py',
            '"clean-machine-bootstrap",',
        ):
            self.assertIn(required, self.host_installer)
        self.assertEqual(
            self.host_installer.count('"clean-machine-bootstrap",'), 2,
        )
        payload_block = self.host_installer.split("payloads=(", 1)[1].split("\n)", 1)[0]
        installed_paths = {
            line.strip() for line in payload_block.splitlines() if line.strip()
        }
        expected_paths = {
            path
            for paths in self.contract_module.PROTECTED_DRIVER_PAYLOADS.values()
            for path in paths
        }
        self.assertEqual(installed_paths, expected_paths)
        for driver in self.contract_module.DRIVER_ENTRYPOINTS:
            self.assertGreaterEqual(self.host_installer.count(f'"{driver}"'), 2)

    def test_authorization_driver_is_isolated_fixed_and_non_admitting(self):
        combined = self.authorization + self.authorization_projector
        for phrase in (
            'DRIVER = "touchid-authorization-fixture"',
            "protected_context(case_id, operator_uid",
            "verify_protected_driver(", "current_machine_identity()",
            '"harness-generation-status"', "validate_broker_receipt(",
            "interactive_authorization_replayed", "authorization_operator_uid_mismatch",
            '"production_store_access": False',
            '"lifecycle_mutation_performed": False',
            "output_mode=0o444", "candidate_authority\": \"none",
        ):
            self.assertIn(phrase, combined)
        for forbidden in (
            'add_argument("--state-root"', 'add_argument("--campaign"',
            'add_argument("--collector"', 'add_argument("--authority"',
            'add_argument("--outcome"',
        ):
            self.assertNotIn(forbidden, combined)

    def test_archive_core_preflights_all_fixed_attacks_without_extraction(self):
        combined = self.archive_preflight + self.archive_fixture
        for phrase in (
            "validate_ustar", "archive_path_absolute", "archive_path_traversal",
            "archive_entry_type_forbidden", "archive_path_duplicate",
            "archive_path_casefold_collision", "archive_path_unicode_collision",
            "archive_expansion_limit_exceeded", "archive_path_alternate_stream",
            "archive_trailing_data", '"extracted": False', '"executed": False',
            '"candidate_authority": "none"', '"production_material_used": False',
        ):
            self.assertIn(phrase, combined)
        self.assertNotIn("extractall", combined)

    def test_archive_driver_is_protected_fixed_case_and_non_admitting(self):
        for phrase in (
            "ACCEPTANCE_CLI.verify_protected_driver(",
            '"host-archive-fixture"',
            "fixed_raw_root(campaign[\"campaign_id\"])",
            "directory_uid=operator_uid",
            "output_mode=0o444",
            'case.get("procedure", {}).get("driver") != "host-archive-fixture"',
            'kind="archive-rejection"',
            '"candidate_authority": "none"',
            '"production_material_used": False',
            "O_EXCL | os.O_NOFOLLOW",
            "sys.dont_write_bytecode = True",
            "archive_driver_protected_invocation_required",
            'value.get("production_boundary") != "HarnessStore.acquire"',
        ):
            self.assertIn(phrase, self.archive)
        for forbidden in (
            'add_argument("--outcome"', 'add_argument("--authority"',
            'add_argument("--kind"', 'add_argument("--archive"',
            "extractall", "subprocess.run(", "os.exec",
        ):
            self.assertNotIn(forbidden, self.archive)

    def test_archive_production_boundary_is_physical_evidence_eligible(self):
        self.assertIn("HARNESS_ARCHIVE_MEDIA_TYPE", self.lifecycle)
        self.assertIn("validate_ustar(archive_raw)", self.lifecycle)
        self.assertIn('PHYSICAL_DRIVER_BLOCKERS: dict[str, str] = {}', self.contract)
        self.assertIn("PHYSICAL_DRIVER_BLOCKERS.get(driver)", self.cli)

    def test_qualification_driver_has_independent_outer_observation_and_no_authority(self):
        combined = (
            self.qualification + self.qualification_supervisor
            + self.qualification_projector + self.qualification_installer
        )
        for phrase in (
            '"--property=PrivateNetwork=yes"',
            '"--property=RestrictAddressFamilies=AF_UNIX"',
            '"--property=IPAddressDeny=any"',
            '"--property=ProtectSystem=strict"',
            '"--property=TasksMax=2"',
            '"--property=UnsetEnvironment=',
            'value.get("physical_evidence_eligible") is not False',
            '"physical_evidence_eligible": True',
            "empty_control_group(",
            "ACCEPTANCE_CLI.verify_protected_driver(",
            "production_scan(",
            "protected_fixture_state(",
            '"admission_performed": False',
            '"activation_performed": False',
            '"selector_changed": False',
            '"session_migrated": False',
            "SUPERVISOR.QUALIFICATION.validate_result(",
            "qualification_existing_observation_mismatch",
            '"candidate_authority": "none"',
            '"production_material_used": False',
        ):
            self.assertIn(phrase, combined)
        for forbidden in (
            'add_argument("--authority"', 'add_argument("--artifact"',
            'add_argument("--kind"', 'add_argument("--outcome"',
            'add_argument("--fixture"', 'add_argument("--network"',
        ):
            self.assertNotIn(forbidden, combined)

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
        self.assertIn("/tmp/harness_archive_preflight.py", self.recovery_installer)
        self.assertIn(
            '"harness_archive_preflight.py": "shared/harness_archive_preflight.py"',
            self.recovery_supervisor,
        )
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
