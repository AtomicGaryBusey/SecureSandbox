#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_bootstrap",
    ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py",
)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
NOW = 2_000_000_000


class Result:
    def __init__(self, returncode: int):
        self.returncode = returncode


class BootstrapAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.campaign_path = self.root / "campaign.json"
        self.observations = self.root / "observations"
        self.raw = self.root / "raw"
        self.home = self.root / "home"
        for path in (self.observations, self.raw, self.home):
            path.mkdir(mode=0o700)
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60,
            "expires_at": NOW + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        self.campaign_path.write_bytes(acceptance.canonical(self.campaign))
        self.campaign_path.chmod(0o600)
        self.enrollment_path = self.root / "enrollment.json"
        self.enrollment = {
            "schema": acceptance.ENROLLMENT_SCHEMA,
            "enrollment_id": str(uuid.uuid4()),
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "observed_at": NOW - 120, "disposable": True,
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "collector": "secure-sandbox-disposable-supervisor-v1",
        }
        self.enrollment["enrollment_sha256"] = acceptance.digest(self.enrollment)
        self.enrollment_path.write_bytes(acceptance.canonical(self.enrollment))
        self.enrollment_path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def case(self, case_id: str) -> dict:
        return acceptance.case_record(acceptance.CASE_BY_ID[case_id])

    def boundary(self) -> dict:
        return {
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "verified", "active_generation_id": None,
            "generation_count": 0, "catalog_sha256": "3" * 64,
            "selector_sha256": "4" * 64, "floor_sha256": "5" * 64,
        }

    def release(self) -> dict:
        return {
            "schema": bootstrap.HOST_RELEASE.SCHEMA, "status": "verified",
            "release_id": "6" * 64, "launcher_sha256": "7" * 64,
            "payloads": {"controller": "8" * 64},
            "host_release_launcher_pair_sha256": "9" * 64,
            "candidate_authority_sha256": "a" * 64,
            "release_tree_identity_sha256": "b" * 64,
            "developer_id_team_id":
                bootstrap.HOST_RELEASE.NATIVE_HOST_PRODUCTS_TEAM_ID,
            "developer_id_team_floor_sha256": "c" * 64,
            "developer_id_team_floor_release_id": "d" * 64,
        }

    def store_status(self, boundary: dict) -> dict:
        return {
            "schema": "secure-sandbox-harness-generation-status-v1",
            "status": "verified", "admission": "open",
            "recovery_pending": False, "active_generation_id": None,
            "predecessor_generation_id": None, "selector_epoch": 0,
            "highest_release_sequence": 0, "revoked_generation_ids": [],
            "generations": [], "boundary": boundary,
        }

    def stack_readback(self, case: dict) -> dict:
        value = {
            "schema": bootstrap.STACK_SCHEMA, "status": "verified",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "source_commit": self.campaign["source_commit"],
            "case_id": case["case_id"],
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "observed_at": NOW,
            "observed": {
                "gateway": "running", "research": "running",
                "target": "stopped", "gateway_net0": "disconnected",
            },
            "reachability": {
                "gateway": "reachable", "research": "reachable",
                "target": "unreachable",
            },
            "parallels_gui_closed": True, "candidate_authority": "none",
            "production_material_used": False,
        }
        value["stack_readback_sha256"] = acceptance.digest(value)
        return value

    def preflight_patch(self, case: dict):
        return mock.patch.object(
            bootstrap, "preflight", return_value=(self.campaign, case),
        )

    def test_clean_install_collects_protected_readbacks_and_projects_all_kinds(self):
        case = self.case("bootstrap-clean-install")
        boundary = self.boundary()

        def control(operation: str):
            return {
                "control-status": {
                    "schema": "secure-sandbox-privileged-control-status-v1",
                    "role": "research",
                },
                "harness-generation-status": self.store_status(boundary),
                "harness-generation-verify-boundary": boundary,
            }[operation]

        with self.preflight_patch(case), \
                mock.patch.object(bootstrap.SUPERVISOR, "prerequisite"), \
                mock.patch.object(bootstrap.HOST_RELEASE, "verify",
                                  return_value=self.release()), \
                mock.patch.object(bootstrap, "stack_readback",
                                  return_value=self.stack_readback(case)), \
                mock.patch.object(bootstrap, "control", side_effect=control):
            result = bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                None, NOW,
            )
        raw_directory = Path(result["raw_directory"])
        self.assertEqual(
            {item.name for item in raw_directory.iterdir()},
            set(bootstrap.CASE_FILES[case["case_id"]].values()),
        )
        with self.preflight_patch(case):
            projected = bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                raw_directory, NOW,
            )
        self.assertEqual(projected["recorded_observation_kinds"], case["evidence_kinds"])
        for kind in case["evidence_kinds"]:
            path = self.observations / f"{case['case_id']}.{kind}.json"
            value = json.loads(path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                value["evidence"]["artifacts"][0]["authority"],
                bootstrap.AUTHORITIES[kind],
            )
            acceptance.validate_observation(
                value, self.campaign, acceptance.CASE_BY_ID[case["case_id"]],
            )

    def test_stack_readback_binds_exact_isolated_inventory(self):
        case = self.case("bootstrap-clean-install")
        observed = {
            "gateway": "running", "research": "running",
            "target": "stopped", "gateway_net0": "disconnected",
        }
        reachable = {
            "gateway": "reachable", "research": "reachable",
            "target": "unreachable",
        }
        with mock.patch.object(
            bootstrap.LIFECYCLE, "require_mutation_prerequisites",
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "gui_running", return_value=False,
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "observe", return_value=(observed, reachable),
        ):
            value = bootstrap.stack_readback(self.campaign, case, NOW)
        bootstrap.validate_stack_readback(self.campaign, case, value, NOW)
        self.assertEqual(value["observed"], observed)

    def test_stack_readback_rejects_connected_gateway(self):
        case = self.case("bootstrap-clean-install")
        observed = {
            "gateway": "running", "research": "running",
            "target": "stopped", "gateway_net0": "connected",
        }
        reachable = {
            "gateway": "reachable", "research": "reachable",
            "target": "unreachable",
        }
        with mock.patch.object(
            bootstrap.LIFECYCLE, "require_mutation_prerequisites",
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "gui_running", return_value=False,
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "observe", return_value=(observed, reachable),
        ), self.assertRaisesRegex(
            bootstrap.BootstrapError, "bootstrap_stack_readback_invalid",
        ):
            bootstrap.stack_readback(self.campaign, case, NOW)

    def test_protected_projector_requests_root_read_only_publication(self):
        case = self.case("bootstrap-clean-install")
        raw_values = {
            kind: acceptance.canonical({"kind": kind})
            for kind in case["evidence_kinds"]
        }
        observations = [
            {
                "observation_sha256": str(index) * 64,
            }
            for index, _kind in enumerate(case["evidence_kinds"], start=1)
        ]
        with mock.patch.object(bootstrap.os, "geteuid", return_value=0), \
                self.preflight_patch(case) as preflight, \
                mock.patch.object(bootstrap, "raw_set_at",
                                  return_value=raw_values) as raw_set, \
                mock.patch.object(bootstrap, "write_snapshot"), \
                mock.patch.object(bootstrap.OBSERVER, "observe",
                                  side_effect=observations) as observe, \
                mock.patch.object(bootstrap, "publish_staged_at") as publish:
            result = bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                self.raw, NOW, operator_uid=501,
            )
        self.assertEqual(result["recorded_observation_kinds"],
                         case["evidence_kinds"])
        preflight.assert_called_once_with(
            self.campaign_path, self.observations, case["case_id"], NOW,
            operator_uid=501, protected_projection=True,
            observations_descriptor=mock.ANY,
        )
        raw_set.assert_called_once_with(
            self.campaign, case, mock.ANY, NOW, 501,
        )
        self.assertTrue(observe.call_args_list)
        self.assertTrue(all(
            call.kwargs["output_mode"] == 0o444
            for call in observe.call_args_list
        ))
        self.assertTrue(publish.call_args_list)
        self.assertTrue(all(
            call.kwargs["mode"] == 0o444
            for call in publish.call_args_list
        ))

    def test_protected_preflight_validates_installed_closures_not_source_tree(self):
        case = self.case("bootstrap-clean-install")
        protected_root = self.root.resolve() / "protected"
        release = protected_root / "releases" / self.campaign["source_commit"]
        release.mkdir(parents=True)
        with mock.patch.object(bootstrap, "ROOT", release), \
                mock.patch.object(
                    bootstrap.ACCEPTANCE_CLI, "PROTECTED_INSTALL_ROOT",
                    protected_root,
                ), \
                mock.patch.object(bootstrap.os, "geteuid", return_value=0), \
                mock.patch.object(
                    bootstrap.ACCEPTANCE_CLI, "driver_readiness",
                    side_effect=AssertionError("source readiness is forbidden"),
                ), \
                mock.patch.object(
                    bootstrap.ACCEPTANCE_CLI, "verify_protected_driver",
                ) as verify, \
                mock.patch.object(
                    bootstrap.SUPERVISOR, "current_machine_identity",
                    return_value=self.campaign["machine_identity_sha256"],
                ), \
                mock.patch.object(
                    bootstrap, "next_bootstrap_case_at", return_value=case,
                ):
            campaign, observed_case = bootstrap.preflight(
                self.campaign_path, self.observations, case["case_id"], NOW,
                operator_uid=self.campaign_path.stat().st_uid,
                protected_projection=True, observations_descriptor=42,
            )
        self.assertEqual(campaign, self.campaign)
        self.assertEqual(observed_case, case)
        self.assertEqual(
            [call.args[2] for call in verify.call_args_list],
            list(bootstrap.ACCEPTANCE_CLI.DRIVER_ENTRYPOINTS),
        )
        self.assertTrue(all(
            call.args[:2] == (protected_root, self.campaign["source_commit"])
            and call.args[3] == 0
            for call in verify.call_args_list
        ))

    def test_source_preflight_verifies_the_executing_checkout_not_cwd(self):
        case = self.case("bootstrap-clean-install")
        with mock.patch.object(
            bootstrap.SUPERVISOR, "verify_source_checkout",
        ) as verify, mock.patch.object(
            bootstrap.SUPERVISOR, "current_machine_identity",
            return_value=self.campaign["machine_identity_sha256"],
        ), mock.patch.object(
            bootstrap, "next_bootstrap_case", return_value=case,
        ):
            campaign, observed_case = bootstrap.preflight(
                self.campaign_path, self.observations, case["case_id"], NOW,
            )
        self.assertEqual(campaign, self.campaign)
        self.assertEqual(observed_case, case)
        verify.assert_called_once_with(self.campaign, bootstrap.ROOT)

    def test_protected_preflight_rejects_invalid_installed_closure(self):
        case = self.case("bootstrap-clean-install")
        protected_root = self.root.resolve() / "protected"
        release = protected_root / "releases" / self.campaign["source_commit"]
        release.mkdir(parents=True)
        with mock.patch.object(bootstrap, "ROOT", release), \
                mock.patch.object(
                    bootstrap.ACCEPTANCE_CLI, "PROTECTED_INSTALL_ROOT",
                    protected_root,
                ), \
                mock.patch.object(bootstrap.os, "geteuid", return_value=0), \
                mock.patch.object(
                    bootstrap.ACCEPTANCE_CLI, "verify_protected_driver",
                    side_effect=acceptance.AcceptanceError(
                        "protected_driver_payload_mismatch",
                    ),
                ), self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "bootstrap_protected_release_required",
                ):
            bootstrap.preflight(
                self.campaign_path, self.observations, case["case_id"], NOW,
                operator_uid=self.campaign_path.stat().st_uid,
                protected_projection=True, observations_descriptor=42,
            )

    def test_protected_publication_uses_open_directory_descriptor(self):
        target = self.root / "published"
        target.mkdir(mode=0o700)
        descriptor = bootstrap.open_private_directory(
            target, "test_observations", target.stat().st_uid,
        )
        try:
            staged = self.root / "staged.json"
            staged.write_bytes(acceptance.canonical({"status": "verified"}))
            staged.chmod(0o600)
            bootstrap.publish_staged_at(
                staged, descriptor, "evidence.json", mode=0o444,
            )
            self.assertEqual(
                (target / "evidence.json").read_bytes(), staged.read_bytes(),
            )
            self.assertEqual(
                (target / "evidence.json").stat().st_mode & 0o777, 0o444,
            )
        finally:
            bootstrap.os.close(descriptor)

    def test_protected_publication_does_not_follow_substituted_parent(self):
        original = self.root / "original-observations"
        moved = self.root / "moved-observations"
        substituted = self.root / "substituted-observations"
        original.mkdir(mode=0o700)
        substituted.mkdir(mode=0o700)
        descriptor = bootstrap.open_private_directory(
            original, "test_observations", original.stat().st_uid,
        )
        try:
            identity = bootstrap.directory_identity(bootstrap.os.fstat(descriptor))
            original.rename(moved)
            original.symlink_to(substituted, target_is_directory=True)
            staged = self.root / "staged-race.json"
            staged.write_bytes(acceptance.canonical({"status": "verified"}))
            staged.chmod(0o600)
            bootstrap.publish_staged_at(
                staged, descriptor, "evidence.json", mode=0o444,
            )
            self.assertTrue((moved / "evidence.json").is_file())
            self.assertFalse((substituted / "evidence.json").exists())
            self.assertNotEqual(
                identity,
                bootstrap.directory_identity(original.lstat()),
            )
        finally:
            bootstrap.os.close(descriptor)

    def test_operator_uid_requires_root_context(self):
        case = self.case("bootstrap-clean-install")
        with mock.patch.object(bootstrap.os, "geteuid", return_value=501), \
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "bootstrap_protected_projection_context_required",
                ):
            bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                self.raw, NOW, operator_uid=501,
            )

    def test_production_scan_binds_clean_enrollment_and_projects_both_kinds(self):
        case = self.case("bootstrap-no-production-material")
        self.enrollment["observed_at"] = NOW - 3 * 86400
        self.enrollment["enrollment_sha256"] = acceptance.digest({
            key: value for key, value in self.enrollment.items()
            if key != "enrollment_sha256"
        })
        self.enrollment_path.write_bytes(acceptance.canonical(self.enrollment))
        runner = mock.Mock(return_value=Result(44))
        with self.preflight_patch(case):
            result = bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home, environment={}, runner=runner,
            )
        raw_directory = Path(result["raw_directory"])
        scan = json.loads((raw_directory / "production-material-scan.json").read_bytes())
        self.assertEqual(scan["status"], "absent")
        self.assertNotIn("values", scan)
        with self.preflight_patch(case):
            projected = bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                raw_directory, NOW,
            )
        self.assertEqual(projected["recorded_observation_kinds"], case["evidence_kinds"])

    def test_production_marker_rejects_and_reserved_case_is_never_reused(self):
        case = self.case("bootstrap-no-production-material")
        runner = mock.Mock(return_value=Result(44))
        with self.preflight_patch(case), self.assertRaisesRegex(
                bootstrap.BootstrapError, "production_material_marker"):
            bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home,
                environment={"OPENAI_API_KEY": "synthetic-but-present"}, runner=runner,
            )
        reserved = self.raw / case["case_id"]
        self.assertTrue(reserved.is_dir())
        self.assertEqual(list(reserved.iterdir()), [])
        with self.preflight_patch(case), self.assertRaisesRegex(
                bootstrap.BootstrapError, "raw_case_exists"):
            bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home, environment={}, runner=runner,
            )

    def test_legacy_host_release_shape_rejects_instead_of_dropping_security_bindings(self):
        case = self.case("bootstrap-clean-install")
        release = self.release()
        for name in (
            "host_release_launcher_pair_sha256", "candidate_authority_sha256",
            "release_tree_identity_sha256", "developer_id_team_id",
            "developer_id_team_floor_sha256",
            "developer_id_team_floor_release_id",
        ):
            release.pop(name)
        value = bootstrap.receipt(
            bootstrap.HOST_SCHEMA, self.campaign, case, NOW,
            {"release": release, "release_sha256": acceptance.digest(release)},
            "receipt_sha256",
        )
        with self.assertRaisesRegex(
                bootstrap.BootstrapError, "bootstrap_host_receipt_invalid"):
            bootstrap.validate_host_receipt(self.campaign, case, value, NOW)

    def test_host_release_rejects_wrong_developer_id_team(self):
        case = self.case("bootstrap-clean-install")
        release = self.release()
        release["developer_id_team_id"] = "AAAAAAAAAA"
        value = bootstrap.receipt(
            bootstrap.HOST_SCHEMA, self.campaign, case, NOW,
            {"release": release, "release_sha256": acceptance.digest(release)},
            "receipt_sha256",
        )
        with self.assertRaisesRegex(
                bootstrap.BootstrapError, "bootstrap_host_receipt_invalid"):
            bootstrap.validate_host_receipt(self.campaign, case, value, NOW)

    def test_surface_is_read_only_and_has_no_evidence_authority_override(self):
        source = (
            ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py"
        ).read_text()
        for forbidden in (
            'add_argument("--authority"', 'add_argument("--artifact"',
            'add_argument("--kind"', 'add_argument("--outcome"',
            'add_parser("install"', 'add_parser("authorize"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("HOST_RELEASE.verify(", source)
        self.assertIn('control("harness-generation-status")', source)
        self.assertIn('control("harness-generation-verify-boundary")', source)
        self.assertIn("bootstrap_protected_release_required", source)
        self.assertIn('project_command.add_argument("--operator-uid"', source)


if __name__ == "__main__":
    unittest.main()
