#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = load("harness_lifecycle_acceptance_cli", ROOT / "scripts/harness-lifecycle-acceptance.py")
enrollment = load("disposable_mac_enrollment", ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py")


NOW = 2_000_000_000


class Runner:
    def __init__(self, credential_present: bool = False, keychain_status: int = 44):
        self.credential_present = credential_present
        self.keychain_status = keychain_status

    def __call__(self, command, **_kwargs):
        if command[0] == "/usr/sbin/ioreg":
            output = (
                b'    "IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"\n'
                b'    "IOPlatformSerialNumber" = "TESTSERIAL"\n'
                b'    "model" = <"MacBookNeo1,1">\n'
            )
            return subprocess.CompletedProcess(command, 0, output, b"")
        status = 0 if self.credential_present else self.keychain_status
        return subprocess.CompletedProcess(command, status, b"", b"")


class DisposableMacEnrollmentTests(unittest.TestCase):
    def test_clean_machine_enrolls_without_exporting_identity_material(self):
        with tempfile.TemporaryDirectory() as directory:
            value = enrollment.enroll(
                acknowledgement=enrollment.ACKNOWLEDGEMENT,
                home=Path(directory), environment={}, now=NOW, runner=Runner(),
                system="Darwin", machine="arm64",
            )
        encoded = json.dumps(value)
        self.assertEqual(value["production_credentials_present"], False)
        self.assertNotIn("TESTSERIAL", encoded)
        self.assertNotIn("AAAAAAAA-BBBB", encoded)

    def test_acknowledgement_platform_environment_path_and_keychain_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = dict(acknowledgement=enrollment.ACKNOWLEDGEMENT, home=home,
                        environment={}, now=NOW, runner=Runner(), system="Darwin", machine="arm64")
            for changes, reason in (
                ({"acknowledgement": "yes"}, "acknowledgement"),
                ({"system": "Linux"}, "disposable_mac"),
                ({"environment": {"OPENAI_API_KEY": "present"}}, "credential_environment"),
                ({"runner": Runner(credential_present=True)}, "credential_marker"),
                ({"runner": Runner(keychain_status=1)}, "keychain_probe_ambiguous"),
            ):
                with self.subTest(reason=reason):
                    with self.assertRaisesRegex(enrollment.AcceptanceError, reason):
                        enrollment.enroll(**{**base, **changes})
            marker = home / ".aws/credentials"
            marker.parent.mkdir()
            marker.touch()
            with self.assertRaisesRegex(enrollment.AcceptanceError, "material_path"):
                enrollment.enroll(**base)


class AcceptanceCLITests(unittest.TestCase):
    def enrollment_value(self):
        value = {
            "schema": enrollment.ENROLLMENT_SCHEMA,
            "enrollment_id": "11111111-1111-4111-8111-111111111111",
            "machine_identity_sha256": "a" * 64,
            "observed_at": NOW,
            "disposable": True,
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "collector": "secure-sandbox-disposable-supervisor-v1",
        }
        value["enrollment_sha256"] = cli.digest(value)
        return value

    def write(self, path, value):
        path.write_bytes(cli.canonical(value))
        path.chmod(0o600)

    def driver_root(self, root):
        for paths in (
            *cli.DRIVER_ENTRYPOINTS.values(),
            *cli.PROTECTED_DRIVER_PAYLOADS.values(),
        ):
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_bytes(b"#!/usr/bin/env python3\n")
                    path.chmod(0o600)
        return root

    def protected_root(self, root, checkout, source_commit):
        release = root / "releases" / source_commit
        release.mkdir(parents=True, mode=0o755)
        records = []
        payloads = sorted({
            path for paths in cli.PROTECTED_DRIVER_PAYLOADS.values()
            for path in paths
        })
        for relative in payloads:
            source = checkout / relative
            destination = release / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o444)
            raw = destination.read_bytes()
            records.append({
                "mode": 0o444, "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            })
        manifest = {
            "schema": cli.PROTECTED_DRIVER_MANIFEST_SCHEMA,
            "suite_id": cli.SUITE_ID,
            "suite_sha256": cli.suite_sha256(),
            "source_commit": source_commit,
            "drivers": {
                driver: list(paths)
                for driver, paths in cli.PROTECTED_DRIVER_PAYLOADS.items()
            },
            "files": records,
        }
        manifest["manifest_sha256"] = cli.digest(manifest)
        path = release / "manifest.json"
        path.write_bytes(cli.canonical(manifest)); path.chmod(0o444)
        return root

    def test_initialize_consumes_canonical_enrollment_and_writes_new_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            output = root / "campaign.json"
            self.write(source, self.enrollment_value())
            drivers = self.driver_root(root / "checkout")
            protected = self.protected_root(
                root / "protected", drivers, "b" * 40,
            )
            value = cli.initialize(
                source, "b" * 40, output, NOW, 3600, driver_root=drivers,
                protected_root=protected, expected_install_uid=os.geteuid(),
            )
            self.assertEqual(cli.trusted_json(output), value)
            self.assertEqual(value["authority"], "acceptance-evidence-only")
            with self.assertRaises(FileExistsError):
                cli.initialize(
                    source, "b" * 40, output, NOW, 3600, driver_root=drivers,
                    protected_root=protected, expected_install_uid=os.geteuid(),
                )

    def test_initialize_fails_closed_until_every_fixed_driver_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            self.write(source, self.enrollment_value())
            with self.assertRaisesRegex(
                cli.AcceptanceError, "driver_inventory_incomplete",
            ):
                cli.initialize(
                    source, "b" * 40, root / "campaign.json", NOW, 3600,
                    driver_root=root / "empty-checkout",
                )
            self.assertFalse((root / "campaign.json").exists())

    def test_readiness_reports_the_actual_incomplete_driver_inventory(self):
        value = cli.driver_readiness(ROOT)
        self.assertEqual(value["status"], "incomplete")
        self.assertFalse(value["campaign_initialization_allowed"])
        self.assertEqual(value["driver_count"], 10)
        self.assertEqual(value["available_driver_count"], 0)
        missing = {
            item["driver"] for item in value["drivers"] if not item["available"]
        }
        self.assertEqual(missing, set(cli.DRIVER_ENTRYPOINTS))
        source_complete = {
            item["driver"] for item in value["drivers"] if item["source_complete"]
        }
        self.assertEqual(source_complete, {
            "clean-machine-bootstrap", "host-provenance-fixture",
            "host-archive-fixture", "research-qualification-fixture",
            "research-recovery-fixture", "cold-boot-readback-fixture",
        })
        self.assertTrue(all(
            item["physical_eligibility"] for item in value["drivers"]
        ))

    def test_checkout_files_never_replace_protected_installation_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = self.driver_root(root / "checkout")
            value = cli.driver_readiness(
                checkout, source_commit="b" * 40,
                protected_root=root / "missing-protected",
                expected_install_uid=os.geteuid(),
            )
            self.assertEqual(value["available_driver_count"], 0)
            self.assertTrue(all(item["source_complete"] for item in value["drivers"]))
            self.assertTrue(all(
                not item["protected_installation"] for item in value["drivers"]
            ))
            protected = self.protected_root(
                root / "protected", checkout, "b" * 40,
            )
            ready = cli.driver_readiness(
                checkout, source_commit="b" * 40, protected_root=protected,
                expected_install_uid=os.geteuid(),
            )
            self.assertTrue(ready["campaign_initialization_allowed"])
            archive = next(
                item for item in ready["drivers"]
                if item["driver"] == "host-archive-fixture"
            )
            self.assertTrue(archive["available"])
            self.assertTrue(archive["physical_eligibility"])
            payload = (
                protected / "releases" / ("b" * 40)
                / cli.PROTECTED_DRIVER_PAYLOADS["host-provenance-fixture"][0]
            )
            payload.chmod(0o644)
            rejected = cli.driver_readiness(
                checkout, source_commit="b" * 40, protected_root=protected,
                expected_install_uid=os.geteuid(),
            )
            provenance = next(
                item for item in rejected["drivers"]
                if item["driver"] == "host-provenance-fixture"
            )
            self.assertFalse(provenance["available"])
            self.assertEqual(
                provenance["installation_error"],
                "protected_driver_file_untrusted",
            )
            payload.chmod(0o444)
            manifest = protected / "releases" / ("b" * 40) / "manifest.json"
            manifest.chmod(0o644)
            manifest.write_bytes(cli.canonical([]))
            manifest.chmod(0o444)
            malformed = cli.driver_readiness(
                checkout, source_commit="b" * 40, protected_root=protected,
                expected_install_uid=os.geteuid(),
            )
            provenance = next(
                item for item in malformed["drivers"]
                if item["driver"] == "host-provenance-fixture"
            )
            self.assertEqual(
                provenance["installation_error"],
                "protected_driver_manifest_invalid",
            )

    def test_noncanonical_or_mutable_enrollment_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            source.write_text(json.dumps(self.enrollment_value()), encoding="utf-8")
            source.chmod(0o600)
            checkout = self.driver_root(root / "checkout")
            protected = self.protected_root(
                root / "protected", checkout, "b" * 40,
            )
            with mock.patch.object(cli, "require_driver_readiness"), \
                    self.assertRaisesRegex(cli.AcceptanceError, "noncanonical"):
                cli.initialize(
                    source, "b" * 40, root / "campaign.json", NOW, 3600,
                    driver_root=checkout, protected_root=protected,
                    expected_install_uid=os.geteuid(),
                )
            self.write(source, self.enrollment_value())
            source.chmod(0o666)
            with mock.patch.object(cli, "require_driver_readiness"), \
                    self.assertRaisesRegex(cli.AcceptanceError, "untrusted"):
                cli.initialize(
                    source, "b" * 40, root / "campaign.json", NOW, 3600,
                    driver_root=checkout, protected_root=protected,
                    expected_install_uid=os.geteuid(),
                )

    def test_catalog_is_read_only_and_exposes_no_mutation_command(self):
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/harness-lifecycle-acceptance.py"), "--help"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "shared")},
        )
        for command in ("catalog", "readiness", "initialize", "verify-campaign", "status", "next",
                        "assemble", "verify-export"):
            self.assertIn(command, result.stdout)
        for forbidden in ("activate", "rollback", "retire", "revoke", "recover", "poweroff"):
            self.assertNotIn(forbidden, result.stdout)

    def test_status_validates_partial_observations_and_identifies_next_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            output = root / "campaign.json"
            observations = root / "observations"
            observations.mkdir(mode=0o700)
            self.write(source, self.enrollment_value())
            checkout = self.driver_root(root / "checkout")
            protected = self.protected_root(
                root / "protected", checkout, "b" * 40,
            )
            with mock.patch.object(cli, "require_driver_readiness"):
                campaign = cli.initialize(
                    source, "b" * 40, output, NOW, 3600,
                    driver_root=checkout, protected_root=protected,
                    expected_install_uid=os.geteuid(),
                )
            first = cli.CASES[0]
            for kind in first.evidence_kinds:
                artifact_content = b"protected-readback"
                artifact_sha256 = hashlib.sha256(artifact_content).hexdigest()
                collector = cli.COLLECTOR_PRIMARY_AUTHORITY
                collector_id = cli.EVIDENCE_KIND_COLLECTOR[kind]
                evidence = {
                    "schema": cli.EVIDENCE_SCHEMA,
                    "evidence_id": str(uuid.uuid4()),
                    "campaign_id": campaign["campaign_id"],
                    "campaign_sha256": campaign["campaign_sha256"],
                    "case_id": first.case_id, "kind": kind,
                    "collector": collector_id,
                    "machine_identity_sha256": campaign["machine_identity_sha256"],
                    "source_commit": campaign["source_commit"],
                    "observed_at": NOW, "outcome": first.expected,
                    "subject_sha256": artifact_sha256,
                    "source_schema": "secure-sandbox-test-source-v1",
                    "source_status": first.expected, "source_sha256": artifact_sha256,
                    "artifacts": [{
                        "name": "protected-readback",
                        "sha256": artifact_sha256,
                        "size": len(artifact_content), "media_type": "application/json",
                        "authority": collector[collector_id],
                        "content_base64": base64.b64encode(artifact_content).decode("ascii"),
                    }],
                    "candidate_statement_used": False,
                }
                evidence["evidence_sha256"] = cli.digest(evidence)
                value = {
                    "schema": cli.OBSERVATION_SCHEMA,
                    "observation_id": str(uuid.uuid4()),
                    "campaign_id": campaign["campaign_id"],
                    "campaign_sha256": campaign["campaign_sha256"],
                    "case_id": first.case_id, "kind": kind,
                    "collector": collector_id,
                    "machine_identity_sha256": campaign["machine_identity_sha256"],
                    "source_commit": campaign["source_commit"],
                    "started_at": NOW, "completed_at": NOW,
                    "outcome": first.expected, "subject_sha256": artifact_sha256,
                    "evidence": evidence, "evidence_sha256": evidence["evidence_sha256"],
                    "candidate_statement_used": False,
                }
                value["observation_sha256"] = cli.digest(value)
                self.write(observations / f"{first.case_id}.{kind}.json", value)
            status = cli.campaign_status(
                campaign, observations, observation_uid=os.geteuid(),
            )
            self.assertEqual(status["completed_cases"], [first.case_id])
            self.assertEqual(status["next_case"], cli.CASES[1].case_id)
            self.assertFalse(status["ready_for_assembly"])
            next_value = cli.next_case(
                campaign, observations, observation_uid=os.geteuid(),
            )
            self.assertEqual(next_value["status"], "pending")
            self.assertEqual(next_value["case"]["case_id"], cli.CASES[1].case_id)
            self.assertEqual(next_value["case"]["procedure"]["action"], cli.CASES[1].case_id)
            self.assertEqual(
                [item["kind"] for item in next_value["missing_evidence"]],
                list(cli.CASES[1].evidence_kinds),
            )
            self.assertEqual(next_value["authority"], "none")
            with self.assertRaisesRegex(cli.AcceptanceError, "untrusted"):
                cli.campaign_status(
                    campaign, observations,
                    observation_uid=os.geteuid() + 1,
                )
            self.write(observations / "unreviewed.json", self.enrollment_value())
            with self.assertRaisesRegex(cli.AcceptanceError, "inventory"):
                cli.campaign_status(
                    campaign, observations, observation_uid=os.geteuid(),
                )


if __name__ == "__main__":
    unittest.main()
