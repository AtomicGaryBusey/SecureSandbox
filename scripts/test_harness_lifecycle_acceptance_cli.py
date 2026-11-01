#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


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

    def test_initialize_consumes_canonical_enrollment_and_writes_new_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            output = root / "campaign.json"
            self.write(source, self.enrollment_value())
            value = cli.initialize(source, "b" * 40, output, NOW, 3600)
            self.assertEqual(cli.trusted_json(output), value)
            self.assertEqual(value["authority"], "acceptance-evidence-only")
            with self.assertRaises(FileExistsError):
                cli.initialize(source, "b" * 40, output, NOW, 3600)

    def test_noncanonical_or_mutable_enrollment_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "enrollment.json"
            source.write_text(json.dumps(self.enrollment_value()), encoding="utf-8")
            source.chmod(0o600)
            with self.assertRaisesRegex(cli.AcceptanceError, "noncanonical"):
                cli.initialize(source, "b" * 40, root / "campaign.json", NOW, 3600)
            self.write(source, self.enrollment_value())
            source.chmod(0o666)
            with self.assertRaisesRegex(cli.AcceptanceError, "untrusted"):
                cli.initialize(source, "b" * 40, root / "campaign.json", NOW, 3600)

    def test_catalog_is_read_only_and_exposes_no_mutation_command(self):
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/harness-lifecycle-acceptance.py"), "--help"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "shared")},
        )
        for command in ("catalog", "initialize", "verify-campaign", "assemble", "verify-export"):
            self.assertIn(command, result.stdout)
        for forbidden in ("activate", "rollback", "retire", "revoke", "recover", "poweroff"):
            self.assertNotIn(forbidden, result.stdout)


if __name__ == "__main__":
    unittest.main()
