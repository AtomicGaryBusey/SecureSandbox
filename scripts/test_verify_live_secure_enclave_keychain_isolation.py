#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name(
    "verify_live_secure_enclave_keychain_isolation.py"
)
SPEC = importlib.util.spec_from_file_location("keychain_isolation", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class KeychainIsolationProbeTests(unittest.TestCase):
    GENERATION = "11111111-1111-4111-8111-111111111111"
    TEAM_ID = "ABCDE" + "12345"
    ACCESS_GROUP = TEAM_ID + ".org.zebeth.SecureSandbox.AuthorizationUI"

    def run_probe(self, lookup_status=-34018, lookup_returncode=0,
                  signature="Signature=adhoc\nTeamIdentifier=not set\n"):
        compile_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        resign_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        signature_result = SimpleNamespace(
            returncode=0, stdout="", stderr=signature
        )
        unentitled_result = SimpleNamespace(
            returncode=lookup_returncode, stdout=f"{lookup_status}\n", stderr=""
        )
        entitlement_result = SimpleNamespace(
            returncode=0,
            stdout=__import__("plistlib").dumps({
                "keychain-access-groups":[self.ACCESS_GROUP]
            }),
            stderr=b"",
        )
        forged_result = SimpleNamespace(
            returncode=-9, stdout="", stderr=""
        )
        with mock.patch.object(
            PROBE.subprocess, "run",
            side_effect=[
                compile_result, signature_result, unentitled_result,
                resign_result, signature_result, entitlement_result,
                forged_result,
            ],
        ):
            return PROBE.probe(self.GENERATION, self.TEAM_ID, self.ACCESS_GROUP)

    def test_missing_entitlement_is_required(self):
        result = self.run_probe()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["lookup_status"], -34018)
        self.assertEqual(result["helper_signature"], "adhoc")
        self.assertTrue(result["forged_access_group_present"])
        self.assertEqual(result["forged_launch_signal"], 9)

    def test_successful_or_item_not_found_lookup_fails(self):
        for status in (0, -25300):
            with self.subTest(status=status), self.assertRaisesRegex(
                PROBE.ProbeError, "unentitled_keychain_lookup_not_rejected"
            ):
                self.run_probe(status, 1)

    def test_approved_team_signature_is_not_a_negative_helper(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "different_signer_identity_invalid"):
            self.run_probe(signature="Signature=adhoc\nTeamIdentifier=" + self.TEAM_ID + "\n")

    def test_generation_must_be_canonical_uuid4(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "generation_id_invalid"):
            PROBE.probe("not-a-generation")

    def test_v2_signing_policy_must_be_exact_and_self_consistent(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name)
            manifest = {
                "bundle":"SecureSandboxAuthorizationUI.app",
                "files":{},
                "schema":"secure-sandbox-touchid-ui-bundle-v2",
                "signing_policy":{
                    "access_group":self.ACCESS_GROUP,
                    "application_identifier":self.ACCESS_GROUP,
                    "bundle_id":"org.zebeth.SecureSandbox.AuthorizationUI",
                    "team_id":self.TEAM_ID,
                },
            }
            (release / "authorization_ui_bundle").write_text(json.dumps(manifest))
            self.assertEqual(
                PROBE.signing_identity(release),
                (self.TEAM_ID, self.ACCESS_GROUP),
            )
            manifest["schema"] = "secure-sandbox-touchid-ui-bundle-v3"
            (release / "authorization_ui_bundle").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(PROBE.ProbeError, "signing_policy_invalid"):
                PROBE.signing_identity(release)
            manifest.pop("signing_policy")
            manifest["schema"] = "secure-sandbox-touchid-ui-bundle-v1"
            (release / "authorization_ui_bundle").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(PROBE.ProbeError, "signing_policy_invalid"):
                PROBE.signing_identity(release)


if __name__ == "__main__":
    unittest.main()
