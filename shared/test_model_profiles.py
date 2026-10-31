#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path

import model_profiles


ROOT = Path(__file__).resolve().parent.parent


class ModelProfileTests(unittest.TestCase):
    def example(self):
        return json.loads((ROOT / "config/model-profiles.example.json").read_text())

    def test_example_is_canonical_and_valid(self):
        path = ROOT / "config/model-profiles.example.json"
        value = self.example()
        self.assertEqual(model_profiles.validate_catalog(value), value)
        self.assertEqual(path.read_bytes(), model_profiles.canonical_json(value))
        self.assertEqual(len(model_profiles.profile_revision(value["profiles"][0])), 64)

    def test_adapter_specific_fields_are_closed(self):
        value = self.example()
        profile = value["profiles"][0]
        profile["settings"]["reasoning_effort"] = "high"
        with self.assertRaisesRegex(model_profiles.ProfileError, "model_profile_settings_invalid"):
            model_profiles.validate_catalog(value)

    def test_rejects_secret_literal_and_non_agents_reference(self):
        for reference in ("secret-token", "op://Personal/item/token", "op://Agents/item/field/extra"):
            value = self.example()
            value["profiles"][0]["credential"]["reference"] = reference
            with self.assertRaisesRegex(model_profiles.ProfileError, "credential_reference_invalid"):
                model_profiles.validate_catalog(value)

    def test_google_profile_requires_exact_origin_deployment_and_service_account(self):
        profile = self.example()["profiles"][0]
        profile.update({
            "adapter": "google-openai-chat-v1",
            "credential": {"reference": "op://Agents/GoogleCyber/service_account_json",
                           "scheme": "google-service-account-json"},
            "deployment": {"location": "global", "project_id": "secure-sandbox-cyber"},
            "model_id": "google/gemini-3.8-flash-cyber",
            "settings": {"maximum_output_tokens": 32768,
                         "reasoning_effort": "high", "temperature_milli": None},
            "upstream_origin": "https://aiplatform.googleapis.com",
        })
        self.assertEqual(model_profiles.validate_profile(profile), profile)
        profile["upstream_origin"] = "https://evil.example"
        with self.assertRaisesRegex(model_profiles.ProfileError, "google_origin_invalid"):
            model_profiles.validate_profile(profile)

    def test_openai_profile_validates_cyber_access(self):
        profile = self.example()["profiles"][0]
        profile.update({
            "adapter": "openai-responses-v1",
            "credential": {"reference": "op://Agents/OpenAIDaybreak/api_key", "scheme": "bearer"},
            "deployment": {},
            "model_id": "gpt-daybreak-red-latest",
            "settings": {"cyber_access": "daybreak_red", "maximum_output_tokens": 32768,
                         "reasoning_effort": "high", "temperature_milli": None},
            "upstream_origin": "https://api.openai.com",
        })
        self.assertEqual(model_profiles.validate_profile(profile), profile)
        profile["settings"]["cyber_access"] = "unrestricted"
        with self.assertRaisesRegex(model_profiles.ProfileError, "cyber_access_invalid"):
            model_profiles.validate_profile(profile)

    def test_duplicate_unsorted_and_unknown_profiles_are_rejected(self):
        value = self.example()
        duplicate = json.loads(json.dumps(value["profiles"][0]))
        value["profiles"].append(duplicate)
        with self.assertRaisesRegex(model_profiles.ProfileError, "id_duplicate"):
            model_profiles.validate_catalog(value)
        duplicate["profile_id"] = "aaa"
        with self.assertRaisesRegex(model_profiles.ProfileError, "catalog_order_invalid"):
            model_profiles.validate_catalog(value)
        duplicate["unexpected"] = True
        with self.assertRaisesRegex(model_profiles.ProfileError, "model_profile_invalid"):
            model_profiles.validate_profile(duplicate)

    def test_write_and_private_load_are_atomic_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            path = root / "profiles.json"
            result = model_profiles.write_catalog(path, self.example())
            self.assertEqual(result["status"], "staged")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(model_profiles.load_catalog(path), self.example())

    def test_private_load_rejects_symlink_and_noncanonical_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            target = root / "target.json"
            target.write_text(json.dumps(self.example()))
            os.chmod(target, 0o600)
            link = root / "profiles.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(model_profiles.ProfileError, "file_untrusted"):
                model_profiles.load_catalog(link)
            link.unlink()
            target.rename(link)
            with self.assertRaisesRegex(model_profiles.ProfileError, "not_canonical"):
                model_profiles.load_catalog(link)


if __name__ == "__main__":
    unittest.main()
