#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PATH = Path(__file__).with_name("model_profile_activation.py")
SPEC = importlib.util.spec_from_file_location("model_profile_activation", PATH)
activation = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(activation)


class ActivationPlanTests(unittest.TestCase):
    def test_current_generation_requires_exact_gateway_research_agreement(self):
        gateway = {"adapter":"anthropic-messages-v1", "mode":"production",
                   "model":"old-model", "profile_id":"old-profile",
                   "profile_sha256":"a" * 64, "vendor_id":"old-vendor"}
        responses = [
            mock.Mock(returncode=0, stdout=activation.canonical(gateway)),
            mock.Mock(returncode=0, stdout=activation.canonical({**gateway, "model":"other"})),
        ]
        with mock.patch.object(activation.subprocess, "run", side_effect=responses), \
                self.assertRaisesRegex(RuntimeError, "generation_mismatch"):
            activation.active_identity()

    def test_mock_plan_is_nonsecret_exact_and_digest_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "config").mkdir()
            source = activation.ROOT / "config/model-profiles.example.json"
            (root / "config/model-profiles.json").write_bytes(source.read_bytes())
            (root / "config/model-profiles.json").chmod(0o600)
            identity = {"adapter":"anthropic-messages-v1", "mode":"production",
                        "model":"old-model", "profile_id":"old-profile",
                        "profile_sha256":"a" * 64, "vendor_id":"old-vendor"}
            current = {"gateway":identity, "research":identity}
            with mock.patch.object(activation, "ROOT", root), \
                    mock.patch.object(activation, "active_identity", return_value=current):
                plan = activation.create_plan("abliterated-glm", "mock", now=1000)
        self.assertEqual(plan["broker"]["mode"], "mock")
        self.assertEqual(plan["broker"]["upstream_ipv4"], [])
        self.assertEqual(plan["current"], current)
        self.assertEqual(plan["current_generation_sha256"], activation.digest(current))
        self.assertNotIn("secret", activation.canonical(plan).decode())
        claimed = plan.pop("plan_sha256")
        self.assertEqual(claimed, activation.digest(plan))

    def test_production_plan_rejects_non_global_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "config").mkdir()
            source = activation.ROOT / "config/model-profiles.example.json"
            (root / "config/model-profiles.json").write_bytes(source.read_bytes())
            (root / "config/model-profiles.json").chmod(0o600)
            answer = [(2, 1, 6, "", ("127.0.0.1", 443))]
            with mock.patch.object(activation, "ROOT", root), \
                    mock.patch.object(activation, "active_identity", return_value={
                        "gateway":{"adapter":"anthropic-messages-v1", "mode":"production",
                                   "model":"old-model", "profile_id":"old-profile",
                                   "profile_sha256":"a" * 64, "vendor_id":"old-vendor"},
                        "research":{"state":"legacy_unbound"}}), \
                    mock.patch("socket.getaddrinfo", return_value=answer):
                with self.assertRaises(ValueError):
                    activation.create_plan("abliterated-glm", "production", now=1000)


if __name__ == "__main__": unittest.main()
