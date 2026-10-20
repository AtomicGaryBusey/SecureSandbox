#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import types
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
import pki_guest_helpers
import pki_lifecycle


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


gateway_pki = load("gateway_pki_generation", ROOT / "gateway" / "pki_generation.py")
research_pki = load("research_pki_generation", ROOT / "research" / "pki_generation.py")


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class GenerationExchangeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        openssl = shutil.which("openssl")
        gateway_pki.OPENSSL = openssl
        research_pki.OPENSSL = openssl
        pki_guest_helpers.OPENSSL = openssl
        self.gateway_live = self.root / "gateway-live"
        self.research_live = self.root / "research-live"
        for directory in ("pki", "telemetry"):
            (self.gateway_live / directory).mkdir(parents=True)
            for name in ("ca.crt", "server.key", "server.crt"):
                (self.gateway_live / directory / name).write_text(f"legacy-{name}\n")
        (self.gateway_live / "pki" / "ca.key").write_text("legacy-ca.key\n")
        for name, (_, config) in gateway_pki.CLIENTS.items():
            config = self.gateway_live / config.relative_to(gateway_pki.LIVE_ROOT)
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(json.dumps({"allowed_client_sha256": [str(name)[0] * 64]}) + "\n")
        for _, directory, _, _ in research_pki.CLIENTS.values():
            live = self.research_live / directory
            live.mkdir(parents=True)
            for name in ("client.key", "client.crt", "ca.crt"):
                (live / name).write_text(f"legacy-{directory}-{name}\n")

    def tearDown(self):
        self.temporary.cleanup()

    def test_fresh_keys_are_signed_and_bound_to_one_manifest(self):
        generation = str(uuid.uuid4())
        gateway = gateway_pki.GatewayPKI(self.root / "gateway-state", self.gateway_live, manage_services=False)
        research = research_pki.ResearchPKI(self.root / "research-state", self.research_live, manage_services=False)
        with gateway.store.locked():
            gateway.prepare(generation)
        with research.store.locked():
            research.prepare(generation)
            research.prepare(generation)
        research_generation = research.generation(generation)
        with gateway.store.locked():
            manifest = gateway.sign(
                generation,
                {name: research_generation / f"{name}.csr" for name in research_pki.CLIENTS},
            )
            self.assertEqual(
                gateway.sign(generation, {name: research_generation / f"{name}.csr" for name in research_pki.CLIENTS}),
                manifest,
            )
        gateway_generation = gateway.generation(generation)
        with research.store.locked():
            imported = research.import_signed(
                generation,
                gateway_generation / "ca.crt",
                {name: gateway_generation / f"{name}.crt" for name in research_pki.CLIENTS},
                gateway_generation / "manifest.json",
            )
            self.assertEqual(
                research.import_signed(
                    generation, gateway_generation / "ca.crt",
                    {name: gateway_generation / f"{name}.crt" for name in research_pki.CLIENTS},
                    gateway_generation / "manifest.json",
                ),
                manifest,
            )
        self.assertEqual(imported, manifest)
        self.assertEqual(
            pki_lifecycle.load_json(gateway.store.path(generation))["manifest_sha256"],
            pki_lifecycle.load_json(research.store.path(generation))["manifest_sha256"],
        )
        for name in research_pki.CLIENTS:
            self.assertNotEqual(
                (research_generation / f"{name}.key").read_bytes(),
                (research_generation / "previous" / f"{name}.key").read_bytes(),
            )

    def test_every_live_phase_recovers_after_mutation_before_journal(self):
        generation = str(uuid.uuid4())
        gateway = gateway_pki.GatewayPKI(self.root / "gateway-state", self.gateway_live, manage_services=False)
        research = research_pki.ResearchPKI(self.root / "research-state", self.research_live, manage_services=False)
        with gateway.store.locked():
            gateway.prepare(generation)
        with research.store.locked():
            research.prepare(generation)
        research_generation = research.generation(generation)
        with gateway.store.locked():
            manifest = gateway.sign(generation, {name: research_generation / f"{name}.csr" for name in research_pki.CLIENTS})
        gateway_generation = gateway.generation(generation)
        with research.store.locked():
            research.import_signed(
                generation, gateway_generation / "ca.crt",
                {name: gateway_generation / f"{name}.crt" for name in research_pki.CLIENTS},
                gateway_generation / "manifest.json",
            )

        group = types.SimpleNamespace(gr_gid=os.getegid())
        stages = [
            (research, lambda: research.activate_dual_trust(generation), "prepared", "research_dual_trust"),
            (gateway, lambda: gateway.activate_dual(generation), "research_dual_trust", "gateway_dual_trust"),
            (research, lambda: research.activate_clients(generation), "gateway_dual_trust", "research_new_clients"),
            (gateway, lambda: gateway.activate_new_only(generation), "research_new_clients", "gateway_new_only"),
            (research, lambda: research.commit(generation), "gateway_new_only", "committed"),
            (gateway, lambda: gateway.commit(generation), "gateway_new_only", "committed"),
        ]
        with mock.patch.object(gateway_pki.grp, "getgrnam", return_value=group), \
             mock.patch.object(research_pki.grp, "getgrnam", return_value=group), \
             mock.patch.object(gateway_pki.os, "fchown"), \
             mock.patch.object(pki_guest_helpers.os, "fchown"), \
             mock.patch.object(gateway_pki.GatewayPKI, "_require_installed"), \
             mock.patch.object(research_pki.ResearchPKI, "_require_installed"):
            for index, (manager, action, expected, target) in enumerate(stages):
                # Mirror the phase already proven by the other guest.
                if index:
                    with manager.store.locked():
                        manager.store.advance(generation, pki_lifecycle.PHASES[pki_lifecycle.PHASES.index(expected) - 1], expected)
                with mock.patch.object(manager.store, "advance", side_effect=pki_lifecycle.LifecycleError("simulated_crash")):
                    with self.assertRaisesRegex(pki_lifecycle.LifecycleError, "simulated_crash"):
                        action()
                self.assertEqual(manager.store.load(generation)["phase"], expected)
                result = action()
                self.assertEqual(result["phase"], target)

        self.assertEqual(research.store.load(generation)["phase"], "committed")
        self.assertEqual(gateway.store.load(generation)["phase"], "committed")
        self.assertEqual(
            json.loads((self.research_live / "pki-generation.json").read_text())["manifest_sha256"],
            manifest["manifest_sha256"],
        )
        self.assertEqual(
            (self.gateway_live / "pki" / "server.crt").read_bytes(),
            (self.gateway_live / "telemetry" / "server.crt").read_bytes(),
        )
        with mock.patch.object(gateway_pki.grp, "getgrnam", return_value=group), \
             mock.patch.object(gateway_pki.GatewayPKI, "_require_installed"):
            (self.gateway_live / "telemetry" / "ca.crt").write_text("tampered\n")
            with self.assertRaises(pki_lifecycle.LifecycleError):
                gateway.commit(generation)
        with mock.patch.object(research_pki.grp, "getgrnam", return_value=group), \
             mock.patch.object(research_pki.ResearchPKI, "_require_installed"):
            (self.research_live / "relay" / "client.crt").write_text("tampered\n")
            with self.assertRaises(pki_lifecycle.LifecycleError):
                research.commit(generation)


if __name__ == "__main__":
    unittest.main()
