#!/usr/bin/env python3

import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from shared import native_egress
from shared.test_native_egress import NOW, inference_grant


PATH = pathlib.Path(__file__).with_name("render_research_firewall.py")
SPEC = importlib.util.spec_from_file_location("render_research_firewall", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ResearchFirewallRenderTests(unittest.TestCase):
    @staticmethod
    def account(name: str):
        values = {
            "native-harness": 4242,
            "native-claude": 4243,
            "native-codex": 4244,
            "claude-relay": 1001,
            "telemetry-exporter": 1002,
            "conversation-shipper": 1003,
            "labadmin": 1004,
            "execution-broker": 1005,
        }
        return type(
            "Account", (), {"pw_uid": values[name], "pw_gid": os.getegid()}
        )()

    def test_native_tunnel_is_exact_uid_endpoint_and_active_grant_scoped(self):
        grant = inference_grant()
        mark = native_egress.conntrack_mark(grant, "research")
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=self.account):
            policy = MODULE.render(grant, now=NOW, native_feature=True)
        claude_allow = (
            'oifname "ctl0" meta skuid 4243 ip daddr 172.30.10.1 '
            f'tcp dport 8643 ct state new ct mark 0 ct mark set {mark} accept'
        )
        codex_allow = (
            'oifname "ctl0" meta skuid 4244 ip daddr 172.30.10.1 '
            f'tcp dport 8643 ct state new ct mark 0 ct mark set {mark} accept'
        )
        self.assertIn(claude_allow, policy)
        self.assertIn(codex_allow, policy)
        self.assertNotIn(
            'meta skuid 4242 ip daddr 172.30.10.1 tcp dport 8643', policy)
        self.assertIn(
            'iifname "ctl0" ip saddr 172.30.10.1 tcp sport 8643 '
            f'ct mark {mark} accept',
            policy,
        )
        self.assertNotIn('meta skuid 1001 ip daddr 172.30.10.1 tcp dport 8643', policy)
        self.assertLess(policy.index("ct mark != 0 drop"), policy.index("ct state established,related accept"))
        self.assertLess(
            policy.index(claude_allow), policy.index("meta skuid 4243 drop"))
        self.assertLess(
            policy.index(codex_allow), policy.index("meta skuid 4244 drop"))
        self.assertLess(
            policy.index("meta skuid 4242 drop"),
            policy.index('oifname "lo" accept'),
        )
        self.assertNotIn("tcp dport 18080 accept", policy)

    def test_native_revocation_keeps_identity_and_conntrack_guards(self):
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=self.account):
            policy = MODULE.render(None, native_feature=True)
        self.assertNotIn("tcp dport 8643 ct mark set", policy)
        self.assertIn("meta skuid 4242 drop", policy)
        self.assertIn("meta skuid 4243 drop", policy)
        self.assertIn("meta skuid 4244 drop", policy)
        self.assertIn("ct mark != 0 drop", policy)

    def test_tampered_or_inactive_grant_is_rejected(self):
        tampered = inference_grant()
        tampered["destinations"][0]["ipv4"] = ["127.0.0.1"]
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=self.account):
            with self.assertRaises(Exception):
                MODULE.render(tampered, now=NOW, native_feature=True)
            with self.assertRaises(Exception):
                MODULE.render(
                    inference_grant(), now=NOW + 600, native_feature=True
                )

    def test_native_harness_cannot_reach_broker_or_any_local_ip_service(self):
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=self.account):
            policy = MODULE.render(inference_grant(), now=NOW, native_feature=True)
        blanket = "meta skuid 4242 drop"
        self.assertIn(blanket, policy)
        self.assertLess(policy.index(blanket), policy.index('oifname "lo" accept'))
        self.assertNotIn("127.0.0.1", policy)
        self.assertNotIn("18080", policy)
        self.assertNotIn("model-broker", policy)

    def test_cli_sentinel_retains_guards_on_unrelated_reload_and_loads_exact_grant(self):
        account = self.account("native-harness")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sentinel = root / "installed"
            grant_path = root / "active.json"
            sentinel.write_bytes(native_egress.INSTALL_STATE_BYTES)
            sentinel.chmod(0o600)
            with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
                native, installed = MODULE.load_native_cli_state(
                    sentinel,
                    grant_path,
                    now=NOW,
                    expected_uid=os.geteuid(),
                    expected_install_gid=os.getegid(),
                )
                policy = MODULE.render(native, native_feature=installed)
            self.assertIn("meta skuid 4242 drop", policy)
            self.assertIn("ct mark != 0 drop", policy)

            grant_path.write_bytes(
                native_egress.canonical_bytes(inference_grant())
            )
            grant_path.chmod(0o640)
            with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
                loaded, installed = MODULE.load_native_cli_state(
                    sentinel,
                    grant_path,
                    now=NOW,
                    expected_uid=os.geteuid(),
                    expected_install_gid=os.getegid(),
                )
            self.assertEqual(loaded, inference_grant())
            self.assertTrue(installed)

            sentinel.unlink()
            with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    MODULE.load_native_cli_state(
                        sentinel,
                        grant_path,
                        now=NOW,
                        expected_uid=os.geteuid(),
                        expected_install_gid=os.getegid(),
                    )


if __name__ == "__main__":
    unittest.main()
