import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from shared import native_egress
from shared.test_native_egress import inference_grant


PATH = pathlib.Path(__file__).with_name("render_gateway_firewall.py")
SPEC = importlib.util.spec_from_file_location("render_gateway_firewall", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GatewayFirewallRenderTests(unittest.TestCase):
    def test_admin_source_is_explicit_and_validated(self):
        policy = MODULE.render(None, None, admin_source_ipv4="192.0.2.10")
        self.assertIn('ip saddr 192.0.2.10 tcp dport 22 accept', policy)
        with self.assertRaises(ValueError):
            MODULE.render(None, None, admin_source_ipv4="192.0.2.10; accept")

    def test_legacy_policy_migration_parser_is_exact(self):
        policy = 'iifname "uplink0" ip saddr 192.0.2.10 tcp dport 22 accept\n'
        self.assertEqual(MODULE.legacy_admin_source(policy), "192.0.2.10")
        with self.assertRaises(ValueError):
            MODULE.legacy_admin_source(policy + policy)
        with self.assertRaises(ValueError):
            MODULE.legacy_admin_source('ip saddr 192.0.2.10 tcp dport 22 accept; drop\n')

    def test_native_tunnel_rule_is_uid_and_exact_pin_scoped(self):
        grant = inference_grant()
        provider_mark = native_egress.conntrack_mark(grant, "provider")
        research_mark = native_egress.conntrack_mark(grant, "research")
        account = type("Account", (), {"pw_uid": 4242, "pw_gid": 4243})()
        with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
            policy = MODULE.render(
                None,
                None,
                native=grant,
                admin_source_ipv4="192.0.2.10",
                now=1_800_000_000,
                native_feature=True,
            )
        self.assertIn("set native_provider_ipv4", policy)
        self.assertIn("flags timeout", policy)
        self.assertIn("timeout 600s", policy)
        self.assertIn("elements = { 8.8.8.8 timeout 600s", policy)
        self.assertIn(
            f'meta skuid 4242 ip daddr @native_provider_ipv4 tcp dport 443 ct state new ct mark 0 ct mark set {provider_mark} accept',
            policy,
        )
        self.assertIn(
            f'iifname "ctl0" ip saddr 172.30.10.2 tcp dport 8643 ct state new ct mark 0 ct mark set {research_mark} accept',
            policy,
        )
        self.assertIn(
            f'iifname "uplink0" ip saddr @native_provider_ipv4 tcp sport 443 ct mark {provider_mark} accept',
            policy,
        )
        self.assertLess(
            policy.index(
                f'meta skuid 4242 ip daddr @native_provider_ipv4 tcp dport 443 ct mark {provider_mark} accept'
            ),
            policy.index("meta skuid 4242 drop"),
        )
        self.assertLess(
            policy.index("meta skuid 4242 drop"),
            policy.index('oifname "lo" accept'),
        )
        self.assertLess(policy.index("ct mark != 0 drop"), policy.index("ct state established,related accept"))
        self.assertNotIn("0.0.0.0/0", policy)

    def test_native_revocation_policy_keeps_guards_but_removes_allows(self):
        account = type("Account", (), {"pw_uid": 4242, "pw_gid": 4243})()
        with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
            policy = MODULE.render(
                None,
                None,
                native=None,
                native_feature=True,
                admin_source_ipv4="192.0.2.10",
            )
        self.assertNotIn("set native_provider_ipv4", policy)
        self.assertNotIn("tcp dport 8643 ct mark set", policy)
        self.assertIn('iifname "ctl0" tcp dport 8643 drop', policy)
        self.assertIn('meta skuid 4242 drop', policy)
        self.assertLess(
            policy.index('meta skuid 4242 drop'),
            policy.index('oifname "lo" accept'),
        )
        self.assertIn("ct mark != 0 drop", policy)

    def test_replacement_grant_does_not_admit_old_marked_flows(self):
        old = inference_grant()
        replacement = inference_grant()
        replacement["grant_id"] = "77777777-7777-4777-8777-777777777777"
        body = {
            field: replacement[field]
            for field in replacement
            if field not in {"schema", "grant_sha256"}
        }
        replacement["grant_sha256"] = native_egress.sha256(body)
        replacement = native_egress.validate_grant(replacement, now=1_800_000_000)
        old_mark = native_egress.conntrack_mark(old, "provider")
        new_mark = native_egress.conntrack_mark(replacement, "provider")
        self.assertNotEqual(old_mark, new_mark)
        account = type("Account", (), {"pw_uid": 4242, "pw_gid": 4243})()
        with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
            policy = MODULE.render(
                None,
                None,
                native=replacement,
                admin_source_ipv4="192.0.2.10",
                now=1_800_000_000,
                native_feature=True,
            )
        self.assertIn(f"ct mark {new_mark} accept", policy)
        self.assertNotIn(f"ct mark {old_mark} accept", policy)
        self.assertIn(
            f"ct state new ct mark 0 ct mark set {new_mark} accept", policy
        )
        for line in policy.splitlines():
            if f"ct mark set {new_mark}" in line:
                self.assertIn("ct state new ct mark 0", line)
        self.assertIn("ct mark != 0 drop", policy)

    def test_native_tunnel_rule_rejects_tampered_grant(self):
        grant = inference_grant()
        grant["destinations"][0]["ipv4"] = ["127.0.0.1"]
        with self.assertRaises(Exception):
            MODULE.render(
                None,
                None,
                native=grant,
                admin_source_ipv4="192.0.2.10",
                now=1_800_000_000,
                native_feature=True,
            )

    def test_native_tunnel_rule_rejects_inactive_grant(self):
        grant = inference_grant()
        with self.assertRaises(Exception):
            MODULE.render(
                None,
                None,
                native=grant,
                admin_source_ipv4="192.0.2.10",
                now=grant["expires_at"],
                native_feature=True,
            )

    def test_cli_state_is_durable_exact_and_ambiguous_state_fails(self):
        account = type(
            "Account", (), {"pw_uid": 4242, "pw_gid": os.getegid()}
        )()
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
                    now=1_800_000_000,
                    expected_uid=os.geteuid(),
                    expected_install_gid=os.getegid(),
                )
                self.assertIsNone(native)
                self.assertTrue(installed)
                policy = MODULE.render(
                    None,
                    None,
                    native=native,
                    native_feature=installed,
                    admin_source_ipv4="192.0.2.10",
                )
            self.assertIn("ct mark != 0 drop", policy)
            self.assertIn("meta skuid 4242 drop", policy)

            grant_path.write_bytes(
                native_egress.canonical_bytes(inference_grant())
            )
            grant_path.chmod(0o640)
            with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
                loaded, installed = MODULE.load_native_cli_state(
                    sentinel,
                    grant_path,
                    now=1_800_000_000,
                    expected_uid=os.geteuid(),
                    expected_install_gid=os.getegid(),
                )
                self.assertEqual(loaded, inference_grant())
                self.assertTrue(installed)
                grant_path.chmod(0o644)
                with self.assertRaises(native_egress.NativeEgressError):
                    MODULE.load_native_cli_state(
                        sentinel,
                        grant_path,
                        now=1_800_000_000,
                        expected_uid=os.geteuid(),
                        expected_install_gid=os.getegid(),
                    )
                grant_path.chmod(0o640)
                grant_path.write_bytes(
                    native_egress.canonical_bytes(inference_grant()) + b" "
                )
                with self.assertRaises(native_egress.NativeEgressError):
                    MODULE.load_native_cli_state(
                        sentinel,
                        grant_path,
                        now=1_800_000_000,
                        expected_uid=os.geteuid(),
                        expected_install_gid=os.getegid(),
                    )

            grant_path.unlink()
            with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError):
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    MODULE.load_native_cli_state(
                        sentinel,
                        grant_path,
                        now=1_800_000_000,
                        expected_uid=os.geteuid(),
                        expected_install_gid=os.getegid(),
                    )

            sentinel.unlink()
            with mock.patch.object(MODULE.pwd, "getpwnam", return_value=account):
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    MODULE.load_native_cli_state(
                        sentinel,
                        grant_path,
                        now=1_800_000_000,
                        expected_uid=os.geteuid(),
                        expected_install_gid=os.getegid(),
                    )


if __name__ == "__main__":
    unittest.main()
