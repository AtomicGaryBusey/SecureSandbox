import importlib.util
import pathlib
import unittest


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


if __name__ == "__main__":
    unittest.main()
