#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativeVendorDeploymentTests(unittest.TestCase):
    def test_gateway_installer_is_transactional_and_defaults_closed(self) -> None:
        text = (ROOT / "scripts/install-native-egress-gateway.sh").read_text()
        self.assertIn("gateway-install.pending.json", text)
        self.assertIn("native_install_transaction.py", text)
        self.assertIn("finalize-recovery", text)
        self.assertIn("commit --pending", text)
        self.assertIn("durable recovery remains pending", text)
        self.assertIn("active native-egress grant blocks installation", text)
        self.assertIn("systemctl stop native-opaque-tunnel.service", text)
        self.assertIn("systemctl disable native-opaque-tunnel.service", text)
        self.assertIn("mktemp /etc/.nftables.conf.native.", text)
        self.assertIn("verify_closed_live_firewall", text)
        self.assertIn("nft -f /etc/nftables.conf", text)
        self.assertIn("native_egress.load_install_state", text)
        self.assertIn("identity_groups=", text)
        self.assertNotIn("is-active --quiet native-opaque-tunnel.service &&", text)
        self.assertNotIn("chmod -R go-rwx", text)
        self.assertNotIn("systemctl enable --now native-opaque-tunnel.service", text)

    def test_native_services_do_not_restart_or_receive_credentials(self) -> None:
        gateway = (ROOT / "gateway/native-opaque-tunnel.service").read_text()
        research = (ROOT / "research/native-harness-supervisor.service").read_text()
        for unit in (gateway, research):
            self.assertIn("Restart=no", unit)
            self.assertIn("NoNewPrivileges=yes", unit)
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("MemoryDenyWriteExecute=yes", unit)
            self.assertNotIn("LoadCredential=", unit)
            self.assertNotIn("Environment=", unit)
            self.assertIn("SupplementaryGroups=", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", research)
        self.assertIn("ConditionPathExists=/var/lib/secure-sandbox/native-egress/active.json", research)

    def test_guest_actuator_requires_installed_feature_and_current_readback(self) -> None:
        text = (ROOT / "shared/native_guest_control.py").read_text()
        self.assertIn("native_egress.load_install_state(INSTALL_STATE)", text)
        self.assertIn("return execute(role, step, request)", text)
        self.assertIn("native_egress.load_grant", text)
        self.assertIn("conntrack_not_empty", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
