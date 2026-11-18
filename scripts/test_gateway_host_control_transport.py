#!/usr/bin/env python3

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("gateway-host-control-transport.py")
SPEC = importlib.util.spec_from_file_location("gateway_host_control_transport", SCRIPT)
CONTROL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CONTROL)


class GatewayHostControlTransportTests(unittest.TestCase):
    def runner(self, arguments, **_kwargs):
        self.calls.append(arguments)
        stdout = b""
        if arguments[1:] == ["list", "chain", "inet", "filter", "input"]:
            stdout = (
                b'table inet filter {\n\tchain input {\n'
                b'\t\tiifname "ctl0" ip saddr 172.30.10.30 tcp dport 22 accept\n'
                b'\t}\n}\n'
            )
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    def setUp(self):
        self.calls = []

    def test_rules_add_only_exact_isolated_host_admission(self):
        old = CONTROL.rules("10.211.55.2", host_control=False)
        new = CONTROL.rules("10.211.55.2", host_control=True)
        rule = b'iifname "ctl0" ip saddr 172.30.10.30 tcp dport 22 accept'
        self.assertNotIn(rule, old)
        self.assertEqual(new.count(rule), 1)
        self.assertEqual(
            new.replace(b"    " + rule + b"\n", b""), old,
        )
        for invalid in ("", "not-an-ip", "2001:db8::1"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    CONTROL.HostControlError, "host_control_admin_source_invalid"):
                CONTROL.rules(invalid, host_control=True)

    def test_install_preserves_predecessor_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nftables = root / "nftables.conf"
            admin = root / "gateway-admin-source-ipv4"
            state = root / "state/network-migrations"
            admin.write_text("10.211.55.2\n", encoding="ascii")
            nftables.write_bytes(CONTROL.rules("10.211.55.2", host_control=False))
            admin.chmod(0o600)
            nftables.chmod(0o600)
            uid = os.geteuid()

            first = CONTROL.install(
                nftables=nftables, admin_path=admin, state_root=state,
                runner=self.runner, expected_uid=uid,
            )
            self.assertEqual(first["status"], "installed")
            self.assertEqual(first["authority"], "guest-firewall-only")
            successor = CONTROL.rules("10.211.55.2", host_control=True)
            predecessor = CONTROL.rules("10.211.55.2", host_control=False)
            self.assertEqual(nftables.read_bytes(), successor)
            backups = list(state.iterdir())
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), predecessor)

            self.calls.clear()
            second = CONTROL.install(
                nftables=nftables, admin_path=admin, state_root=state,
                runner=self.runner, expected_uid=uid,
            )
            self.assertEqual(second["status"], "verified")
            self.assertIsNone(second["backup_sha256"])
            self.assertEqual(list(state.iterdir()), backups)
            self.assertIn(
                [str(CONTROL.NFT), "list", "chain", "inet", "filter", "input"],
                self.calls,
            )

    def test_install_rejects_unknown_predecessor_and_wrong_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nftables = root / "nftables.conf"
            admin = root / "gateway-admin-source-ipv4"
            state = root / "state/network-migrations"
            admin.write_text("10.211.55.2\n", encoding="ascii")
            nftables.write_text("flush ruleset\n", encoding="ascii")
            admin.chmod(0o600)
            nftables.chmod(0o600)
            with self.assertRaisesRegex(
                    CONTROL.HostControlError, "host_control_predecessor_invalid"):
                CONTROL.install(
                    nftables=nftables, admin_path=admin, state_root=state,
                    runner=self.runner, expected_uid=os.geteuid(),
                )
            with mock.patch.object(CONTROL.os, "geteuid", return_value=99):
                with self.assertRaisesRegex(
                        CONTROL.HostControlError, "host_control_root_required"):
                    CONTROL.install(
                        nftables=nftables, admin_path=admin, state_root=state,
                        runner=self.runner, expected_uid=0,
                    )

if __name__ == "__main__":
    unittest.main()
