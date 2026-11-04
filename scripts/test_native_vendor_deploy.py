#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativeVendorDeploymentTests(unittest.TestCase):
    def _closed_nft_validator(self) -> str:
        text = (ROOT / "scripts/install-native-egress-gateway.sh").read_text()
        section = text.split("verify_closed_live_firewall() {", 1)[1]
        return section.split("python3 -c '\n", 1)[1].split(
            "\n' \"$native_uid\"", 1
        )[0]

    @staticmethod
    def _closed_ruleset(uid: int = 1001) -> dict:
        def chain(name: str) -> dict:
            return {"chain": {"family": "inet", "table": "filter", "name": name,
                              "type": "filter", "hook": name, "prio": 0,
                              "policy": "drop"}}

        def rule(chain_name: str, left: dict, op: str, right: object,
                 verdict: str) -> dict:
            return {"rule": {"family": "inet", "table": "filter",
                             "chain": chain_name,
                             "expr": [{"match": {"left": left, "op": op,
                                                   "right": right}},
                                      {verdict: None}]}}

        return {"nftables": [
            {"table": {"family": "inet", "name": "filter"}},
            chain("input"), chain("forward"), chain("output"),
            rule("input", {"ct": {"key": "mark"}}, "!=", 0, "drop"),
            rule("output", {"meta": {"key": "skuid"}}, "==", uid, "drop"),
            rule("output", {"ct": {"key": "mark"}}, "!=", 0, "drop"),
            rule("input", {"ct": {"key": "state"}}, "in",
                 ["established", "related"], "accept"),
            rule("output", {"ct": {"key": "state"}}, "in",
                 ["established", "related"], "accept"),
        ]}

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
        self.assertIn("SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD", text)
        self.assertIn("os.O_NOFOLLOW|os.O_CLOEXEC", text)
        self.assertIn("source_manifest_sha256", text)
        self.assertIn('"source_manifest":json.loads', text)
        self.assertIn("native-state-v1", text)
        self.assertIn("LEDGER_SCHEMA_VERSION", text)
        self.assertIn("native_install_archive", (ROOT / "shared/native_install_transaction.py").read_text())
        self.assertIn('apply_restored_firewall "$pre_firewall_sha256"', text)
        self.assertIn('verify_service_prestate "$pre_service_load"', text)
        self.assertIn("native_latest_readback_failed", text)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", text)
        self.assertIn(
            'install -o root -g root -m 755 "$policy_hash" '
            "/usr/local/libexec/secure-sandbox/update-policy-hash.sh",
            text,
        )
        self.assertNotIn("is-active --quiet native-opaque-tunnel.service &&", text)
        self.assertNotIn("chmod -R go-rwx", text)
        self.assertNotIn("systemctl enable --now native-opaque-tunnel.service", text)
        self.assertNotIn("systemctl disable native-opaque-tunnel.service >/dev/null 2>&1 || true", text)
        self.assertNotIn('python3 "$install_transaction" recover', text)
        self.assertLess(text.index('if [[ -e "$pending"'), text.index("source_snapshot="))
        self.assertLess(text.index(' begin --pending "$pending"'), text.index("groupadd --system"))
        self.assertLess(text.index("latest=/var/lib/secure-sandbox"), text.rindex("commit --pending"))
        subprocess.run(
            ["bash", "-n", str(ROOT / "scripts/install-native-egress-gateway.sh")],
            check=True,
        )

    def test_closed_nft_readback_rejects_order_bypass_and_extra_table(self) -> None:
        validator = self._closed_nft_validator()
        safe = self._closed_ruleset()
        subprocess.run(
            [sys.executable, "-c", validator, "1001"],
            input=json.dumps(safe),
            text=True,
            check=True,
        )

        accept_before_drop = copy.deepcopy(safe)
        accept_before_drop["nftables"].insert(
            4,
            {"rule": {"family": "inet", "table": "filter", "chain": "output",
                      "expr": [{"accept": None}]}},
        )
        rejected = subprocess.run(
            [sys.executable, "-c", validator, "1001"],
            input=json.dumps(accept_before_drop),
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("native_nft_owner_drop_order_invalid", rejected.stderr)

        extra_table = copy.deepcopy(safe)
        extra_table["nftables"].append(
            {"table": {"family": "ip", "name": "bypass"}}
        )
        rejected = subprocess.run(
            [sys.executable, "-c", validator, "1001"],
            input=json.dumps(extra_table),
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("native_nft_table_set_invalid", rejected.stderr)

    def test_gateway_policy_identity_covers_native_files_and_missing_drift(self) -> None:
        policy = (ROOT / "scripts/update-policy-hash.sh").read_text()
        gateway = policy.split("  gateway)", 1)[1].split("    ;;", 1)[0]
        native_paths = (
            "/usr/local/libexec/secure-sandbox/shared/native_egress.py",
            "/usr/local/libexec/secure-sandbox/native_guest_control.py",
            "/usr/local/libexec/secure-sandbox/native_opaque_tunnel.py",
            "/etc/systemd/system/native-opaque-tunnel.service",
            "/etc/secure-sandbox/native-egress-installed",
            "/etc/secure-sandbox/native-egress-role",
            "/etc/secure-sandbox/gateway-admin-source-ipv4",
        )
        for path in native_paths:
            self.assertIn(path, gateway)
        self.assertIn(
            "/usr/local/libexec/secure-sandbox/update-policy-hash.sh", policy
        )
        self.assertIn('sha256sum "$file"', policy)
        self.assertIn("printf 'MISSING  %s\\n' \"$file\"", policy)

        def identity(path: Path) -> str:
            if path.is_file():
                line = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n"
            else:
                line = f"MISSING  {path}\n"
            return hashlib.sha256(line.encode("ascii")).hexdigest()

        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "native_opaque_tunnel.py"
            artifact.write_bytes(b"version-one\n")
            original = identity(artifact)
            artifact.write_bytes(b"version-two\n")
            drifted = identity(artifact)
            artifact.unlink()
            missing = identity(artifact)
        self.assertEqual(len({original, drifted, missing}), 3)

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
        self.assertIn(
            "ConditionPathExists=!/var/lib/secure-sandbox/native-vendor/install/"
            "native-research-install.pending.json",
            research,
        )
        self.assertIn(
            "ConditionPathExists=!/var/lib/secure-sandbox/native-egress-control/gateway-install.pending.json",
            gateway,
        )

    def test_guest_actuator_requires_installed_feature_and_current_readback(self) -> None:
        text = (ROOT / "shared/native_guest_control.py").read_text()
        self.assertIn("native_egress.load_install_state(INSTALL_STATE)", text)
        self.assertIn("return execute(role, step, request)", text)
        self.assertIn("native_egress.load_grant", text)
        self.assertIn("conntrack_not_empty", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
