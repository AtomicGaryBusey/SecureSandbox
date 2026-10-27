import base64
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_autoinstall_seed", ROOT / "scripts/verify-autoinstall-seed.py")
assert SPEC and SPEC.loader
SEED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEED)


class SeedContentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        for relative in SEED.PAYLOADS.values():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"payload:{relative}\n".encode())
        (self.repo / "runs").mkdir()
        (self.repo / "runs/control_key.pub").write_text("ssh-ed25519 AAAATEST control\n", encoding="ascii")
        for role, relative in SEED.NETPLANS.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"network:\n  version: 2\n  # {role}\n", encoding="ascii")

    def tearDown(self):
        self.temporary.cleanup()

    def content(self, role="gateway"):
        commands = ["    - install -d -m 0700 /target/root/secure-sandbox-control-bootstrap"]
        modes = {
            "privileged_control.py": "0755", "privileged_control_entry.py": "0755",
            "install-privileged-control.sh": "0755", "privileged-control.sudoers": "0600",
            "sshd-control.conf": "0600",
        }
        for name, relative in SEED.PAYLOADS.items():
            encoded = base64.b64encode((self.repo / relative).read_bytes()).decode()
            commands.append(
                f"    - /bin/sh -c \"printf '%s' '{encoded}' | base64 -d > /target/root/secure-sandbox-control-bootstrap/{name} && chmod {modes[name]} /target/root/secure-sandbox-control-bootstrap/{name}\""
            )
        netplan = base64.b64encode((self.repo / SEED.NETPLANS[role]).read_bytes()).decode()
        commands.append(
            f"    - /bin/sh -c \"printf '%s' '{netplan}' | base64 -d > /target/root/secure-sandbox-control-bootstrap/netplan.yaml && chmod 0600 /target/root/secure-sandbox-control-bootstrap/netplan.yaml\""
        )
        key = base64.b64encode((self.repo / "runs/control_key.pub").read_bytes()).decode()
        commands.append(
            f"    - /bin/sh -c \"printf '%s' '{key}' | base64 -d > /target/root/secure-sandbox-control-bootstrap/control_key.pub && chmod 0600 /target/root/secure-sandbox-control-bootstrap/control_key.pub\""
        )
        commands.append(
            "    - /bin/sh -c \"if [ -e /target/etc/netplan/00-installer-config.yaml ]; then [ ! -e /target/etc/netplan/00-installer-config.yaml.installer-backup ] && mv -- /target/etc/netplan/00-installer-config.yaml /target/etc/netplan/00-installer-config.yaml.installer-backup; fi\""
        )
        commands.append(
            "    - install -D -m 0600 /target/root/secure-sandbox-control-bootstrap/netplan.yaml /target/etc/netplan/10-secure-sandbox.yaml"
        )
        commands.append("    - curtin in-target -- netplan generate")
        commands.append(
            f"    - curtin in-target -- /root/secure-sandbox-control-bootstrap/install-privileged-control.sh {role} /root/secure-sandbox-control-bootstrap/control_key.pub"
        )
        commands.append("    - rm -rf /target/root/secure-sandbox-control-bootstrap")
        user = "\n".join([
            "#cloud-config", "autoinstall:", "  version: 1", "  identity:",
            f"    hostname: {SEED.ROLES[role]}", "    username: labadmin",
            "    password: '$6$test$hash'", "  late-commands:", *commands,
            "  shutdown: poweroff", "",
        ]).encode()
        meta = f"instance-id: secure-sandbox-{role}\nlocal-hostname: {SEED.ROLES[role]}\n".encode()
        return meta, user

    def test_exact_generated_shape_is_accepted(self):
        meta, user = self.content()
        SEED.verify_content(self.repo, meta, user, "gateway")

    def test_payload_substitution_and_private_key_are_rejected(self):
        meta, user = self.content()
        altered = re.sub(
            rb"(printf '%s' ')([A-Za-z])",
            lambda match: match.group(1) + (b"A" if match.group(2) != b"A" else b"B"),
            user,
            count=1,
        )
        with self.assertRaises(SEED.SeedFailure):
            SEED.verify_content(self.repo, meta, altered, "gateway")
        with self.assertRaisesRegex(SEED.SeedFailure, "seed_private_key_forbidden"):
            SEED.verify_content(self.repo, meta, user + b"BEGIN OPENSSH PRIVATE KEY\n", "gateway")
        with self.assertRaisesRegex(SEED.SeedFailure, "seed_schema_invalid"):
            SEED.verify_content(
                self.repo,
                meta,
                user.replace(b"  late-commands:", b"  packages:\n    - auditd\n  late-commands:"),
                "gateway",
            )

    def test_role_binding_is_enforced(self):
        meta, user = self.content("gateway")
        with self.assertRaisesRegex(SEED.SeedFailure, "seed_metadata_invalid"):
            SEED.verify_content(self.repo, meta, user, "research")

    def test_netplan_substitution_and_sequence_are_rejected(self):
        meta, user = self.content("research")
        gateway_netplan = base64.b64encode((self.repo / SEED.NETPLANS["gateway"]).read_bytes())
        research_netplan = base64.b64encode((self.repo / SEED.NETPLANS["research"]).read_bytes())
        with self.assertRaisesRegex(SEED.SeedFailure, "seed_payload_mismatch:netplan.yaml"):
            SEED.verify_content(self.repo, meta, user.replace(research_netplan, gateway_netplan), "research")
        with self.assertRaisesRegex(SEED.SeedFailure, "seed_install_sequence_invalid"):
            SEED.verify_content(
                self.repo,
                meta,
                user.replace(b"curtin in-target -- netplan generate", b"curtin in-target -- netplan apply"),
                "research",
            )


if __name__ == "__main__":
    unittest.main()
