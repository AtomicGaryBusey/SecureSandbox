#!/usr/bin/env python3

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts/ensure-ssh-identities.sh"


class SSHIdentityReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.runs = self.root / "runs"
        self.bin = self.root / "bin"
        self.scripts.mkdir()
        self.runs.mkdir()
        self.bin.mkdir()
        readiness = SOURCE.read_text(encoding="utf-8")
        readiness = readiness.replace("/usr/bin/ssh-keygen", str(self.bin / "ssh-keygen"))
        readiness = readiness.replace("/usr/bin/ssh-add", str(self.bin / "ssh-add"))
        readiness = readiness.replace(
            'provisioning_socket=/tmp/secure-sandbox-ssh-agent.sock',
            f'provisioning_socket={self.root / "provisioning.sock"}',
        ).replace(
            'control_socket=/tmp/secure-sandbox-control-ssh-agent.sock',
            f'control_socket={self.root / "control.sock"}',
        )
        self.readiness = self.scripts / "ensure-ssh-identities.sh"
        self.readiness.write_text(readiness, encoding="utf-8")
        self.readiness.chmod(0o755)
        (self.runs / "provisioning_key.pub").write_text("provisioning\n", encoding="ascii")
        (self.runs / "control_key.pub").write_text("control\n", encoding="ascii")
        self.log = self.root / "load.log"
        (self.scripts / "labctl").write_text(
            '#!/bin/bash\nprintf "%s\\n" "$*" >>"$MOCK_LOAD_LOG"\n'
            'exit 0\n', encoding="utf-8",
        )
        (self.scripts / "labctl").chmod(0o755)
        (self.bin / "ssh-keygen").write_text(
            '#!/bin/bash\ncase "$2" in *provisioning*) echo "256 PROVISIONING key" ;; '
            '*) echo "256 CONTROL key" ;; esac\n', encoding="utf-8",
        )
        (self.bin / "ssh-add").write_text(
            '#!/bin/bash\ncase "$SSH_AUTH_SOCK" in *provisioning*) echo "256 PROVISIONING key" ;; '
            '*) echo "256 CONTROL key" ;; esac\n', encoding="utf-8",
        )
        for path in (self.bin / "ssh-keygen", self.bin / "ssh-add"):
            path.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def run(self, result=None, **extra):
        if result is not None:
            return super().run(result)
        environment = os.environ.copy()
        environment.update({
            "MOCK_LOAD_LOG": str(self.log),
            "MOCK_PROVISIONING_SOCKET": str(self.root / "provisioning.sock"),
            "MOCK_CONTROL_SOCKET": str(self.root / "control.sock"),
        })
        environment.update(extra)
        return subprocess.run(
            [str(self.readiness)], env=environment, text=True, capture_output=True, check=False,
        )

    def make_sockets(self):
        # A FIFO is not enough: readiness deliberately insists on Unix sockets.
        import socket
        sockets = []
        for name in ("provisioning.sock", "control.sock"):
            value = socket.socket(socket.AF_UNIX)
            value.bind(str(self.root / name))
            sockets.append(value)
        return sockets

    def test_matching_identities_require_no_vault_load(self):
        sockets = self.make_sockets()
        try:
            result = self.run()
        finally:
            for value in sockets:
                value.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())

    def test_missing_identities_are_restored_and_rechecked(self):
        # The mock loader cannot create Unix sockets, so pre-create them while
        # making the first check fail via an empty agent listing.
        sockets = self.make_sockets()
        ssh_add = self.bin / "ssh-add"
        ssh_add.write_text(
            '#!/bin/bash\nmarker="$MOCK_LOAD_LOG"\n[[ -s "$marker" ]] || exit 1\n'
            'case "$SSH_AUTH_SOCK" in *provisioning*) echo "256 PROVISIONING key" ;; '
            '*) echo "256 CONTROL key" ;; esac\n', encoding="utf-8",
        )
        ssh_add.chmod(0o755)
        try:
            result = self.run()
        finally:
            for value in sockets:
                value.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "key-load\n")
        self.assertIn("identities restored", result.stderr)

    def test_failed_restoration_fails_closed(self):
        result = self.run(MOCK_RESTORE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("secure_sandbox_ssh_identity_restore_failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
