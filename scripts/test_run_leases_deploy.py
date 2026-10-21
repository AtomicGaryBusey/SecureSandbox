#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


class RunLeaseDeployTests(unittest.TestCase):
    def test_research_transaction_includes_conversation_shipper_policy(self):
        deploy = (REPO / "scripts/deploy-run-leases.sh").read_text(encoding="utf-8")
        install = (REPO / "scripts/install-run-leases-research.sh").read_text(encoding="utf-8")
        rollback = (REPO / "research/rollback-run-leases-research.sh").read_text(
            encoding="utf-8"
        )
        verifier = (REPO / "scripts/verify-boundaries.sh").read_text(encoding="utf-8")
        self.assertIn('"$root_dir/research/conversation-shipper.service"', deploy)
        self.assertIn(
            'install -o root -g root -m 644 "$shipper_unit" '
            "/etc/systemd/system/conversation-shipper.service",
            install,
        )
        self.assertIn("/etc/systemd/system/conversation-shipper.service", rollback)
        self.assertNotIn("systemd-run --wait --pipe --quiet --scope", verifier)

    def test_guest_rollback_scripts_restore_their_own_inode_atomically(self):
        for relative, installed in (
            ("gateway/rollback-run-leases-gateway.sh",
             "/usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh"),
            ("research/rollback-run-leases-research.sh",
             "/usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh"),
        ):
            source = (REPO / relative).read_text(encoding="utf-8")
            self.assertIn(f"self_destination={installed}", source)
            self.assertIn('[[ "$destination" != "$self_destination" ]] || continue', source)
            self.assertIn('mv -f -- "$self_tmp" "$self_destination"', source)
            subprocess.run(["bash", "-n", str(REPO / relative)], check=True)

    def test_second_guest_failure_rolls_back_recorded_first_guest_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            scripts = root / "scripts"; scripts.mkdir(parents=True)
            (root / "config").mkdir()
            source = (REPO / "scripts/deploy-run-leases.sh").read_text(encoding="utf-8")
            source = source.replace("/bin/sync", "/usr/bin/true")
            deploy = scripts / "deploy-run-leases.sh"
            deploy.write_text(source, encoding="utf-8"); deploy.chmod(0o755)
            binary = Path(directory) / "bin"; binary.mkdir()
            log = Path(directory) / "ssh.log"
            (binary / "op-agents").write_text("#!/bin/bash\nprintf 'secret\\n'\n", encoding="utf-8")
            (binary / "scp").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            (binary / "date").write_text("#!/bin/bash\nprintf '20261020T120000Z\\n'\n", encoding="utf-8")
            jq = shutil.which("jq")
            self.assertIsNotNone(jq)
            (binary / "jq").write_text(f"#!/bin/bash\nexec {jq} \"$@\"\n", encoding="utf-8")
            ssh = binary / "ssh"
            ssh.write_text("""#!/bin/bash
case "$*" in *"sudo -S"*) cat >/dev/null || true;; esac
printf '%s\n' "$*" >>"$SSH_LOG"
case "$*" in
  *"install-run-leases-gateway.sh"*)
    backup="$(printf '%s' "$*" | sed -E 's/.*SECURE_SANDBOX_BACKUP_ID=([^ ]+).*/\\1/')"
    printf 'run-leases-gateway:installed:%s\n' "$backup" ;;
  *"install-run-leases-research.sh"*) exit 23 ;;
  *) exit 0 ;;
esac
""", encoding="utf-8")
            for path in binary.iterdir():
                path.chmod(0o755)
            environment = os.environ.copy()
            environment.update({"PATH":f"{binary}:/usr/bin:/bin", "SSH_LOG":str(log)})
            result = subprocess.run([str(deploy)], env=environment, text=True,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            commands = log.read_text(encoding="utf-8")
            self.assertRegex(commands, r"rollback-run-leases-gateway\.sh run-leases-gateway-")
            self.assertFalse((root / "runs/run-leases-deploy.pending.json").exists())


if __name__ == "__main__":
    unittest.main()
