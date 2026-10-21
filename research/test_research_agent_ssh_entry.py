import unittest
import uuid
from pathlib import Path

import research_agent_ssh_entry as entry


class ResearchAgentSshEntryTests(unittest.TestCase):
    def test_sshd_policy_disables_all_forwarding_for_agent(self):
        policy = Path(__file__).with_name("sshd-agent-fixed-command.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("Match User agent\n", policy)
        self.assertIn("    DisableForwarding yes\n", policy)

    def test_accepts_only_launcher_and_canonical_resume(self):
        self.assertEqual(entry.command(entry.LAUNCHER), [entry.LAUNCHER])
        session = str(uuid.uuid4())
        self.assertEqual(entry.command(f"{entry.LAUNCHER} --resume {session}"),
                         [entry.LAUNCHER, "--resume", session])
        for value in ("", "/bin/sh", entry.LAUNCHER + "; id",
                      entry.LAUNCHER + " --resume invalid", "id -un"):
            with self.assertRaises(ValueError):
                entry.command(value)


if __name__ == "__main__":
    unittest.main()
