#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUTHORITY_MODULES = (
    "native_vendor_stack.py",
    "native_stack_runtime_binding.py",
    "model_stack_runtime_binding.py",
    "session_context_binding.py",
    "runtime_authority.py",
)


class RuntimeAuthorityDeploymentTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_research_transaction_deploys_and_restores_every_authority_module(self):
        deploy = self.text("scripts/deploy-run-leases.sh")
        installer = self.text("scripts/install-run-leases-research.sh")
        rollback = self.text("research/rollback-run-leases-research.sh")
        for module in AUTHORITY_MODULES:
            self.assertIn(f'shared/{module}', deploy, module)
            self.assertIn(f'/tmp/{module}', installer, module)
            destination = f'/usr/local/libexec/secure-sandbox/shared/{module}'
            self.assertIn(destination, installer, module)
            self.assertIn(destination, rollback, module)
        policy_destination = "/usr/local/libexec/secure-sandbox/update-policy-hash.sh"
        self.assertIn(policy_destination, installer)
        self.assertIn(policy_destination, rollback)
        self.assertLess(
            installer.index(
                "sync -d /var/lib/secure-sandbox/policy-backups/"
                "run-leases-research-install.pending"
            ),
            installer.index(f'install -o root -g root -m 755 "$update_policy" {policy_destination}'),
        )

    def test_research_policy_identity_covers_every_authority_module(self):
        policy = self.text("scripts/update-policy-hash.sh")
        research = policy.split("  research)", 1)[1].split("    ;;", 1)[0]
        for module in AUTHORITY_MODULES:
            self.assertIn(
                f'/usr/local/libexec/secure-sandbox/shared/{module}', research, module
            )

    def test_install_and_rollback_reject_legacy_or_partial_live_state(self):
        for relative in (
            "scripts/install-run-leases-research.sh",
            "research/rollback-run-leases-research.sh",
        ):
            source = self.text(relative)
            gate = source.index("unreconciled Research lease state")
            first_mutation = min(
                position
                for token in ("install -d", "systemctl disable", "cp --no-dereference")
                if (position := source.find(token)) >= 0
            )
            self.assertLess(gate, first_mutation, relative)
            self.assertIn("/run/secure-sandbox/run-lease.json", source, relative)
            self.assertIn("/run/secure-sandbox/run-process.json", source, relative)
            self.assertNotIn(
                "rm -f /run/secure-sandbox/run-lease.json "
                "/run/secure-sandbox/run-process.json",
                source,
                relative,
            )

    def test_host_preflight_rejects_live_research_authority_state(self):
        deploy = self.text("scripts/deploy-run-leases.sh")
        preflight = deploy.split("sandbox-research-admin '", 1)[1].split("'", 1)[0]
        for path in (
            "/run/secure-sandbox/run-lease.json",
            "/run/secure-sandbox/run-process.json",
            "/var/lib/secure-sandbox/run-lifecycle/active.json",
            "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json",
        ):
            self.assertIn(path, preflight)


if __name__ == "__main__":
    unittest.main()
