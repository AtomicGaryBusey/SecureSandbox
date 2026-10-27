from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AzureEvidencePlaneTests(unittest.TestCase):
    def test_installer_preserves_a_live_metadata_shipper(self):
        text = (ROOT / "scripts/install-azure-shipper.sh").read_text()
        self.assertIn("shipper_was_enabled", text)
        self.assertIn("shipper_was_active", text)
        self.assertIn("systemctl restart azure-shipper.service", text)
        self.assertLess(text.index("shipper_was_active=0"), text.index("install -o root -g root -m 755"))
        self.assertNotIn("systemctl disable --now azure-shipper.service >/dev/null 2>&1 || true\n\necho", text)

    def test_boundary_turns_a_configured_shipper_failure_into_fail(self):
        text = (ROOT / "scripts/verify-boundaries.sh").read_text()
        enabled = 'systemctl is-enabled --quiet azure-shipper'
        active = 'check "Azure off-host shipper is active"'
        self.assertIn(enabled, text)
        self.assertIn(active, text)
        self.assertLess(text.index(enabled), text.index(active))

    def test_cloud_template_has_cost_and_ingestion_safety_controls(self):
        text = (ROOT / "azure/main.bicep").read_text()
        for required in (
            "dailyQuotaGb: json('0.1')",
            "3913510d-42f4-4e42-8a64-420c390055eb",
            "protect-security-evidence",
            "secsandbox",  # the default stable prefix
            "ingestion-health",
            "Microsoft.Consumption/budgets@2024-08-01",
            "Actual_GreaterThanOrEqualTo_80_Percent",
            "Forecasted_GreaterThanOrEqualTo_100_Percent",
        ):
            self.assertIn(required, text)

    def test_deployer_rejects_delete_or_unsupported_what_if(self):
        text = (ROOT / "scripts/deploy-azure-evidence-alerting-ddd.sh").read_text()
        self.assertIn('changeType=="Delete"', text)
        self.assertIn('changeType=="Unsupported"', text)
        self.assertIn("op://Agents/SecureSandbox-Azure-Ingestion/username", text)
        self.assertNotIn("op-agents read 'op://Agents/SecureSandbox-Azure-Ingestion/credential' | cat", text)


if __name__ == "__main__":
    unittest.main()
