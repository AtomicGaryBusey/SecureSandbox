#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from shared.harness_runtime_binding import make_binding as make_harness_binding
from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    make_binding as make_model_stack_binding,
    make_brokered_binding,
)
from shared.runtime_authority import make_binding as make_runtime_authority
from shared.session_context_binding import make_binding as make_session_context_binding


ROOT = Path(__file__).resolve().parent.parent
LABCTL = ROOT / "scripts/labctl"


class LabctlLeaseV3Tests(unittest.TestCase):
    run_id = "11111111-1111-4111-8111-111111111111"
    lease_id = "22222222-2222-4222-8222-222222222222"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.capture = self.root / "renew.json"
        self.lease_path = self.root / "lease.json"
        self.lifecycle_path = self.root / "lifecycle.json"
        self.gateway_status_path = self.root / "gateway-status.json"
        self.control = self.root / "control-client"
        self.control.write_text(
            """#!/bin/bash
set -euo pipefail
host="$4"; mode="$5"; operation="$6"
if [[ "$host:$mode:$operation" == "sandbox-gateway-control:run:lease-renew" ]]; then
  cat "$MOCK_LEASE"
elif [[ "$host:$mode:$operation" == "sandbox-research-control:pipe:watchdog-renew-v3" ]]; then
  cat >"$MOCK_CAPTURE"
  printf '%s\n' '{"schema":"secure-sandbox-research-run-renew-result-v3","status":"verified"}'
elif [[ "$host:$mode:$operation" == "sandbox-research-control:run:watchdog-status" ]]; then
  cat "$MOCK_LIFECYCLE"
elif [[ "$host:$mode:$operation" == "sandbox-gateway-control:run:lease-status" ]]; then
  cat "$MOCK_GATEWAY_STATUS"
else
  exit 3
fi
""",
            encoding="ascii",
        )
        self.control.chmod(0o755)
        source = LABCTL.read_text(encoding="utf-8")
        source = source.replace(
            'root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"',
            f'root_dir="{ROOT}"',
        ).replace(
            'control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"',
            f'control_client="{self.control}"',
        )
        self.labctl = self.root / "labctl"
        self.labctl.write_text(source, encoding="utf-8")
        self.labctl.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lease(self) -> dict:
        now = int(time.time())
        harness = make_harness_binding(
            harness_id="claude-code", generation_id="1" * 64,
            manifest_sha256="2" * 64, executable_sha256="3" * 64,
            inventory_sha256="4" * 64, adapter_id="claude-core-v1",
            adapter_sha256="5" * 64,
        )
        brokered = make_brokered_binding(
            adapter="anthropic-messages-v1", model="abliterated-model-large-v2",
            profile_id="abliterated-glm", profile_sha256="6" * 64,
            provider_mode="mock", vendor_id="abliteration",
        )
        context = make_session_context_binding(
            session_id="33333333-3333-4333-8333-333333333333",
            source_id=None, source_manifest_sha256=None,
            persona_sha256="7" * 64, tool_catalog_sha256="8" * 64,
            extension_set_sha256="9" * 64,
        )
        authority = make_runtime_authority(
            model_stack_binding=make_model_stack_binding(BROKERED_MODE, brokered),
            session_context_binding=context, harness_binding=harness,
        )
        return {
            "schema": "secure-sandbox-run-lease-v3", "lease_id": self.lease_id,
            "run_id": self.run_id, "profile": "standard", "issued_at": now - 300,
            "expires_at": now + 600, "maximum_expires_at": now + 3600,
            "runtime_authority": authority,
            "brokered_transport": {
                "schema": "secure-sandbox-brokered-run-transport-v1",
                "relay_sha256": "a" * 64, "policy_sha256": "b" * 64,
            },
            "limits": {"max_requests": 10, "max_input_tokens": 1000,
                       "max_output_tokens": 1000, "max_cost_microusd": 1000},
            "pricing": {"input_microusd_per_million_tokens": 1,
                        "output_microusd_per_million_tokens": 1},
            "renewals": 1,
        }

    def run_renew(self, lease: dict) -> subprocess.CompletedProcess[str]:
        self.lease_path.write_text(json.dumps(lease), encoding="ascii")
        environment = os.environ.copy()
        environment.update({"MOCK_LEASE": str(self.lease_path),
                            "MOCK_CAPTURE": str(self.capture),
                            "MOCK_LIFECYCLE": str(self.lifecycle_path),
                            "MOCK_GATEWAY_STATUS": str(self.gateway_status_path)})
        return subprocess.run(
            [str(self.labctl), "lease", "renew", self.run_id, "300"],
            env=environment, text=True, capture_output=True, check=False,
        )

    def run_reconcile_plan(self, summary: dict) -> subprocess.CompletedProcess[str]:
        self.lifecycle_path.write_text(json.dumps({
            "schema": "secure-sandbox-run-lifecycle-v2",
            "phase": "local_closed", "run_id": self.run_id,
            "lease_id": self.lease_id,
        }), encoding="ascii")
        self.gateway_status_path.write_text(json.dumps({
            "lease": summary["lease"], "counters": summary["final_counters"],
            "summary": summary,
        }), encoding="ascii")
        environment = os.environ.copy()
        environment.update({"MOCK_LEASE": str(self.lease_path),
                            "MOCK_CAPTURE": str(self.capture),
                            "MOCK_LIFECYCLE": str(self.lifecycle_path),
                            "MOCK_GATEWAY_STATUS": str(self.gateway_status_path)})
        return subprocess.run(
            [str(self.labctl), "lease", "reconcile-plan", self.run_id],
            env=environment, text=True, capture_output=True, check=False,
        )

    def test_renew_pipes_exact_canonical_gateway_lease(self) -> None:
        lease = self.lease()
        result = self.run_renew(lease)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), lease)
        payload = self.capture.read_bytes()
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(
            payload,
            (json.dumps(
                {"schema": "secure-sandbox-research-run-renew-v3",
                 "gateway_lease": lease},
                allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            ) + "\n").encode("ascii"),
        )

    def test_renew_rejects_mutated_authority_before_research_pipe(self) -> None:
        lease = self.lease()
        lease["runtime_authority"]["session_context_binding"]["session_id"] = self.run_id
        result = self.run_renew(lease)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Gateway renewal response", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_renew_rejects_legacy_and_inexact_transport_before_research_pipe(self) -> None:
        legacy = self.lease()
        legacy["schema"] = "secure-sandbox-run-lease-v2"
        result = self.run_renew(legacy)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())

        inexact = self.lease()
        inexact["brokered_transport"]["unexpected"] = "forbidden"
        result = self.run_renew(inexact)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())

    def test_removed_argv_renew_operation_is_absent(self) -> None:
        source = LABCTL.read_text(encoding="utf-8")
        self.assertNotIn("watchdog-renew \"$run_id\"", source)
        self.assertIn("watchdog-renew-v3", source)

    def test_reconcile_plan_requires_exact_v2_summary_containing_v3_lease(self) -> None:
        lease = self.lease()
        counters = {
            "schema": "secure-sandbox-run-lease-counter-v1",
            "lease_id": self.lease_id, "run_id": self.run_id,
            "requests": 0, "input_tokens": 0, "output_tokens": 0,
            "cost_microusd": 0, "reservations": {},
            "settled_reservations": [], "updated_at": lease["expires_at"],
        }
        summary = {
            "schema": "secure-sandbox-run-lease-summary-v2", "lease": lease,
            "final_counters": counters, "finalized_at": lease["expires_at"],
            "reason": "completed",
        }
        result = self.run_reconcile_plan(summary)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        canonical = (json.dumps(summary, allow_nan=False, ensure_ascii=True,
                                separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
        self.assertEqual(plan, {
            "schema": "secure-sandbox-lease-reconcile-plan-v1",
            "run_id": self.run_id, "lease_id": self.lease_id,
            "gateway_summary_sha256": hashlib.sha256(canonical).hexdigest(),
        })

        legacy = json.loads(json.dumps(summary))
        legacy["schema"] = "secure-sandbox-run-lease-summary-v1"
        rejected = self.run_reconcile_plan(legacy)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not bind the expected run and lease", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
