#!/usr/bin/env python3
"""User-facing planner and authorization requester for VM maintenance."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
COORDINATOR = Path("/usr/local/libexec/secure-sandbox-host/current/vm_maintenance")
RESOURCE = "SecureSandbox-Gateway,SecureSandbox-Research,SecureSandbox-Target"
LEGACY_RESOURCE = "SecureSandbox quarantined VM data preservation"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("create", "reprovision", "preserve-legacy"))
    parser.add_argument("--generation")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    parser.add_argument("--purpose")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    if args.operation == "preserve-legacy" and not args.generation:
        parser.error("preserve-legacy requires --generation")
    plan_command = [
        str(COORDINATOR), f"plan-{args.operation}", "--repo", str(repo),
        "--invoking-uid", str(os.geteuid()),
    ]
    if args.generation:
        plan_command.extend(["--generation", args.generation])
    plan_result = subprocess.run(
        plan_command,
        check=False, text=True, stdout=subprocess.PIPE,
    )
    if plan_result.returncode:
        return plan_result.returncode
    plan = json.loads(plan_result.stdout)
    print(json.dumps(plan, indent=2, sort_keys=True))
    if not args.apply:
        print("Dry run only. Re-run with --apply and attributed identity after reviewing this plan.")
        return 0
    if not args.requesting_agent or not args.requesting_session:
        parser.error("--apply requires --requesting-agent and --requesting-session")
    if args.operation == "preserve-legacy":
        parameters = {
            "repo": str(repo), "generation": args.generation,
            "plan_operation": plan["operation"],
            "recovery_transaction_sha256": plan.get("recovery_transaction_sha256"),
            "plan_sha256": plan["plan_sha256"], "prlctl_sha256": plan["prlctl_sha256"],
            "protected_control_client_sha256": plan["protected_control_client_sha256"],
            "protected_ssh_config_sha256": plan["protected_ssh_config_sha256"],
            "legacy_vm_uuid": {role: plan["sources"][role]["legacy_vm_uuid"] for role in ("gateway", "research", "target")},
            "source_tree_sha256": {role: plan["sources"][role]["disk"]["tree_metadata_sha256"] for role in ("gateway", "research", "target")},
            "transport_vm_uuid": {name: plan["transport_vms"][name]["uuid"] for name in ("SecureSandbox-Gateway", "SecureSandbox-Research")},
            "tools": plan["tools"],
        }
        default_purpose = "Preserve legacy VM data and import verified GLM continuity state"
        resource = LEGACY_RESOURCE
    else:
        parameters = {
            "repo": str(repo), "plan_sha256": plan["plan_sha256"],
            "prlctl_sha256": plan["prlctl_sha256"],
            "installer_sha256": plan["installer_sha256"], "seed_sha256": plan["seed_sha256"],
        }
        default_purpose = ("Create the reviewed SecureSandbox VM set" if args.operation == "create"
                           else "Reprovision the reviewed SecureSandbox VM set with recoverable quarantine")
        resource = RESOURCE
    purpose = args.purpose or default_purpose
    command = [
        str(BROKER), "request", "--agent", args.requesting_agent, "--session", args.requesting_session,
        "--purpose", purpose, "--resource", resource, "--operation", f"vm-{args.operation}",
        "--parameters-json", json.dumps(parameters, separators=(",", ":"), sort_keys=True),
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
