#!/usr/bin/env python3
"""Protected Host coordinator for an exact Touch ID-authorized model plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


MAX_PLAN = 256 * 1024


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def validate_plan(raw: str, now: int | None = None) -> dict:
    if not raw or len(raw.encode("utf-8")) > MAX_PLAN: raise ValueError("model_profile_plan_size_invalid")
    value = json.loads(raw)
    unsigned = {key:item for key, item in value.items() if key != "plan_sha256"}
    current = int(time.time()) if now is None else now
    if (value.get("schema") != "secure-sandbox-model-profile-activation-plan-v1"
            or value.get("plan_sha256") != hashlib.sha256(canonical(unsigned)).hexdigest()
            or not isinstance(value.get("created_at"), int)
            or not isinstance(value.get("expires_at"), int)
            or not value["created_at"] <= current < value["expires_at"]
            or value["expires_at"] - value["created_at"] > 300):
        raise ValueError("model_profile_plan_invalid")
    return value


def control(release: Path, host: str, kind: str, operation: str,
            arguments: list[str] | None = None, payload: bytes | None = None) -> dict:
    command = [str(release / "control_client"), "client", "--ssh-config",
               str(release / "ssh_config"), host, kind, operation, *(arguments or [])]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False, timeout=90)
    if result.returncode:
        raise RuntimeError(f"model_profile_{operation}_failed")
    return json.loads(result.stdout or b"{}")


def activate(plan: dict, release: Path) -> dict:
    payload = canonical(plan)
    gateway_done = False
    try:
        gateway = control(release, "sandbox-gateway-control", "pipe",
                          "model-profile-activate", payload=payload)
        gateway_done = True
        research = control(release, "sandbox-research-control", "pipe",
                           "model-profile-activate", payload=payload)
    except Exception:
        if gateway_done:
            control(release, "sandbox-gateway-control", "run", "model-profile-rollback",
                    [plan["activation_id"]])
        raise
    expected = {"activation_id":plan["activation_id"], "plan_sha256":plan["plan_sha256"],
                "profile_sha256":plan["broker"]["profile_sha256"], "status":"verified"}
    if any(gateway.get(key) != value or research.get(key) != value
           for key, value in expected.items()):
        control(release, "sandbox-research-control", "run", "model-profile-rollback",
                [plan["activation_id"]])
        control(release, "sandbox-gateway-control", "run", "model-profile-rollback",
                [plan["activation_id"]])
        raise RuntimeError("model_profile_readback_mismatch")
    gateway_status = control(release, "sandbox-gateway-control", "run",
                             "model-profile-status")
    research_status = control(release, "sandbox-research-control", "run",
                              "model-profile-research-status")
    for observed in (gateway_status, research_status):
        if (observed.get("profile_id") != plan["broker"]["profile_id"]
                or observed.get("profile_sha256") != plan["broker"]["profile_sha256"]
                or observed.get("adapter") != plan["broker"]["adapter"]
                or observed.get("model") != plan["broker"]["allowed_models"][0]
                or observed.get("vendor_id") != plan["broker"]["vendor_id"]):
            control(release, "sandbox-research-control", "run", "model-profile-rollback",
                    [plan["activation_id"]])
            control(release, "sandbox-gateway-control", "run", "model-profile-rollback",
                    [plan["activation_id"]])
            raise RuntimeError("model_profile_independent_readback_mismatch")
    return {"activation_id":plan["activation_id"], "gateway":gateway,
            "plan_sha256":plan["plan_sha256"], "research":research,
            "schema":"secure-sandbox-model-profile-host-activation-v1", "status":"verified"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("activate", nargs="?")
    parser.add_argument("--plan-json", required=True)
    args = parser.parse_args()
    release = Path(__file__).resolve().parent
    try:
        plan = validate_plan(args.plan_json)
        print(json.dumps(activate(plan, release), separators=(",", ":"), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({"error":str(error), "status":"rejected"}, separators=(",", ":"))); return 1


if __name__ == "__main__": raise SystemExit(main())
