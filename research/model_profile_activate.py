#!/usr/bin/env python3
"""Transactional Research-side active model identity record."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


ACTIVE = Path("/etc/secure-sandbox/active-model-profile.json")
BACKUPS = Path("/var/lib/secure-sandbox/model-profile-backups")
LIFECYCLE = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
FAILURE = Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json")
MAX_PLAN = 256 * 1024


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def validate_plan(raw: bytes, now: int | None = None) -> dict:
    if not raw or len(raw) > MAX_PLAN: raise ValueError("model_profile_plan_size_invalid")
    value = json.loads(raw)
    unsigned = {key:item for key, item in value.items() if key != "plan_sha256"}
    current = int(time.time()) if now is None else now
    if (value.get("schema") != "secure-sandbox-model-profile-activation-plan-v1"
            or value.get("plan_sha256") != hashlib.sha256(canonical(unsigned)).hexdigest()
            or not isinstance(value.get("created_at"), int)
            or not isinstance(value.get("expires_at"), int)
            or not value["created_at"] <= current < value["expires_at"]):
        raise ValueError("model_profile_plan_invalid")
    broker = value.get("broker")
    if (not isinstance(broker, dict)
            or broker.get("adapter") not in {
                "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
            or not isinstance(broker.get("allowed_models"), list)
            or len(broker["allowed_models"]) != 1
            or re.fullmatch(r"[a-z][a-z0-9-]{0,47}", str(broker.get("profile_id"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(broker.get("profile_sha256"))) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,47}", str(broker.get("vendor_id"))) is None):
        raise ValueError("model_profile_identity_invalid")
    return value


def atomic(path: Path, value: dict, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical(value) + b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, 0, 0); os.chmod(temporary, mode); os.replace(temporary, path)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def activate(plan: dict) -> dict:
    if LIFECYCLE.exists() or FAILURE.exists(): raise RuntimeError("model_profile_research_not_idle")
    result = subprocess.run(["pgrep", "-x", "claude"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False)
    if result.returncode == 0: raise RuntimeError("model_profile_harness_active")
    activation = plan["activation_id"]; backup = BACKUPS / activation
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700); backup.mkdir(mode=0o700)
    if ACTIVE.exists(): shutil.copy2(ACTIVE, backup / "active-model-profile.json")
    broker = plan["broker"]
    record = {"activated_at":int(time.time()), "activation_id":activation,
              "adapter":broker["adapter"], "mode":broker["mode"],
              "model":broker["allowed_models"][0], "plan_sha256":plan["plan_sha256"],
              "profile_id":broker["profile_id"], "profile_sha256":broker["profile_sha256"],
              "schema":"secure-sandbox-active-model-profile-v1", "status":"verified",
              "vendor_id":broker["vendor_id"]}
    try:
        atomic(ACTIVE, record)
        subprocess.run(["/usr/local/libexec/secure-sandbox/update-policy-hash.sh", "research"],
                       check=True, timeout=30)
    except Exception:
        rollback(activation)
        raise
    return record


def rollback(activation_id: str) -> dict:
    if re.fullmatch(r"[0-9a-f-]{36}", activation_id) is None:
        raise ValueError("model_profile_activation_id_invalid")
    backup = BACKUPS / activation_id / "active-model-profile.json"
    if backup.is_file(): shutil.copy2(backup, ACTIVE)
    else:
        try: ACTIVE.unlink()
        except FileNotFoundError: pass
    subprocess.run(["/usr/local/libexec/secure-sandbox/update-policy-hash.sh", "research"],
                   check=True, timeout=30)
    return {"activation_id":activation_id, "schema":"secure-sandbox-model-profile-rollback-v1",
            "status":"verified"}


def main() -> int:
    if os.geteuid() != 0: raise SystemExit("root required")
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "status":
            value = json.loads(ACTIVE.read_text(encoding="ascii"))
            print(json.dumps(value, separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) == 3 and sys.argv[1] == "rollback":
            print(json.dumps(rollback(sys.argv[2]), separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) != 1: raise ValueError("model_profile_operation_invalid")
        plan = validate_plan(sys.stdin.buffer.read(MAX_PLAN + 1))
        print(json.dumps(activate(plan), separators=(",", ":"), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({"error":str(error), "status":"rejected"}, separators=(",", ":"))); return 1


if __name__ == "__main__": raise SystemExit(main())
