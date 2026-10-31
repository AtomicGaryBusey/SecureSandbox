#!/usr/bin/env python3
"""Transactional Research-side active model identity record."""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path


ACTIVE = Path("/etc/secure-sandbox/active-model-profile.json")
BACKUPS = Path("/var/lib/secure-sandbox/model-profile-backups")
LIFECYCLE = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
FAILURE = Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json")
FENCE = Path("/var/lib/secure-sandbox/model-profile-activation.pending")
LEASE_LOCK = Path("/run/secure-sandbox/run-lease.lock")
RUN_ID = Path("/run/secure-sandbox/run-id")
EVIDENCE_RUN_ID = Path("/run/secure-sandbox/evidence-run-id")
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


def status(path: Path = ACTIVE, trusted_uid: int = 0) -> dict:
    try: metadata = path.lstat()
    except FileNotFoundError:
        return {"schema":"secure-sandbox-active-model-profile-v1",
                "state":"legacy_unbound", "status":"verified"}
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != trusted_uid
            or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o644):
        raise PermissionError("model_profile_active_record_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="ascii") as handle: value = json.load(handle)
    required = {"activated_at", "activation_id", "adapter", "mode", "model",
                "plan_sha256", "profile_id", "profile_sha256", "schema", "status",
                "vendor_id"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("schema") != "secure-sandbox-active-model-profile-v1"
            or value.get("status") != "verified"
            or value.get("adapter") not in {
                "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
            or value.get("mode") not in {"mock", "production"}
            or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", str(value.get("activation_id"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("plan_sha256"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("profile_sha256"))) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,47}", str(value.get("profile_id"))) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,47}", str(value.get("vendor_id"))) is None
            or not isinstance(value.get("model"), str) or not value["model"]
            or not isinstance(value.get("activated_at"), int)):
        raise ValueError("model_profile_active_record_invalid")
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


def fence(activation_id: str, plan_sha256: str) -> dict:
    if (re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", activation_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None):
        raise ValueError("model_profile_fence_identity_invalid")
    LEASE_LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(LEASE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600); fcntl.flock(descriptor, fcntl.LOCK_EX)
        if (LIFECYCLE.exists() or FAILURE.exists()
                or RUN_ID.exists() or EVIDENCE_RUN_ID.exists()):
            raise RuntimeError("model_profile_research_not_idle")
        result = subprocess.run(["pgrep", "-x", "claude"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
        if result.returncode != 1:
            raise RuntimeError("model_profile_harness_state_unavailable")
        record = {"activation_id":activation_id, "plan_sha256":plan_sha256,
                  "schema":"secure-sandbox-model-profile-admission-fence-v1",
                  "status":"fenced"}
        if FENCE.exists():
            if json.loads(FENCE.read_text(encoding="ascii")) != record:
                raise RuntimeError("model_profile_fence_conflict")
        else:
            atomic(FENCE, record, 0o600)
        return record
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)


def require_fence(plan: dict) -> None:
    try: record = json.loads(FENCE.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("model_profile_admission_not_fenced") from error
    if (record.get("activation_id") != plan["activation_id"]
            or record.get("plan_sha256") != plan["plan_sha256"]
            or record.get("status") != "fenced"):
        raise RuntimeError("model_profile_admission_fence_mismatch")


def unfence(activation_id: str) -> dict:
    try: record = json.loads(FENCE.read_text(encoding="ascii"))
    except FileNotFoundError:
        return {"activation_id":activation_id,
                "schema":"secure-sandbox-model-profile-admission-fence-v1",
                "status":"open"}
    if record.get("activation_id") != activation_id:
        raise RuntimeError("model_profile_admission_fence_mismatch")
    FENCE.unlink()
    directory = os.open(FENCE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return {"activation_id":activation_id,
            "schema":"secure-sandbox-model-profile-admission-fence-v1",
            "status":"open"}


def activate(plan: dict) -> dict:
    require_fence(plan)
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
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", activation_id) is None:
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
            value = status()
            print(json.dumps(value, separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) == 4 and sys.argv[1] == "fence":
            print(json.dumps(fence(sys.argv[2], sys.argv[3]), separators=(",", ":"),
                             sort_keys=True)); return 0
        if len(sys.argv) == 3 and sys.argv[1] == "unfence":
            print(json.dumps(unfence(sys.argv[2]), separators=(",", ":"),
                             sort_keys=True)); return 0
        if len(sys.argv) == 3 and sys.argv[1] == "rollback":
            print(json.dumps(rollback(sys.argv[2]), separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) != 1: raise ValueError("model_profile_operation_invalid")
        plan = validate_plan(sys.stdin.buffer.read(MAX_PLAN + 1))
        print(json.dumps(activate(plan), separators=(",", ":"), sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps({"error":str(error), "status":"rejected"}, separators=(",", ":"))); return 1


if __name__ == "__main__": raise SystemExit(main())
