#!/usr/bin/env python3
"""Protected Host coordinator for an exact Touch ID-authorized model plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import stat
import tempfile
import time
from pathlib import Path


MAX_PLAN = 256 * 1024
STATE_ROOT = Path("/usr/local/var/lib/secure-sandbox/model-profile-transactions")
RECEIPT = Path("/usr/local/var/lib/secure-sandbox/model-profile/activation.json")
TERMINAL_PHASES = {"committed", "rolled_back"}


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
            or value["expires_at"] - value["created_at"] > 300
            or value.get("current_generation_sha256") != hashlib.sha256(
                canonical(value.get("current"))).hexdigest()):
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


def atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(canonical(value) + b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def private_json(path: Path) -> dict | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise PermissionError("model_profile_host_receipt_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="ascii") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("model_profile_host_receipt_invalid")
    return value


def persist(path: Path, transaction: dict, phase: str, **fields: object) -> None:
    transaction.update(fields)
    transaction["phase"] = phase
    transaction["updated_at"] = int(time.time())
    atomic(path, transaction)


def activation_failure(transaction: dict, error: BaseException | str) -> None:
    code = str(error)
    transaction["activation_error_code"] = code[:240] if code else type(error).__name__


def identity(value: dict) -> dict:
    return {key:value.get(key) for key in (
        "adapter", "mode", "model", "profile_id", "profile_sha256", "vendor_id"
    )}


def authority_snapshot(release: Path, allow_legacy: bool = True) -> tuple[dict, dict, dict]:
    gateway = control(release, "sandbox-gateway-control", "run", "model-profile-status")
    research = control(release, "sandbox-research-control", "run",
                       "model-profile-research-status")
    research_identity = ({"state":"legacy_unbound"}
                         if research == {"schema":"secure-sandbox-active-model-profile-v1",
                                         "state":"legacy_unbound", "status":"verified"}
                         else identity(research))
    if research_identity == {"state":"legacy_unbound"}:
        if not allow_legacy: raise RuntimeError("model_profile_current_generation_mismatch")
    elif identity(gateway) != research_identity:
        raise RuntimeError("model_profile_current_generation_mismatch")
    return {"gateway":identity(gateway), "research":research_identity}, gateway, research


def active_status(release: Path) -> tuple[dict, dict]:
    _, gateway, research = authority_snapshot(release, allow_legacy=False)
    return gateway, research


def recover(transaction: dict, release: Path, path: Path,
            receipt_path: Path = RECEIPT) -> None:
    activation_id = transaction["activation_id"]
    errors = []
    persist(path, transaction, "rolling_back")
    if transaction.get("research_may_have_changed"):
        try:
            control(release, "sandbox-research-control", "run", "model-profile-rollback",
                    [activation_id])
        except Exception as error: errors.append(str(error))
    if transaction.get("gateway_may_have_changed"):
        try:
            control(release, "sandbox-gateway-control", "run", "model-profile-rollback",
                    [activation_id])
        except Exception as error: errors.append(str(error))
    if not errors and transaction.get("prior_identity"):
        try:
            snapshot, _, _ = authority_snapshot(release)
            if snapshot != transaction["prior_authority"]:
                errors.append("model_profile_rollback_readback_mismatch")
        except Exception as error: errors.append(str(error))
    if not errors:
        try:
            prior_receipt = transaction.get("prior_host_receipt")
            if prior_receipt is None:
                try: receipt_path.unlink()
                except FileNotFoundError: pass
            elif isinstance(prior_receipt, dict):
                atomic(receipt_path, prior_receipt)
            else:
                errors.append("model_profile_prior_host_receipt_invalid")
        except Exception as error: errors.append(str(error))
    if not errors:
        for host in ("sandbox-research-control", "sandbox-gateway-control"):
            try:
                control(release, host, "run", "model-profile-unfence", [activation_id])
            except Exception as error: errors.append(str(error))
    if errors:
        persist(path, transaction, "recovery_required", error_codes=errors[:4])
        raise RuntimeError("model_profile_recovery_required")
    persist(path, transaction, "rolled_back", status="verified")


def recover_incomplete(release: Path, state_root: Path = STATE_ROOT,
                       receipt_path: Path = RECEIPT) -> None:
    if not state_root.exists(): return
    records = sorted(state_root.glob("*.json"))
    if len(records) > 64: raise RuntimeError("model_profile_transaction_state_unbounded")
    for path in records:
        value = json.loads(path.read_text(encoding="ascii"))
        if value.get("phase") not in TERMINAL_PHASES:
            recover(value, release, path, receipt_path)


def activate(plan: dict, release: Path, state_root: Path = STATE_ROOT,
             receipt_path: Path = RECEIPT) -> dict:
    recover_incomplete(release, state_root, receipt_path)
    payload = canonical(plan)
    prior_authority, gateway_before, research_before = authority_snapshot(release)
    prior_identity = identity(gateway_before)
    if (prior_authority != plan["current"]
            or hashlib.sha256(canonical(prior_authority)).hexdigest()
            != plan["current_generation_sha256"]):
        raise RuntimeError("model_profile_current_generation_changed")
    transaction = {
        "activation_id":plan["activation_id"], "created_at":int(time.time()),
        "gateway_may_have_changed":False, "plan":plan,
        "plan_sha256":plan["plan_sha256"], "prior_identity":prior_identity,
        "prior_authority":prior_authority,
        "prior_host_receipt":private_json(receipt_path),
        "research_may_have_changed":False,
        "schema":"secure-sandbox-model-profile-host-transaction-v1",
        "status":"pending",
    }
    path = state_root / f"{plan['activation_id']}.json"
    if path.exists(): raise RuntimeError("model_profile_activation_replay")
    persist(path, transaction, "prepared")
    try:
        persist(path, transaction, "fencing")
        control(release, "sandbox-gateway-control", "run", "model-profile-fence",
                [plan["activation_id"], plan["plan_sha256"]])
        control(release, "sandbox-research-control", "run", "model-profile-fence",
                [plan["activation_id"], plan["plan_sha256"]])
        persist(path, transaction, "fenced")
        fenced_authority, _, _ = authority_snapshot(release)
        if fenced_authority != prior_authority:
            raise RuntimeError("model_profile_fenced_generation_changed")
        persist(path, transaction, "gateway_activation_pending", gateway_may_have_changed=True)
        gateway = control(release, "sandbox-gateway-control", "pipe",
                          "model-profile-activate", payload=payload)
        persist(path, transaction, "gateway_activated")
        persist(path, transaction, "research_activation_pending", research_may_have_changed=True)
        research = control(release, "sandbox-research-control", "pipe",
                           "model-profile-activate", payload=payload)
        persist(path, transaction, "research_activated")
    except Exception as error:
        activation_failure(transaction, error)
        recover(transaction, release, path, receipt_path)
        raise
    expected = {"activation_id":plan["activation_id"], "plan_sha256":plan["plan_sha256"],
                "profile_sha256":plan["broker"]["profile_sha256"], "status":"verified"}
    if any(gateway.get(key) != value or research.get(key) != value
           for key, value in expected.items()):
        activation_failure(transaction, "model_profile_readback_mismatch")
        recover(transaction, release, path, receipt_path)
        raise RuntimeError("model_profile_readback_mismatch")
    try:
        gateway_status = control(release, "sandbox-gateway-control", "run",
                                 "model-profile-status")
        research_status = control(release, "sandbox-research-control", "run",
                                  "model-profile-research-status")
        for observed in (gateway_status, research_status):
            if (observed.get("activation_id") != plan["activation_id"]
                    or observed.get("plan_sha256") != plan["plan_sha256"]
                    or observed.get("mode") != plan["broker"]["mode"]
                    or observed.get("profile_id") != plan["broker"]["profile_id"]
                    or observed.get("profile_sha256") != plan["broker"]["profile_sha256"]
                    or observed.get("adapter") != plan["broker"]["adapter"]
                    or observed.get("model") != plan["broker"]["allowed_models"][0]
                    or observed.get("vendor_id") != plan["broker"]["vendor_id"]):
                raise RuntimeError("model_profile_independent_readback_mismatch")
    except Exception as error:
        activation_failure(transaction, error)
        recover(transaction, release, path, receipt_path)
        raise
    receipt = {"activation_id":plan["activation_id"], "gateway":gateway,
            "plan_sha256":plan["plan_sha256"], "research":research,
            "schema":"secure-sandbox-model-profile-host-activation-v1", "status":"verified"}
    persist(path, transaction, "readback_verified")
    persist(path, transaction, "committing")
    atomic(receipt_path, receipt)
    try:
        control(release, "sandbox-research-control", "run", "model-profile-unfence",
                [plan["activation_id"]])
        control(release, "sandbox-gateway-control", "run", "model-profile-unfence",
                [plan["activation_id"]])
    except Exception:
        persist(path, transaction, "recovery_required",
                error_codes=["model_profile_admission_reopen_failed"])
        raise RuntimeError("model_profile_recovery_required")
    persist(path, transaction, "committed", status="verified")
    return receipt


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
