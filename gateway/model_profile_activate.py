#!/usr/bin/env python3
"""Transactional Gateway half of a protected model-profile activation."""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import model_broker
import run_lease


BROKER_CONFIG = Path("/etc/secure-sandbox/broker.json")
LEASE_PROFILES = Path("/etc/secure-sandbox/run-lease-profiles.json")
BACKUPS = Path("/var/lib/secure-sandbox/model-profile-backups")
RECEIPT = Path("/var/lib/secure-sandbox/model-profile-activation.json")
FENCE = Path("/var/lib/secure-sandbox/model-profile-activation.pending")
LEASE_LOCK = Path("/var/lib/secure-sandbox/run-leases/counters/.lock")
LEASES = Path("/var/lib/secure-sandbox/run-leases/leases")
MAX_PLAN = 256 * 1024
MAX_CREDENTIAL = 64 * 1024
PRODUCTION_DROPIN = Path("/etc/systemd/system/model-broker.service.d/production.conf")
PRODUCTION_DROPIN_CONTENT = (
    b"[Service]\n"
    b"LoadCredentialEncrypted=provider_token:/etc/credstore.encrypted/model-broker.provider_token\n"
)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def quiet_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
    """Run a helper without contaminating the operation's single JSON result."""
    return subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs
    )


def validated_plan(raw: bytes, now: int | None = None) -> dict:
    if not raw or len(raw) > MAX_PLAN:
        raise ValueError("model_profile_plan_size_invalid")
    value = json.loads(raw)
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-model-profile-activation-plan-v1"):
        raise ValueError("model_profile_plan_invalid")
    claimed = value.get("plan_sha256")
    unsigned = {key: item for key, item in value.items() if key != "plan_sha256"}
    if claimed != hashlib.sha256(canonical(unsigned)).hexdigest():
        raise ValueError("model_profile_plan_digest_mismatch")
    current = int(time.time()) if now is None else now
    if (not isinstance(value.get("created_at"), int)
            or not isinstance(value.get("expires_at"), int)
            or not value["created_at"] <= current < value["expires_at"]
            or value["expires_at"] - value["created_at"] > 300):
        raise ValueError("model_profile_plan_expired")
    run_lease.load_profiles_from_value(value.get("lease_profiles"))
    return value


def atomic(path: Path, value: dict, mode: int, uid: int, gid: int) -> None:
    atomic_bytes(path, canonical(value) + b"\n", mode, uid, gid)


def atomic_bytes(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, uid, gid); os.chmod(temporary, mode); os.replace(temporary, path)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def backup_dropin(backup: Path) -> None:
    try: metadata = PRODUCTION_DROPIN.lstat()
    except FileNotFoundError:
        (backup / "production.conf.absent").touch(mode=0o600)
        return
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
            or metadata.st_mode & 0o022):
        raise PermissionError("model_profile_credential_dropin_untrusted")
    shutil.copy2(PRODUCTION_DROPIN, backup / "production.conf")


def set_dropin(production: bool) -> None:
    if production:
        PRODUCTION_DROPIN.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic_bytes(PRODUCTION_DROPIN, PRODUCTION_DROPIN_CONTENT, 0o644, 0, 0)
    else:
        try: PRODUCTION_DROPIN.unlink()
        except FileNotFoundError: pass


def restore_dropin(backup: Path) -> None:
    if (backup / "production.conf").is_file():
        atomic_bytes(PRODUCTION_DROPIN, (backup / "production.conf").read_bytes(), 0o644, 0, 0)
    elif (backup / "production.conf.absent").is_file():
        set_dropin(False)
    else:
        raise RuntimeError("model_profile_credential_dropin_backup_missing")


def fence(activation_id: str, plan_sha256: str) -> dict:
    import re
    if (re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", activation_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None):
        raise ValueError("model_profile_fence_identity_invalid")
    LEASE_LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(LEASE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600); fcntl.flock(descriptor, fcntl.LOCK_EX)
        if LEASES.exists() and any(LEASES.iterdir()):
            raise RuntimeError("model_profile_active_lease")
        record = {"activation_id":activation_id, "plan_sha256":plan_sha256,
                  "schema":"secure-sandbox-model-profile-admission-fence-v1",
                  "status":"fenced"}
        if FENCE.exists():
            if run_lease.read_json(FENCE) != record:
                raise RuntimeError("model_profile_fence_conflict")
        else:
            atomic(FENCE, record, 0o600, 0, 0)
        return record
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)


def require_fence(plan: dict) -> None:
    try: record = run_lease.read_json(FENCE)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("model_profile_admission_not_fenced") from error
    if (record.get("activation_id") != plan["activation_id"]
            or record.get("plan_sha256") != plan["plan_sha256"]
            or record.get("status") != "fenced"):
        raise RuntimeError("model_profile_admission_fence_mismatch")


def unfence(activation_id: str) -> dict:
    try: record = run_lease.read_json(FENCE)
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
    if any(BROKER_CONFIG.parent.joinpath("run-leases", name).exists() for name in ("install.pending",)):
        raise RuntimeError("model_profile_activation_blocked")
    leases = Path("/var/lib/secure-sandbox/run-leases/leases")
    if leases.exists() and any(leases.iterdir()):
        raise RuntimeError("model_profile_active_lease")
    current = run_lease.read_json(BROKER_CONFIG)
    immutable = {key: current[key] for key in (
        "listen_address", "listen_port", "server_certificate", "server_private_key",
        "client_ca_certificate", "allowed_client_sha256", "lease_state_directory",
    )}
    config = {**immutable, **plan["broker"], "session_id": plan["activation_id"]}
    model_broker.validate_config(config)
    if config["mode"] == "production":
        staged = Path("/etc/credstore.encrypted") / f"model-profile-{config['profile_sha256']}.credential"
        metadata = staged.with_suffix(".json")
        try: staged_record = json.loads(metadata.read_text(encoding="ascii"))
        except (OSError, json.JSONDecodeError): staged_record = None
        if (not staged.is_file() or not isinstance(staged_record, dict)
                or staged_record.get("profile_sha256") != config["profile_sha256"]
                or staged_record.get("credential_reference_sha256") != plan["credential_reference_sha256"]
                or staged_record.get("credential_scheme") != config["credential_scheme"]):
            raise RuntimeError("model_profile_credential_not_staged")
    generation = plan["activation_id"]
    backup = BACKUPS / generation
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup.mkdir(mode=0o700)
    shutil.copy2(BROKER_CONFIG, backup / "broker.json")
    shutil.copy2(LEASE_PROFILES, backup / "run-lease-profiles.json")
    shutil.copy2("/etc/nftables.conf", backup / "nftables.conf")
    backup_dropin(backup)
    if RECEIPT.exists(): shutil.copy2(RECEIPT, backup / "activation-receipt.json")
    active_credential = Path("/etc/credstore.encrypted/model-broker.provider_token")
    if active_credential.exists(): shutil.copy2(active_credential, backup / "provider_token")
    broker_stat = BROKER_CONFIG.stat(); lease_stat = LEASE_PROFILES.stat()
    try:
        atomic(BROKER_CONFIG, config, 0o640, broker_stat.st_uid, broker_stat.st_gid)
        atomic(LEASE_PROFILES, plan["lease_profiles"], 0o644,
               lease_stat.st_uid, lease_stat.st_gid)
        if config["mode"] == "production":
            staged = Path("/etc/credstore.encrypted") / f"model-profile-{config['profile_sha256']}.credential"
            shutil.copy2(staged, active_credential); os.chown(active_credential, 0, 0)
            os.chmod(active_credential, 0o600)
        else:
            try: active_credential.unlink()
            except FileNotFoundError: pass
        set_dropin(config["mode"] == "production")
        quiet_run(["systemctl", "daemon-reload"], check=True, timeout=30)
        quiet_run(["/usr/local/libexec/secure-sandbox/render_gateway_firewall.py",
                   "--broker-config", str(BROKER_CONFIG), "--azure-config",
                   "/etc/secure-sandbox/azure-shipper.json", "--archive-config",
                   "/etc/secure-sandbox/conversation-azure.json", "--output",
                   "/etc/nftables.conf.new"], check=True, timeout=30)
        quiet_run(["nft", "-c", "-f", "/etc/nftables.conf.new"], check=True, timeout=10)
        os.replace("/etc/nftables.conf.new", "/etc/nftables.conf")
        quiet_run(["nft", "-f", "/etc/nftables.conf"], check=True, timeout=10)
        quiet_run(["systemctl", "restart", "model-broker.service"], check=True, timeout=30)
        quiet_run(["systemctl", "is-active", "--quiet", "model-broker.service"], check=True)
        quiet_run(["/usr/local/libexec/secure-sandbox/update-policy-hash.sh", "gateway"],
                  check=True, timeout=30)
    except Exception:
        shutil.copy2(backup / "broker.json", BROKER_CONFIG)
        shutil.copy2(backup / "run-lease-profiles.json", LEASE_PROFILES)
        shutil.copy2(backup / "nftables.conf", "/etc/nftables.conf")
        if (backup / "provider_token").exists(): shutil.copy2(backup / "provider_token", active_credential)
        else:
            try: active_credential.unlink()
            except FileNotFoundError: pass
        restore_dropin(backup)
        quiet_run(["systemctl", "daemon-reload"], check=False)
        quiet_run(["nft", "-f", "/etc/nftables.conf"], check=False)
        quiet_run(["systemctl", "restart", "model-broker.service"], check=False)
        quiet_run(["/usr/local/libexec/secure-sandbox/update-policy-hash.sh", "gateway"],
                  check=False)
        if (backup / "activation-receipt.json").exists():
            shutil.copy2(backup / "activation-receipt.json", RECEIPT)
        else:
            try: RECEIPT.unlink()
            except FileNotFoundError: pass
        raise
    receipt = {"activated_at":int(time.time()), "activation_id":generation,
               "adapter":config["adapter"], "model":config["allowed_models"][0],
               "mode":config["mode"], "plan_sha256":plan["plan_sha256"],
               "profile_id":config["profile_id"], "profile_sha256":config["profile_sha256"],
               "schema":"secure-sandbox-model-profile-activation-receipt-v1",
               "status":"verified", "vendor_id":config["vendor_id"]}
    atomic(RECEIPT, receipt, 0o644, 0, 0)
    return receipt


def stage_credential(profile_sha256: str, reference_sha256: str,
                     scheme: str, raw: bytes) -> dict:
    import re
    if (re.fullmatch(r"[0-9a-f]{64}", profile_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", reference_sha256) is None
            or scheme not in {"bearer", "anthropic-api-key", "google-service-account-json"}
            or not raw or len(raw) > MAX_CREDENTIAL or b"\x00" in raw):
        raise ValueError("model_profile_credential_invalid")
    directory = Path("/etc/credstore.encrypted"); directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"model-profile-{profile_sha256}.credential"
    quiet_run(["systemd-creds", "encrypt", "--with-key=host",
               "--name=provider_token", "-", str(destination)],
              input=raw, check=True, timeout=30)
    os.chown(destination, 0, 0); os.chmod(destination, 0o600)
    atomic(destination.with_suffix(".json"), {
        "credential_reference_sha256":reference_sha256, "credential_scheme":scheme,
        "profile_sha256":profile_sha256,
        "schema":"secure-sandbox-model-profile-staged-credential-v1",
    }, 0o600, 0, 0)
    return {"profile_sha256":profile_sha256,
            "schema":"secure-sandbox-model-profile-credential-stage-v1", "status":"staged"}


def rollback(activation_id: str) -> dict:
    if __import__("re").fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", activation_id) is None:
        raise ValueError("model_profile_activation_id_invalid")
    backup = BACKUPS / activation_id
    if not backup.is_dir(): raise ValueError("model_profile_backup_missing")
    shutil.copy2(backup / "broker.json", BROKER_CONFIG)
    shutil.copy2(backup / "run-lease-profiles.json", LEASE_PROFILES)
    shutil.copy2(backup / "nftables.conf", "/etc/nftables.conf")
    restore_dropin(backup)
    active_credential = Path("/etc/credstore.encrypted/model-broker.provider_token")
    if (backup / "provider_token").exists(): shutil.copy2(backup / "provider_token", active_credential)
    else:
        try: active_credential.unlink()
        except FileNotFoundError: pass
    quiet_run(["systemctl", "daemon-reload"], check=True, timeout=30)
    quiet_run(["nft", "-f", "/etc/nftables.conf"], check=True, timeout=10)
    quiet_run(["systemctl", "restart", "model-broker.service"], check=True, timeout=30)
    quiet_run(["/usr/local/libexec/secure-sandbox/update-policy-hash.sh", "gateway"],
              check=True, timeout=30)
    if (backup / "activation-receipt.json").exists():
        shutil.copy2(backup / "activation-receipt.json", RECEIPT)
    else:
        try: RECEIPT.unlink()
        except FileNotFoundError: pass
    return {"activation_id":activation_id, "schema":"secure-sandbox-model-profile-rollback-v1",
            "status":"verified"}


def main() -> int:
    if os.geteuid() != 0: raise SystemExit("root required")
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "stage-credential":
            raw = sys.stdin.buffer.read(MAX_CREDENTIAL + 1)
            print(json.dumps(stage_credential(sys.argv[2], sys.argv[3], sys.argv[4], raw),
                             separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) == 4 and sys.argv[1] == "fence":
            print(json.dumps(fence(sys.argv[2], sys.argv[3]), separators=(",", ":"),
                             sort_keys=True)); return 0
        if len(sys.argv) == 3 and sys.argv[1] == "unfence":
            print(json.dumps(unfence(sys.argv[2]), separators=(",", ":"),
                             sort_keys=True)); return 0
        if len(sys.argv) == 3 and sys.argv[1] == "rollback":
            print(json.dumps(rollback(sys.argv[2]), separators=(",", ":"), sort_keys=True)); return 0
        if len(sys.argv) != 1: raise ValueError("model_profile_operation_invalid")
        plan = validated_plan(sys.stdin.buffer.read(MAX_PLAN + 1))
        print(json.dumps(activate(plan), separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"error":str(error), "status":"rejected"}, separators=(",", ":")))
        return 1


if __name__ == "__main__": raise SystemExit(main())
