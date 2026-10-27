#!/usr/bin/env python3
"""Exercise the deployed Research expiry boundary with a real v2 envelope."""
import hashlib, importlib.util, json, os, stat, sys, tempfile, time
from pathlib import Path

BROKER = Path("/usr/local/libexec/secure-sandbox/execution_broker.py")

def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"

def load(path):
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1 or len(raw) > 65536
            or canonical(value) != raw):
        raise RuntimeError("expiry_input_untrusted")
    return value

def verify_expired_approval(approval, envelope, broker, observed_at=None):
    observed_at = int(time.time()) if observed_at is None else observed_at
    if (approval.get("schema") != "secure-sandbox-execution-approval-request-v1"
            or envelope.get("schema") != "secure-sandbox-execution-approval-envelope-v2"
            or envelope.get("attestation", {}).get("approval") != approval
            or not isinstance(approval.get("expires_at"), int)
            or isinstance(approval.get("expires_at"), bool)
            or observed_at <= approval["expires_at"]):
        raise RuntimeError("expiry_request_invalid")
    config = broker.load_config()
    approval_config = config.get("approval", {})
    if (config.get("schema") != "secure-sandbox-execution-broker-v3"
            or approval_config.get("mode") != "active-v2"
            or approval_config.get("minimum_protocol") != 2
            or approval_config.get("minimum_epoch")
            != approval_config.get("generation_epoch")):
        raise RuntimeError("live_approval_configuration_invalid")
    try:
        attestation, attestation_sha256 = broker.verify_v2_envelope(
            envelope, approval, config
        )
    except broker.Rejected as error:
        raise RuntimeError("live_signed_envelope_invalid") from error
    with tempfile.TemporaryDirectory(prefix="expiry-audit-", dir="/run") as directory:
        root = Path(directory)
        for name in ("pending", "claims", "responses", "consumed"):
            (root / name).mkdir(mode=0o700)
        response = {"schema":"secure-sandbox-execution-approval-response-v1",
                    "approval_id":approval["approval_id"], "status":"approved",
                    "envelope":envelope}
        response_path = root / "responses" / f"{approval['approval_id']}.json"
        response_path.write_bytes(canonical(response)); response_path.chmod(0o640)
        try:
            broker.await_operator_approval(approval, config, root=root, trusted_uid=0)
        except broker.Rejected as error:
            if str(error) != "approval_expired": raise
        else:
            raise RuntimeError("expired_approval_accepted")
        if (any((root / "pending").iterdir()) or any((root / "consumed").iterdir())
                or not response_path.is_file()):
            raise RuntimeError("expired_approval_state_changed")
    result = {"schema":"secure-sandbox-live-expiry-evidence-v1", "status":"verified",
            "approval_id":approval["approval_id"], "expires_at":approval["expires_at"],
            "observed_at":observed_at, "generation_id":approval_config["generation_id"],
            "generation_epoch":approval_config["generation_epoch"],
            "public_key_sha256":approval_config["public_key_sha256"],
            "signature_algorithm":approval_config["algorithm"],
            "approval":approval, "envelope":envelope,
            "approval_request_sha256":hashlib.sha256(canonical(approval)).hexdigest(),
            "approval_attestation_sha256":attestation_sha256,
            "signed_envelope_sha256":hashlib.sha256(canonical(envelope)).hexdigest(),
            "verified_attestation_generation_id":attestation["key_generation_id"],
            "verified_attestation_generation_epoch":attestation["key_generation_epoch"],
            "rejection":"approval_expired", "consumed_marker_absent":True,
            "rejection_precedes_target_dispatch":True}
    result["evidence_sha256"] = hashlib.sha256(canonical(result)).hexdigest()
    return result

def load_deployed_broker(path=BROKER):
    spec = importlib.util.spec_from_file_location("deployed_execution_broker", path)
    if spec is None or spec.loader is None: raise RuntimeError("deployed_broker_unavailable")
    broker = importlib.util.module_from_spec(spec)
    module_directory = str(path.parent)
    sys.path.insert(0, module_directory)
    try:
        spec.loader.exec_module(broker)
    finally:
        if sys.path[0] == module_directory:
            sys.path.pop(0)
    return broker

def main():
    if os.geteuid() != 0 or len(sys.argv) != 3: raise RuntimeError("expiry_audit_invalid")
    approval, envelope = load(Path(sys.argv[1])), load(Path(sys.argv[2]))
    broker = load_deployed_broker()
    print(json.dumps(verify_expired_approval(approval, envelope, broker),
                     separators=(",", ":"), sort_keys=True))

if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(json.dumps({"schema":"secure-sandbox-live-expiry-evidence-v1",
                          "status":"rejected", "error":str(error)},
                         separators=(",", ":"), sort_keys=True))
        raise SystemExit(1)
