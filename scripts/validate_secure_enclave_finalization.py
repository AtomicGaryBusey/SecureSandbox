#!/usr/bin/env python3
"""Strictly validate restartable Secure Enclave finalization evidence."""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
VERIFIER_KEYS = {
    "acceptance_attempt_id", "acceptance_attempt_number", "acceptance_binding_sha256",
    "approval_attestation_sha256", "approval_id", "consumed_marker_sha256",
    "generation_epoch", "generation_id", "host_receipt_sha256", "host_release_id",
    "prepared_host_boot_sha256", "research_receipt_id", "research_receipt_sha256",
    "research_release_id", "run_id", "schema", "session_id", "status",
    "transaction_id", "verified_at", "verified_host_boot_sha256", "verifier_sha256",
}
NEGATIVE_KEYS = {"approval_id", "replay_rejected", "schema", "status", "verified_at",
                 "wrong_key_rejected"}

class ValidationError(RuntimeError): pass

def canonical_v2(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("ascii")

def load(path: Path) -> dict:
    try: value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("finalization_evidence_invalid") from error
    if not isinstance(value, dict): raise ValidationError("finalization_evidence_invalid")
    return value

def validate_verifier(state: dict, current_boot: str) -> str:
    prepared, research, verifier = (state.get(name) for name in
                                    ("prepared", "research_evidence", "host_acceptance_verifier"))
    if not all(isinstance(value, dict) for value in (prepared, research, verifier)):
        raise ValidationError("finalize_verifier_checkpoint_invalid")
    assert isinstance(prepared, dict) and isinstance(research, dict) and isinstance(verifier, dict)
    if (set(verifier) != VERIFIER_KEYS
            or verifier.get("schema") != "secure-sandbox-execution-approval-acceptance-verifier-v1"
            or verifier.get("status") != "verified"):
        raise ValidationError("finalize_verifier_checkpoint_invalid")
    for name in ("transaction_id", "generation_id", "generation_epoch", "host_release_id",
                 "research_release_id"):
        if verifier.get(name) != prepared.get(name):
            raise ValidationError("finalize_verifier_checkpoint_invalid")
    for name in ("run_id", "session_id", "approval_id", "acceptance_attempt_id",
                 "acceptance_attempt_number", "approval_attestation_sha256",
                 "research_receipt_id", "research_receipt_sha256", "consumed_marker_sha256",
                 "acceptance_binding_sha256"):
        if verifier.get(name) != research.get(name):
            raise ValidationError("finalize_verifier_checkpoint_invalid")
    prepared_boot = state.get("host_boot")
    if not isinstance(prepared_boot, str) or not prepared_boot or not current_boot:
        raise ValidationError("finalize_verifier_checkpoint_invalid")
    digest = lambda value: hashlib.sha256(value.encode("ascii")).hexdigest()
    if (verifier.get("prepared_host_boot_sha256") != digest(prepared_boot)
            or verifier.get("verified_host_boot_sha256") != digest(current_boot)
            or prepared_boot == current_boot):
        raise ValidationError("finalize_verifier_checkpoint_invalid")
    recorded = verifier.get("verifier_sha256")
    unsigned = dict(verifier); unsigned.pop("verifier_sha256")
    if (not isinstance(recorded, str) or not SHA256.fullmatch(recorded)
            or recorded != hashlib.sha256(canonical_v2(unsigned)).hexdigest()):
        raise ValidationError("finalize_verifier_checkpoint_invalid")
    return recorded

def validate_negative(value: dict, approval_id: str) -> None:
    if (set(value) != NEGATIVE_KEYS
            or value.get("schema") != "secure-sandbox-execution-approval-negative-gates-v1"
            or value.get("status") != "verified" or value.get("approval_id") != approval_id
            or value.get("wrong_key_rejected") is not True
            or value.get("replay_rejected") is not True
            or not isinstance(value.get("verified_at"), int)
            or isinstance(value.get("verified_at"), bool) or value["verified_at"] < 1):
        raise ValidationError("finalize_negative_gate_result_invalid")

PUBLIC_RECEIPT_FIELDS = {
    "approval_key_generation_epoch", "approval_key_generation_id",
    "approval_public_key_sha256", "approval_signature_algorithm",
    "authorization_method", "authorization_receipt_sha256",
    "authorization_ui_bundle_sha256", "ceremony", "completed_at",
    "host_release_id", "operation", "request_id", "request_sha256",
    "schema", "status",
}

def validate_cancellation(path: Path, public_receipt_root: Path,
                          host_release_id: str, ui_bundle_sha256: str,
                          generation_id: str, generation_epoch: int,
                          public_key_sha256: str, expected_uid: int = 0) -> dict:
    try: lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValidationError("second_sign_cancellation_invalid") from error
    if not lines or not lines[-1]: raise ValidationError("second_sign_cancellation_invalid")
    try: terminal = json.loads(lines[-1])
    except json.JSONDecodeError as error: raise ValidationError("second_sign_cancellation_invalid") from error
    if terminal != {
        "action":"start_new_request_when_ready",
        "code":"operator_cancelled",
        "operation":"execution-approval-sign",
        "outcome":"cancelled",
        "phase":"ceremony",
        "request_id":terminal.get("request_id"),
        "retry":"new-request",
        "schema":"secure-sandbox-operator-diagnostic-v1",
    } or not isinstance(terminal.get("request_id"), str) \
            or UUID4.fullmatch(terminal["request_id"]) is None:
        raise ValidationError("second_sign_cancellation_invalid")
    try:
        root_info = public_receipt_root.lstat()
        receipt_path = public_receipt_root / f"{terminal['request_id']}.json"
        info = receipt_path.lstat()
        raw = receipt_path.read_bytes()
        receipt = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("second_sign_cancellation_receipt_invalid") from error
    if (not public_receipt_root.is_dir() or public_receipt_root.is_symlink()
            or root_info.st_uid != expected_uid
            or (root_info.st_mode & 0o777) != 0o755
            or not receipt_path.is_file() or receipt_path.is_symlink()
            or info.st_uid != expected_uid or (info.st_mode & 0o777) != 0o644
            or info.st_nlink != 1
            or raw != canonical_v2(receipt) + b"\n"
            or set(receipt) != PUBLIC_RECEIPT_FIELDS
            or receipt.get("schema")
            != "secure-sandbox-operator-cancellation-receipt-v1"
            or receipt.get("status") != "cancelled"
            or receipt.get("request_id") != terminal["request_id"]
            or not isinstance(receipt.get("request_sha256"), str)
            or SHA256.fullmatch(receipt["request_sha256"]) is None
            or receipt.get("operation") != "execution-approval-sign"
            or receipt.get("ceremony") != "cancel-test"
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("host_release_id") != host_release_id
            or receipt.get("authorization_ui_bundle_sha256") != ui_bundle_sha256
            or not isinstance(receipt.get("authorization_receipt_sha256"), str)
            or SHA256.fullmatch(receipt["authorization_receipt_sha256"]) is None
            or receipt.get("approval_key_generation_id") != generation_id
            or receipt.get("approval_key_generation_epoch") != generation_epoch
            or receipt.get("approval_public_key_sha256") != public_key_sha256
            or receipt.get("approval_signature_algorithm")
            != "ecdsa-p256-sha256-x962-low-s"
            or not isinstance(receipt.get("completed_at"), int)
            or isinstance(receipt.get("completed_at"), bool)
            or receipt["completed_at"] < 1):
        raise ValidationError("second_sign_cancellation_receipt_invalid")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="action", required=True)
    verifier = sub.add_parser("verifier"); verifier.add_argument("--state", type=Path, required=True); verifier.add_argument("--current-boot", required=True)
    negative = sub.add_parser("negative"); negative.add_argument("--evidence", type=Path, required=True); negative.add_argument("--approval-id", required=True)
    cancellation = sub.add_parser("cancellation")
    cancellation.add_argument("--stderr", type=Path, required=True)
    cancellation.add_argument("--public-receipt-root", type=Path, required=True)
    cancellation.add_argument("--host-release-id", required=True)
    cancellation.add_argument("--ui-bundle-sha256", required=True)
    cancellation.add_argument("--generation-id", required=True)
    cancellation.add_argument("--generation-epoch", type=int, required=True)
    cancellation.add_argument("--public-key-sha256", required=True)
    args = parser.parse_args()
    if args.action == "verifier": print(validate_verifier(load(args.state), args.current_boot))
    elif args.action == "negative": validate_negative(load(args.evidence), args.approval_id)
    else:
        print(json.dumps(validate_cancellation(
            args.stderr, args.public_receipt_root, args.host_release_id,
            args.ui_bundle_sha256, args.generation_id, args.generation_epoch,
            args.public_key_sha256,
        ), separators=(",", ":"), sort_keys=True))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except ValidationError as error: print(str(error), file=__import__("sys").stderr); raise SystemExit(1)
