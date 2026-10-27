#!/usr/bin/env python3
"""Read-only completion audit for the Secure Enclave execution-approval DDD."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "secure-sandbox-secure-enclave-ddd-checkpoint-v1"
class AuditError(RuntimeError):
    pass


def read_user_json(path: Path, uid: int, mode: int = 0o600) -> dict[str, Any]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"untrusted_json:{path.name}") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode or not isinstance(value, dict)):
        raise AuditError(f"untrusted_json:{path.name}")
    return value


def require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AuditError(f"{label}_invalid")
    return value


def require_equal(left: object, right: object, label: str) -> None:
    if left != right:
        raise AuditError(f"{label}_mismatch")


def canonical_v2(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AuditError("canonical_json_invalid") from error
    if b"\n" in encoded or b"\r" in encoded:
        raise AuditError("canonical_json_invalid")
    return encoded


def verify_cold_boot_evidence(state: dict[str, Any], prepared: dict[str, Any],
                              bridge: bool, protected_digest: str,
                              bridge_ui_bundle_sha256: str) -> None:
    evidence = state.get("cold_boot_evidence")
    if (not isinstance(evidence, dict)
            or evidence.get("schema") != "secure-sandbox-host-reboot-acceptance-v1"
            or evidence.get("bridge_predecessor_exception") is not bridge
            or not isinstance(evidence.get("prior_boot"), str)
            or not evidence["prior_boot"]
            or not isinstance(evidence.get("rebooted_boot"), str)
            or not evidence["rebooted_boot"]
            or evidence["prior_boot"] == evidence["rebooted_boot"]):
        raise AuditError("cold_boot_evidence_invalid")
    boundary = require_digest(evidence.get("boundary_sha256"), "cold_boot_boundary")
    require_equal(
        state.get("post_reboot_boundary_sha256"), boundary,
        "cold_boot_boundary_record",
    )
    recorded = require_digest(
        state.get("cold_boot_acceptance_sha256"), "cold_boot_evidence"
    )
    require_equal(recorded, protected_digest, "protected_cold_boot_evidence")
    expected = hashlib.sha256(canonical_v2(evidence)).hexdigest()
    require_equal(recorded, expected, "cold_boot_evidence_digest")
    proof = evidence.get("checkpoint_host_verification")
    proof_digest = evidence.get("checkpoint_host_verification_sha256")
    research_proof = evidence.get("checkpoint_research_verification")
    research_proof_digest = evidence.get(
        "checkpoint_research_verification_sha256"
    )
    successor_deployment = evidence.get("bridge_successor_deployment")
    successor_release = evidence.get("bridge_successor_release_id")
    successor_deployment_digest = evidence.get(
        "bridge_successor_deployment_sha256"
    )
    if not bridge:
        if (proof is not None or proof_digest is not None
                or research_proof is not None
                or research_proof_digest is not None
                or successor_deployment is not None
                or successor_release is not None
                or successor_deployment_digest is not None):
            raise AuditError("unexpected_checkpoint_release_verification")
        return
    if (not isinstance(proof, dict)
            or proof.get("schema")
            != "secure-sandbox-checkpoint-host-release-verification-v1"
            or proof.get("status") != "verified"):
        raise AuditError("checkpoint_host_verification_invalid")
    for name in (
        "release_id", "generation_id", "generation_epoch", "public_key_sha256",
    ):
        expected_value = prepared.get(
            "host_release_id" if name == "release_id" else name
        )
        require_equal(proof.get(name), expected_value, f"checkpoint_{name}")
    require_equal(
        proof.get("authorization_ui_bundle_sha256"), bridge_ui_bundle_sha256,
        "checkpoint_ui_bundle",
    )
    require_digest(proof.get("launcher_sha256"), "checkpoint_launcher")
    require_equal(
        require_digest(proof_digest, "checkpoint_host_verification"),
        hashlib.sha256(canonical_v2(proof) + b"\n").hexdigest(),
        "checkpoint_host_verification_digest",
    )
    if (not isinstance(research_proof, dict)
            or research_proof.get("schema")
            != "secure-sandbox-checkpoint-research-boundary-verification-v1"
            or research_proof.get("status") != "verified"
            or research_proof.get("receipt_boundary_verified") is not True):
        raise AuditError("checkpoint_research_verification_invalid")
    require_equal(
        research_proof.get("release_id"), prepared.get("research_release_id"),
        "checkpoint_research_release",
    )
    for name in (
        "execution_broker_sha256", "source_execution_broker_sha256",
        "transition_sha256", "watchdog_sha256",
    ):
        require_digest(research_proof.get(name), f"checkpoint_research_{name}")
    if (research_proof["execution_broker_sha256"]
            == research_proof["source_execution_broker_sha256"]):
        raise AuditError("checkpoint_research_bridge_exception_not_proven")
    require_equal(
        require_digest(
            research_proof_digest, "checkpoint_research_verification"
        ),
        hashlib.sha256(canonical_v2(research_proof) + b"\n").hexdigest(),
        "checkpoint_research_verification_digest",
    )
    if (not isinstance(successor_deployment, dict)
            or successor_deployment.get("schema")
            != "secure-sandbox-host-controller-release-v1"
            or successor_deployment.get("status")
            not in ("deployed", "already_deployed")):
        raise AuditError("bridge_successor_deployment_invalid")
    successor_release = require_digest(
        successor_release, "bridge_successor_release"
    )
    require_equal(
        successor_deployment.get("release_id"), successor_release,
        "bridge_successor_deployment_release",
    )
    if successor_release == prepared.get("host_release_id"):
        raise AuditError("bridge_successor_not_advanced")
    require_equal(
        require_digest(
            successor_deployment_digest, "bridge_successor_deployment"
        ),
        hashlib.sha256(canonical_v2(successor_deployment) + b"\n").hexdigest(),
        "bridge_successor_deployment_digest",
    )


def verify_acceptance_evidence(state: dict[str, Any], prepared: dict[str, Any],
                               protected_verifier: dict[str, Any]) -> None:
    research = state.get("research_evidence")
    verifier = state.get("host_acceptance_verifier")
    negatives = state.get("negative_gates")
    if (not isinstance(research, dict)
            or research.get("schema")
            != "secure-sandbox-execution-approval-acceptance-evidence-v1"
            or research.get("status") != "verified"
            or not isinstance(verifier, dict)
            or verifier.get("schema")
            != "secure-sandbox-execution-approval-acceptance-verifier-v1"
            or verifier.get("status") != "verified"
            or not isinstance(negatives, dict)
            or negatives.get("schema")
            != "secure-sandbox-execution-approval-negative-gates-v1"
            or negatives.get("status") != "verified"
            or negatives.get("wrong_key_rejected") is not True
            or negatives.get("replay_rejected") is not True):
        raise AuditError("execution_evidence_invalid")
    for name in (
        "transaction_id", "generation_id", "generation_epoch", "host_release_id",
        "research_release_id",
    ):
        require_equal(research.get(name), prepared.get(name), f"research_{name}")
        require_equal(verifier.get(name), prepared.get(name), f"verifier_{name}")
    for name in (
        "run_id", "session_id", "approval_id", "acceptance_attempt_id",
        "acceptance_attempt_number", "approval_attestation_sha256",
        "research_receipt_id", "research_receipt_sha256",
        "consumed_marker_sha256", "acceptance_binding_sha256",
    ):
        require_equal(verifier.get(name), research.get(name), f"verifier_{name}")
    verifier_digest = require_digest(verifier.get("verifier_sha256"), "verifier")
    unsigned = dict(verifier)
    unsigned.pop("verifier_sha256", None)
    require_equal(
        verifier_digest, hashlib.sha256(canonical_v2(unsigned)).hexdigest(),
        "verifier_digest",
    )
    require_equal(verifier, protected_verifier, "protected_acceptance_verifier")


def verify_bridge_commit_repairs(state: dict[str, Any],
                                 source_release_id: str) -> None:
    current = require_digest(
        state.get("bridge_successor_release_id"), "bridge_successor_release"
    )
    repairs = state.get("bridge_commit_repairs", [])
    if not isinstance(repairs, list) or len(repairs) > 3:
        raise AuditError("bridge_commit_repair_chain_invalid")
    required = {
        "schema", "reason", "from_release_id", "to_release_id", "deployment",
        "deployment_sha256", "protected_cold_boot_acceptance_sha256",
        "recorded_at",
    }
    for repair in repairs:
        if (not isinstance(repair, dict) or set(repair) != required
                or repair.get("schema")
                != "secure-sandbox-execution-approval-bridge-commit-repair-v1"
                or repair.get("reason")
                != "empty_legacy_completion_directory_mode_migration"
                or repair.get("from_release_id") != current
                or repair.get("to_release_id") == current
                or repair.get("protected_cold_boot_acceptance_sha256")
                != state.get("cold_boot_acceptance_sha256")
                or not isinstance(repair.get("recorded_at"), int)
                or isinstance(repair.get("recorded_at"), bool)
                or repair["recorded_at"] < 1):
            raise AuditError("bridge_commit_repair_chain_invalid")
        deployment = repair.get("deployment")
        if (not isinstance(deployment, dict)
                or deployment.get("schema")
                != "secure-sandbox-host-controller-release-v1"
                or deployment.get("status") not in {"deployed", "already_deployed"}
                or deployment.get("release_id") != repair.get("to_release_id")):
            raise AuditError("bridge_commit_repair_deployment_invalid")
        require_equal(
            require_digest(
                repair.get("deployment_sha256"),
                "bridge_commit_repair_deployment",
            ),
            hashlib.sha256(canonical_v2(deployment) + b"\n").hexdigest(),
            "bridge_commit_repair_deployment_digest",
        )
        current = require_digest(
            repair.get("to_release_id"), "bridge_commit_repair_release"
        )
    require_equal(current, source_release_id, "bridge_commit_repair_source_release")


def verify_live_expiry_evidence(value: dict[str, Any],
                                prepared: dict[str, Any], broker: Any,
                                trusted_uid: int) -> None:
    recorded_evidence_digest = value.get("evidence_sha256")
    unsigned_evidence = dict(value)
    unsigned_evidence.pop("evidence_sha256", None)
    if (value.get("schema") != "secure-sandbox-live-expiry-evidence-v1"
            or value.get("status") != "verified"
            or value.get("rejection") != "approval_expired"
            or value.get("consumed_marker_absent") is not True
            or value.get("rejection_precedes_target_dispatch") is not True
            or recorded_evidence_digest
            != hashlib.sha256(canonical_v2(unsigned_evidence) + b"\n").hexdigest()):
        raise AuditError("live_expiry_evidence_invalid")
    try:
        approval_id = uuid.UUID(value["approval_id"])
    except (KeyError, TypeError, ValueError) as error:
        raise AuditError("live_expiry_evidence_invalid") from error
    if approval_id.version != 4 or str(approval_id) != value["approval_id"]:
        raise AuditError("live_expiry_evidence_invalid")
    expires_at = value.get("expires_at")
    observed_at = value.get("observed_at")
    if (not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or not isinstance(observed_at, int) or isinstance(observed_at, bool)
            or observed_at <= expires_at):
        raise AuditError("live_expiry_evidence_invalid")
    for name in (
        "generation_id", "generation_epoch", "public_key_sha256",
    ):
        require_equal(value.get(name), prepared.get(name), f"live_expiry_{name}")
    require_equal(
        value.get("signature_algorithm"), prepared.get("algorithm"),
        "live_expiry_algorithm",
    )
    approval = value.get("approval")
    envelope = value.get("envelope")
    if (not isinstance(approval, dict) or not isinstance(envelope, dict)
            or approval.get("approval_id") != value.get("approval_id")
            or approval.get("expires_at") != expires_at):
        raise AuditError("live_expiry_signed_request_invalid")
    approval_digest = hashlib.sha256(canonical_v2(approval) + b"\n").hexdigest()
    require_equal(
        value.get("approval_request_sha256"), approval_digest,
        "live_expiry_approval_request",
    )
    envelope_digest = hashlib.sha256(canonical_v2(envelope) + b"\n").hexdigest()
    require_equal(
        value.get("signed_envelope_sha256"), envelope_digest,
        "live_expiry_signed_envelope",
    )
    config = {
        "schema":"secure-sandbox-execution-broker-v3",
        "approval":{
            "mode":"active-v2", "minimum_protocol":2,
            "minimum_epoch":prepared["generation_epoch"],
            "generation_id":prepared["generation_id"],
            "generation_epoch":prepared["generation_epoch"],
            "algorithm":prepared["algorithm"],
            "public_key_sha256":prepared["public_key_sha256"],
            "public_key_spki_der_b64":prepared["public_key_spki_der_b64"],
        },
    }
    try:
        attestation, attestation_digest = broker.verify_v2_envelope(
            envelope, approval, config
        )
    except Exception as error:
        raise AuditError("live_expiry_signature_invalid") from error
    require_equal(
        value.get("approval_attestation_sha256"), attestation_digest,
        "live_expiry_attestation",
    )
    require_equal(
        value.get("verified_attestation_generation_id"),
        attestation.get("key_generation_id"), "live_expiry_attestation_generation",
    )
    require_equal(
        value.get("verified_attestation_generation_epoch"),
        attestation.get("key_generation_epoch"), "live_expiry_attestation_epoch",
    )
    response = {
        "schema":"secure-sandbox-execution-approval-response-v1",
        "approval_id":approval["approval_id"], "status":"approved",
        "envelope":envelope,
    }
    with tempfile.TemporaryDirectory(prefix="completion-expiry-replay-") as directory:
        root = Path(directory)
        for name in ("pending", "claims", "responses", "consumed"):
            (root / name).mkdir(mode=0o700)
        response_path = root / "responses" / f"{approval['approval_id']}.json"
        response_path.write_bytes(canonical_v2(response) + b"\n")
        response_path.chmod(0o640)
        try:
            broker.await_operator_approval(
                approval, config, root=root, trusted_uid=trusted_uid
            )
        except broker.Rejected as error:
            if str(error) != "approval_expired":
                raise AuditError("live_expiry_replay_wrong_rejection") from error
        else:
            raise AuditError("live_expiry_replay_accepted")
        if (any((root / "pending").iterdir())
                or any((root / "consumed").iterdir())
                or not response_path.is_file()):
            raise AuditError("live_expiry_replay_state_changed")


def completion_status(broker: Path, transaction_id: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(broker), "execution-approval-completion-status", "--transaction-id",
         transaction_id],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=15,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise AuditError("protected_completion_invalid")
    return value


def verify_completion_status(value: dict[str, Any], prepared: dict[str, Any],
                             expected_status: str) -> dict[str, Any]:
    if (value.get("schema")
            != "secure-sandbox-execution-approval-completion-receipt-v1"
            or value.get("status") != expected_status):
        raise AuditError("protected_completion_invalid")
    for name in (
        "transaction_id", "generation_id", "generation_epoch", "algorithm",
        "public_key_sha256", "operator_uid", "host_release_id",
        "research_release_id", "previous_generation_id", "previous_generation_epoch",
    ):
        require_equal(value.get(name), prepared.get(name), f"protected_{name}")
    for name in (
        "research_activation_sha256", "cold_boot_acceptance_sha256",
        "acceptance_verifier_sha256", "acceptance_binding_sha256",
    ):
        require_digest(value.get(name), f"protected_{name}")
    verifier = value.get("acceptance_verifier")
    if not isinstance(verifier, dict):
        raise AuditError("protected_completion_invalid")
    require_equal(
        verifier.get("verifier_sha256"), value["acceptance_verifier_sha256"],
        "protected_verifier_digest",
    )
    recorded = require_digest(value.get("receipt_sha256"), "completion_receipt")
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    require_equal(
        recorded, hashlib.sha256(canonical_v2(unsigned)).hexdigest(),
        "completion_receipt_digest",
    )
    return verifier


def load_support(repo: Path):
    path = repo / "scripts/secure_enclave_ddd_support.py"
    spec = importlib.util.spec_from_file_location("secure_enclave_ddd_support", path)
    if spec is None or spec.loader is None:
        raise AuditError("support_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_research_broker(repo: Path):
    path = repo / "research/execution_broker.py"
    spec = importlib.util.spec_from_file_location(
        "secure_enclave_completion_execution_broker", path
    )
    if spec is None or spec.loader is None:
        raise AuditError("research_broker_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    module_directory = str(path.parent)
    sys.path.insert(0, module_directory)
    try:
        spec.loader.exec_module(module)
    finally:
        if sys.path[0] == module_directory:
            sys.path.pop(0)
    return module


def load_keychain_isolation_probe(repo: Path):
    path = repo / "scripts/verify_live_secure_enclave_keychain_isolation.py"
    spec = importlib.util.spec_from_file_location(
        "secure_enclave_keychain_isolation_probe", path
    )
    if spec is None or spec.loader is None:
        raise AuditError("keychain_isolation_probe_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_research_release_id(repo: Path) -> str:
    combined = b"".join(
        hashlib.sha256((repo / relative).read_bytes()).digest()
        for relative in (
            "research/execution_broker.py",
            "research/execution_approval_transition.py",
            "research/run_lease_watchdog.py",
        )
    )
    return hashlib.sha256(combined).hexdigest()


def verify_live_touchid_peer_isolation(
    socket_path: Path = Path("/var/run/secure-sandbox-authorization.sock"),
    socket_factory: Any = socket.socket,
) -> None:
    def exact(connection: socket.socket, count: int) -> bytes:
        chunks: list[bytes] = []
        remaining = count
        while remaining:
            chunk = connection.recv(remaining)
            if not chunk:
                raise AuditError("touchid_peer_rejection_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    connection = socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(10)
        connection.connect(str(socket_path))
        connection.shutdown(socket.SHUT_WR)
        magic, status, stdout_size, stderr_size = struct.unpack(
            "!4sIII", exact(connection, 16)
        )
        if (magic != b"SSAR" or status != 1 or stdout_size != 0
                or not 1 <= stderr_size <= 65536):
            raise AuditError("touchid_peer_rejection_invalid")
        stderr = exact(connection, stderr_size)
        if connection.recv(1):
            raise AuditError("touchid_peer_rejection_trailing_data")
    finally:
        connection.close()
    try:
        value = json.loads(stderr)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError("touchid_peer_rejection_invalid") from error
    if (value != {
        "schema":"secure-sandbox-touchid-approval-v1",
        "status":"rejected", "error":"touchid_peer_identity_mismatch",
    } or canonical_v2(value) + b"\n" != stderr):
        raise AuditError("touchid_peer_rejection_invalid")


def audit(repo: Path, install_root: Path, state_dir: Path,
          history_root: Path, uid: int,
          software_keys: tuple[Path, Path] | None = None,
          bridge_ui_bundle_sha256: str = "",
          require_live_expiry: bool = False,
          require_live_peer_isolation: bool = False,
          require_live_keychain_isolation: bool = False) -> dict[str, Any]:
    require_digest(bridge_ui_bundle_sha256, "bridge_ui_bundle")
    state = read_user_json(state_dir / "state.json", uid)
    if state.get("schema") != SCHEMA or state.get("stage") != "complete":
        raise AuditError("completion_checkpoint_missing")
    prepared = state.get("prepared")
    if not isinstance(prepared, dict):
        raise AuditError("prepared_record_missing")
    generation_id = prepared.get("generation_id")
    generation_epoch = prepared.get("generation_epoch")
    previous_generation_id = prepared.get("previous_generation_id")
    previous_generation_epoch = prepared.get("previous_generation_epoch")
    if (not isinstance(generation_id, str)
            or not isinstance(previous_generation_id, str)
            or not isinstance(generation_epoch, int) or isinstance(generation_epoch, bool)
            or generation_epoch < 2
            or not isinstance(previous_generation_epoch, int)
            or isinstance(previous_generation_epoch, bool)
            or previous_generation_epoch < 1
            or generation_epoch <= previous_generation_epoch):
        raise AuditError("forward_rotation_not_proven")
    public_key_sha256 = require_digest(
        prepared.get("public_key_sha256"), "public_key_sha256"
    )
    require_equal(
        prepared.get("algorithm"), "ecdsa-p256-sha256-x962-low-s",
        "prepared_algorithm",
    )
    host_release_id = require_digest(prepared.get("host_release_id"), "host_release_id")
    research_release_id = require_digest(
        prepared.get("research_release_id"), "research_release_id"
    )
    require_equal(
        source_research_release_id(repo), research_release_id,
        "source_research_release",
    )

    broker = install_root / "current/authorization_broker"
    completed = subprocess.run(
        [str(broker), "execution-approval-public-key"], check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=15, env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    active = json.loads(completed.stdout)
    if (not isinstance(active, dict)
            or active.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or active.get("status") != "active"
            or active.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"):
        raise AuditError("live_identity_invalid")
    for name, expected in (
        ("generation_id", generation_id), ("generation_epoch", generation_epoch),
        ("public_key_sha256", public_key_sha256),
    ):
        require_equal(active.get(name), expected, f"active_{name}")

    support = load_support(repo)
    source_release_id = support.source_host_release_id(repo)
    host_verification = support.verify_postactivation_host_release(
        repo, install_root, Path("/usr/local/bin/secure-sandbox-claude")
    )
    if (not isinstance(host_verification, dict)
            or host_verification.get("status") != "verified"):
        raise AuditError("host_release_verification_invalid")
    require_equal(
        host_verification.get("release_id"), source_release_id, "source_release"
    )
    require_equal(host_release_id, source_release_id, "generation_host_release")
    protected_final = completion_status(broker, prepared["transaction_id"])
    final_verifier = verify_completion_status(
        protected_final, prepared, "software_retired"
    )

    handoff = read_user_json(history_root / "forward-rotation-handoff.json", uid)
    if handoff.get("schema") != "secure-sandbox-secure-enclave-forward-rotation-handoff-v1":
        raise AuditError("rotation_handoff_invalid")
    require_equal(
        handoff.get("source_host_release_id"), source_release_id,
        "rotation_source_release",
    )
    require_equal(
        handoff.get("bridge_generation_id"), previous_generation_id,
        "bridge_generation",
    )
    bridge_transaction = handoff.get("bridge_transaction_id")
    if not isinstance(bridge_transaction, str):
        raise AuditError("bridge_transaction_invalid")
    bridge = read_user_json(
        history_root / f"{bridge_transaction}.bridge/state.json", uid
    )
    if bridge.get("schema") != SCHEMA or bridge.get("stage") != "bridge_committed":
        raise AuditError("bridge_checkpoint_invalid")
    bridge_prepared = bridge.get("prepared")
    if not isinstance(bridge_prepared, dict):
        raise AuditError("bridge_checkpoint_invalid")
    require_equal(
        bridge_prepared.get("generation_id"), previous_generation_id,
        "bridge_checkpoint_generation",
    )
    require_equal(
        bridge_prepared.get("generation_epoch"), previous_generation_epoch,
        "bridge_checkpoint_epoch",
    )
    require_equal(
        bridge_prepared.get("transaction_id"), bridge_transaction,
        "bridge_checkpoint_transaction",
    )
    protected_bridge = completion_status(broker, bridge_transaction)
    bridge_verifier = verify_completion_status(
        protected_bridge, bridge_prepared, "committed"
    )
    verify_acceptance_evidence(bridge, bridge_prepared, bridge_verifier)
    verify_cold_boot_evidence(
        bridge, bridge_prepared, True,
        protected_bridge["cold_boot_acceptance_sha256"],
        bridge_ui_bundle_sha256,
    )
    bridge_cold = bridge["cold_boot_evidence"]
    require_equal(
        bridge.get("bridge_successor_release_id"),
        bridge_cold.get("bridge_successor_release_id"),
        "bridge_successor_checkpoint_release",
    )
    require_equal(
        bridge.get("bridge_successor_deployment"),
        bridge_cold.get("bridge_successor_deployment"),
        "bridge_successor_checkpoint_deployment",
    )
    verify_bridge_commit_repairs(bridge, source_release_id)

    cancellation = state.get("cancellation_evidence")
    if (not isinstance(cancellation, dict)
            or cancellation.get("schema")
            != "secure-sandbox-execution-approval-cancellation-evidence-v1"
            or cancellation.get("status") != "cancelled"
            or cancellation.get("stdout_empty") is not True):
        raise AuditError("cancellation_evidence_invalid")
    for name, expected in (
        ("generation_id", generation_id), ("generation_epoch", generation_epoch),
        ("public_key_sha256", public_key_sha256),
    ):
        require_equal(cancellation.get(name), expected, f"cancellation_{name}")
    require_digest(cancellation.get("request_sha256"), "cancellation_request_sha256")
    require_digest(cancellation.get("stderr_sha256"), "cancellation_stderr_sha256")

    retirement = state.get("software_retirement")
    if (not isinstance(retirement, dict)
            or retirement.get("schema")
            != "secure-sandbox-execution-approval-migration-result-v2"
            or retirement.get("status") != "software_retired"):
        raise AuditError("software_retirement_invalid")
    for name, expected in (
        ("transaction_id", prepared.get("transaction_id")),
        ("generation_id", generation_id), ("generation_epoch", generation_epoch),
    ):
        require_equal(retirement.get(name), expected, f"retirement_{name}")
    obsolete_keys = software_keys or (
        Path("/usr/local/var/lib/secure-sandbox/execution-approval/id_ed25519"),
        Path("/usr/local/var/lib/secure-sandbox/execution-approval/id_ed25519.pub"),
    )
    for obsolete in obsolete_keys:
        try:
            obsolete.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AuditError("software_key_absence_unverifiable") from error
        else:
            raise AuditError("software_key_still_present")

    verify_acceptance_evidence(state, prepared, final_verifier)
    verify_cold_boot_evidence(
        state, prepared, False, protected_final["cold_boot_acceptance_sha256"],
        bridge_ui_bundle_sha256,
    )
    require_digest(state.get("final_boundary_sha256"), "final_boundary")
    live_expiry_verified = False
    if require_live_expiry:
        expiry = read_user_json(state_dir / "live-expiry-evidence.json", uid)
        verify_live_expiry_evidence(
            expiry, prepared, load_research_broker(repo), uid
        )
        live_expiry_verified = True
    live_peer_isolation_verified = False
    if require_live_peer_isolation:
        verify_live_touchid_peer_isolation()
        live_peer_isolation_verified = True
    live_keychain_isolation_verified = False
    if require_live_keychain_isolation:
        keychain_result = load_keychain_isolation_probe(repo).probe(generation_id)
        if (keychain_result.get("status") != "verified"
                or keychain_result.get("generation_id") != generation_id
                or keychain_result.get("lookup_status") != -34018
                or keychain_result.get("lookup_result_absent") is not True
                or keychain_result.get("helper_signature") != "adhoc"
                or keychain_result.get("unentitled_lookup_status") != -34018
                or keychain_result.get("forged_access_group_present") is not True
                or keychain_result.get("forged_launch_signal") != 9
                or keychain_result.get("authentication_ui") != "fail"):
            raise AuditError("live_keychain_isolation_invalid")
        live_keychain_isolation_verified = True

    return {
        "schema":"secure-sandbox-secure-enclave-ddd-completion-audit-v1",
        "status":"verified",
        "generation_id":generation_id,
        "generation_epoch":generation_epoch,
        "previous_generation_id":previous_generation_id,
        "previous_generation_epoch":previous_generation_epoch,
        "algorithm":active["algorithm"],
        "public_key_sha256":public_key_sha256,
        "host_release_id":host_release_id,
        "research_release_id":research_release_id,
        "bridge_transaction_id":bridge_transaction,
        "software_key_absent":True,
        "cancellation_verified":True,
        "approved_execution_verified":True,
        "wrong_key_rejected":True,
        "replay_rejected":True,
        "live_expiry_verified":live_expiry_verified,
        "live_peer_isolation_verified":live_peer_isolation_verified,
        "live_keychain_isolation_verified":live_keychain_isolation_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--install-root", type=Path,
        default=Path("/usr/local/libexec/secure-sandbox-host"),
    )
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--history-root", type=Path)
    parser.add_argument("--require-live-expiry", action="store_true")
    parser.add_argument("--require-live-peer-isolation", action="store_true")
    parser.add_argument("--require-live-keychain-isolation", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    state_dir = args.state_dir or repo / ".private/secure-enclave-execution-approval-ddd"
    history_root = args.history_root or repo / ".private/secure-enclave-execution-approval-ddd-history"
    try:
        local_config = read_user_json(
            repo / ".private/secure-enclave-ddd.json", os.geteuid()
        )
        bridge_ui_bundle_sha256 = local_config.get(
            "legacy_launchservices_ui_bundle_sha256"
        )
        result = audit(
            repo, args.install_root, state_dir, history_root, os.geteuid(),
            bridge_ui_bundle_sha256=bridge_ui_bundle_sha256,
            require_live_expiry=args.require_live_expiry,
            require_live_peer_isolation=args.require_live_peer_isolation,
            require_live_keychain_isolation=args.require_live_keychain_isolation,
        )
    except (AuditError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({
            "schema":"secure-sandbox-secure-enclave-ddd-completion-audit-v1",
            "status":"rejected", "error":str(error),
        }, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
