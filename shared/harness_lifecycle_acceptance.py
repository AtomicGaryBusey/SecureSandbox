#!/usr/bin/env python3
"""Fail-closed contracts for disposable-Mac harness lifecycle acceptance.

The candidate harness is never an evidence authority.  This module validates a
complete campaign assembled from bounded observations emitted by fixed outer
collectors.  It deliberately does not execute lifecycle mutations.
"""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


CAMPAIGN_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-campaign-v4"
ENROLLMENT_SCHEMA = "secure-sandbox-disposable-mac-enrollment-v1"
PROCEDURE_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-procedure-v1"
EVIDENCE_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-evidence-v3"
OBSERVATION_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-observation-v4"
RECEIPT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-receipt-v4"
EXPORT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-export-v4"
VERDICT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-verdict-v4"
SUITE_ID = "secure-sandbox-disposable-mac-harness-lifecycle-v4"
PROTECTED_DRIVER_MANIFEST_SCHEMA = (
    "secure-sandbox-harness-lifecycle-acceptance-driver-install-v1"
)
MAX_CAMPAIGN_SECONDS = 14 * 86400
MAX_OBSERVATION_SECONDS = 3600
MAX_DETAIL_BYTES = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
CASE_ID = re.compile(r"[a-z][a-z0-9-]{0,95}")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,191}")
ARTIFACT_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")

DRIVER_ENTRYPOINTS = {
    "clean-machine-bootstrap": (
        "scripts/harness-lifecycle-acceptance-bootstrap.py",
    ),
    "host-provenance-fixture": (
        "scripts/harness-lifecycle-acceptance-provenance.py",
        "scripts/install-harness-lifecycle-acceptance-host.sh",
    ),
    "host-archive-fixture": (
        "scripts/harness-lifecycle-acceptance-archive.py",
        "scripts/install-harness-lifecycle-acceptance-host.sh",
    ),
    "research-qualification-fixture": (
        "scripts/harness-lifecycle-acceptance-qualification.py",
        "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
        "scripts/harness-lifecycle-acceptance-qualification-observe.py",
        "scripts/install-harness-lifecycle-acceptance-qualification.sh",
    ),
    "touchid-authorization-fixture": (
        "scripts/harness-lifecycle-acceptance-authorization.py",
    ),
    "bound-session-runtime-fixture": (
        "scripts/harness-lifecycle-acceptance-runtime.py",
    ),
    "protected-management-fixture": (
        "scripts/harness-lifecycle-acceptance-management.py",
    ),
    "research-recovery-fixture": (
        "scripts/harness-lifecycle-acceptance-supervisor.py",
        "scripts/harness-lifecycle-acceptance-recovery.py",
        "scripts/harness-lifecycle-acceptance-recovery-observe.py",
        "scripts/install-harness-lifecycle-acceptance-recovery.sh",
    ),
    "cold-boot-readback-fixture": (
        "scripts/harness-lifecycle-acceptance-cold-boot.py",
    ),
    "independent-export-fixture": (
        "scripts/harness-lifecycle-acceptance-export.py",
    ),
}
PROTECTED_DRIVER_PAYLOADS = {
    driver: tuple(
        path for path in entrypoints
        if not path.startswith("scripts/install-")
    )
    for driver, entrypoints in DRIVER_ENTRYPOINTS.items()
}
PROTECTED_DRIVER_PAYLOADS["host-provenance-fixture"] = (
    "scripts/harness-lifecycle-acceptance-provenance.py",
    "scripts/harness-lifecycle-acceptance-observe.py",
    "scripts/harness-lifecycle-acceptance-supervisor.py",
    "scripts/harness-lifecycle-acceptance.py",
    "shared/harness_lifecycle.py",
    "shared/harness_lifecycle_acceptance.py",
    "shared/harness_lifecycle_provenance_fixture.py",
)
PROTECTED_DRIVER_PAYLOADS["host-archive-fixture"] = (
    "scripts/harness-lifecycle-acceptance-archive.py",
    "scripts/harness-lifecycle-acceptance-observe.py",
    "scripts/harness-lifecycle-acceptance-supervisor.py",
    "scripts/harness-lifecycle-acceptance.py",
    "shared/harness_archive_preflight.py",
    "shared/harness_lifecycle.py",
    "shared/harness_lifecycle_acceptance.py",
    "shared/harness_lifecycle_archive_fixture.py",
    "shared/harness_lifecycle_provenance_fixture.py",
)
PROTECTED_DRIVER_PAYLOADS["research-qualification-fixture"] = (
    "scripts/harness-lifecycle-acceptance-qualification.py",
    "shared/harness_lifecycle_acceptance.py",
    "shared/harness_lifecycle_qualification_fixture.py",
    "shared/harness_qualification.py",
    "shared/harness_qualification_fixture.py",
    "shared/claude_core_adapter.py",
    "fixtures/harness-qualification/malicious_harness.py",
)
PROTECTED_DRIVER_PAYLOADS["research-recovery-fixture"] = (
    "scripts/harness-lifecycle-acceptance-supervisor.py",
    "scripts/harness-lifecycle-acceptance-recovery.py",
    "scripts/harness-lifecycle-acceptance-recovery-observe.py",
    "shared/harness_archive_preflight.py",
    "shared/harness_generation_store.py",
    "shared/harness_lifecycle.py",
    "shared/harness_lifecycle_acceptance.py",
    "shared/harness_lifecycle_acceptance_fixture.py",
    "shared/harness_runtime_binding.py",
    "shared/privileged_workflow.py",
)
PHYSICAL_DRIVER_BLOCKERS: dict[str, str] = {}


class AcceptanceError(RuntimeError):
    """Stable, content-free acceptance failure."""


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected: str
    evidence_kinds: tuple[str, ...]
    requires_touch_id: bool = False
    requires_reboot: bool = False
    destructive: bool = False


def _cases() -> tuple[Case, ...]:
    cases = [
        Case("bootstrap-clean-install", "bootstrap", "passed",
             ("host-install-readback", "research-install-readback", "boundary-readback"), destructive=True),
        Case("bootstrap-no-production-material", "bootstrap", "passed",
             ("production-material-scan", "machine-enrollment")),
        Case("acquire-clean-carrier", "provenance", "passed", ("acquisition-receipt", "quarantine-readback")),
        Case("reject-redirect", "provenance", "rejected", ("acquisition-rejection",)),
        Case("reject-oversized-artifact", "provenance", "rejected", ("acquisition-rejection",)),
        Case("reject-artifact-substitution", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-bad-signature", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-unknown-signer", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-revoked-signer", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-expired-signer", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-broken-chain", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-stale-metadata", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-future-metadata", "provenance", "rejected", ("verification-rejection",)),
        Case("reject-release-rollback", "provenance", "rejected", ("floor-rejection",)),
        Case("reject-release-freeze", "provenance", "rejected", ("freshness-rejection",)),
        Case("accept-release-fast-forward", "provenance", "passed", ("verification-receipt",)),
        Case("reject-release-equivocation", "provenance", "rejected", ("equivocation-rejection",)),
        Case("reject-inconsistent-provenance", "provenance", "rejected", ("verification-rejection",)),
    ]
    for attack in (
        "absolute-path", "dotdot", "symlink", "hardlink", "special-file", "sparse-file",
        "duplicate-path", "case-fold-collision", "unicode-collision", "archive-bomb",
        "alternate-stream", "trailing-data",
    ):
        cases.append(Case(f"reject-archive-{attack}", "archive", "rejected", ("archive-rejection",)))
    cases.extend((
        Case("qualification-no-preexecution", "qualification", "passed", ("execution-observation", "quarantine-readback")),
        Case("qualification-zero-production-authority", "qualification", "passed", ("authority-readback", "production-material-scan")),
        Case("qualification-deny-updater", "qualification", "rejected", ("isolation-observation",)),
        Case("qualification-deny-login", "qualification", "rejected", ("isolation-observation",)),
        Case("qualification-deny-model-switch", "qualification", "rejected", ("isolation-observation",)),
        Case("qualification-deny-tool-switch", "qualification", "rejected", ("isolation-observation",)),
        Case("qualification-deny-extension", "qualification", "rejected", ("isolation-observation",)),
        Case("qualification-deny-child-process", "qualification", "rejected", ("process-observation",)),
        Case("qualification-deny-credential", "qualification", "rejected", ("credential-observation",)),
        Case("qualification-deny-network", "qualification", "rejected", ("network-observation",)),
        Case("touchid-approve-exact-plan", "authorization", "passed", ("broker-receipt", "plan-readback"), requires_touch_id=True),
        Case("touchid-cancel", "authorization", "rejected", ("broker-rejection", "selector-readback"), requires_touch_id=True),
        Case("touchid-expired-plan", "authorization", "rejected", ("broker-rejection", "selector-readback"), requires_touch_id=True),
        Case("touchid-replay", "authorization", "rejected", ("broker-rejection", "selector-readback"), requires_touch_id=True),
        Case("touchid-changed-plan", "authorization", "rejected", ("broker-rejection", "selector-readback"), requires_touch_id=True),
        Case("touchid-wrong-generation", "authorization", "rejected", ("broker-rejection", "selector-readback"), requires_touch_id=True),
        Case("activate-future-session", "runtime", "passed", ("selector-readback", "session-binding", "runtime-readback"), destructive=True),
        Case("preserve-old-session-pinning", "runtime", "passed", ("session-binding", "runtime-readback")),
        Case("legacy-session-fails-closed", "runtime", "rejected", ("session-rejection",)),
        Case("legacy-session-touchid-migration", "runtime", "passed", ("broker-receipt", "session-binding"), requires_touch_id=True),
        Case("rollback-explicit", "management", "passed", ("broker-receipt", "selector-readback", "boundary-readback"), requires_touch_id=True, destructive=True),
        Case("retire-zero-reference", "management", "passed", ("broker-receipt", "catalog-readback"), requires_touch_id=True, destructive=True),
        Case("reject-retire-referenced", "management", "rejected", ("reference-rejection", "catalog-readback"), requires_touch_id=True),
        Case("reclaim-zero-reference", "management", "passed", ("reclamation-receipt", "evidence-retention-readback"), destructive=True),
        Case("revoke-generation", "management", "passed", ("broker-receipt", "floor-readback", "runtime-denial"), requires_touch_id=True, destructive=True),
        Case("emergency-containment", "management", "passed", ("containment-receipt", "runtime-denial", "boundary-readback"), destructive=True),
    ))
    for transition in (
        "stage-created", "plan-written", "journal-prepared", "fenced",
        "workflow-authorized", "release-published",
        "catalog-written", "floor-written", "selector-written", "health-passed",
        "workflow-activated", "workflow-verified", "workflow-committed", "fence-removed",
        "journal-removed",
    ):
        cases.append(Case(
            f"process-loss-{transition}", "recovery", "passed",
            ("fault-injection-receipt", "recovery-receipt", "boundary-readback"),
            destructive=True,
        ))
        cases.append(Case(
            f"power-loss-{transition}", "recovery", "passed",
            ("fault-injection-receipt", "cold-boot-readback", "recovery-receipt", "boundary-readback"),
            requires_reboot=True, destructive=True,
        ))
    cases.extend((
        Case("cold-boot-host-readback", "cold-boot", "passed", ("cold-boot-readback", "host-release-readback"), requires_reboot=True),
        Case("cold-boot-research-readback", "cold-boot", "passed", ("cold-boot-readback", "research-release-readback"), requires_reboot=True),
        Case("cold-boot-catalog-selector-readback", "cold-boot", "passed", ("cold-boot-readback", "catalog-readback", "selector-readback"), requires_reboot=True),
        Case("cold-boot-executable-policy-readback", "cold-boot", "passed", ("cold-boot-readback", "runtime-readback", "policy-readback"), requires_reboot=True),
        Case("independent-evidence-export", "evidence", "passed", ("export-readback", "candidate-independence-readback")),
    ))
    return tuple(cases)


CASES = _cases()
CASE_BY_ID = {case.case_id: case for case in CASES}
COLLECTORS = frozenset({
    "secure-sandbox-host-controller-v1",
    "secure-sandbox-research-controller-v1",
    "secure-sandbox-privileged-control-v1",
    "secure-sandbox-touchid-broker-v1",
    "secure-sandbox-disposable-supervisor-v1",
    "secure-sandbox-cold-boot-supervisor-v1",
    "secure-sandbox-evidence-exporter-v1",
})
ARTIFACT_AUTHORITIES = frozenset({
    "protected-host", "protected-research", "privileged-control", "touchid-broker",
    "disposable-supervisor", "cold-boot-supervisor", "evidence-exporter",
})
COLLECTOR_PRIMARY_AUTHORITY = {
    "secure-sandbox-host-controller-v1": "protected-host",
    "secure-sandbox-research-controller-v1": "protected-research",
    "secure-sandbox-privileged-control-v1": "privileged-control",
    "secure-sandbox-touchid-broker-v1": "touchid-broker",
    "secure-sandbox-disposable-supervisor-v1": "disposable-supervisor",
    "secure-sandbox-cold-boot-supervisor-v1": "cold-boot-supervisor",
    "secure-sandbox-evidence-exporter-v1": "evidence-exporter",
}
EVIDENCE_KIND_COLLECTOR = {
    "acquisition-receipt": "secure-sandbox-host-controller-v1",
    "acquisition-rejection": "secure-sandbox-host-controller-v1",
    "archive-rejection": "secure-sandbox-host-controller-v1",
    "authority-readback": "secure-sandbox-host-controller-v1",
    "boundary-readback": "secure-sandbox-privileged-control-v1",
    "broker-receipt": "secure-sandbox-touchid-broker-v1",
    "broker-rejection": "secure-sandbox-touchid-broker-v1",
    "candidate-independence-readback": "secure-sandbox-evidence-exporter-v1",
    "catalog-readback": "secure-sandbox-research-controller-v1",
    "cold-boot-readback": "secure-sandbox-cold-boot-supervisor-v1",
    "containment-receipt": "secure-sandbox-privileged-control-v1",
    "credential-observation": "secure-sandbox-research-controller-v1",
    "equivocation-rejection": "secure-sandbox-host-controller-v1",
    "evidence-retention-readback": "secure-sandbox-research-controller-v1",
    "execution-observation": "secure-sandbox-research-controller-v1",
    "export-readback": "secure-sandbox-evidence-exporter-v1",
    "fault-injection-receipt": "secure-sandbox-disposable-supervisor-v1",
    "floor-readback": "secure-sandbox-research-controller-v1",
    "floor-rejection": "secure-sandbox-host-controller-v1",
    "freshness-rejection": "secure-sandbox-host-controller-v1",
    "host-install-readback": "secure-sandbox-host-controller-v1",
    "host-release-readback": "secure-sandbox-host-controller-v1",
    "isolation-observation": "secure-sandbox-research-controller-v1",
    "machine-enrollment": "secure-sandbox-disposable-supervisor-v1",
    "network-observation": "secure-sandbox-research-controller-v1",
    "plan-readback": "secure-sandbox-privileged-control-v1",
    "policy-readback": "secure-sandbox-host-controller-v1",
    "process-observation": "secure-sandbox-research-controller-v1",
    "production-material-scan": "secure-sandbox-disposable-supervisor-v1",
    "quarantine-readback": "secure-sandbox-host-controller-v1",
    "reclamation-receipt": "secure-sandbox-research-controller-v1",
    "recovery-receipt": "secure-sandbox-research-controller-v1",
    "reference-rejection": "secure-sandbox-privileged-control-v1",
    "research-install-readback": "secure-sandbox-research-controller-v1",
    "research-release-readback": "secure-sandbox-research-controller-v1",
    "runtime-denial": "secure-sandbox-research-controller-v1",
    "runtime-readback": "secure-sandbox-research-controller-v1",
    "selector-readback": "secure-sandbox-research-controller-v1",
    "session-binding": "secure-sandbox-host-controller-v1",
    "session-rejection": "secure-sandbox-host-controller-v1",
    "verification-receipt": "secure-sandbox-host-controller-v1",
    "verification-rejection": "secure-sandbox-host-controller-v1",
}
if ({kind for case in CASES for kind in case.evidence_kinds} != set(EVIDENCE_KIND_COLLECTOR)
        or any(collector not in COLLECTORS for collector in EVIDENCE_KIND_COLLECTOR.values())):
    raise RuntimeError("acceptance evidence collector map is incomplete")
SOURCE_STATUS = {
    "passed": frozenset({
        "passed", "verified", "committed", "recorded", "installed", "qualified",
        "recovered", "contained", "absent", "current", "open",
    }),
    "rejected": frozenset({
        "rejected", "denied", "cancelled", "expired", "blocked", "failed-closed",
    }),
}


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AcceptanceError("json_not_canonicalizable") from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def suite_sha256() -> str:
    return digest({
        "suite_id": SUITE_ID,
        "cases": [case_record(case) for case in CASES],
    })


def procedure_record(case: Case) -> dict[str, object]:
    """Return the immutable operator protocol for one physical case."""
    driver = {
        "bootstrap": "clean-machine-bootstrap",
        "provenance": "host-provenance-fixture",
        "archive": "host-archive-fixture",
        "qualification": "research-qualification-fixture",
        "authorization": "touchid-authorization-fixture",
        "runtime": "bound-session-runtime-fixture",
        "management": "protected-management-fixture",
        "recovery": "research-recovery-fixture",
        "cold-boot": "cold-boot-readback-fixture",
        "evidence": "independent-export-fixture",
    }[case.category]
    baseline = {
        "bootstrap": "factory-reset-test-account",
        "provenance": "clean-host-quarantine",
        "archive": "verified-synthetic-archive-carrier",
        "qualification": "verified-synthetic-candidate",
        "authorization": "staged-exact-generation-plan",
        "runtime": "two-retained-synthetic-generations",
        "management": "two-retained-synthetic-generations",
        "recovery": "fresh-activation-transaction",
        "cold-boot": "committed-synthetic-generation",
        "evidence": "complete-observation-inventory",
    }[case.category]
    if case.case_id == "touchid-cancel":
        interaction = "touchid-cancel"
    elif case.case_id == "touchid-replay":
        interaction = "touchid-approve-then-replay"
    elif case.case_id == "touchid-expired-plan":
        interaction = "touchid-after-expiry"
    elif case.case_id in {"touchid-changed-plan", "touchid-wrong-generation"}:
        interaction = "touchid-mismatched-request"
    elif case.requires_touch_id:
        interaction = "touchid-approve-exact"
    elif case.case_id.startswith("process-loss-"):
        interaction = "supervisor-process-kill"
    elif case.case_id.startswith("power-loss-"):
        interaction = "supervisor-research-vm-hard-power"
    elif case.requires_reboot:
        interaction = "supervisor-research-vm-cold-boot"
    else:
        interaction = "none"
    checkpoint = None
    if case.case_id.startswith(("process-loss-", "power-loss-")):
        checkpoint = case.case_id.split("-loss-", 1)[1]
    if case.category == "provenance":
        network = "synthetic-loopback-carrier-only"
    elif case.category == "qualification":
        network = "deny-all-and-observe"
    else:
        network = "no-new-egress"
    if case.category == "evidence":
        postcondition = "off-machine-export-independently-verified"
    elif case.category == "recovery":
        postcondition = "deterministic-recovery-and-boundary-verified"
    elif case.expected == "rejected":
        postcondition = "protected-state-unchanged"
    else:
        postcondition = "expected-state-independently-read-back"
    value: dict[str, object] = {
        "schema": PROCEDURE_SCHEMA,
        "case_id": case.case_id,
        "driver": driver,
        "baseline": baseline,
        "action": case.case_id,
        "interaction": interaction,
        "network": network,
        "interruption_checkpoint": checkpoint,
        "postcondition": postcondition,
        "reset": ("archive-and-restore-disposable-baseline"
                  if case.category != "evidence" else "erase-or-quarantine-after-export"),
    }
    value["procedure_sha256"] = digest(value)
    return value


def case_record(case: Case) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "category": case.category,
        "expected": case.expected,
        "evidence_kinds": list(case.evidence_kinds),
        "collectors": {kind: EVIDENCE_KIND_COLLECTOR[kind] for kind in case.evidence_kinds},
        "procedure": procedure_record(case),
        "requires_touch_id": case.requires_touch_id,
        "requires_reboot": case.requires_reboot,
        "destructive": case.destructive,
    }


def _exact(value: dict[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise AcceptanceError(f"{label}_fields_invalid")


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as error:
        raise AcceptanceError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != str(value):
        raise AcceptanceError(f"{label}_invalid")
    return str(parsed)


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AcceptanceError(f"{label}_invalid")
    return value


def _commit(value: object) -> str:
    if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
        raise AcceptanceError("source_commit_invalid")
    return value


def validate_evidence(value: object, campaign: dict[str, Any], case: Case) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("evidence_invalid")
    _exact(value, {
        "schema", "evidence_id", "campaign_id", "campaign_sha256", "case_id", "kind",
        "collector", "machine_identity_sha256", "source_commit", "observed_at", "outcome",
        "subject_sha256", "source_schema", "source_status", "source_sha256", "artifacts",
        "candidate_statement_used", "evidence_sha256",
    }, "evidence")
    if (value["schema"] != EVIDENCE_SCHEMA
            or value["campaign_id"] != campaign["campaign_id"]
            or value["campaign_sha256"] != campaign["campaign_sha256"]
            or value["case_id"] != case.case_id
            or value["kind"] not in case.evidence_kinds
            or value["collector"] != EVIDENCE_KIND_COLLECTOR.get(value["kind"])
            or value["machine_identity_sha256"] != campaign["machine_identity_sha256"]
            or value["source_commit"] != campaign["source_commit"]
            or value["outcome"] != case.expected
            or value["candidate_statement_used"] is not False):
        raise AcceptanceError("evidence_binding_invalid")
    _uuid4(value["evidence_id"], "evidence_id")
    _sha(value["subject_sha256"], "subject_sha256")
    _sha(value["source_sha256"], "source_sha256")
    _commit(value["source_commit"])
    if (not isinstance(value["observed_at"], int) or isinstance(value["observed_at"], bool)
            or not campaign["created_at"] <= value["observed_at"] <= campaign["expires_at"]
            or not isinstance(value["source_schema"], str)
            or TOKEN.fullmatch(value["source_schema"]) is None
            or not isinstance(value["source_status"], str)
            or TOKEN.fullmatch(value["source_status"]) is None
            or value["source_status"] not in SOURCE_STATUS[case.expected]):
        raise AcceptanceError("evidence_source_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 16:
        raise AcceptanceError("evidence_artifacts_invalid")
    names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise AcceptanceError("evidence_artifact_invalid")
        _exact(artifact, {"name", "sha256", "size", "media_type", "authority",
                          "content_base64"},
               "evidence_artifact")
        name = artifact["name"]
        if (not isinstance(name, str) or ARTIFACT_NAME.fullmatch(name) is None or name in names
                or not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool)
                or not 1 <= artifact["size"] <= MAX_DETAIL_BYTES
                or not isinstance(artifact["media_type"], str)
                or TOKEN.fullmatch(artifact["media_type"]) is None
                or artifact["authority"] not in ARTIFACT_AUTHORITIES
                or not isinstance(artifact["content_base64"], str)):
            raise AcceptanceError("evidence_artifact_invalid")
        expected_sha = _sha(artifact["sha256"], "evidence_artifact_sha256")
        try:
            content = base64.b64decode(artifact["content_base64"], validate=True)
        except (ValueError, binascii.Error) as error:
            raise AcceptanceError("evidence_artifact_content_invalid") from error
        if (len(content) != artifact["size"]
                or hashlib.sha256(content).hexdigest() != expected_sha
                or base64.b64encode(content).decode("ascii") != artifact["content_base64"]):
            raise AcceptanceError("evidence_artifact_content_mismatch")
        names.add(name)
    if (artifacts[0]["authority"] != COLLECTOR_PRIMARY_AUTHORITY[value["collector"]]
            or value["source_sha256"] != artifacts[0]["sha256"]
            or value["subject_sha256"] != artifacts[0]["sha256"]):
        raise AcceptanceError("evidence_primary_authority_mismatch")
    supplied = value["evidence_sha256"]
    unsigned = {key: item for key, item in value.items() if key != "evidence_sha256"}
    if _sha(supplied, "evidence_sha256") != digest(unsigned):
        raise AcceptanceError("evidence_digest_invalid")
    return value


def validate_enrollment(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("enrollment_invalid")
    _exact(value, {
        "schema", "enrollment_id", "machine_identity_sha256", "observed_at", "disposable",
        "production_data_present", "production_credentials_present", "synthetic_credentials_only",
        "collector", "enrollment_sha256",
    }, "enrollment")
    if (value["schema"] != ENROLLMENT_SCHEMA or value["disposable"] is not True
            or value["production_data_present"] is not False
            or value["production_credentials_present"] is not False
            or value["synthetic_credentials_only"] is not True
            or value["collector"] != "secure-sandbox-disposable-supervisor-v1"):
        raise AcceptanceError("enrollment_policy_invalid")
    _uuid4(value["enrollment_id"], "enrollment_id")
    _sha(value["machine_identity_sha256"], "machine_identity_sha256")
    observed = value["observed_at"]
    if (not isinstance(observed, int) or isinstance(observed, bool)
            or observed > now + 300 or now - observed > 86400):
        raise AcceptanceError("enrollment_time_invalid")
    unsigned = {key: item for key, item in value.items() if key != "enrollment_sha256"}
    if _sha(value["enrollment_sha256"], "enrollment_sha256") != digest(unsigned):
        raise AcceptanceError("enrollment_digest_invalid")
    return value


def validate_campaign(value: object, now: int, *, allow_expired: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("campaign_invalid")
    _exact(value, {
        "schema", "campaign_id", "suite_id", "suite_sha256", "machine_identity_sha256",
        "source_commit", "created_at", "expires_at", "environment", "production_data_present",
        "production_credentials_present", "synthetic_credentials_only", "authority",
        "campaign_sha256",
    }, "campaign")
    if (value["schema"] != CAMPAIGN_SCHEMA or value["suite_id"] != SUITE_ID
            or value["suite_sha256"] != suite_sha256()
            or value["environment"] != "disposable-mac"
            or value["production_data_present"] is not False
            or value["production_credentials_present"] is not False
            or value["synthetic_credentials_only"] is not True
            or value["authority"] != "acceptance-evidence-only"):
        raise AcceptanceError("campaign_policy_invalid")
    _uuid4(value["campaign_id"], "campaign_id")
    _sha(value["machine_identity_sha256"], "machine_identity_sha256")
    _commit(value["source_commit"])
    created, expires = value["created_at"], value["expires_at"]
    if (not isinstance(created, int) or isinstance(created, bool)
            or not isinstance(expires, int) or isinstance(expires, bool)
            or created > now + 300 or expires <= created
            or (not allow_expired and not created <= now < expires)
            or expires - created > MAX_CAMPAIGN_SECONDS):
        raise AcceptanceError("campaign_time_invalid")
    supplied = value["campaign_sha256"]
    unsigned = {key: item for key, item in value.items() if key != "campaign_sha256"}
    if _sha(supplied, "campaign_sha256") != digest(unsigned):
        raise AcceptanceError("campaign_digest_invalid")
    return value


def validate_observation(value: object, campaign: dict[str, Any], case: Case) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("observation_invalid")
    _exact(value, {
        "schema", "observation_id", "campaign_id", "campaign_sha256", "case_id",
        "kind", "collector", "machine_identity_sha256", "source_commit", "started_at",
        "completed_at", "outcome", "subject_sha256", "evidence", "evidence_sha256",
        "candidate_statement_used", "observation_sha256",
    }, "observation")
    if (value["schema"] != OBSERVATION_SCHEMA
            or value["campaign_id"] != campaign["campaign_id"]
            or value["campaign_sha256"] != campaign["campaign_sha256"]
            or value["case_id"] != case.case_id
            or value["kind"] not in case.evidence_kinds
            or value["collector"] != EVIDENCE_KIND_COLLECTOR.get(value["kind"])
            or value["machine_identity_sha256"] != campaign["machine_identity_sha256"]
            or value["source_commit"] != campaign["source_commit"]
            or value["candidate_statement_used"] is not False):
        raise AcceptanceError("observation_binding_invalid")
    _uuid4(value["observation_id"], "observation_id")
    _sha(value["subject_sha256"], "subject_sha256")
    _commit(value["source_commit"])
    evidence = validate_evidence(value["evidence"], campaign, case)
    if (value["evidence_sha256"] != evidence["evidence_sha256"]
            or evidence["kind"] != value["kind"]
            or evidence["collector"] != value["collector"]
            or evidence["outcome"] != value["outcome"]
            or evidence["subject_sha256"] != value["subject_sha256"]):
        raise AcceptanceError("observation_evidence_mismatch")
    started, completed = value["started_at"], value["completed_at"]
    if (not isinstance(started, int) or isinstance(started, bool)
            or not isinstance(completed, int) or isinstance(completed, bool)
            or not campaign["created_at"] <= started <= completed <= campaign["expires_at"]
            or completed - started > MAX_OBSERVATION_SECONDS
            or value["outcome"] != case.expected):
        raise AcceptanceError("observation_result_invalid")
    supplied = value["observation_sha256"]
    unsigned = {key: item for key, item in value.items() if key != "observation_sha256"}
    if _sha(supplied, "observation_sha256") != digest(unsigned):
        raise AcceptanceError("observation_digest_invalid")
    return value


def validate_receipt(value: object, campaign: dict[str, Any], sequence: int,
                     previous_sha256: str | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("receipt_invalid")
    _exact(value, {
        "schema", "receipt_id", "campaign_id", "campaign_sha256", "case_id", "sequence",
        "expected", "result", "observation_sha256", "previous_receipt_sha256",
        "completed_at", "receipt_sha256",
    }, "receipt")
    case_id = value.get("case_id")
    case = CASE_BY_ID.get(case_id) if isinstance(case_id, str) else None
    if (case is None or value["schema"] != RECEIPT_SCHEMA
            or value["campaign_id"] != campaign["campaign_id"]
            or value["campaign_sha256"] != campaign["campaign_sha256"]
            or value["sequence"] != sequence or value["expected"] != case.expected
            or value["result"] != "passed" or value["previous_receipt_sha256"] != previous_sha256):
        raise AcceptanceError("receipt_binding_invalid")
    _uuid4(value["receipt_id"], "receipt_id")
    observations = value["observation_sha256"]
    if (not isinstance(observations, list) or len(observations) != len(case.evidence_kinds)
            or any(not isinstance(item, str) or SHA256.fullmatch(item) is None for item in observations)):
        raise AcceptanceError("receipt_observations_invalid")
    completed = value["completed_at"]
    if (not isinstance(completed, int) or isinstance(completed, bool)
            or not campaign["created_at"] <= completed <= campaign["expires_at"]):
        raise AcceptanceError("receipt_time_invalid")
    supplied = value["receipt_sha256"]
    unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if _sha(supplied, "receipt_sha256") != digest(unsigned):
        raise AcceptanceError("receipt_digest_invalid")
    return value


def assemble_export(campaign: dict[str, Any], raw_observations: list[object],
                    completed_at: int) -> dict[str, Any]:
    """Assemble a complete export from fixed-collector observations.

    This creates no observation and cannot turn a missing or rejected case into
    a pass.  Receipt order is the immutable suite order.
    """
    validated_campaign = validate_campaign(campaign, completed_at)
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for raw in raw_observations:
        if not isinstance(raw, dict) or not isinstance(raw.get("case_id"), str):
            raise AcceptanceError("observation_invalid")
        case = CASE_BY_ID.get(raw["case_id"])
        if case is None:
            raise AcceptanceError("observation_case_unknown")
        observation = validate_observation(raw, validated_campaign, case)
        by_kind = grouped.setdefault(case.case_id, {})
        if observation["kind"] in by_kind:
            raise AcceptanceError("observation_kind_duplicate")
        by_kind[observation["kind"]] = observation
    if set(grouped) != set(CASE_BY_ID):
        raise AcceptanceError("observation_case_inventory_invalid")
    ordered_observations: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    previous: str | None = None
    for sequence, case in enumerate(CASES):
        by_kind = grouped[case.case_id]
        if set(by_kind) != set(case.evidence_kinds):
            raise AcceptanceError("observation_kind_inventory_invalid")
        bound = [by_kind[kind] for kind in case.evidence_kinds]
        ordered_observations.extend(bound)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "receipt_id": str(uuid.uuid4()),
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "case_id": case.case_id,
            "sequence": sequence,
            "expected": case.expected,
            "result": "passed",
            "observation_sha256": [item["observation_sha256"] for item in bound],
            "previous_receipt_sha256": previous,
            "completed_at": max(item["completed_at"] for item in bound),
        }
        receipt["receipt_sha256"] = digest(receipt)
        validate_receipt(receipt, campaign, sequence, previous)
        receipts.append(receipt)
        previous = receipt["receipt_sha256"]
    value = {
        "schema": EXPORT_SCHEMA,
        "campaign": campaign,
        "suite_sha256": campaign["suite_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"],
        "observations": ordered_observations,
        "receipts": receipts,
        "final_receipt_sha256": previous,
        "completed_at": completed_at,
        "status": "verified",
        "candidate_authority": "none",
        "production_material_used": False,
    }
    value["export_sha256"] = digest(value)
    validate_export(value, campaign, completed_at)
    return value


def validate_export(value: object, campaign: dict[str, Any], now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptanceError("export_invalid")
    _exact(value, {
        "schema", "campaign", "suite_sha256", "machine_identity_sha256", "source_commit",
        "observations", "receipts", "final_receipt_sha256", "completed_at", "status",
        "candidate_authority", "production_material_used", "export_sha256",
    }, "export")
    embedded = validate_campaign(value["campaign"], now, allow_expired=True)
    if embedded != campaign:
        raise AcceptanceError("export_campaign_mismatch")
    if (value["schema"] != EXPORT_SCHEMA or value["suite_sha256"] != suite_sha256()
            or value["machine_identity_sha256"] != campaign["machine_identity_sha256"]
            or value["source_commit"] != campaign["source_commit"]
            or value["status"] != "verified"
            or value["candidate_authority"] != "none"
            or value["production_material_used"] is not False):
        raise AcceptanceError("export_policy_invalid")
    observations = value["observations"]
    receipts = value["receipts"]
    if not isinstance(observations, list) or not isinstance(receipts, list) or len(receipts) != len(CASES):
        raise AcceptanceError("export_inventory_invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    for raw in observations:
        if not isinstance(raw, dict):
            raise AcceptanceError("export_observation_invalid")
        supplied = raw.get("observation_sha256")
        if not isinstance(supplied, str) or supplied in by_digest:
            raise AcceptanceError("export_observation_duplicate")
        by_digest[supplied] = raw
    expected_observation_count = sum(len(case.evidence_kinds) for case in CASES)
    if len(by_digest) != expected_observation_count:
        raise AcceptanceError("export_observation_inventory_invalid")
    previous = None
    seen_cases: set[str] = set()
    for sequence, raw in enumerate(receipts):
        receipt = validate_receipt(raw, campaign, sequence, previous)
        case = CASE_BY_ID[receipt["case_id"]]
        if case.case_id in seen_cases:
            raise AcceptanceError("export_case_duplicate")
        seen_cases.add(case.case_id)
        bound = [validate_observation(by_digest[item], campaign, case)
                 for item in receipt["observation_sha256"]]
        if [item["kind"] for item in bound] != list(case.evidence_kinds):
            raise AcceptanceError("export_evidence_order_invalid")
        previous = receipt["receipt_sha256"]
    if seen_cases != set(CASE_BY_ID) or value["final_receipt_sha256"] != previous:
        raise AcceptanceError("export_case_inventory_invalid")
    completed = value["completed_at"]
    if (not isinstance(completed, int) or isinstance(completed, bool)
            or not campaign["created_at"] <= completed <= campaign["expires_at"]):
        raise AcceptanceError("export_time_invalid")
    supplied = value["export_sha256"]
    unsigned = {key: item for key, item in value.items() if key != "export_sha256"}
    if _sha(supplied, "export_sha256") != digest(unsigned):
        raise AcceptanceError("export_digest_invalid")
    return value


def verdict(value: object, now: int) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("campaign"), dict):
        raise AcceptanceError("export_invalid")
    campaign = validate_campaign(value["campaign"], now, allow_expired=True)
    accepted = validate_export(value, campaign, now)
    result = {
        "schema": VERDICT_SCHEMA,
        "status": "accepted-for-separate-admission-decision",
        "campaign_id": campaign["campaign_id"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"],
        "suite_sha256": campaign["suite_sha256"],
        "case_count": len(CASES),
        "export_sha256": accepted["export_sha256"],
        "authority": "acceptance-evidence-only",
    }
    result["verdict_sha256"] = digest(result)
    return result
