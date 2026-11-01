#!/usr/bin/env python3
"""Cold-boot only the disposable Research VM and project fixed readbacks."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
sys.dont_write_bytecode = True
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any


PROTECTED_RELEASES = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance/releases"
)


def require_protected_main_path(path: Path, effective_uid: int) -> None:
    """Reject privileged checkout execution before any local module import."""
    if effective_uid != 0:
        return
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROTECTED_RELEASES)
    except ValueError as error:
        raise SystemExit("cold_boot_driver_protected_invocation_required") from error
    if (len(relative.parts) != 3 or relative.parts[1:] != ("scripts", path.name)
            or len(relative.parts[0]) != 40
            or any(character not in "0123456789abcdef" for character in relative.parts[0])):
        raise SystemExit("cold_boot_driver_protected_invocation_required")


if __name__ == "__main__":
    require_protected_main_path(Path(__file__), os.geteuid())


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
    validate_observation,
)
from harness_runtime_binding import HarnessBindingError, validate_binding  # noqa: E402


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-cold-boot-driver-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-cold-boot-error-v1"
COLD_BOOT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-cold-boot-readback-v1"
READBACK_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-persistence-readback-v1"
ACKNOWLEDGEMENT = "COLD BOOT ONLY THE DISPOSABLE RESEARCH VM"
MEDIA_TYPE = "application/json"
PROTECTED_ROOT = Path("/usr/local/libexec/secure-sandbox-harness-acceptance")
PROTECTED_STATE_ROOT = Path("/var/db/SecureSandbox/harness-lifecycle-acceptance")
DRIVER = "cold-boot-readback-fixture"
CASE_FILES = {
    "cold-boot-host-readback": ("cold-boot-readback", "host-release-readback"),
    "cold-boot-research-readback": ("cold-boot-readback", "research-release-readback"),
    "cold-boot-catalog-selector-readback": (
        "cold-boot-readback", "catalog-readback", "selector-readback",
    ),
    "cold-boot-executable-policy-readback": (
        "cold-boot-readback", "runtime-readback", "policy-readback",
    ),
}
AUTHORITIES = {
    "cold-boot-readback": "cold-boot-supervisor",
    "host-release-readback": "protected-host",
    "research-release-readback": "protected-research",
    "catalog-readback": "protected-research",
    "selector-readback": "protected-research",
    "runtime-readback": "protected-research",
    "policy-readback": "protected-host",
}
SUPPORT = {
    "cold-boot-readback": (),
    "host-release-readback": ("cold-boot-readback",),
    "research-release-readback": ("cold-boot-readback",),
    "catalog-readback": ("cold-boot-readback",),
    "selector-readback": ("catalog-readback", "cold-boot-readback"),
    "runtime-readback": ("cold-boot-readback",),
    "policy-readback": ("runtime-readback", "cold-boot-readback"),
}
READBACK_FIELDS = {
    "host-release-readback": {
        "protected_manifest", "protected_manifest_sha256", "protected_suite_sha256",
    },
    "research-release-readback": {
        "store_status", "store_status_sha256", "boundary", "boundary_sha256",
        "active_generation_id",
    },
    "catalog-readback": {"boundary", "catalog_sha256", "generation_count"},
    "selector-readback": {"boundary", "selector_sha256", "active_generation_id"},
    "runtime-readback": {"runtime_binding", "runtime_binding_sha256"},
    "policy-readback": {
        "active_record", "runtime_binding", "generation_id", "policy_sha256",
        "manifest_sha256",
    },
}
READBACK_BASE_FIELDS = {
    "schema", "status", "kind", "campaign_id", "campaign_sha256",
    "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
    "observed_at", "candidate_authority", "production_material_used",
    "readback_sha256",
}


class ColdBootError(RuntimeError):
    """Stable, content-free cold-boot acceptance failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ColdBootError("cold_boot_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_cold_boot_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_cold_boot_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
ACCEPTANCE_CLI = load_script(
    "harness_lifecycle_acceptance_cold_boot_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)


def private_directory(path: Path, label: str, expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise ColdBootError(f"{label}_untrusted")


def reserve_case(root: Path, case_id: str) -> Path:
    private_directory(root, "cold_boot_raw_root")
    destination = root / case_id
    if os.path.lexists(destination):
        raise ColdBootError("cold_boot_raw_case_exists")
    destination.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return destination


def trusted_json(path: Path, expected_uid: int | None = None) -> dict[str, Any]:
    try:
        return ACCEPTANCE_CLI.trusted_json(path, expected_uid=expected_uid)
    except AcceptanceError as error:
        raise ColdBootError("cold_boot_input_untrusted") from error


def next_case(campaign: dict[str, Any], observations: Path,
              case_id: str, operator_uid: int) -> dict[str, Any]:
    try:
        result = ACCEPTANCE_CLI.next_case(
            campaign, observations, observation_uid=0, directory_uid=operator_uid,
        )
    except (AcceptanceError, OSError) as error:
        raise ColdBootError("cold_boot_case_status_invalid") from error
    case = result.get("case")
    if (result.get("status") != "pending" or not isinstance(case, dict)
            or case.get("case_id") != case_id or case_id not in CASE_FILES
            or case.get("category") != "cold-boot"
            or case.get("expected") != "passed"
            or case.get("requires_reboot") is not True
            or case.get("procedure", {}).get("driver") != DRIVER
            or case.get("procedure", {}).get("interaction")
               != "supervisor-research-vm-cold-boot"
            or case.get("evidence_kinds") != list(CASE_FILES[case_id])):
        raise ColdBootError("cold_boot_case_invalid")
    return case


def preflight(campaign_path: Path, observations: Path, case_id: str,
              now: int, operator_uid: int) -> tuple[
                  dict[str, Any], dict[str, Any], dict[str, Any],
              ]:
    try:
        campaign = validate_campaign(trusted_json(campaign_path, operator_uid), now)
        if SUPERVISOR.current_machine_identity() != campaign["machine_identity_sha256"]:
            raise ColdBootError("cold_boot_machine_identity_mismatch")
        manifest = ACCEPTANCE_CLI.verify_protected_driver(
            PROTECTED_ROOT, campaign["source_commit"], DRIVER, 0,
        )
    except (AcceptanceError, SUPERVISOR.SupervisorError) as error:
        raise ColdBootError("cold_boot_preflight_failed") from error
    private_directory(observations, "cold_boot_observations", operator_uid)
    return campaign, next_case(campaign, observations, case_id, operator_uid), manifest


def control(operation: str) -> dict[str, Any]:
    try:
        return SUPERVISOR.json_command([
            str(SUPERVISOR.CONTROL_CLIENT), "client", "--ssh-config",
            str(SUPERVISOR.SSH_CONFIG), "--timeout-seconds", "30",
            SUPERVISOR.RESEARCH_CONTROL, "run", operation,
        ], timeout=40, canonical_output=False)
    except SUPERVISOR.SupervisorError as error:
        raise ColdBootError("cold_boot_research_readback_failed") from error


def valid_boot(campaign: dict[str, Any], case: dict[str, Any], value: dict[str, Any]) -> None:
    try:
        SUPERVISOR.validate_boot(campaign, case, value)
    except SUPERVISOR.SupervisorError as error:
        raise ColdBootError("cold_boot_identity_invalid") from error


def validate_store(status: dict[str, Any], boundary: dict[str, Any]) -> None:
    try:
        SUPERVISOR.validate_boundary(boundary)
    except SUPERVISOR.SupervisorError as error:
        raise ColdBootError("cold_boot_boundary_invalid") from error
    if (status.get("schema") != "secure-sandbox-harness-generation-status-v1"
            or status.get("status") != "verified"
            or status.get("admission") != "open"
            or status.get("recovery_pending") is not False
            or status.get("boundary") != boundary
            or status.get("active_generation_id") != boundary.get("active_generation_id")
            or not isinstance(status.get("generations"), list)):
        raise ColdBootError("cold_boot_store_status_invalid")


def receipt(campaign: dict[str, Any], case: dict[str, Any], kind: str,
            now: int, fields: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": READBACK_SCHEMA, "status": "verified", "kind": kind,
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"], "case_id": case["case_id"],
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observed_at": now, **fields, "candidate_authority": "none",
        "production_material_used": False,
    }
    value["readback_sha256"] = digest(value)
    return value


def validate_receipt(campaign: dict[str, Any], case: dict[str, Any],
                     kind: str, value: dict[str, Any], now: int) -> None:
    unsigned = {name: item for name, item in value.items()
                if name != "readback_sha256"}
    if (kind not in READBACK_FIELDS
            or set(value) != READBACK_BASE_FIELDS | READBACK_FIELDS[kind]
            or value.get("schema") != READBACK_SCHEMA or value.get("status") != "verified"
            or value.get("kind") != kind
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256") != case["procedure"]["procedure_sha256"]
            or not isinstance(value.get("observed_at"), int)
            or not campaign["created_at"] <= value["observed_at"] < campaign["expires_at"]
            or value["observed_at"] > now + 300 or now - value["observed_at"] > 3600
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("readback_sha256") != digest(unsigned)):
        raise ColdBootError("cold_boot_readback_invalid")
    hashes = {
        "host-release-readback": ("protected_manifest_sha256", "protected_suite_sha256"),
        "research-release-readback": ("store_status_sha256", "boundary_sha256"),
        "catalog-readback": ("catalog_sha256",),
        "selector-readback": ("selector_sha256",),
        "runtime-readback": ("runtime_binding_sha256",),
        "policy-readback": ("generation_id", "policy_sha256", "manifest_sha256"),
    }[kind]
    if any(not isinstance(value.get(name), str)
           or SUPERVISOR.SHA256.fullmatch(value[name]) is None for name in hashes):
        raise ColdBootError("cold_boot_readback_invalid")
    if kind in {"research-release-readback", "selector-readback"}:
        active = value.get("active_generation_id")
        if (active is not None and (not isinstance(active, str)
                                    or SUPERVISOR.SHA256.fullmatch(active) is None)):
            raise ColdBootError("cold_boot_readback_invalid")
    if kind == "catalog-readback":
        count = value.get("generation_count")
        if (not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 1024):
            raise ColdBootError("cold_boot_readback_invalid")
    if kind == "runtime-readback":
        try:
            binding = validate_binding(value.get("runtime_binding"))
        except HarnessBindingError as error:
            raise ColdBootError("cold_boot_readback_invalid") from error
        if binding["binding_sha256"] != value["runtime_binding_sha256"]:
            raise ColdBootError("cold_boot_readback_invalid")
    if kind == "host-release-readback":
        manifest = value.get("protected_manifest")
        if (not isinstance(manifest, dict)
                or manifest.get("manifest_sha256") != value["protected_manifest_sha256"]
                or manifest.get("suite_sha256") != value["protected_suite_sha256"]
                or digest({name: item for name, item in manifest.items()
                           if name != "manifest_sha256"}) != value["protected_manifest_sha256"]):
            raise ColdBootError("cold_boot_readback_invalid")
    if kind == "research-release-readback":
        status = value.get("store_status"); boundary = value.get("boundary")
        if not isinstance(status, dict) or not isinstance(boundary, dict):
            raise ColdBootError("cold_boot_readback_invalid")
        validate_store(status, boundary)
        if (digest(status) != value["store_status_sha256"]
                or digest(boundary) != value["boundary_sha256"]
                or boundary["active_generation_id"] != value["active_generation_id"]):
            raise ColdBootError("cold_boot_readback_invalid")
    if kind in {"catalog-readback", "selector-readback"}:
        boundary = value.get("boundary")
        if not isinstance(boundary, dict):
            raise ColdBootError("cold_boot_readback_invalid")
        try:
            SUPERVISOR.validate_boundary(boundary)
        except SUPERVISOR.SupervisorError as error:
            raise ColdBootError("cold_boot_readback_invalid") from error
        if kind == "catalog-readback" and (
                boundary["catalog_sha256"] != value["catalog_sha256"]
                or boundary["generation_count"] != value["generation_count"]):
            raise ColdBootError("cold_boot_readback_invalid")
        if kind == "selector-readback" and (
                boundary["selector_sha256"] != value["selector_sha256"]
                or boundary["active_generation_id"] != value["active_generation_id"]):
            raise ColdBootError("cold_boot_readback_invalid")
    if kind == "policy-readback":
        record = value.get("active_record"); binding_value = value.get("runtime_binding")
        if not isinstance(record, dict):
            raise ColdBootError("cold_boot_readback_invalid")
        try:
            binding = validate_binding(binding_value)
        except HarnessBindingError as error:
            raise ColdBootError("cold_boot_readback_invalid") from error
        if (record.get("generation_id") != value["generation_id"]
                or record.get("policy_sha256") != value["policy_sha256"]
                or record.get("manifest_sha256") != value["manifest_sha256"]
                or binding["harness_generation_id"] != value["generation_id"]
                or binding["harness_manifest_sha256"] != value["manifest_sha256"]):
            raise ColdBootError("cold_boot_readback_invalid")


def validate_cold_readback(campaign: dict[str, Any], case: dict[str, Any],
                           value: dict[str, Any], now: int) -> None:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "observed_at", "pre_boot", "post_boot", "vm_before", "vm_stopped",
        "vm_restarted", "vm_after", "gateway_unchanged", "target_unchanged",
        "candidate_authority", "production_material_used", "cold_boot_sha256",
    }
    unsigned = {name: item for name, item in value.items()
                if name != "cold_boot_sha256"}
    inventories = [value.get(name) for name in (
        "vm_before", "vm_stopped", "vm_restarted", "vm_after",
    )]
    if (set(value) != expected or value.get("schema") != COLD_BOOT_SCHEMA
            or value.get("status") != "verified"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != case["case_id"]
            or value.get("procedure_sha256") != case["procedure"]["procedure_sha256"]
            or not isinstance(value.get("observed_at"), int)
            or not campaign["created_at"] <= value["observed_at"] < campaign["expires_at"]
            or value["observed_at"] > now + 300 or now - value["observed_at"] > 3600
            or any(not isinstance(item, dict)
                   or set(item) != {"gateway", "research", "target"}
                   or any(state not in {"running", "stopped", "suspended", "unknown"}
                          for state in item.values()) for item in inventories)
            or inventories[0]["research"] != "running"
            or inventories[1]["research"] != "stopped"
            or inventories[2]["research"] != "running"
            or inventories[3] != inventories[0]
            or any(item["gateway"] != inventories[0]["gateway"]
                   or item["target"] != inventories[0]["target"]
                   for item in inventories[1:])
            or value.get("gateway_unchanged") is not True
            or value.get("target_unchanged") is not True
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("cold_boot_sha256") != digest(unsigned)):
        raise ColdBootError("cold_boot_raw_readback_invalid")
    pre = value.get("pre_boot"); post = value.get("post_boot")
    if not isinstance(pre, dict) or not isinstance(post, dict):
        raise ColdBootError("cold_boot_raw_readback_invalid")
    valid_boot(campaign, case, pre); valid_boot(campaign, case, post)
    if pre["research_boot_sha256"] == post["research_boot_sha256"]:
        raise ColdBootError("cold_boot_raw_readback_invalid")


def active_record(status: dict[str, Any], binding: dict[str, str]) -> dict[str, Any]:
    matches = [item for item in status["generations"]
               if isinstance(item, dict)
               and item.get("generation_id") == binding["harness_generation_id"]]
    if len(matches) != 1 or matches[0].get("status") != "active":
        raise ColdBootError("cold_boot_active_record_invalid")
    record = matches[0]
    if (record.get("manifest_sha256") != binding["harness_manifest_sha256"]
            or record.get("inventory_sha256") != binding["harness_inventory_sha256"]
            or record.get("adapter_id") != binding["harness_adapter_id"]
            or record.get("adapter_sha256") != binding["harness_adapter_sha256"]
            or not isinstance(record.get("policy_sha256"), str)
            or SUPERVISOR.SHA256.fullmatch(record["policy_sha256"]) is None):
        raise ColdBootError("cold_boot_active_record_invalid")
    return record


def collect(campaign_path: Path, observations: Path, case_id: str, raw_root: Path,
            acknowledgement: str, now: int, operator_uid: int) -> dict[str, Any]:
    campaign, case, manifest = preflight(
        campaign_path, observations, case_id, now, operator_uid,
    )
    if acknowledgement != ACKNOWLEDGEMENT:
        raise ColdBootError("cold_boot_acknowledgement_required")
    for path in (SUPERVISOR.PRLCTL, SUPERVISOR.PGREP, SUPERVISOR.SSH,
                 SUPERVISOR.CONTROL_CLIENT, SUPERVISOR.SSH_CONFIG):
        SUPERVISOR.prerequisite(path, executable=path != SUPERVISOR.SSH_CONFIG)
    lock = SUPERVISOR.acquire_lock()
    destination: Path | None = None
    before: dict[str, str] | None = None
    restore_check_required = False
    try:
        SUPERVISOR.require_gui_closed()
        before = SUPERVISOR.vm_inventory()
        if before["research"] != "running":
            raise ColdBootError("cold_boot_research_not_running")
        destination = reserve_case(raw_root, case_id)
        pre_boot = SUPERVISOR.remote_json(campaign, "boot-readback", case_id)
        valid_boot(campaign, case, pre_boot)
        SUPERVISOR.require_gui_closed()
        restore_check_required = True
        SUPERVISOR.command(
            [str(SUPERVISOR.PRLCTL), "stop", SUPERVISOR.RESEARCH_VM, "--kill"],
            timeout=30,
        )
        SUPERVISOR.wait_vm_state(SUPERVISOR.RESEARCH_VM, "stopped")
        stopped = SUPERVISOR.vm_inventory()
        if (stopped["gateway"] != before["gateway"]
                or stopped["target"] != before["target"]
                or stopped["research"] != "stopped"):
            raise ColdBootError("cold_boot_power_scope_violation")
        SUPERVISOR.require_gui_closed()
        SUPERVISOR.command(
            [str(SUPERVISOR.PRLCTL), "start", SUPERVISOR.RESEARCH_VM], timeout=30,
        )
        SUPERVISOR.wait_vm_state(SUPERVISOR.RESEARCH_VM, "running", 60)
        SUPERVISOR.wait_research_control()
        restarted = SUPERVISOR.vm_inventory()
        if (restarted["gateway"] != before["gateway"]
                or restarted["target"] != before["target"]
                or restarted["research"] != "running"):
            raise ColdBootError("cold_boot_restart_scope_violation")
        restore_check_required = False
        post_boot = SUPERVISOR.remote_json(campaign, "boot-readback", case_id)
        valid_boot(campaign, case, post_boot)
        if pre_boot["research_boot_sha256"] == post_boot["research_boot_sha256"]:
            raise ColdBootError("cold_boot_identity_unchanged")
        after = SUPERVISOR.vm_inventory()
        if after != before:
            raise ColdBootError("cold_boot_final_vm_state_changed")

        status = control("harness-generation-status")
        boundary = control("harness-generation-verify-boundary")
        runtime = control("harness-active-runtime")
        validate_store(status, boundary)
        try:
            binding = validate_binding(runtime)
        except HarnessBindingError as error:
            raise ColdBootError("cold_boot_runtime_binding_invalid") from error
        record = active_record(status, binding)
        cold = {
            "schema": COLD_BOOT_SCHEMA, "status": "verified",
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"], "case_id": case_id,
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "observed_at": now, "pre_boot": pre_boot, "post_boot": post_boot,
            "vm_before": before, "vm_stopped": stopped,
            "vm_restarted": restarted, "vm_after": after,
            "gateway_unchanged": True, "target_unchanged": True,
            "candidate_authority": "none", "production_material_used": False,
        }
        cold["cold_boot_sha256"] = digest(cold)
        validate_cold_readback(campaign, case, cold, now)
        readbacks = {
            "cold-boot-readback": cold,
            "host-release-readback": receipt(campaign, case, "host-release-readback", now, {
                "protected_manifest": manifest,
                "protected_manifest_sha256": manifest["manifest_sha256"],
                "protected_suite_sha256": manifest["suite_sha256"],
            }),
            "research-release-readback": receipt(campaign, case, "research-release-readback", now, {
                "store_status": status, "boundary": boundary,
                "store_status_sha256": digest(status),
                "boundary_sha256": digest(boundary),
                "active_generation_id": boundary["active_generation_id"],
            }),
            "catalog-readback": receipt(campaign, case, "catalog-readback", now, {
                "boundary": boundary,
                "catalog_sha256": boundary["catalog_sha256"],
                "generation_count": boundary["generation_count"],
            }),
            "selector-readback": receipt(campaign, case, "selector-readback", now, {
                "boundary": boundary,
                "selector_sha256": boundary["selector_sha256"],
                "active_generation_id": boundary["active_generation_id"],
            }),
            "runtime-readback": receipt(campaign, case, "runtime-readback", now, {
                "runtime_binding": binding,
                "runtime_binding_sha256": binding["binding_sha256"],
            }),
            "policy-readback": receipt(campaign, case, "policy-readback", now, {
                "active_record": record, "runtime_binding": binding,
                "generation_id": record["generation_id"],
                "policy_sha256": record["policy_sha256"],
                "manifest_sha256": record["manifest_sha256"],
            }),
        }
        for kind in CASE_FILES[case_id]:
            value = readbacks[kind]
            if kind != "cold-boot-readback":
                validate_receipt(campaign, case, kind, value, now)
            SUPERVISOR.write_new(destination / f"{kind}.json", value)
        directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if restore_check_required and before is not None:
            try:
                SUPERVISOR.require_gui_closed()
                current = SUPERVISOR.vm_inventory()
                if (current["research"] == "stopped"
                        and current["gateway"] == before["gateway"]
                        and current["target"] == before["target"]):
                    SUPERVISOR.command(
                        [str(SUPERVISOR.PRLCTL), "start", SUPERVISOR.RESEARCH_VM],
                        timeout=30,
                    )
                    SUPERVISOR.wait_vm_state(SUPERVISOR.RESEARCH_VM, "running", 60)
            except (ColdBootError, SUPERVISOR.SupervisorError, OSError):
                pass
        os.close(lock)
    result = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "raw_directory": str(destination),
        "raw_files": [f"{kind}.json" for kind in CASE_FILES[case_id]],
        "candidate_authority": "none", "production_material_used": False,
    }
    result["driver_sha256"] = digest(result)
    return result


def raw_set(campaign: dict[str, Any], case: dict[str, Any], raw_directory: Path,
            now: int) -> tuple[dict[str, Path], dict[str, bytes]]:
    private_directory(raw_directory, "cold_boot_raw_directory")
    kinds = CASE_FILES[case["case_id"]]
    expected = {f"{kind}.json" for kind in kinds}
    entries = {item.name: item for item in raw_directory.iterdir()}
    if set(entries) != expected:
        raise ColdBootError("cold_boot_raw_inventory_invalid")
    paths = {kind: entries[f"{kind}.json"] for kind in kinds}
    values = {kind: trusted_json(path) for kind, path in paths.items()}
    validate_cold_readback(campaign, case, values["cold-boot-readback"], now)
    for kind in kinds[1:]:
        validate_receipt(campaign, case, kind, values[kind], now)
    if "runtime-readback" in values and "policy-readback" in values:
        binding = values["runtime-readback"]["runtime_binding"]
        policy = values["policy-readback"]
        if (policy["generation_id"] != binding["harness_generation_id"]
                or policy["manifest_sha256"] != binding["harness_manifest_sha256"]):
            raise ColdBootError("cold_boot_runtime_policy_mismatch")
    return paths, {kind: canonical(value) for kind, value in values.items()}


def existing_observation(path: Path, campaign: dict[str, Any], case: dict[str, Any],
                         kind: str, raw_values: dict[str, bytes]) -> str:
    try:
        raw = OBSERVER.trusted_read(path)
        value = json.loads(raw)
    except (AcceptanceError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ColdBootError("cold_boot_existing_observation_invalid") from error
    expected = [kind, *SUPPORT[kind]]
    evidence = value.get("evidence") if isinstance(value, dict) else None
    artifacts = evidence.get("artifacts") if isinstance(evidence, dict) else None
    if (not isinstance(value, dict) or canonical(value) != raw
            or value.get("kind") != kind or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts if isinstance(item, dict)] != expected
            or any(not isinstance(item, dict)
                   or item.get("authority") != AUTHORITIES[item_kind]
                   or item.get("sha256")
                      != hashlib.sha256(raw_values[item_kind]).hexdigest()
                   for item, item_kind in zip(artifacts, expected))):
        raise ColdBootError("cold_boot_existing_observation_mismatch")
    try:
        validate_observation(value, campaign, CASE_BY_ID[case["case_id"]])
    except AcceptanceError as error:
        raise ColdBootError("cold_boot_existing_observation_invalid") from error
    return value["observation_sha256"]


def write_snapshot(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ColdBootError("cold_boot_snapshot_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int, operator_uid: int) -> dict[str, Any]:
    campaign, case, _ = preflight(
        campaign_path, observations, case_id, now, operator_uid,
    )
    _, raw_values = raw_set(campaign, case, raw_directory, now)
    private_directory(observations, "cold_boot_observation_directory", operator_uid)
    existing: dict[str, str] = {}; missing: list[str] = []
    for kind in CASE_FILES[case_id]:
        destination = observations / f"{case_id}.{kind}.json"
        if os.path.lexists(destination):
            existing[kind] = existing_observation(
                destination, campaign, case, kind, raw_values,
            )
        else:
            missing.append(kind)
    projected = dict(existing)
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-cold-boot-projection.") as temporary:
        stage = Path(temporary); stage.chmod(0o700)
        snapshots = stage / "raw"; snapshots.mkdir(mode=0o700)
        outputs = stage / "observations"; outputs.mkdir(mode=0o700)
        snapshot_paths: dict[str, Path] = {}
        for kind, raw in raw_values.items():
            path = snapshots / f"{kind}.json"; write_snapshot(path, raw)
            snapshot_paths[kind] = path
        for kind in missing:
            artifacts = [
                [item, AUTHORITIES[item], str(snapshot_paths[item]), MEDIA_TYPE]
                for item in (kind, *SUPPORT[kind])
            ]
            result = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifacts, output_directory=outputs, now=now,
                output_mode=0o444,
            )
            projected[kind] = result["observation_sha256"]
        for kind in missing:
            name = f"{case_id}.{kind}.json"
            value = trusted_json(outputs / name)
            OBSERVER.write_new(observations / name, value, 0o444)
    descriptor = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    result = {
        "schema": SCHEMA, "status": "projected",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "observation_sha256": {
            kind: projected[kind] for kind in CASE_FILES[case_id]
        },
        "resumed_observation_kinds": [kind for kind in CASE_FILES[case_id]
                                       if kind in existing],
        "recorded_observation_kinds": missing,
        "candidate_authority": "none", "production_material_used": False,
    }
    result["driver_sha256"] = digest(result)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Collect or project Research cold-boot evidence")
    commands = value.add_subparsers(dest="command", required=True)
    collect_command = commands.add_parser("collect")
    project_command = commands.add_parser("project")
    for command in (collect_command, project_command):
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--observations", type=Path, required=True)
        command.add_argument("--case", required=True)
        command.add_argument("--operator-uid", type=int, required=True)
    collect_command.add_argument("--acknowledge", default="")
    return value


def fixed_raw_root(campaign_id: str) -> Path:
    if os.geteuid() != 0:
        raise ColdBootError("cold_boot_root_required")
    current = PROTECTED_STATE_ROOT
    for path in (current, current / campaign_id, current / campaign_id / "cold-boot"):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
        private_directory(path, "cold_boot_protected_state", 0)
    return current / campaign_id / "cold-boot"


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ColdBootError("cold_boot_root_context_required")
    campaign = validate_campaign(
        trusted_json(args.campaign, args.operator_uid), now,
    )
    raw_root = fixed_raw_root(campaign["campaign_id"])
    raw_directory = raw_root / args.case
    if args.command == "collect":
        result = collect(
            args.campaign, args.observations, args.case, raw_root,
            args.acknowledge, now, args.operator_uid,
        )
    else:
        result = project(
            args.campaign, args.observations, args.case, raw_directory, now,
            args.operator_uid,
        )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, ColdBootError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, (AcceptanceError, ColdBootError)) \
            else "cold_boot_io_failed"
        print(json.dumps({"schema": ERROR_SCHEMA, "status": "rejected", "error": reason},
                         ensure_ascii=True, separators=(",", ":"), sort_keys=True),
              file=sys.stderr)
        raise SystemExit(1)
