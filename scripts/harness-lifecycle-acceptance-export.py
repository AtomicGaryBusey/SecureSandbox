#!/usr/bin/env python3
"""Create the final evidence observations and copy a verified export off-host."""

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
    if effective_uid != 0:
        return
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROTECTED_RELEASES)
    except ValueError as error:
        raise SystemExit("export_driver_protected_invocation_required") from error
    if (len(relative.parts) != 3 or relative.parts[1:] != ("scripts", path.name)
            or len(relative.parts[0]) != 40
            or any(character not in "0123456789abcdef" for character in relative.parts[0])):
        raise SystemExit("export_driver_protected_invocation_required")


if __name__ == "__main__":
    require_protected_main_path(Path(__file__), os.geteuid())


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASES,
    CASE_BY_ID,
    canonical,
    case_record,
    digest,
    assemble_export,
    validate_campaign,
    validate_observation,
    verdict,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-export-driver-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-export-error-v1"
EXPORT_READBACK_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-export-readback-v1"
INDEPENDENCE_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-candidate-independence-v1"
CASE_ID = "independent-evidence-export"
DRIVER = "independent-export-fixture"
MEDIA_TYPE = "application/json"
PROTECTED_ROOT = PROTECTED_RELEASES.parent
PROTECTED_STATE_ROOT = Path("/var/db/SecureSandbox/harness-lifecycle-acceptance")
EXPORT_FILENAME = "secure-sandbox-harness-lifecycle-acceptance-export.json"
VERDICT_FILENAME = "secure-sandbox-harness-lifecycle-acceptance-verdict.json"
KINDS = ("export-readback", "candidate-independence-readback")
PRIOR_NAMES = [
    f"{case.case_id}.{kind}.json"
    for case in CASES if case.case_id != CASE_ID for kind in case.evidence_kinds
]


class ExportDriverError(RuntimeError):
    """Stable, content-free independent-export failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ExportDriverError("export_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI = load_script(
    "harness_lifecycle_acceptance_export_cli",
    ROOT / "scripts/harness-lifecycle-acceptance.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_export_observer",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)


def private_directory(path: Path, label: str, uid: int) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise ExportDriverError(f"{label}_untrusted")
    return info


def fixed_raw_root(campaign_id: str) -> Path:
    if os.geteuid() != 0:
        raise ExportDriverError("export_root_required")
    current = PROTECTED_STATE_ROOT
    for path in (current, current / campaign_id, current / campaign_id / "export"):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
        private_directory(path, "export_protected_state", 0)
    return current / campaign_id / "export"


def preflight(campaign_path: Path, observations: Path, operator_uid: int,
              now: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        campaign = validate_campaign(
            CLI.trusted_json(campaign_path, expected_uid=operator_uid), now,
        )
        manifest = CLI.verify_protected_driver(
            PROTECTED_ROOT, campaign["source_commit"], DRIVER, 0,
        )
        pending = CLI.next_case(
            campaign, observations, observation_uid=0, directory_uid=operator_uid,
        )
    except (AcceptanceError, OSError) as error:
        raise ExportDriverError("export_preflight_failed") from error
    case = pending.get("case")
    if pending.get("status") == "complete" and case is None:
        case = case_record(CASE_BY_ID[CASE_ID])
    missing = pending.get("missing_evidence")
    missing_kinds = [item.get("kind") for item in missing] \
        if isinstance(missing, list) and all(isinstance(item, dict) for item in missing) else []
    if (not isinstance(case, dict) or case.get("case_id") != CASE_ID
            or case.get("category") != "evidence"
            or case.get("procedure", {}).get("driver") != DRIVER
            or case.get("evidence_kinds") != list(KINDS)
            or (pending.get("status") == "pending" and (
                not missing_kinds
                or missing_kinds != [kind for kind in KINDS if kind in missing_kinds]
                or any(item.get("collector") != "secure-sandbox-evidence-exporter-v1"
                       for item in missing)
            ))
            or pending.get("status") not in {"pending", "complete"}):
        raise ExportDriverError("export_case_not_next")
    return campaign, case, manifest


def prior_inventory(campaign: dict[str, Any], observations: Path,
                    operator_uid: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    private_directory(observations, "export_observations", operator_uid)
    final_names = {f"{CASE_ID}.{kind}.json" for kind in KINDS}
    expected = [
        (case, kind, f"{case.case_id}.{kind}.json")
        for case in CASES if case.case_id != CASE_ID for kind in case.evidence_kinds
    ]
    entries = {item.name: item for item in observations.iterdir()}
    prior_names = {name for _, _, name in expected}
    if not prior_names.issubset(entries) or not set(entries).issubset(prior_names | final_names):
        raise ExportDriverError("export_prior_inventory_invalid")
    values: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for case, kind, name in expected:
        try:
            value = CLI.trusted_json(entries[name], expected_uid=0)
            validate_observation(value, campaign, case)
        except (AcceptanceError, OSError) as error:
            raise ExportDriverError("export_prior_observation_invalid") from error
        if value["kind"] != kind:
            raise ExportDriverError("export_prior_filename_binding_invalid")
        values.append(value)
        records.append({
            "name": name, "observation_sha256": value["observation_sha256"],
            "file_sha256": hashlib.sha256(canonical(value)).hexdigest(),
        })
    return values, records


def common(campaign: dict[str, Any], case: dict[str, Any], now: int,
           schema: str, status: str) -> dict[str, Any]:
    return {
        "schema": schema, "status": status,
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"], "case_id": CASE_ID,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observed_at": now, "candidate_authority": "none",
        "production_material_used": False,
    }


def make_raw(campaign: dict[str, Any], case: dict[str, Any], manifest: dict[str, Any],
             records: list[dict[str, Any]], now: int) -> dict[str, dict[str, Any]]:
    inventory_sha256 = digest(records)
    names_sha256 = digest([item["name"] for item in records])
    export_readback = {
        **common(campaign, case, now, EXPORT_READBACK_SCHEMA, "verified"),
        "prior_observation_count": len(records),
        "expected_final_observation_count": sum(len(item.evidence_kinds) for item in CASES),
        "prior_observation_inventory_sha256": inventory_sha256,
        "prior_observation_names_sha256": names_sha256,
        "receipt_order": [item.case_id for item in CASES],
        "assembly_ready_after_projection": True,
    }
    export_readback["readback_sha256"] = digest(export_readback)
    independence = {
        **common(campaign, case, now, INDEPENDENCE_SCHEMA, "verified"),
        "protected_manifest_sha256": manifest["manifest_sha256"],
        "exporter_payload_sha256": next(
            item["sha256"] for item in manifest["files"]
            if item["path"] == "scripts/harness-lifecycle-acceptance-export.py"
        ),
        "candidate_statement_used": False,
        "candidate_executable_invoked": False,
        "candidate_network_used": False,
        "provider_credentials_read": False,
        "lifecycle_mutation_performed": False,
        "export_authority": "acceptance-evidence-only",
    }
    independence["independence_sha256"] = digest(independence)
    return {"export-readback": export_readback,
            "candidate-independence-readback": independence}


def validate_raw(campaign: dict[str, Any], case: dict[str, Any],
                 values: dict[str, dict[str, Any]], now: int) -> None:
    export = values.get("export-readback"); independence = values.get(
        "candidate-independence-readback",
    )
    if not isinstance(export, dict) or not isinstance(independence, dict):
        raise ExportDriverError("export_raw_invalid")
    export_unsigned = {name: item for name, item in export.items()
                       if name != "readback_sha256"}
    independence_unsigned = {name: item for name, item in independence.items()
                             if name != "independence_sha256"}
    expected_prior = sum(len(item.evidence_kinds) for item in CASES) - len(KINDS)
    common_fields = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "procedure_sha256",
        "observed_at", "candidate_authority", "production_material_used",
    }
    export_fields = common_fields | {
        "prior_observation_count", "expected_final_observation_count",
        "prior_observation_inventory_sha256", "prior_observation_names_sha256",
        "receipt_order", "assembly_ready_after_projection", "readback_sha256",
    }
    independence_fields = common_fields | {
        "protected_manifest_sha256", "exporter_payload_sha256",
        "candidate_statement_used", "candidate_executable_invoked",
        "candidate_network_used", "provider_credentials_read",
        "lifecycle_mutation_performed", "export_authority", "independence_sha256",
    }
    common_valid = all(
        value.get("campaign_id") == campaign["campaign_id"]
        and value.get("campaign_sha256") == campaign["campaign_sha256"]
        and value.get("machine_identity_sha256") == campaign["machine_identity_sha256"]
        and value.get("source_commit") == campaign["source_commit"]
        and value.get("case_id") == CASE_ID
        and value.get("procedure_sha256") == case["procedure"]["procedure_sha256"]
        and isinstance(value.get("observed_at"), int)
        and campaign["created_at"] <= value["observed_at"] < campaign["expires_at"]
        and value["observed_at"] <= now + 300
        and value.get("candidate_authority") == "none"
        and value.get("production_material_used") is False
        for value in (export, independence)
    )
    if (not common_valid or set(export) != export_fields
            or set(independence) != independence_fields
            or export.get("schema") != EXPORT_READBACK_SCHEMA
            or export.get("status") != "verified"
            or export.get("prior_observation_count") != expected_prior
            or export.get("expected_final_observation_count") != expected_prior + 2
            or any(not isinstance(export.get(name), str)
                   or len(export[name]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in export[name])
                   for name in ("prior_observation_inventory_sha256",
                                "prior_observation_names_sha256"))
            or export.get("prior_observation_names_sha256") != digest(PRIOR_NAMES)
            or export.get("receipt_order") != [item.case_id for item in CASES]
            or export.get("assembly_ready_after_projection") is not True
            or export.get("readback_sha256") != digest(export_unsigned)
            or independence.get("schema") != INDEPENDENCE_SCHEMA
            or independence.get("status") != "verified"
            or any(independence.get(name) is not False for name in (
                "candidate_statement_used", "candidate_executable_invoked",
                "candidate_network_used", "provider_credentials_read",
                "lifecycle_mutation_performed",
            ))
            or independence.get("export_authority") != "acceptance-evidence-only"
            or any(not isinstance(independence.get(name), str)
                   or len(independence[name]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in independence[name])
                   for name in ("protected_manifest_sha256", "exporter_payload_sha256"))
            or independence.get("independence_sha256") != digest(independence_unsigned)):
        raise ExportDriverError("export_raw_invalid")


def write_root_raw(path: Path, value: dict[str, Any]) -> None:
    payload = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ExportDriverError("export_raw_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def raw_values(raw: Path, expected: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not os.path.lexists(raw):
        private_directory(raw.parent, "export_raw_root", 0)
        temporary = Path(tempfile.mkdtemp(
            dir=raw.parent, prefix=".independent-evidence-export.new.",
        ))
        temporary.chmod(0o700)
        for kind in KINDS:
            write_root_raw(temporary / f"{kind}.json", expected[kind])
        descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, raw)
        descriptor = os.open(raw.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return expected
    private_directory(raw, "export_raw_case", 0)
    entries = {item.name: item for item in raw.iterdir()}
    if set(entries) != {f"{kind}.json" for kind in KINDS}:
        raise ExportDriverError("export_raw_inventory_invalid")
    observed = {
        kind: CLI.trusted_json(entries[f"{kind}.json"], expected_uid=0)
        for kind in KINDS
    }
    if (observed["export-readback"].get("prior_observation_inventory_sha256")
            != expected["export-readback"]["prior_observation_inventory_sha256"]
            or observed["candidate-independence-readback"].get(
                "protected_manifest_sha256",
            ) != expected["candidate-independence-readback"]["protected_manifest_sha256"]
            or observed["candidate-independence-readback"].get(
                "exporter_payload_sha256",
            ) != expected["candidate-independence-readback"]["exporter_payload_sha256"]):
        raise ExportDriverError("export_raw_resume_mismatch")
    return observed


def existing_final(path: Path, campaign: dict[str, Any], kind: str,
                   raw_value: dict[str, Any]) -> None:
    try:
        value = CLI.trusted_json(path, expected_uid=0)
        validate_observation(value, campaign, CASE_BY_ID[CASE_ID])
    except (AcceptanceError, OSError) as error:
        raise ExportDriverError("export_existing_observation_invalid") from error
    artifacts = value.get("evidence", {}).get("artifacts")
    raw_sha256 = hashlib.sha256(canonical(raw_value)).hexdigest()
    if (value.get("kind") != kind or not isinstance(artifacts, list)
            or len(artifacts) != 1 or artifacts[0].get("name") != kind
            or artifacts[0].get("authority") != "evidence-exporter"
            or artifacts[0].get("sha256") != raw_sha256):
        raise ExportDriverError("export_existing_observation_mismatch")


def write_operator_file(path: Path, value: dict[str, Any], operator_uid: int) -> None:
    payload = canonical(value)
    temporary = path.parent / f".{path.name}.new"
    if os.path.lexists(temporary):
        info = temporary.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid not in {0, operator_uid} or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400):
            raise ExportDriverError("export_output_temporary_untrusted")
        temporary.unlink()
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400,
    )
    try:
        os.fchown(descriptor, operator_uid, -1)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ExportDriverError("export_output_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()


def publish_operator_file(path: Path, value: dict[str, Any], operator_uid: int,
                          maximum: int) -> None:
    if os.path.lexists(path):
        try:
            observed = CLI.trusted_json(path, maximum, expected_uid=operator_uid)
        except (AcceptanceError, OSError) as error:
            raise ExportDriverError("export_existing_output_untrusted") from error
        if observed != value:
            raise ExportDriverError("export_existing_output_mismatch")
        return
    write_operator_file(path, value, operator_uid)


def all_observations(campaign: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    values = []
    for case in CASES:
        for kind in case.evidence_kinds:
            value = CLI.trusted_json(
                path / f"{case.case_id}.{kind}.json", expected_uid=0,
            )
            validate_observation(value, campaign, case)
            if value["kind"] != kind:
                raise ExportDriverError("export_observation_binding_invalid")
            values.append(value)
    return values


def run(campaign_path: Path, observations: Path, output_directory: Path,
        operator_uid: int, now: int) -> dict[str, Any]:
    campaign, case, manifest = preflight(
        campaign_path, observations, operator_uid, now,
    )
    _, records = prior_inventory(campaign, observations, operator_uid)
    output_info = private_directory(output_directory, "export_output_directory", operator_uid)
    observation_info = private_directory(observations, "export_observations", operator_uid)
    if output_info.st_dev == observation_info.st_dev:
        raise ExportDriverError("export_output_not_off_host_volume")
    allowed_output_names = {
        EXPORT_FILENAME, VERDICT_FILENAME,
        f".{EXPORT_FILENAME}.new", f".{VERDICT_FILENAME}.new",
    }
    if any(item.name not in allowed_output_names
           for item in output_directory.iterdir()):
        raise ExportDriverError("export_output_directory_not_empty")
    raw = fixed_raw_root(campaign["campaign_id"]) / CASE_ID
    expected_values = make_raw(campaign, case, manifest, records, now)
    values = raw_values(raw, expected_values)
    validate_raw(campaign, case, values, now)

    with tempfile.TemporaryDirectory(prefix="secure-sandbox-export-projection.") as temporary:
        stage = Path(temporary); stage.chmod(0o700)
        for kind in KINDS:
            destination = observations / f"{CASE_ID}.{kind}.json"
            if os.path.lexists(destination):
                existing_final(destination, campaign, kind, values[kind])
                continue
            result = OBSERVER.observe(
                campaign=campaign, case_id=CASE_ID, kind=kind,
                artifact_arguments=[
                    [kind, "evidence-exporter", str(raw / f"{kind}.json"), MEDIA_TYPE],
                ], output_directory=stage, now=now, output_mode=0o444,
            )
            if result["kind"] != kind:
                raise ExportDriverError("export_projection_invalid")
        for kind in KINDS:
            name = f"{CASE_ID}.{kind}.json"
            if not os.path.lexists(stage / name):
                continue
            value = CLI.trusted_json(stage / name, expected_uid=0)
            OBSERVER.write_new(observations / name, value, 0o444)
    directory = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

    export_path = output_directory / EXPORT_FILENAME
    if os.path.lexists(export_path):
        try:
            exported = CLI.trusted_json(
                export_path, 32 * 1024 * 1024, expected_uid=operator_uid,
            )
            accepted = verdict(exported, now)
        except (AcceptanceError, OSError) as error:
            raise ExportDriverError("export_existing_output_untrusted") from error
    else:
        exported = assemble_export(campaign, all_observations(campaign, observations), now)
        accepted = verdict(exported, now)
    publish_operator_file(
        export_path, exported, operator_uid, 32 * 1024 * 1024,
    )
    publish_operator_file(
        output_directory / VERDICT_FILENAME, accepted, operator_uid, 64 * 1024,
    )
    directory = os.open(output_directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    result = {
        "schema": SCHEMA, "status": "exported",
        "campaign_id": campaign["campaign_id"],
        "export_sha256": exported["export_sha256"],
        "verdict_sha256": accepted["verdict_sha256"],
        "output_directory": str(output_directory),
        "candidate_authority": "none", "production_material_used": False,
    }
    result["driver_sha256"] = digest(result)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Finalize and export acceptance evidence")
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    value.add_argument("--operator-uid", type=int, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ExportDriverError("export_root_context_required")
    result = run(
        args.campaign, args.observations, args.output_directory,
        args.operator_uid, int(time.time()),
    )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, ExportDriverError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ExportDriverError) else "export_failed"
        print(json.dumps({"schema": ERROR_SCHEMA, "status": "rejected", "error": reason},
                         ensure_ascii=True, separators=(",", ":"), sort_keys=True),
              file=sys.stderr)
        raise SystemExit(1)
