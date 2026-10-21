#!/usr/bin/env python3
"""Build sealed direct-dependency bundles from verified imported npm sources."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import sys
import syslog
import time
import uuid

from source_integrity import (
    IntegrityError,
    MAX_INDEX_BYTES,
    canonical,
    fixed_tree_path,
    load_control_json,
    registered_source,
    verify_source,
)

WORKSPACE = "/home/agent/research-workspace"
SOURCE_INDEX = f"{WORKSPACE}/repos/INDEX.json"
BUNDLE_ROOT = f"{WORKSPACE}/dependency-bundles"
BUNDLE_INDEX = f"{BUNDLE_ROOT}/INDEX.json"
STATE_ROOT = "/var/lib/secure-sandbox/dependency-orchestration"
PLAN_ROOT = f"{STATE_ROOT}/plans"
TRANSACTION_ROOT = f"{STATE_ROOT}/transactions"
LOCK = f"{STATE_ROOT}/orchestrator.lock"
RUN_MARKER = "/run/secure-sandbox/run-id"
LIFECYCLE_MARKERS = ("/var/lib/secure-sandbox/run-lifecycle/active.json",
                     "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json")
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
MAX_DEPENDENCIES = 64
MAX_BUNDLES = 256
MAX_PENDING_PLANS = 64
MAX_PLAN_RECORDS = MAX_BUNDLES + MAX_PENDING_PLANS
PLAN_TTL_SECONDS = 3600
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
NPM_PACKAGE_RE = re.compile(r"^@[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}$")
SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")


class DependencyError(ValueError):
    pass


def atomic_json(path: str, value: object, mode: int) -> None:
    temporary = f"{path}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        payload = canonical(value) + b"\n"
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short atomic JSON write")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def sync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def bundle_index() -> dict:
    value = load_control_json(BUNDLE_INDEX, 16 * 1024 * 1024)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-dependency-bundle-index-v1" or not isinstance(value.get("bundles"), list):
        raise DependencyError("invalid_bundle_index")
    if len(value["bundles"]) > MAX_BUNDLES:
        raise DependencyError("bundle_limit_exceeded")
    identifiers = []
    for item in value["bundles"]:
        if not isinstance(item, dict) or not UUID_RE.fullmatch(str(item.get("bundle_id", ""))):
            raise DependencyError("invalid_bundle_index")
        identifiers.append(item["bundle_id"])
    if len(identifiers) != len(set(identifiers)):
        raise DependencyError("invalid_bundle_index")
    return value


def bundle_manifest(bundle_id: str) -> dict:
    if not UUID_RE.fullmatch(bundle_id):
        raise DependencyError("invalid_bundle_id")
    directory = os.path.join(BUNDLE_ROOT, bundle_id)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise DependencyError("untrusted_dependency_bundle")
    value = load_control_json(os.path.join(directory, "manifest.json"), 1024 * 1024)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-dependency-bundle-v1" or value.get("bundle_id") != bundle_id:
        raise DependencyError("invalid_dependency_bundle")
    if not UUID_RE.fullmatch(str(value.get("plan_id", ""))):
        raise DependencyError("invalid_dependency_bundle")
    return value


def bundle_summary(manifest: dict) -> dict:
    return {
        "bundle_id": manifest["bundle_id"],
        "plan_id": manifest["plan_id"],
        "root_source_id": manifest["root_source_id"],
        "root_package_name": manifest["root_package_name"],
        "root_package_version": manifest["root_package_version"],
        "dependency_set_sha256": manifest["dependency_set_sha256"],
        "dependency_count": len(manifest["dependencies"]),
        "manifest_path": f"dependency-bundles/{manifest['bundle_id']}/manifest.json",
        "created_at": manifest["created_at"],
    }


def emit(event: str, *, plan_id: str = "", bundle_id: str = "", dependency_set_sha256: str = "", count: int = 0, missing: int = 0, error: str = "") -> None:
    record = {
        "event": event,
        "plan_id": plan_id,
        "bundle_id": bundle_id,
        "dependency_set_sha256": dependency_set_sha256,
        "dependency_count": count,
        "missing_count": missing,
        "error": error,
    }
    try:
        syslog.openlog("secure-sandbox-dependency-orchestrator", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if error else syslog.LOG_INFO, json.dumps(record, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def require_root_and_idle() -> None:
    if os.geteuid() != 0:
        raise DependencyError("root_required")
    if os.path.exists(RUN_MARKER) or any(os.path.exists(path) for path in LIFECYCLE_MARKERS):
        raise DependencyError("active_agent_run")


def read_package_json(record: dict) -> dict:
    baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
    path = os.path.join(baseline, "package.json")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > MAX_PACKAGE_JSON_BYTES:
        raise DependencyError("untrusted_package_manifest")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(descriptor, MAX_PACKAGE_JSON_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) != info.st_size or len(data) > MAX_PACKAGE_JSON_BYTES:
        raise DependencyError("untrusted_package_manifest")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as failure:
        raise DependencyError("invalid_package_manifest") from failure
    if not isinstance(value, dict):
        raise DependencyError("invalid_package_manifest")
    return value


def package_identity(source_id: str) -> tuple[dict, dict]:
    verification = verify_source(source_id, "baseline")
    if verification.get("anchor_status") != "import_validated" or verification.get("baseline", {}).get("status") != "match":
        raise DependencyError("source_not_verified")
    record = registered_source(source_id)
    if record.get("source_kind") != "npm_package":
        raise DependencyError("source_not_npm_package")
    name, version = record.get("package_name"), record.get("package_version")
    if not isinstance(name, str) or not NPM_PACKAGE_RE.fullmatch(name) or not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
        raise DependencyError("invalid_registered_package")
    package = read_package_json(record)
    if package.get("name") != name or package.get("version") != version:
        raise DependencyError("package_identity_mismatch")
    return record, package


def exact_dependencies(package: dict) -> list[dict]:
    dependencies = package.get("dependencies", {})
    if dependencies is None:
        dependencies = {}
    if not isinstance(dependencies, dict) or len(dependencies) > MAX_DEPENDENCIES:
        raise DependencyError("invalid_dependencies")
    result = []
    for name in sorted(dependencies):
        version = dependencies[name]
        if not isinstance(name, str) or not NPM_PACKAGE_RE.fullmatch(name):
            raise DependencyError("unsupported_dependency_name")
        if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
            raise DependencyError("non_exact_dependency_version")
        result.append({"name": name, "version": version})
    return result


def source_records() -> list[dict]:
    value = load_control_json(SOURCE_INDEX, MAX_INDEX_BYTES)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-source-registry-v1" or not isinstance(value.get("sources"), list):
        raise DependencyError("invalid_source_index")
    return [record for record in value["sources"] if isinstance(record, dict)]


def resolve_dependencies(dependencies: list[dict]) -> list[dict]:
    records = source_records()
    resolved = []
    for dependency in dependencies:
        matches = [record for record in records if (
            record.get("source_kind") == "npm_package"
            and record.get("package_name") == dependency["name"]
            and record.get("package_version") == dependency["version"]
            and record.get("registry_integrity_verified") is True
        )]
        if len(matches) > 1:
            raise DependencyError("ambiguous_dependency_source")
        item = dict(dependency)
        item["source_id"] = matches[0].get("source_id") if matches else None
        if matches:
            verified_record, _ = package_identity(str(item["source_id"]))
            if verified_record.get("package_name") != dependency["name"] or verified_record.get("package_version") != dependency["version"]:
                raise DependencyError("dependency_source_identity_mismatch")
            item["npm_integrity"] = matches[0].get("npm_integrity")
            item["tree_manifest_sha256"] = matches[0].get("tree_manifest_sha256")
        resolved.append(item)
    return resolved


def dependency_digest(source_id: str, root_tree_hash: str, dependencies: list[dict]) -> str:
    identity = {
        "schema": "secure-sandbox-dependency-set-v1",
        "root_source_id": source_id,
        "root_tree_manifest_sha256": root_tree_hash,
        "dependencies": [{"name": item["name"], "version": item["version"]} for item in dependencies],
    }
    return hashlib.sha256(canonical(identity)).hexdigest()


def prune_and_count_plans(now: int) -> tuple[int, int]:
    records = []
    for entry in os.scandir(PLAN_ROOT):
        match = re.fullmatch(r"([0-9a-f-]{36})\.json", entry.name)
        if not match or not entry.is_file(follow_symlinks=False) or not UUID_RE.fullmatch(match.group(1)):
            continue
        records.append((entry.path, load_plan(match.group(1))))
    expired = [
        path for path, value in records
        if value.get("state") == "planned"
        and int(value.get("expires_unix", 0)) < now
        and not os.path.exists(transaction_path(str(value.get("plan_id", ""))))
    ]
    for path in expired:
        os.unlink(path)
    if expired:
        sync_directory(PLAN_ROOT)
    retained = [(path, value) for path, value in records if path not in set(expired)]
    pending = sum(value.get("state") == "planned" for _, value in retained)
    return len(retained), pending


def _plan_locked(source_id: str) -> dict:
    now = int(time.time())
    total, pending = prune_and_count_plans(now)
    if total >= MAX_PLAN_RECORDS:
        raise DependencyError("plan_record_limit_reached")
    if pending >= MAX_PENDING_PLANS:
        raise DependencyError("pending_plan_limit_reached")
    if len(bundle_index()["bundles"]) >= MAX_BUNDLES:
        raise DependencyError("bundle_limit_reached")
    root_record, package = package_identity(source_id)
    dependencies = exact_dependencies(package)
    resolved = resolve_dependencies(dependencies)
    plan_id = str(uuid.uuid4())
    digest = dependency_digest(source_id, str(root_record["tree_manifest_sha256"]), dependencies)
    value = {
        "schema": "secure-sandbox-dependency-plan-v1",
        "plan_id": plan_id,
        "root_source_id": source_id,
        "root_package_name": root_record["package_name"],
        "root_package_version": root_record["package_version"],
        "root_tree_manifest_sha256": root_record["tree_manifest_sha256"],
        "dependency_set_sha256": digest,
        "dependencies": resolved,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expires_unix": now + PLAN_TTL_SECONDS,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + PLAN_TTL_SECONDS)),
        "state": "planned",
        "policy_version": "dependency-orchestration-v1",
    }
    atomic_json(f"{PLAN_ROOT}/{plan_id}.json", value, 0o600)
    missing = sum(item["source_id"] is None for item in resolved)
    emit("dependency_plan_created", plan_id=plan_id, dependency_set_sha256=digest, count=len(resolved), missing=missing)
    return value


def plan(source_id: str) -> dict:
    require_root_and_idle()
    with open(LOCK, "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as failure:
            raise DependencyError("dependency_operation_in_progress") from failure
        return _plan_locked(source_id)


def load_plan(plan_id: str) -> dict:
    if not isinstance(plan_id, str) or not UUID_RE.fullmatch(plan_id):
        raise DependencyError("invalid_plan_id")
    value = load_control_json(f"{PLAN_ROOT}/{plan_id}.json", 1024 * 1024)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-dependency-plan-v1" or value.get("plan_id") != plan_id:
        raise DependencyError("invalid_dependency_plan")
    return value


def status(plan_id: str) -> dict:
    value = load_plan(plan_id)
    dependencies = resolve_dependencies([
        {"name": item.get("name"), "version": item.get("version")}
        for item in value.get("dependencies", []) if isinstance(item, dict)
    ])
    return {
        "plan_id": plan_id,
        "state": value.get("state"),
        "expires_at": value.get("expires_at"),
        "dependency_set_sha256": value.get("dependency_set_sha256"),
        "dependencies": dependencies,
        "missing": [{"name": item["name"], "version": item["version"]} for item in dependencies if item["source_id"] is None],
    }


def package_link_path(node_modules: str, package_name: str) -> str:
    parts = package_name.split("/")
    destination = os.path.join(node_modules, *parts)
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    return destination


def transaction_path(plan_id: str) -> str:
    return os.path.join(TRANSACTION_ROOT, f"{plan_id}.json")


def remove_transaction(plan_id: str) -> None:
    try:
        os.unlink(transaction_path(plan_id))
    except FileNotFoundError:
        return
    sync_directory(TRANSACTION_ROOT)


def cleanup_temporary_bundles() -> None:
    removed = False
    for entry in os.scandir(BUNDLE_ROOT):
        if not re.fullmatch(r"\.bundle-[0-9a-f-]{36}\.new", entry.name):
            continue
        info = entry.stat(follow_symlinks=False)
        bundle_id = entry.name[len(".bundle-"):-len(".new")]
        if not UUID_RE.fullmatch(bundle_id) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise DependencyError("untrusted_temporary_bundle")
        shutil.rmtree(entry.path)
        removed = True
    if removed:
        sync_directory(BUNDLE_ROOT)


def matching_bundles(plan_id: str) -> list[dict]:
    manifests = []
    directories = 0
    for entry in os.scandir(BUNDLE_ROOT):
        if not UUID_RE.fullmatch(entry.name):
            continue
        directories += 1
        if directories > MAX_BUNDLES:
            raise DependencyError("bundle_directory_limit_exceeded")
        manifest = bundle_manifest(entry.name)
        if manifest.get("plan_id") == plan_id:
            manifests.append(manifest)
    return manifests


def validate_manifest_plan(manifest: dict, value: dict) -> None:
    expected = {
        "plan_id": value.get("plan_id"),
        "root_source_id": value.get("root_source_id"),
        "root_package_name": value.get("root_package_name"),
        "root_package_version": value.get("root_package_version"),
        "root_tree_manifest_sha256": value.get("root_tree_manifest_sha256"),
        "dependency_set_sha256": value.get("dependency_set_sha256"),
    }
    if any(manifest.get(key) != item for key, item in expected.items()):
        raise DependencyError("bundle_plan_binding_mismatch")
    if manifest.get("scope") != "direct_runtime_dependencies" or manifest.get("lifecycle_execution") != "disabled" or manifest.get("transitive_completeness") is not False:
        raise DependencyError("invalid_dependency_bundle")
    if not isinstance(manifest.get("dependencies"), list) or len(manifest["dependencies"]) > MAX_DEPENDENCIES:
        raise DependencyError("invalid_dependency_bundle")


def recover_plan(value: dict, index: dict) -> tuple[dict | None, dict]:
    plan_id = str(value.get("plan_id", ""))
    path = transaction_path(plan_id)
    transaction = None
    if os.path.exists(path):
        transaction = load_control_json(path, 1024 * 1024)
        if not isinstance(transaction, dict) or transaction.get("schema") != "secure-sandbox-dependency-transaction-v1" or transaction.get("plan_id") != plan_id or not UUID_RE.fullmatch(str(transaction.get("bundle_id", ""))):
            raise DependencyError("invalid_dependency_transaction")
    if transaction is not None:
        destination = os.path.join(BUNDLE_ROOT, transaction["bundle_id"])
        manifests = [bundle_manifest(transaction["bundle_id"])] if os.path.exists(destination) else []
        if manifests and manifests[0].get("plan_id") != plan_id:
            raise DependencyError("bundle_plan_binding_mismatch")
    else:
        manifests = matching_bundles(plan_id)
    if len(manifests) > 1:
        raise DependencyError("ambiguous_plan_bundle")
    if not manifests:
        if transaction is not None:
            remove_transaction(plan_id)
        return None, index
    manifest = manifests[0]
    validate_manifest_plan(manifest, value)
    bundle_id = manifest["bundle_id"]
    indexed = [item for item in index["bundles"] if item.get("bundle_id") == bundle_id]
    if len(indexed) > 1:
        raise DependencyError("invalid_bundle_index")
    summary = bundle_summary(manifest)
    if indexed:
        if indexed[0].get("plan_id") not in (None, plan_id):
            raise DependencyError("bundle_index_inconsistent")
        for key in ("root_source_id", "root_package_name", "root_package_version", "dependency_set_sha256", "dependency_count", "manifest_path", "created_at"):
            if indexed[0].get(key) != summary[key]:
                raise DependencyError("bundle_index_inconsistent")
    else:
        if len(index["bundles"]) >= MAX_BUNDLES:
            raise DependencyError("bundle_limit_reached")
        index = {"schema": index["schema"], "bundles": [*index["bundles"], summary]}
        atomic_json(BUNDLE_INDEX, index, 0o444)
    if value.get("state") != "completed" or value.get("bundle_id") != bundle_id:
        completed = dict(value)
        completed["state"] = "completed"
        completed["bundle_id"] = bundle_id
        completed["completed_at"] = manifest["created_at"]
        atomic_json(f"{PLAN_ROOT}/{plan_id}.json", completed, 0o600)
    if transaction is not None:
        remove_transaction(plan_id)
    return manifest, index


def _apply_locked(plan_id: str) -> dict:
    value = load_plan(plan_id)
    cleanup_temporary_bundles()
    index = bundle_index()
    transaction_exists = os.path.exists(transaction_path(plan_id))
    if value.get("state") == "planned" or transaction_exists:
        recovered, index = recover_plan(value, index)
        if recovered is not None:
            emit("dependency_bundle_completed", plan_id=plan_id, bundle_id=recovered["bundle_id"], dependency_set_sha256=recovered["dependency_set_sha256"], count=len(recovered["dependencies"]))
            return recovered
    if value.get("state") != "planned":
        raise DependencyError("plan_not_available")
    if int(value.get("expires_unix", 0)) < int(time.time()):
        raise DependencyError("plan_expired")
    if len(index["bundles"]) >= MAX_BUNDLES:
        raise DependencyError("bundle_limit_reached")
    root_record, package = package_identity(str(value.get("root_source_id", "")))
    dependencies = exact_dependencies(package)
    digest = dependency_digest(str(value["root_source_id"]), str(root_record["tree_manifest_sha256"]), dependencies)
    if digest != value.get("dependency_set_sha256") or root_record.get("tree_manifest_sha256") != value.get("root_tree_manifest_sha256"):
        raise DependencyError("dependency_plan_binding_mismatch")
    resolved = resolve_dependencies(dependencies)
    missing = [item for item in resolved if item["source_id"] is None]
    if missing:
        emit("dependency_bundle_rejected", plan_id=plan_id, dependency_set_sha256=digest, count=len(resolved), missing=len(missing), error="dependency_sources_missing")
        raise DependencyError("dependency_sources_missing")
    bundle_id = str(uuid.uuid4())
    temporary = f"{BUNDLE_ROOT}/.bundle-{bundle_id}.new"
    destination = f"{BUNDLE_ROOT}/{bundle_id}"
    os.mkdir(temporary, 0o700)
    published = False
    try:
        node_modules = os.path.join(temporary, "node_modules")
        os.mkdir(node_modules, 0o700)
        root_baseline = fixed_tree_path(root_record.get("baseline_path"), "baselines")
        os.symlink(os.path.relpath(root_baseline, temporary), os.path.join(temporary, "root-package"))
        for item in resolved:
            record = registered_source(str(item["source_id"]))
            baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
            link = package_link_path(node_modules, item["name"])
            os.symlink(os.path.relpath(baseline, os.path.dirname(link)), link)
        manifest = {
            "schema": "secure-sandbox-dependency-bundle-v1",
            "bundle_id": bundle_id,
            "plan_id": plan_id,
            "root_source_id": value["root_source_id"],
            "root_package_name": value["root_package_name"],
            "root_package_version": value["root_package_version"],
            "root_tree_manifest_sha256": value["root_tree_manifest_sha256"],
            "dependency_set_sha256": digest,
            "dependencies": resolved,
            "scope": "direct_runtime_dependencies",
            "lifecycle_execution": "disabled",
            "transitive_completeness": False,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "policy_version": "dependency-orchestration-v1",
        }
        atomic_json(os.path.join(temporary, "manifest.json"), manifest, 0o444)
        for current, directories, files in os.walk(temporary, topdown=False, followlinks=False):
            for name in files:
                os.chown(os.path.join(current, name), 0, 0, follow_symlinks=False)
                os.chmod(os.path.join(current, name), 0o444, follow_symlinks=False)
            for name in directories:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    os.chown(path, 0, 0)
                    os.chmod(path, 0o555)
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o555)
        atomic_json(transaction_path(plan_id), {
            "schema": "secure-sandbox-dependency-transaction-v1",
            "plan_id": plan_id,
            "bundle_id": bundle_id,
            "created_at": manifest["created_at"],
        }, 0o600)
        os.replace(temporary, destination)
        published = True
        sync_directory(BUNDLE_ROOT)
    except Exception:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    summary = bundle_summary(manifest)
    updated_index = {"schema": index["schema"], "bundles": [*index["bundles"], summary]}
    atomic_json(BUNDLE_INDEX, updated_index, 0o444)
    completed_plan = dict(value)
    completed_plan["state"] = "completed"
    completed_plan["bundle_id"] = bundle_id
    completed_plan["completed_at"] = manifest["created_at"]
    atomic_json(f"{PLAN_ROOT}/{plan_id}.json", completed_plan, 0o600)
    remove_transaction(plan_id)
    emit("dependency_bundle_completed", plan_id=plan_id, bundle_id=bundle_id, dependency_set_sha256=digest, count=len(resolved))
    return manifest


def apply(plan_id: str) -> dict:
    require_root_and_idle()
    with open(LOCK, "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as failure:
            raise DependencyError("dependency_operation_in_progress") from failure
        return _apply_locked(plan_id)


def list_bundles() -> dict:
    return bundle_index()


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    planner = subparsers.add_parser("plan")
    planner.add_argument("source_id")
    checker = subparsers.add_parser("status")
    checker.add_argument("plan_id")
    applier = subparsers.add_parser("apply")
    applier.add_argument("plan_id")
    subparsers.add_parser("list")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            output = plan(args.source_id)
        elif args.command == "status":
            output = status(args.plan_id)
        elif args.command == "apply":
            output = apply(args.plan_id)
        else:
            output = list_bundles()
        print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    except (DependencyError, IntegrityError, OSError, ValueError) as failure:
        detail = str(failure)
        error = detail if re.fullmatch(r"[a-z0-9_]{1,80}", detail) else "dependency_orchestration_failed"
        print(json.dumps({"status": "rejected", "error": error}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
