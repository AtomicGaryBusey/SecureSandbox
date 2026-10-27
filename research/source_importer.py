#!/usr/bin/env python3
"""Validate, stage, and publish hostile source archives without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import struct
import subprocess
import sys
import syslog
import tarfile
import tempfile
import time
import unicodedata
import uuid

WORKSPACE = "/home/agent/research-workspace"
BASELINES = f"{WORKSPACE}/baselines"
REPOS = f"{WORKSPACE}/repos"
MANIFESTS = f"{WORKSPACE}/source-manifests"
ROOT = "/var/lib/secure-sandbox/source-acquisition"
STAGING = f"{ROOT}/staging"
REGISTRY = f"{ROOT}/registry.json"
OUTBOX = "/var/lib/secure-sandbox/conversation-outbox"
RECIPIENT_FILE = "/etc/secure-sandbox/conversation-recipient.txt"
AGE = "/usr/local/bin/age"
RUN_MARKER = "/run/secure-sandbox/run-id"
LIFECYCLE_MARKERS = ("/var/lib/secure-sandbox/run-lifecycle/active.json",
                     "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_PATH_BYTES = 240
MAX_COMPONENTS = 32
PUBLICATION_SCHEMA = "secure-sandbox-source-publication-transaction-v1"
MAX_PUBLICATION_TRANSACTION_BYTES = 2 * 1024 * 1024
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NPM_PACKAGE_RE = re.compile(r"^@[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}$")
SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")


def emit(value: dict) -> None:
    value = dict(value)
    try:
        with open(RUN_MARKER, encoding="ascii") as handle:
            run_id = handle.read(64).strip()
    except OSError:
        run_id = "preflight"
    value["run_id"] = run_id if run_id == "boundary-test" or UUID_RE.fullmatch(run_id) else "preflight"
    rendered = json.dumps(value, separators=(",", ":"), sort_keys=True)
    try:
        syslog.openlog("secure-sandbox-source-importer", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if value.get("event") == "source_import_rejected" else syslog.LOG_INFO, rendered)
    except Exception:
        pass
    print(rendered, flush=True)


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def atomic_json(path: str, value: object, mode: int = 0o600) -> None:
    temporary = path + ".new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        data = canonical(value) + b"\n"
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short atomic JSON write")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def sync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(path: str) -> None:
    for current, directories, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            item = os.path.join(current, name)
            info = os.lstat(item)
            if not stat.S_ISREG(info.st_mode):
                continue
            descriptor = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        sync_directory(current)


def publication_transaction_path(source_id: str) -> str:
    return os.path.join(ROOT, f"publication-{source_id}.transaction.json")


def publication_identity(path: str) -> dict[str, int | str]:
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        raise ValueError("publication_artifact_type_invalid")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "kind": kind}


def validate_publication_identity(path: str, expected: dict) -> None:
    try:
        observed = publication_identity(path)
    except FileNotFoundError as error:
        raise ValueError("publication_recovery_artifact_missing") from error
    if observed != expected:
        raise ValueError("publication_recovery_identity_mismatch")


def bounded_json(path: str, maximum: int) -> object:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in {0o444, 0o600}
                or info.st_size < 2 or info.st_size > maximum):
            raise ValueError("publication_transaction_invalid")
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != info.st_size:
            raise ValueError("publication_transaction_invalid")
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("publication_transaction_invalid") from error


def remove_publication_path(path: str, expected_uid: int) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if info.st_uid != expected_uid or stat.S_ISLNK(info.st_mode):
        raise ValueError("publication_recovery_identity_mismatch")
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    elif stat.S_ISREG(info.st_mode):
        os.unlink(path)
    else:
        raise ValueError("publication_recovery_identity_mismatch")
    sync_directory(os.path.dirname(path))


def registry_digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_publication_layout(source_id: str, transaction: dict) -> None:
    record = transaction["record"]
    worktree_path = record.get("worktree_path")
    if (record.get("source_id") != source_id or not isinstance(worktree_path, str)
            or not worktree_path.startswith("repos/") or "/" in worktree_path[6:]):
        raise ValueError("publication_transaction_invalid")
    expected = [
        (os.path.join(BASELINES, f".source-{source_id}.new"), os.path.join(BASELINES, source_id)),
        (os.path.join(REPOS, f".source-{source_id}.new"), os.path.join(REPOS, worktree_path[6:])),
        (os.path.join(MANIFESTS, f".{source_id}.new"), os.path.join(MANIFESTS, f"{source_id}.json")),
    ]
    artifacts = transaction["artifacts"]
    if any(item.get("temporary") != temporary or item.get("final") != final
           for item, (temporary, final) in zip(artifacts, expected)):
        raise ValueError("publication_transaction_invalid")
    expected_pending = [os.path.join(ROOT, f"registry-{source_id}.pending"),
                        os.path.join(REPOS, f".INDEX-{source_id}.pending")]
    if transaction.get("pending") != expected_pending:
        raise ValueError("publication_transaction_invalid")
    prior = transaction["prior_registry"]
    updated = transaction["updated_registry"]
    if (prior.get("schema") != "secure-sandbox-source-registry-v1"
            or not isinstance(prior.get("sources"), list)
            or updated != {"schema": prior["schema"], "sources": [*prior["sources"], record]}):
        raise ValueError("publication_transaction_invalid")


def recover_publication(source_id: str) -> dict | None:
    path = publication_transaction_path(source_id)
    try:
        transaction = bounded_json(path, MAX_PUBLICATION_TRANSACTION_BYTES)
    except FileNotFoundError:
        return None
    if (not isinstance(transaction, dict) or transaction.get("schema") != PUBLICATION_SCHEMA
            or transaction.get("source_id") != source_id
            or transaction.get("phase") not in {"preparing", "prepared"}
            or transaction.get("control_uid") != os.geteuid()
            or not isinstance(transaction.get("record"), dict)
            or not isinstance(transaction.get("prior_registry"), dict)
            or not isinstance(transaction.get("updated_registry"), dict)):
        raise ValueError("publication_transaction_invalid")
    artifacts = transaction.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise ValueError("publication_transaction_invalid")
    if not all(isinstance(item, dict) for item in artifacts):
        raise ValueError("publication_transaction_invalid")
    validate_publication_layout(source_id, transaction)
    if transaction["phase"] == "preparing":
        if any(os.path.lexists(str(item.get("final", ""))) for item in artifacts if isinstance(item, dict)):
            raise ValueError("publication_recovery_ambiguous")
        for item in artifacts:
            if not isinstance(item, dict) or not isinstance(item.get("temporary"), str) or not isinstance(item.get("uid"), int):
                raise ValueError("publication_transaction_invalid")
            remove_publication_path(item["temporary"], item["uid"])
        for pending in transaction.get("pending", []):
            if not isinstance(pending, str):
                raise ValueError("publication_transaction_invalid")
            remove_publication_path(pending, transaction["control_uid"])
        os.unlink(path)
        sync_directory(ROOT)
        return None
    for item in artifacts:
        if (not isinstance(item, dict) or not isinstance(item.get("temporary"), str)
                or not isinstance(item.get("final"), str) or not isinstance(item.get("identity"), dict)):
            raise ValueError("publication_transaction_invalid")
        temporary_exists = os.path.lexists(item["temporary"])
        final_exists = os.path.lexists(item["final"])
        if temporary_exists and final_exists:
            raise ValueError("publication_recovery_ambiguous")
        current = item["final"] if final_exists else item["temporary"]
        validate_publication_identity(current, item["identity"])
        if not final_exists:
            os.replace(item["temporary"], item["final"])
            sync_directory(os.path.dirname(item["final"]))
    prior = transaction["prior_registry"]
    updated = transaction["updated_registry"]
    for registry_path, mode in ((REGISTRY, 0o600), (os.path.join(REPOS, "INDEX.json"), 0o444)):
        try:
            current = bounded_json(registry_path, MAX_PUBLICATION_TRANSACTION_BYTES)
        except FileNotFoundError:
            current = prior
        if registry_digest(current) == registry_digest(prior):
            atomic_json(registry_path, updated, mode)
        elif registry_digest(current) != registry_digest(updated):
            raise ValueError("publication_recovery_registry_mismatch")
    for pending in transaction.get("pending", []):
        if not isinstance(pending, str):
            raise ValueError("publication_transaction_invalid")
        remove_publication_path(pending, transaction["control_uid"])
    os.unlink(path)
    sync_directory(ROOT)
    staged = os.path.join(STAGING, source_id)
    if os.path.isdir(staged) and not os.path.islink(staged):
        shutil.rmtree(staged)
        sync_directory(STAGING)
    return transaction["record"]


def load_json(path: str, default: object) -> object:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def validate_text(value: str, label: str, maximum: int = MAX_PATH_BYTES) -> str:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise ValueError(f"{label}_invalid_utf8") from error
    if not value or len(encoded) > maximum:
        raise ValueError(f"{label}_length")
    for character in value:
        code = ord(character)
        if code < 0x20 or 0x7F <= code <= 0x9F or unicodedata.category(character) == "Cf":
            raise ValueError(f"{label}_control")
    return value


def normalized_path(name: str) -> tuple[str, ...]:
    # GitHub wraps entries in one synthetic repository/SHA directory. Keep the
    # 240-byte policy on every component and on the repository-relative path;
    # do not charge that transport envelope against the relative-path budget.
    name = validate_text(name, "path", MAX_PATH_BYTES * 2)
    if name.startswith("/") or "\\" in name:
        raise ValueError("unsafe_path")
    components = tuple(name.split("/"))
    if len(components) > MAX_COMPONENTS + 1 or any(part in {"", ".", ".."} for part in components):
        raise ValueError("unsafe_path")
    for component in components:
        validate_text(component, "component")
    return components


def validate_manifest(value: object) -> dict:
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-source-plan-v1":
        raise ValueError("invalid_manifest")
    repository = str(value.get("repository", ""))
    commit = str(value.get("resolved_commit", ""))
    plan_id = str(value.get("plan_id", ""))
    archive_sha = str(value.get("archive_sha256", ""))
    source_kind = str(value.get("source_kind", "github_archive"))
    if not REPOSITORY_RE.fullmatch(repository) or not SHA_RE.fullmatch(commit):
        raise ValueError("invalid_manifest_identity")
    if source_kind == "npm_package":
        if not NPM_PACKAGE_RE.fullmatch(str(value.get("package_name", ""))) or not SEMVER_RE.fullmatch(str(value.get("package_version", ""))):
            raise ValueError("invalid_manifest_identity")
        if not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", str(value.get("npm_integrity", ""))):
            raise ValueError("invalid_manifest_identity")
        if value.get("registry_integrity_verified") is not True:
            raise ValueError("npm_integrity_not_verified")
    elif source_kind != "github_archive":
        raise ValueError("invalid_source_kind")
    if not UUID_RE.fullmatch(plan_id) or not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
        raise ValueError("invalid_manifest_identity")
    if value.get("state") != "exported" or int(value.get("archive_bytes", -1)) > MAX_ARCHIVE_BYTES:
        raise ValueError("invalid_manifest_state")
    return value


def read_frame() -> tuple[dict, str]:
    header = sys.stdin.buffer.read(8)
    if len(header) != 8:
        raise ValueError("truncated_frame")
    length = struct.unpack(">Q", header)[0]
    if length < 2 or length > MAX_MANIFEST_BYTES:
        raise ValueError("invalid_manifest_length")
    manifest_bytes = sys.stdin.buffer.read(length)
    if len(manifest_bytes) != length:
        raise ValueError("truncated_manifest")
    try:
        manifest = validate_manifest(json.loads(manifest_bytes))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_manifest_json") from error
    descriptor, archive_path = tempfile.mkstemp(prefix="archive-", suffix=".tar.gz", dir=STAGING)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = sys.stdin.buffer.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("archive_too_large")
            digest.update(chunk)
            os.write(descriptor, chunk)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        os.unlink(archive_path)
        raise
    os.close(descriptor)
    if total != int(manifest["archive_bytes"]) or digest.hexdigest() != manifest["archive_sha256"]:
        os.unlink(archive_path)
        raise ValueError("archive_mismatch")
    return manifest, archive_path


def inspect_members(archive: tarfile.TarFile) -> tuple[list[tuple[tarfile.TarInfo, tuple[str, ...]]], list[str]]:
    entries: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []
    exact: set[str] = set()
    folded: set[str] = set()
    normalized: set[str] = set()
    roots: set[str] = set()
    warnings: set[str] = set()
    total_bytes = 0
    for member in archive:
        if len(entries) >= MAX_ENTRIES:
            raise ValueError("too_many_entries")
        components = normalized_path(member.name.rstrip("/") if member.isdir() else member.name)
        roots.add(components[0])
        relative = components[1:]
        if not relative:
            if not member.isdir():
                raise ValueError("invalid_archive_root")
            continue
        relative_text = "/".join(relative)
        if len(relative_text.encode("utf-8")) > MAX_PATH_BYTES or len(relative) > MAX_COMPONENTS:
            raise ValueError("path_too_long")
        fold = relative_text.casefold()
        normal = unicodedata.normalize("NFC", relative_text)
        if relative_text in exact or fold in folded or normal in normalized:
            raise ValueError("path_collision")
        exact.add(relative_text); folded.add(fold); normalized.add(normal)
        if member.pax_headers and any(key not in {"path", "linkpath", "mtime", "comment"} for key in member.pax_headers):
            raise ValueError("extended_attributes")
        if (member.sparse is not None or member.islnk() or member.issym()
                or member.isdev() or member.isfifo()):
            raise ValueError("unsupported_member_type")
        if not (member.isdir() or member.isfile()):
            raise ValueError("unsupported_member_type")
        if member.mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError("privileged_mode")
        if member.isfile():
            if member.size < 0 or member.size > MAX_FILE_BYTES:
                raise ValueError("file_too_large")
            total_bytes += member.size
            if total_bytes > MAX_EXPANDED_BYTES:
                raise ValueError("expanded_archive_too_large")
        entries.append((member, relative))
    if len(roots) != 1:
        raise ValueError("multiple_archive_roots")
    return entries, sorted(warnings)


def write_regular(archive: tarfile.TarFile, member: tarfile.TarInfo, destination: str) -> str:
    source = archive.extractfile(member)
    if source is None:
        raise ValueError("missing_file_payload")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > member.size or total > MAX_FILE_BYTES:
                raise ValueError("file_size_mismatch")
            digest.update(chunk)
            os.write(descriptor, chunk)
        if total != member.size:
            raise ValueError("file_size_mismatch")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        source.close()
    return digest.hexdigest()


def extract_archive(archive_path: str, destination: str) -> tuple[str, int, int, list[str], list[dict]]:
    baseline = os.path.join(destination, "baseline")
    worktree = os.path.join(destination, "worktree")
    os.mkdir(baseline, 0o700)
    os.mkdir(worktree, 0o700)
    records: list[dict] = []
    total_bytes = 0
    with tarfile.open(archive_path, "r:gz", encoding="utf-8", errors="strict") as archive:
        entries, warnings = inspect_members(archive)
        for member, relative in sorted(entries, key=lambda item: (len(item[1]), item[1])):
            baseline_path = os.path.join(baseline, *relative)
            worktree_path = os.path.join(worktree, *relative)
            os.makedirs(os.path.dirname(baseline_path), mode=0o700, exist_ok=True)
            os.makedirs(os.path.dirname(worktree_path), mode=0o700, exist_ok=True)
            relative_text = "/".join(relative)
            if member.isdir():
                os.makedirs(baseline_path, mode=0o700, exist_ok=True)
                os.makedirs(worktree_path, mode=0o700, exist_ok=True)
                records.append({"path": relative_text, "type": "directory"})
            elif member.isfile():
                digest = write_regular(archive, member, baseline_path)
                shutil.copyfile(baseline_path, worktree_path, follow_symlinks=False)
                os.chmod(worktree_path, 0o600)
                total_bytes += member.size
                records.append({"path": relative_text, "type": "file", "bytes": member.size, "sha256": digest, "git_mode": member.mode & 0o777})
                if relative_text in {".gitmodules", ".lfsconfig"}:
                    warnings.append(f"present:{relative_text}")
                elif member.size <= 1024:
                    with open(baseline_path, "rb") as handle:
                        if handle.read(200).startswith(b"version https://git-lfs.github.com/spec/v1"):
                            warnings.append("git_lfs_pointer_present")
            else:
                raise ValueError("unsupported_member_type")
    tree_hash = hashlib.sha256(canonical(records)).hexdigest()
    return tree_hash, len(records), total_bytes, sorted(set(warnings)), records


def chmod_tree(root: str, directory_mode: int, file_mode: int, uid: int, gid: int, preserve_symlinks: bool) -> None:
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = os.path.join(current, name)
            if os.path.islink(path):
                if preserve_symlinks:
                    os.lchown(path, uid, gid)
                continue
            os.chmod(path, file_mode, follow_symlinks=False)
            os.chown(path, uid, gid, follow_symlinks=False)
        for name in directories:
            path = os.path.join(current, name)
            if os.path.islink(path):
                if preserve_symlinks:
                    os.lchown(path, uid, gid)
                continue
            os.chmod(path, directory_mode, follow_symlinks=False)
            os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(root, directory_mode)
    os.chown(root, uid, gid)


def encrypt_provenance(provenance: dict, source_id: str) -> str:
    with open(RECIPIENT_FILE, encoding="ascii") as handle:
        recipient = handle.read(256).strip()
    temporary = os.path.join(OUTBOX, f".source-{source_id}.new")
    result = subprocess.run([AGE, "-r", recipient, "-o", temporary], input=canonical(provenance) + b"\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError("evidence_encryption_failed")
    with open(temporary, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    final_name = f"source-{source_id}-000000000001-{digest}.age"
    os.chmod(temporary, 0o640)
    os.chown(temporary, 0, __import__("grp").getgrnam("conversation-shipper").gr_gid)
    os.replace(temporary, os.path.join(OUTBOX, final_name))
    directory = os.open(OUTBOX, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return final_name


def stage() -> None:
    if os.path.exists(RUN_MARKER) or any(os.path.exists(path) for path in LIFECYCLE_MARKERS):
        raise ValueError("active_agent_run")
    manifest, archive_path = read_frame()
    source_id = str(uuid.uuid4())
    destination = os.path.join(STAGING, source_id)
    os.mkdir(destination, 0o700)
    try:
        tree_hash, file_count, expanded_bytes, warnings, records = extract_archive(archive_path, destination)
        provenance = {
            "schema": "secure-sandbox-source-provenance-v1",
            "source_id": source_id,
            "acquisition_id": manifest["plan_id"],
            "source_kind": manifest.get("source_kind", "github_archive"),
            "repository": manifest["repository"],
            "repository_sha256": hashlib.sha256(manifest["repository"].encode()).hexdigest(),
            "requested_ref": manifest["requested_ref"],
            "resolved_commit": manifest["resolved_commit"],
            "archive_sha256": manifest["archive_sha256"],
            "archive_bytes": manifest["archive_bytes"],
            "tree_manifest_sha256": tree_hash,
            "file_count": file_count,
            "expanded_bytes": expanded_bytes,
            "warnings": warnings,
            "policy_version": "source-acquisition-v1",
            "gateway_fetched_at": manifest["fetched_at"],
            "research_staged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        for key in ("package_name", "package_version", "npm_integrity", "registry_integrity_verified"):
            if key in manifest:
                provenance[key] = manifest[key]
        evidence_name = encrypt_provenance(provenance, source_id)
        provenance["evidence_name"] = evidence_name
        atomic_json(os.path.join(destination, "provenance.json"), provenance)
        atomic_json(os.path.join(destination, "integrity-manifest.json"), {
            "schema": "secure-sandbox-source-integrity-v1",
            "source_id": source_id,
            "source_kind": manifest.get("source_kind", "github_archive"),
            "repository": manifest["repository"],
            "resolved_commit": manifest["resolved_commit"],
            "tree_manifest_sha256": tree_hash,
            "entries": records,
        })
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        try:
            os.unlink(archive_path)
        except FileNotFoundError:
            pass
    emit({
        "event": "source_import_staged",
        "source_id": source_id,
        "plan_id": manifest["plan_id"],
        "repository": manifest["repository"],
        "resolved_commit": manifest["resolved_commit"],
        "evidence_name": evidence_name,
        "state": "staged",
    })


def publish(source_id: str) -> None:
    if not UUID_RE.fullmatch(source_id):
        raise ValueError("invalid_source_id")
    if os.path.exists(RUN_MARKER) or any(os.path.exists(path) for path in LIFECYCLE_MARKERS):
        raise ValueError("active_agent_run")
    recovered = recover_publication(source_id)
    if recovered is not None:
        output = dict(recovered)
        output["event"] = "source_import_completed"
        output["recovered"] = True
        emit(output)
        return
    staged = os.path.join(STAGING, source_id)
    provenance = load_json(os.path.join(staged, "provenance.json"), None)
    if not isinstance(provenance, dict) or provenance.get("source_id") != source_id:
        raise ValueError("source_not_staged")
    owner, repository = provenance["repository"].split("/", 1)
    repo_name = f"{owner}--{repository}--{provenance['resolved_commit'][:12]}--{source_id}"
    baseline_final = os.path.join(BASELINES, source_id)
    worktree_final = os.path.join(REPOS, repo_name)
    manifest_final = os.path.join(MANIFESTS, f"{source_id}.json")
    baseline_temporary = os.path.join(BASELINES, f".source-{source_id}.new")
    worktree_temporary = os.path.join(REPOS, f".source-{source_id}.new")
    manifest_temporary = os.path.join(MANIFESTS, f".{source_id}.new")
    if os.path.lexists(baseline_final) or os.path.lexists(worktree_final) or os.path.lexists(manifest_final):
        raise ValueError("publication_collision")
    agent = pwd.getpwnam("agent")
    baseline_stage = os.path.join(staged, "baseline")
    worktree_stage = os.path.join(staged, "worktree")
    if os.path.lexists(baseline_temporary) or os.path.lexists(worktree_temporary) or os.path.lexists(manifest_temporary):
        raise ValueError("stale_publication_temporary")
    registry = load_json(REGISTRY, {"schema": "secure-sandbox-source-registry-v1", "sources": []})
    if not isinstance(registry, dict) or not isinstance(registry.get("sources"), list):
        raise ValueError("invalid_registry")
    record = {
        "source_id": source_id,
        "source_kind": provenance.get("source_kind", "github_archive"),
        "repository": provenance["repository"],
        "resolved_commit": provenance["resolved_commit"],
        "archive_sha256": provenance["archive_sha256"],
        "tree_manifest_sha256": provenance["tree_manifest_sha256"],
        "baseline_path": f"baselines/{source_id}",
        "worktree_path": f"repos/{repo_name}",
        "integrity_manifest_path": f"source-manifests/{source_id}.json",
        "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "warnings": provenance["warnings"],
        "policy_version": provenance["policy_version"],
        "evidence_name": provenance["evidence_name"],
    }
    for key in ("package_name", "package_version", "npm_integrity", "registry_integrity_verified"):
        if key in provenance:
            record[key] = provenance[key]
    updated_registry = {"schema": registry["schema"], "sources": [*registry["sources"], record]}
    registry_pending = os.path.join(ROOT, f"registry-{source_id}.pending")
    index_pending = os.path.join(REPOS, f".INDEX-{source_id}.pending")
    transaction_path = publication_transaction_path(source_id)
    artifacts = [
        {"temporary": baseline_temporary, "final": baseline_final, "uid": os.geteuid()},
        {"temporary": worktree_temporary, "final": worktree_final, "uid": agent.pw_uid},
        {"temporary": manifest_temporary, "final": manifest_final, "uid": os.geteuid()},
    ]
    transaction = {
        "schema": PUBLICATION_SCHEMA,
        "source_id": source_id,
        "phase": "preparing",
        "control_uid": os.geteuid(),
        "record": record,
        "prior_registry": registry,
        "updated_registry": updated_registry,
        "artifacts": artifacts,
        "pending": [registry_pending, index_pending],
    }
    atomic_json(transaction_path, transaction)
    try:
        shutil.copytree(baseline_stage, baseline_temporary, symlinks=True)
        shutil.copytree(worktree_stage, worktree_temporary, symlinks=False)
        shutil.copyfile(os.path.join(staged, "integrity-manifest.json"), manifest_temporary, follow_symlinks=False)
        chmod_tree(baseline_temporary, 0o555, 0o444, 0, 0, True)
        chmod_tree(worktree_temporary, 0o755, 0o644, agent.pw_uid, agent.pw_gid, False)
        os.chmod(manifest_temporary, 0o444, follow_symlinks=False)
        os.chown(manifest_temporary, 0, 0, follow_symlinks=False)
        fsync_tree(baseline_temporary)
        fsync_tree(worktree_temporary)
        descriptor = os.open(manifest_temporary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        sync_directory(MANIFESTS)
        atomic_json(registry_pending, updated_registry)
        atomic_json(index_pending, updated_registry, 0o444)
        transaction["phase"] = "prepared"
        for item in artifacts:
            item["identity"] = publication_identity(item["temporary"])
        atomic_json(transaction_path, transaction)
        os.replace(baseline_temporary, baseline_final)
        sync_directory(BASELINES)
        os.replace(worktree_temporary, worktree_final)
        sync_directory(REPOS)
        os.replace(manifest_temporary, manifest_final)
        sync_directory(MANIFESTS)
        os.replace(registry_pending, REGISTRY)
        sync_directory(ROOT)
        os.replace(index_pending, os.path.join(REPOS, "INDEX.json"))
        sync_directory(REPOS)
    except Exception:
        raise
    shutil.rmtree(staged)
    sync_directory(STAGING)
    os.unlink(transaction_path)
    sync_directory(ROOT)
    output = dict(record)
    output["event"] = "source_import_completed"
    emit(output)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("root required")
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("stage")
    publisher = subparsers.add_parser("publish")
    publisher.add_argument("source_id")
    args = parser.parse_args()
    try:
        if args.command == "stage":
            stage()
        else:
            publish(args.source_id)
    except Exception as error:
        detail = str(error)
        error_class = detail if re.fullmatch(r"[a-z0-9_]{1,80}", detail) else type(error).__name__
        emit({"event": "source_import_rejected", "error": error_class})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
