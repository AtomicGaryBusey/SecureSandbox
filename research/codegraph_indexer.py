#!/usr/bin/env python3
"""Build a sealed CodeGraph project from a verified immutable source."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import time

from source_integrity import (
    IntegrityError,
    canonical,
    expected_records,
    fixed_tree_path,
    load_control_json,
    registered_source,
    verify_source,
    MAX_MANIFEST_BYTES,
)

ROOT = "/var/lib/secure-sandbox/codegraph-indexes"
BUILD_ROOT = "/var/lib/secure-sandbox/codegraph-builds"
MARKER_ROOT = "/home/agent/research-workspace/codegraph-indexes"
NODE = "/opt/secure-sandbox/codegraph/node"
RUNNER = "/usr/local/libexec/secure-sandbox/codegraph_runner.cjs"
BUNDLE_SHA256 = "d75e7f0f7b754443ae01a02643df2af46e281f6dc4abd3fb272f01281113b528"
BUILD_COMMIT = "8877995f2914efbc8bd5ae1443c539d6cfcfd2f1+patch.725bfe2733d1"
MAX_FILES = 25_000
MAX_BYTES = 512 * 1024 * 1024


class GraphIndexError(ValueError):
    pass


def hash_file(path: str) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(descriptor)


def copy_verified(source: str, destination: str, records: dict[str, dict]) -> tuple[int, int]:
    files = 0
    total = 0
    for relative in sorted(records):
        expected = records[relative]
        target = os.path.join(destination, relative)
        if expected["type"] == "directory":
            os.makedirs(target, mode=0o755, exist_ok=True)
            continue
        if expected["type"] != "file":
            continue
        files += 1
        total += int(expected["bytes"])
        if files > MAX_FILES or total > MAX_BYTES:
            raise GraphIndexError("codegraph_source_limit")
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        source_path = os.path.join(source, relative)
        source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        digest = hashlib.sha256()
        copied = 0
        try:
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                copied += len(chunk)
                digest.update(chunk)
                os.write(target_fd, chunk)
            os.fsync(target_fd)
        finally:
            os.close(source_fd)
            os.close(target_fd)
        if copied != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
            raise GraphIndexError("source_changed_during_graph_copy")
    return files, total


def directory_digest(root: str) -> str:
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in files:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                raise GraphIndexError("unexpected_graph_artifact")
            digest.update(canonical([relative, info.st_size, hash_file(path)]))
    return digest.hexdigest()


def seal_tree(root: str) -> None:
    for current, directories, files in os.walk(root, topdown=False):
        for name in files:
            path = os.path.join(current, name)
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o444, follow_symlinks=False)
        for name in directories:
            path = os.path.join(current, name)
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o555, follow_symlinks=False)
    os.chown(root, 0, 0)
    os.chmod(root, 0o555)


def build(source_id: str, diagnostic: bool = False) -> dict:
    if os.geteuid() != 0:
        raise GraphIndexError("root_required")
    verification = verify_source(source_id, "baseline")
    if verification.get("anchor_status") != "import_validated" or verification.get("baseline", {}).get("status") != "match":
        raise GraphIndexError("source_not_verified")
    record = registered_source(source_id)
    manifest_path = fixed_tree_path(record.get("integrity_manifest_path"), "source-manifests")
    manifest = load_control_json(manifest_path, MAX_MANIFEST_BYTES)
    records = expected_records(manifest)
    baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
    os.makedirs(ROOT, mode=0o755, exist_ok=True)
    os.makedirs(MARKER_ROOT, mode=0o755, exist_ok=True)
    os.makedirs(BUILD_ROOT, mode=0o755, exist_ok=True)
    os.chown(BUILD_ROOT, 0, 0)
    os.chmod(BUILD_ROOT, 0o755)
    destination = f"{ROOT}/{source_id}"
    temporary = f"{BUILD_ROOT}/.build-{source_id}-{os.getpid()}"
    if os.path.lexists(destination) or os.path.lexists(temporary):
        raise GraphIndexError("codegraph_index_exists")
    project = f"{temporary}/project"
    os.makedirs(project, mode=0o755)
    try:
        source_files, source_bytes = copy_verified(baseline, project, records)
        graph_dir = f"{project}/.codegraph"
        os.mkdir(graph_dir, 0o700)
        indexer = pwd.getpwnam("codegraph-indexer")
        os.chown(graph_dir, indexer.pw_uid, indexer.pw_gid)
        unit = f"secure-sandbox-codegraph-index-{source_id[:8]}-{os.getpid()}"
        command = [
            "/usr/bin/systemd-run", "--pipe", "--wait", "--collect", "--quiet",
            f"--unit={unit}", "--uid=codegraph-indexer", "--gid=codegraph-runtime",
            "--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
            "--property=PrivateDevices=yes", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
            "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
            "--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes",
            "--property=MemoryDenyWriteExecute=no", "--property=MemoryMax=2G",
            "--property=TasksMax=64", f"--property=ReadWritePaths={graph_dir}",
            "--setenv=HOME=/var/empty", "--setenv=DO_NOT_TRACK=1",
            "--setenv=CODEGRAPH_TELEMETRY=0", "--setenv=CODEGRAPH_NO_UPDATE_CHECK=1",
            "--setenv=CODEGRAPH_NO_WATCH=1", "--setenv=CODEGRAPH_NO_INSTALL_REFRESH=1",
            "--setenv=CODEGRAPH_NO_PROMPT_HOOK=1", "--setenv=CODEGRAPH_NO_RELAUNCH=1",
            NODE, "--liftoff-only", "--disable-warning=ExperimentalWarning", RUNNER, "index", project,
        ]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
        if completed.returncode != 0:
            if diagnostic:
                detail = completed.stderr.decode("utf-8", "replace")[:2000]
                detail = "".join(character if character in "\n\t" or 0x20 <= ord(character) < 0x7f else "?" for character in detail)
                print(detail, file=__import__("sys").stderr)
            raise GraphIndexError("codegraph_index_failed")
        result = json.loads(completed.stdout)
        for current, directories, files in os.walk(graph_dir):
            for name in list(files):
                if name.endswith((".lock", ".pid", "-wal", "-shm")):
                    os.unlink(os.path.join(current, name))
        index_digest = directory_digest(graph_dir)
        metadata = {
            "schema": "secure-sandbox-codegraph-index-v1",
            "source_id": source_id,
            "repository": record.get("repository"),
            "resolved_commit": record.get("resolved_commit"),
            "tree_manifest_sha256": record.get("tree_manifest_sha256"),
            "corpus_index_content_sha256": "",
            "codegraph_version": "1.6.2",
            "codegraph_build_commit": BUILD_COMMIT,
            "codegraph_bundle_sha256": BUNDLE_SHA256,
            "codegraph_index_sha256": index_digest,
            "source_files": source_files,
            "source_bytes": source_bytes,
            "files_processed": int(result.get("filesProcessed", 0)),
            "nodes_created": int(result.get("nodesCreated", 0)),
            "edges_created": int(result.get("edgesCreated", 0)),
            "index_errors": result.get("errors", []),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # Bind the graph to the already validated corpus index when available.
        import sqlite3
        corpus_path = f"/home/agent/research-workspace/corpus-indexes/{source_id}.sqlite3"
        connection = sqlite3.connect(f"file:{corpus_path}?mode=ro&immutable=1", uri=True)
        try:
            metadata["corpus_index_content_sha256"] = dict(connection.execute("SELECT key,value FROM metadata"))["index_content_sha256"]
        finally:
            connection.close()
        metadata_path = f"{temporary}/metadata.json"
        with open(metadata_path, "x", encoding="utf-8") as handle:
            json.dump(metadata, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        seal_tree(temporary)
        os.replace(temporary, destination)
        marker_temporary = f"{MARKER_ROOT}/.{source_id}.new"
        marker_final = f"{MARKER_ROOT}/{source_id}.json"
        with open(marker_temporary, "x", encoding="utf-8") as handle:
            json.dump(metadata, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(marker_temporary, 0, 0)
        os.chmod(marker_temporary, 0o444)
        os.replace(marker_temporary, marker_final)
        return {**metadata, "status": "indexed"}
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["index"])
    parser.add_argument("source_id")
    parser.add_argument("--diagnostic", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.source_id, diagnostic=args.diagnostic), separators=(",", ":"), sort_keys=True))
    except (GraphIndexError, IntegrityError, OSError, ValueError):
        print(json.dumps({"status": "rejected", "error": "codegraph_index_rejected"}, separators=(",", ":")), file=__import__("sys").stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
