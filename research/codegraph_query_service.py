#!/usr/bin/env python3
"""Peer-authenticated, source-UUID-only CodeGraph query broker."""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import stat
import subprocess

from bounded_unix_server import serve as serve_bounded
from source_integrity import MAX_MANIFEST_BYTES, load_control_json

GRAPH_ROOT = "/var/lib/secure-sandbox/codegraph-indexes"
SOCKET_PATH = "/run/secure-sandbox-codegraph/query.sock"
NODE = "/opt/secure-sandbox/codegraph/node"
RUNNER = "/usr/local/libexec/secure-sandbox/codegraph_runner.cjs"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MAX_REQUEST_BYTES = 4096
ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "HOME": "/var/empty",
    "DO_NOT_TRACK": "1",
    "CODEGRAPH_TELEMETRY": "0",
    "CODEGRAPH_NO_UPDATE_CHECK": "1",
    "CODEGRAPH_NO_WATCH": "1",
    "CODEGRAPH_NO_INSTALL_REFRESH": "1",
    "CODEGRAPH_NO_PROMPT_HOOK": "1",
    "CODEGRAPH_NO_RELAUNCH": "1",
}
REACHABILITY_ERRORS = {
    "entrypoint_not_found",
    "ambiguous_entrypoint",
    "target_not_found",
    "ambiguous_target",
}


def reject(error: str) -> dict:
    return {"status": "rejected", "error": error}


def validate_graph(source_id: str) -> tuple[str, dict]:
    graph = f"{GRAPH_ROOT}/{source_id}"
    project = f"{graph}/project"
    metadata_path = f"{graph}/metadata.json"
    for path, expected_type in ((graph, "dir"), (project, "dir"), (f"{project}/.codegraph", "dir"), (metadata_path, "file")):
        info = os.lstat(path)
        valid_type = stat.S_ISDIR(info.st_mode) if expected_type == "dir" else stat.S_ISREG(info.st_mode)
        if not valid_type or info.st_uid != 0 or info.st_mode & 0o022 or (expected_type == "file" and info.st_nlink != 1):
            raise ValueError("untrusted_codegraph_index")
    metadata = load_control_json(metadata_path, MAX_MANIFEST_BYTES)
    required = {
        "schema": "secure-sandbox-codegraph-index-v1",
        "source_id": source_id,
        "codegraph_build_commit": "8877995f2914efbc8bd5ae1443c539d6cfcfd2f1+patch.725bfe2733d1",
        "codegraph_bundle_sha256": "d75e7f0f7b754443ae01a02643df2af46e281f6dc4abd3fb272f01281113b528",
    }
    if not isinstance(metadata, dict) or any(metadata.get(key) != value for key, value in required.items()):
        raise ValueError("codegraph_index_binding_mismatch")
    if not isinstance(metadata.get("repository"), str) or not metadata["repository"]:
        raise ValueError("codegraph_index_binding_mismatch")
    for key in ("tree_manifest_sha256", "corpus_index_content_sha256", "codegraph_index_sha256"):
        if not isinstance(metadata.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", metadata[key]):
            raise ValueError("codegraph_index_binding_mismatch")
    if not isinstance(metadata.get("resolved_commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", metadata["resolved_commit"]):
        raise ValueError("codegraph_index_binding_mismatch")
    return project, metadata


def handle(request: object) -> dict:
    if not isinstance(request, dict):
        return reject("invalid_request")
    operation = request.get("operation", "explore")
    allowed = {"source_id", "query", "limit"} if operation == "explore" else {
        "operation", "source_id", "entrypoint", "target", "max_depth"
    }
    if set(request) != allowed or operation not in {"explore", "reachability"}:
        return reject("invalid_request")
    source_id = request.get("source_id")
    if not isinstance(source_id, str) or not UUID_RE.fullmatch(source_id):
        return reject("invalid_source_id")
    if operation == "explore":
        query, limit = request["query"], request["limit"]
        if not isinstance(query, str) or not query or len(query) > 256 or "\x00" in query:
            return reject("invalid_query")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10:
            return reject("invalid_limit")
        runner_arguments = ["query", query, str(limit)]
    else:
        max_depth = request.get("max_depth")
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 12:
            return reject("invalid_max_depth")
        for role in ("entrypoint", "target"):
            selector = request.get(role)
            if not isinstance(selector, dict) or set(selector) != {"symbol", "file_path"}:
                return reject(f"invalid_{role}_selector")
            symbol, file_path = selector.get("symbol"), selector.get("file_path")
            if not isinstance(symbol, str) or not symbol or len(symbol) > 128 or "\x00" in symbol:
                return reject(f"invalid_{role}_selector")
            if (not isinstance(file_path, str) or not file_path or len(file_path) > 512 or
                    "\x00" in file_path or file_path.startswith("/") or
                    any(part in {"", ".", ".."} for part in file_path.split("/"))):
                return reject(f"invalid_{role}_selector")
        selectors = {
            "entrypoint": {"symbol": request["entrypoint"]["symbol"], "filePath": request["entrypoint"]["file_path"]},
            "target": {"symbol": request["target"]["symbol"], "filePath": request["target"]["file_path"]},
        }
        runner_arguments = ["reachability", json.dumps(selectors, separators=(",", ":")), str(max_depth)]
    try:
        project, metadata = validate_graph(source_id)
        completed = subprocess.run(
            [NODE, "--liftoff-only", "--disable-warning=ExperimentalWarning", RUNNER,
             runner_arguments[0], project, *runner_arguments[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENVIRONMENT,
            timeout=25,
            check=False,
        )
        if completed.returncode != 0:
            if operation == "reachability" and len(completed.stderr) <= 4096:
                try:
                    diagnostic = json.loads(completed.stderr)
                    error = diagnostic.get("error") if isinstance(diagnostic, dict) else None
                    if error in REACHABILITY_ERRORS:
                        return reject(error)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            return reject("codegraph_query_failed")
        if len(completed.stdout) > 48 * 1024:
            return reject("codegraph_query_failed")
        result = json.loads(completed.stdout)
        if not isinstance(result, dict) or result.get("status") != "ok":
            return reject("codegraph_query_failed")
        if operation == "explore" and not isinstance(result.get("text"), str):
            return reject("codegraph_query_failed")
        if operation == "reachability" and not isinstance(result.get("reachable"), bool):
            return reject("codegraph_query_failed")
        return {"status": "ok", "result": result, "metadata": metadata}
    except subprocess.TimeoutExpired:
        return reject("codegraph_query_timeout")
    except Exception:
        return reject("codegraph_query_rejected")


def main() -> None:
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o755, exist_ok=True)
    allowed_uid = pwd.getpwnam("agent").pw_uid

    def encoded(value: dict) -> bytes:
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"

    def bounded_handle(raw: bytes) -> bytes:
        try:
            if (len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n")
                    or raw.count(b"\n") != 1):
                raise ValueError
            return encoded(handle(json.loads(raw)))
        except Exception:
            return encoded(reject("invalid_request"))

    serve_bounded(
        SOCKET_PATH, MAX_REQUEST_BYTES, 3, bounded_handle,
        lambda: encoded(reject("request_incomplete")),
        allowed_uids={0, allowed_uid},
        unauthorized=lambda: encoded(reject("unauthorized_peer")),
        overloaded=lambda: encoded(reject("service_busy")),
        failed=lambda: encoded(reject("internal_error")),
        terminator=b"\n",
        socket_uid=pwd.getpwnam("codegraph-query").pw_uid,
        socket_gid=grp.getgrnam("codegraph-client").gr_gid,
    )


if __name__ == "__main__":
    main()
