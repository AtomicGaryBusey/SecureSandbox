#!/usr/bin/env python3
"""Bounded client for the root-managed CodeGraph query service."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket

GRAPH_ROOT = "/home/agent/research-workspace/codegraph-indexes"
SOCKET_PATH = "/run/secure-sandbox-codegraph/query.sock"
MAX_RESPONSE_BYTES = 64 * 1024
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class CodeGraphError(ValueError):
    pass


def metadata_path(source_id: str) -> str:
    if not isinstance(source_id, str) or not UUID_RE.fullmatch(source_id):
        raise CodeGraphError("invalid_source_id")
    return f"{GRAPH_ROOT}/{source_id}.json"


def graph_available(source_id: str) -> bool:
    return os.path.isfile(metadata_path(source_id))


def request_graph(source_id: str, request: dict) -> tuple[dict, dict]:
    if not graph_available(source_id):
        raise CodeGraphError("codegraph_not_indexed")
    wire_request = json.dumps({"source_id": source_id, **request}, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(wire_request) > 4096:
        raise CodeGraphError("codegraph_request_too_large")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(30)
    try:
        client.connect(SOCKET_PATH)
        client.sendall(wire_request)
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = client.recv(8192)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_RESPONSE_BYTES:
                raise CodeGraphError("codegraph_response_too_large")
    except (OSError, TimeoutError) as failure:
        raise CodeGraphError("codegraph_service_unavailable") from failure
    finally:
        client.close()
    try:
        payload = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as failure:
        raise CodeGraphError("invalid_codegraph_response") from failure
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise CodeGraphError(str(payload.get("error", "codegraph_query_rejected")))
    result = payload.get("result")
    metadata = payload.get("metadata")
    if not isinstance(result, dict) or not isinstance(metadata, dict):
        raise CodeGraphError("invalid_codegraph_response")
    return result, metadata


def explore_graph(source_id: str, query: str, limit: int) -> dict:
    result, metadata = request_graph(source_id, {"query": query, "limit": limit})
    text = result.get("text")
    if not isinstance(text, str) or len(text) > 40000:
        raise CodeGraphError("invalid_codegraph_response")
    return {
        "schema": "secure-sandbox-corpus-exploration-v2",
        "source_id": source_id,
        "repository": metadata["repository"],
        "resolved_commit": metadata["resolved_commit"],
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "index_content_sha256": metadata["corpus_index_content_sha256"],
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "semantic_backend": "codegraph-1.6.2-source-uuid-adapter",
        "codegraph_adapter": "enabled",
        "codegraph_build_commit": metadata["codegraph_build_commit"],
        "codegraph_bundle_sha256": metadata["codegraph_bundle_sha256"],
        "codegraph_index_sha256": metadata["codegraph_index_sha256"],
        "returned": 1 if text else 0,
        "results": [],
        "graph_context": {
            "content_trust": "untrusted_source_content",
            "format": "codegraph_markdown",
            "text": text,
        },
    }


def analyze_reachability(
    source_id: str,
    entrypoint_symbol: str,
    entrypoint_file: str,
    target_symbol: str,
    target_file: str,
    max_depth: int = 8,
) -> dict:
    result, metadata = request_graph(source_id, {
        "operation": "reachability",
        "entrypoint": {"symbol": entrypoint_symbol, "file_path": entrypoint_file},
        "target": {"symbol": target_symbol, "file_path": target_file},
        "max_depth": max_depth,
    })
    if not isinstance(result.get("reachable"), bool) or not isinstance(result.get("path"), list):
        raise CodeGraphError("invalid_codegraph_response")
    binding = {
        "source_id": source_id,
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "corpus_index_content_sha256": metadata["corpus_index_content_sha256"],
        "codegraph_build_commit": metadata["codegraph_build_commit"],
        "codegraph_bundle_sha256": metadata["codegraph_bundle_sha256"],
        "codegraph_index_sha256": metadata["codegraph_index_sha256"],
        "entrypoint_symbol": entrypoint_symbol,
        "entrypoint_file": entrypoint_file,
        "target_symbol": target_symbol,
        "target_file": target_file,
        "max_depth": max_depth,
        "edge_profile": result.get("edgeProfile"),
    }
    return {
        "schema": "secure-sandbox-static-reachability-v1",
        "source_id": source_id,
        "repository": metadata["repository"],
        "resolved_commit": metadata["resolved_commit"],
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "index_content_sha256": metadata["corpus_index_content_sha256"],
        "codegraph_build_commit": metadata["codegraph_build_commit"],
        "codegraph_bundle_sha256": metadata["codegraph_bundle_sha256"],
        "codegraph_index_sha256": metadata["codegraph_index_sha256"],
        "analysis_id": hashlib.sha256(json.dumps(binding, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
        "evidence_class": "static_graph_reachability",
        "configuration_basis": "caller_selected_default_entrypoint",
        "measured_execution": False,
        "exhaustive": False,
        "reachable": result["reachable"],
        "outcome": "static_path_found" if result["reachable"] else "no_static_path_within_bound",
        "max_depth": max_depth,
        "nodes_examined": int(result.get("nodesExamined", 0)),
        "truncated": bool(result.get("truncated", False)),
        "edge_profile": result.get("edgeProfile"),
        "entrypoint": result.get("entrypoint"),
        "target": result.get("target"),
        "path": result["path"],
        "limitations": [
            "The caller selected the entrypoint as representative of repository defaults; the graph does not prove that configuration premise.",
            "Static graph edges do not prove runtime branch conditions, exploitability, or observed execution.",
            "No path means only that this bounded graph and edge profile found none; dynamic dispatch or unresolved calls may be absent.",
        ],
    }
