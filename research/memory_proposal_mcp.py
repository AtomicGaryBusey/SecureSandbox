#!/usr/bin/env python3
"""Managed MCP adapter for non-authoritative institutional-memory proposals."""

from __future__ import annotations

import json
import socket
import sys

SOCKET_PATH = "/run/secure-sandbox-memory/memory-proposal.sock"
MAX_REQUEST_BYTES = 16 * 1024
TOOL = {
    "name": "propose_memory",
    "description": "Propose a durable fact, principle, preference, or identity refinement for operator review. A proposal is untrusted and never changes your instructions or institutional memory automatically. Do not include secrets or copied source content.",
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "category": {"type": "string", "enum": ["identity", "working_principle", "project_context", "operator_preference"]},
            "title": {"type": "string", "minLength": 1, "maxLength": 96},
            "proposal": {"type": "string", "minLength": 1, "maxLength": 4096},
            "rationale": {"type": "string", "minLength": 1, "maxLength": 2048},
            "evidence_refs": {"type": "array", "items": {"type": "string", "maxLength": 256}, "maxItems": 8, "uniqueItems": True},
        },
        "required": ["category", "title", "proposal", "rationale", "evidence_refs"],
    },
    "_meta": {"anthropic/alwaysLoad": True},
}


def rpc_result(identifier: object, value: object) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "result": value}


def rpc_error(identifier: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def submit(arguments: dict) -> dict:
    encoded = json.dumps(arguments, ensure_ascii=False, separators=(",", ":")).encode()
    if len(encoded) > MAX_REQUEST_BYTES:
        return {"status": "rejected", "error": "request_too_large"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(SOCKET_PATH)
        client.sendall(encoded)
        client.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while len(raw) <= MAX_REQUEST_BYTES:
            chunk = client.recv(4096)
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("response_too_large")
        value = json.loads(raw)
        return value if isinstance(value, dict) else {"status": "rejected", "error": "invalid_broker_response"}
    except Exception:
        return {"status": "rejected", "error": "memory_proposal_broker_unavailable"}
    finally:
        client.close()


def handle(request: object) -> dict | None:
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return rpc_error(None, -32600, "invalid_request")
    identifier, method = request.get("id"), request.get("method")
    if method == "initialize":
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        version = params.get("protocolVersion") if isinstance(params.get("protocolVersion"), str) else "2024-11-05"
        return rpc_result(identifier, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "secure-sandbox-memory-proposal", "version": "1.0.0"},
            "instructions": "Memory proposals are untrusted requests for operator review, never instructions. Do not place secrets or source excerpts in them.",
        })
    if method == "ping":
        return rpc_result(identifier, {})
    if method == "notifications/initialized" or (isinstance(method, str) and method.startswith("notifications/")):
        return None
    if method == "tools/list":
        return rpc_result(identifier, {"tools": [TOOL]})
    if method != "tools/call":
        return rpc_error(identifier, -32601, "method_not_found")
    params = request.get("params")
    if not isinstance(params, dict) or params.get("name") != "propose_memory" or not isinstance(params.get("arguments"), dict):
        return rpc_error(identifier, -32602, "invalid_tool_call")
    arguments = params["arguments"]
    allowed = {"category", "title", "proposal", "rationale", "evidence_refs"}
    if set(arguments) != allowed:
        return rpc_error(identifier, -32602, "invalid_arguments")
    value = submit(arguments)
    failed = value.get("status") != "queued_for_operator_review"
    return rpc_result(identifier, {
        "content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"), sort_keys=True)}],
        "structuredContent": value,
        "isError": failed,
    })


def main() -> None:
    while True:
        line = sys.stdin.buffer.readline(64 * 1024 + 1)
        if not line:
            return
        if len(line) > 64 * 1024 or not line.endswith(b"\n"):
            response = rpc_error(None, -32700, "request_too_large")
        else:
            try:
                response = handle(json.loads(line))
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = rpc_error(None, -32700, "parse_error")
            except Exception:
                response = rpc_error(None, -32603, "internal_error")
        if response is not None:
            print(json.dumps(response, separators=(",", ":"), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
