#!/usr/bin/env python3
"""Minimal stdio MCP adapter for the read-only source integrity verifier."""

from __future__ import annotations

import json
import sys
import syslog

from source_integrity import IntegrityError, verify_source
from review_bundle import ReviewBundleError, verify_review_bundle

MAX_REQUEST_BYTES = 64 * 1024
SOURCE_TOOL = {
    "name": "verify_source",
    "description": "Recompute a registered SecureSandbox source baseline against its import-time hash manifest and optionally compare the writable worktree. Accepts only a source UUID and fixed scope; it cannot read arbitrary paths, return file contents, execute code, or use the network.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "source_id": {"type": "string", "description": "Registered source UUID from repos/INDEX.json"},
            "scope": {"type": "string", "enum": ["baseline", "worktree", "both"], "default": "both"},
        },
        "required": ["source_id"],
        "additionalProperties": False,
    },
    "_meta": {"anthropic/alwaysLoad": True},
}
REVIEW_TOOL = {
    "name": "verify_review_bundle",
    "description": "Verify a sealed operator-published SecureSandbox white-box review bundle against its root-owned SHA-256 manifest. Accepts only a strict bundle identifier; it cannot hash arbitrary paths, return file contents, execute code, or use the network.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "bundle_id": {"type": "string", "description": "Review bundle identifier ending in -review"},
        },
        "required": ["bundle_id"],
        "additionalProperties": False,
    },
    "_meta": {"anthropic/alwaysLoad": True},
}


def audit(source_id: object, scope: object, status: str, verification: dict | None = None) -> None:
    """Emit content-free verification metadata; the tool result remains the primary evidence."""
    baseline_mismatch = bool(
        verification is not None
        and isinstance(verification.get("baseline"), dict)
        and verification["baseline"].get("status") == "changed"
    )
    event = {
        "event": "source_integrity_baseline_mismatch" if baseline_mismatch else (
            "source_integrity_verified" if status not in {"rejected", "internal_error"} else "source_integrity_rejected"
        ),
        "source_id": source_id if isinstance(source_id, str) and len(source_id) <= 64 else "",
        "scope": scope if scope in {"baseline", "worktree", "both"} else "invalid",
        "status": status,
    }
    if verification is not None:
        event["anchor_status"] = str(verification.get("anchor_status", ""))[:64]
        event["change_count"] = sum(
            int(section.get("missing", 0)) + int(section.get("added", 0)) + int(section.get("modified", 0))
            for name, section in verification.items()
            if name in {"baseline", "worktree"} and isinstance(section, dict)
        )
        event["baseline_status"] = str(verification.get("baseline", {}).get("status", "not_checked"))[:32]
        event["worktree_status"] = str(verification.get("worktree", {}).get("status", "not_checked"))[:32]
    try:
        syslog.openlog("secure-sandbox-source-integrity", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_ERR if baseline_mismatch else (
            syslog.LOG_INFO if status in {"match", "legacy_unanchored_match"} else syslog.LOG_WARNING),
                      json.dumps(event, separators=(",", ":"), sort_keys=True))
    except Exception:
        # Verification must not fail merely because the best-effort telemetry path is unavailable.
        pass


def audit_review_bundle(bundle_id: object, status: str, verification: dict | None = None) -> None:
    event = {
        "event": "review_bundle_verified" if status == "verified" else "review_bundle_rejected",
        "bundle_id": bundle_id if isinstance(bundle_id, str) and len(bundle_id) <= 64 else "",
        "status": status,
    }
    if verification is not None:
        event["manifest_sha256"] = str(verification.get("manifest_sha256", ""))[:64]
        event["file_count"] = int(verification.get("file_count", 0))
    try:
        syslog.openlog("secure-sandbox-source-integrity", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO if status == "verified" else syslog.LOG_WARNING,
                      json.dumps(event, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def result(request_id: object, value: object) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error(request_id: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(request: object) -> dict | None:
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return error(request.get("id") if isinstance(request, dict) else None, -32600, "invalid_request")
    request_id = request.get("id")
    method = request.get("method")
    if method == "notifications/initialized" or (isinstance(method, str) and method.startswith("notifications/")):
        return None
    if method == "initialize":
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        version = params.get("protocolVersion") if isinstance(params.get("protocolVersion"), str) else "2024-11-05"
        return result(request_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "secure-sandbox-source-integrity", "version": "1.1.0"},
            "instructions": "Use verify_source for registered source trees and verify_review_bundle for sealed operator-published white-box review bundles. Neither tool accepts arbitrary paths or returns file content.",
        })
    if method == "ping":
        return result(request_id, {})
    if method == "tools/list":
        return result(request_id, {"tools": [SOURCE_TOOL, REVIEW_TOOL]})
    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict) or params.get("name") not in {"verify_source", "verify_review_bundle"} or not isinstance(params.get("arguments"), dict):
            return error(request_id, -32602, "invalid_tool_call")
        arguments = params["arguments"]
        if params["name"] == "verify_review_bundle":
            if set(arguments) - {"bundle_id"}:
                return error(request_id, -32602, "invalid_tool_arguments")
            try:
                verification = verify_review_bundle(arguments.get("bundle_id", ""))
            except ReviewBundleError as failure:
                audit_review_bundle(arguments.get("bundle_id"), "rejected")
                payload = {"status": "rejected", "error": str(failure)}
                return result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"), sort_keys=True)}], "isError": True})
            except Exception:
                audit_review_bundle(arguments.get("bundle_id"), "internal_error")
                payload = {"status": "rejected", "error": "internal_error"}
                return result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"), sort_keys=True)}], "isError": True})
            audit_review_bundle(arguments.get("bundle_id"), "verified", verification)
            payload = json.dumps(verification, separators=(",", ":"), sort_keys=True)
            return result(request_id, {"content": [{"type": "text", "text": payload}], "structuredContent": verification, "isError": False})
        if set(arguments) - {"source_id", "scope"}:
            return error(request_id, -32602, "invalid_tool_arguments")
        try:
            verification = verify_source(arguments.get("source_id", ""), arguments.get("scope", "both"))
        except IntegrityError as failure:
            audit(arguments.get("source_id"), arguments.get("scope", "both"), "rejected")
            payload = {"status": "rejected", "error": str(failure)}
            return result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"), sort_keys=True)}], "isError": True})
        except Exception:
            audit(arguments.get("source_id"), arguments.get("scope", "both"), "internal_error")
            payload = {"status": "rejected", "error": "internal_error"}
            return result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"), sort_keys=True)}], "isError": True})
        audit(arguments.get("source_id"), arguments.get("scope", "both"), verification["overall_status"], verification)
        payload = json.dumps(verification, separators=(",", ":"), sort_keys=True)
        return result(request_id, {"content": [{"type": "text", "text": payload}], "structuredContent": verification, "isError": False})
    return error(request_id, -32601, "method_not_found")


def main() -> None:
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            response = error(None, -32700, "request_too_large")
        else:
            try:
                request = json.loads(line)
                response = handle(request)
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = error(None, -32700, "parse_error")
            except Exception:
                response = error(None, -32603, "internal_error")
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":"), sort_keys=True) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
