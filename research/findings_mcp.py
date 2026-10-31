#!/usr/bin/env python3
"""Managed MCP adapter for non-authoritative candidate findings."""

from __future__ import annotations

import json
import re
import socket
import sys

SOCKET_PATH = "/run/secure-sandbox-findings/findings.sock"
MAX_REQUEST_BYTES = 64 * 1024

EVIDENCE = {
    "type": "object",
    "description": "A typed evidence reference. For exhaustive_corpus_search or measured_execution, send exactly class, source_id, and receipt_id. For static_graph_reachability, copy exactly finding_evidence_pointer: class, source_id, and analysis_id. The trusted broker resolves all remaining fields.",
    "additionalProperties": True,
    "properties": {
        "class": {"type":"string","enum":["static_source_review","exhaustive_corpus_search","static_graph_reachability","measured_execution","report_reference","operator_reported"]},
        "source_id":{"type":"string"}, "path":{"type":"string"}, "line":{"type":"integer"},
        "receipt_id":{"type":"string","description":"Trusted receipt UUID pointer. This is the only receipt locator to transcribe."},
        "receipt_sha256":{"type":"string","description":"Legacy compatibility only; omit for new submissions."},
        "instrument":{"type":"string","enum":["search_corpus","scan_corpus"]},
        "request_sha256":{"type":"string"}, "result_set_sha256":{"type":"string"}, "exhaustive":{"type":"boolean"},
        "analysis_id":{"type":"string","description":"Opaque CodeGraph analysis UUID. Copy finding_evidence_pointer from analyze_reachability; do not reconstruct the full projection."}, "codegraph_index_sha256":{"type":"string"}, "measured_execution":{"type":"boolean"},
        "caller_selected_entrypoint":{"type":"boolean"}, "request_id":{"type":"string"}, "run_id":{"type":"string"},
        "code_sha256":{"type":"string"}, "stdout_sha256":{"type":"string"}, "fixture_manifest_sha256":{"type":"string"},
        "image_digest":{"type":"string"}, "reference":{"type":"string"},
    },
    "required": ["class"],
}

SUBMIT = {
    "name":"submit_candidate_finding",
    "description":"Submit a bounded security hypothesis with typed evidence references. For exhaustive-search and measured-execution evidence, copy class, source_id, and receipt_id. For static reachability, copy finding_evidence_pointer (class, source_id, analysis_id). The broker resolves and verifies every remaining field internally. The result is only a candidate: it does not validate the claim or severity and cannot alter adjudication state.",
    "inputSchema":{"type":"object","additionalProperties":False,"properties":{
        "claim":{"type":"string","minLength":1,"maxLength":512},
        "affected":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"object","additionalProperties":False,"properties":{"source_id":{"type":"string"},"path":{"type":"string"},"symbol":{"type":"string"},"line":{"type":"integer","minimum":1}},"required":["source_id","path","symbol","line"]}},
        "evidence":{"type":"array","minItems":1,"maxItems":16,"items":EVIDENCE},
        "reproduction_conditions":{"type":"string","minLength":1,"maxLength":2048},
        "limitations":{"type":"string","minLength":1,"maxLength":2048},
        "counterargument":{"type":"string","minLength":1,"maxLength":2048},
        "proposed_severity":{"type":"string","enum":["info","low","medium","high","critical"]},
        "severity_rationale":{"type":"string","minLength":1,"maxLength":2048},
    },"required":["claim","affected","evidence","reproduction_conditions","limitations","counterargument","proposed_severity","severity_rationale"]},
    "_meta":{"anthropic/alwaysLoad":True},
}

AMEND = {
    "name":"amend_candidate_finding",
    "description":"Append evidence or qualifications to your existing candidate. This never edits the original and never changes adjudication state.",
    "inputSchema":{"type":"object","additionalProperties":False,"properties":{
        "finding_id":{"type":"string"}, "evidence":{"type":"array","minItems":1,"maxItems":16,"items":EVIDENCE},
        "limitations":{"type":"string","minLength":1,"maxLength":2048},
        "counterargument":{"type":"string","minLength":1,"maxLength":2048},
        "note":{"type":"string","minLength":1,"maxLength":1024},
    },"required":["finding_id","evidence","limitations","counterargument","note"]},
    "_meta":{"anthropic/alwaysLoad":True},
}


def rpc_result(identifier: object, value: object) -> dict:
    return {"jsonrpc":"2.0","id":identifier,"result":value}


def rpc_error(identifier: object, code: int, message: str) -> dict:
    return {"jsonrpc":"2.0","id":identifier,"error":{"code":code,"message":message}}


SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


def display_value(value: object, field: str = "") -> object:
    if isinstance(value, dict):
        return {key: display_value(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [display_value(item, field) for item in value]
    if isinstance(value, str) and (field.endswith("_sha256") or field == "content_sha256"):
        if SHA256.fullmatch(value):
            return " ".join(value[index:index + 8] for index in range(0, 64, 8))
    if isinstance(value, str) and field == "image_digest":
        match = IMAGE_DIGEST.fullmatch(value)
        if match:
            digest = match.group(1)
            return "sha256:" + " ".join(digest[index:index + 8] for index in range(0, 64, 8))
    return value


def display_json(value: object) -> str:
    return json.dumps(display_value(value),separators=(",",":"),sort_keys=True)


def broker(operation: str, arguments: dict) -> dict:
    encoded=json.dumps({"operation":operation,"arguments":arguments},ensure_ascii=False,separators=(",",":")).encode()
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); client.settimeout(3)
    try:
        client.connect(SOCKET_PATH); client.sendall(encoded); client.shutdown(socket.SHUT_WR); raw=bytearray()
        while len(raw)<=MAX_REQUEST_BYTES:
            chunk=client.recv(4096)
            if not chunk: break
            raw.extend(chunk)
        if len(raw)>MAX_REQUEST_BYTES: raise ValueError
        value=json.loads(raw)
        return value if isinstance(value,dict) else {"status":"rejected","error":"invalid_broker_response"}
    except Exception: return {"status":"rejected","error":"findings_broker_unavailable"}
    finally: client.close()


def handle(request: object) -> dict | None:
    if not isinstance(request,dict) or request.get("jsonrpc")!="2.0": return rpc_error(None,-32600,"invalid_request")
    identifier,method=request.get("id"),request.get("method")
    if method=="initialize":
        params=request.get("params") if isinstance(request.get("params"),dict) else {}
        version=params.get("protocolVersion") if isinstance(params.get("protocolVersion"),str) else "2024-11-05"
        return rpc_result(identifier,{"protocolVersion":version,"capabilities":{"tools":{"listChanged":False}},
            "serverInfo":{"name":"secure-sandbox-findings","version":"1.0.0"},
            "instructions":"Findings are untrusted candidates. Submission or amendment never validates a claim or proposed severity. Use typed evidence references, state limitations, and include the strongest counterargument."})
    if method=="ping": return rpc_result(identifier,{})
    if method=="notifications/initialized" or (isinstance(method,str) and method.startswith("notifications/")): return None
    if method=="tools/list": return rpc_result(identifier,{"tools":[SUBMIT,AMEND]})
    if method!="tools/call": return rpc_error(identifier,-32601,"method_not_found")
    params=request.get("params")
    if not isinstance(params,dict) or not isinstance(params.get("arguments"),dict): return rpc_error(identifier,-32602,"invalid_tool_call")
    name=params.get("name")
    if name==SUBMIT["name"]: operation="submit"; allowed=set(SUBMIT["inputSchema"]["required"])
    elif name==AMEND["name"]: operation="amend"; allowed=set(AMEND["inputSchema"]["required"])
    else: return rpc_error(identifier,-32602,"invalid_tool_call")
    if set(params["arguments"])!=allowed: return rpc_error(identifier,-32602,"invalid_arguments")
    value=broker(operation,params["arguments"]); failed=value.get("status") not in {"submitted","amended","already_submitted"}
    return rpc_result(identifier,{"content":[{"type":"text","text":display_json(value)}],
        "structuredContent":value,"isError":failed})


def main() -> None:
    while True:
        line=sys.stdin.buffer.readline(128*1024+1)
        if not line: return
        if len(line)>128*1024 or not line.endswith(b"\n"):
            oversized=len(line)>128*1024
            while oversized and line and not line.endswith(b"\n"):
                line=sys.stdin.buffer.readline(128*1024+1)
            error="request_too_large" if oversized else "request_incomplete"
            broker("transport_reject",{"error":error})
            response=rpc_error(None,-32700,error)
        else:
            try: response=handle(json.loads(line))
            except (UnicodeDecodeError,json.JSONDecodeError):
                broker("transport_reject",{"error":"finding_invalid"})
                response=rpc_error(None,-32700,"parse_error")
            except Exception: response=rpc_error(None,-32603,"internal_error")
        if response is not None: print(json.dumps(response,separators=(",",":"),sort_keys=True),flush=True)


if __name__=="__main__": main()
