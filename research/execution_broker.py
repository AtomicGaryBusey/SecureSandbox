#!/usr/bin/env python3
"""Validate registered fixtures and broker fixed-policy execution to Target."""

from __future__ import annotations

import base64
import collections
import hashlib
import http.client
import json
import os
import socket
import stat
import syslog
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from source_integrity import (
    MAX_MANIFEST_BYTES, IntegrityError, expected_records, fixed_tree_path,
    hash_regular, load_control_json, registered_source, safe_relative,
)
from evidence_receipts import ReceiptError, active_run, publish

CONFIG = "/etc/secure-sandbox/execution-broker.json"
MAX_BODY = 128 * 1024
MAX_CODE = 24 * 1024
MAX_FILES = 16
MAX_FIXTURES = 1024 * 1024
MAX_OUTPUT = 64 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 3.0
REJECTION_TOKENS = {
    "active_run_required","active_run_untrusted",
    "control_file_changed","control_file_too_large","file_too_large","filesystem_changed_during_verification",
    "filesystem_race","fixture_changed","fixture_integrity_mismatch","fixture_not_registered_file",
    "fixtures_too_large","integrity_manifest_hash_mismatch","invalid_code_or_source","invalid_control_json",
    "invalid_fixture_path","invalid_fixture_paths","invalid_integrity_manifest","invalid_request","invalid_scope",
    "invalid_source_id","invalid_source_index","invalid_timeout","registered_tree_missing","source_manifest_unavailable",
    "request_incomplete","source_not_registered","too_many_entries","tree_too_large","tree_unreadable","unsafe_fixture",
    "unsafe_fixture_path","unsafe_path_collision","unsafe_registered_path","untrusted_control_file",
}


class Rejected(ValueError):
    pass


def rejection_token(error: Exception) -> str:
    value = str(error)
    return value if value in REJECTION_TOKENS else "invalid_request"


def load_config() -> dict:
    info = os.stat(CONFIG, follow_symlinks=False)
    if info.st_uid != 0 or info.st_mode & 0o027:
        raise RuntimeError("unsafe_config")
    with open(CONFIG, encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schema") != "secure-sandbox-execution-broker-v1" or len(str(value.get("token", ""))) < 40:
        raise RuntimeError("invalid_config")
    return value


def audit(event: str, request_id: str = "", source_id: str = "", code_hash: str = "", status: str = "", duration_ms: int = 0) -> None:
    record = {
        "event": event, "request_id": request_id[:64], "source_id": source_id[:64],
        "code_sha256": code_hash[:64], "status": status[:160], "duration_ms": int(duration_ms),
    }
    try:
        syslog.openlog("secure-sandbox-execution", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if event.endswith(("rejected", "failed", "timed_out")) else syslog.LOG_INFO,
                      json.dumps(record, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def read_fixture(baseline: str, relative: str, expected: dict) -> tuple[bytes, str]:
    relative = safe_relative(relative)
    record = expected.get(relative)
    if not isinstance(record, dict) or record.get("type") != "file":
        raise Rejected("fixture_not_registered_file")
    path = os.path.join(baseline, relative)
    required = baseline.rstrip("/") + "/"
    if not os.path.normpath(path).startswith(required):
        raise Rejected("unsafe_fixture_path")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Rejected("unsafe_fixture")
    digest, size = hash_regular(path, info)
    if digest != record.get("sha256") or size != record.get("bytes"):
        raise Rejected("fixture_integrity_mismatch")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(descriptor, size + 1)
    finally:
        os.close(descriptor)
    if len(data) != size:
        raise Rejected("fixture_changed")
    return data, digest


def validate_and_forward(value: object, config: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"source_id", "code", "fixture_paths", "timeout_seconds"}:
        raise Rejected("invalid_request")
    source_id = value["source_id"]
    code = value["code"]
    paths = value["fixture_paths"]
    timeout = value["timeout_seconds"]
    if not isinstance(source_id, str) or not isinstance(code, str) or not 1 <= len(code.encode("utf-8")) <= MAX_CODE:
        raise Rejected("invalid_code_or_source")
    if not isinstance(paths, list) or len(paths) > MAX_FILES or len(set(map(str, paths))) != len(paths):
        raise Rejected("invalid_fixture_paths")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 10:
        raise Rejected("invalid_timeout")
    record = registered_source(source_id)
    manifest_relative = record.get("integrity_manifest_path")
    if not manifest_relative:
        raise Rejected("source_manifest_unavailable")
    manifest = load_control_json(fixed_tree_path(manifest_relative, "source-manifests"), MAX_MANIFEST_BYTES)
    if not isinstance(manifest, dict) or manifest.get("source_id") != source_id:
        raise Rejected("invalid_integrity_manifest")
    expected = expected_records(manifest)
    baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
    fixtures = []
    total = 0
    for path in paths:
        if not isinstance(path, str):
            raise Rejected("invalid_fixture_path")
        data, digest = read_fixture(baseline, path, expected)
        total += len(data)
        if total > MAX_FIXTURES:
            raise Rejected("fixtures_too_large")
        fixtures.append({"path": path, "content_b64": base64.b64encode(data).decode("ascii"), "sha256": digest})
    run_id = active_run()
    request_id = str(uuid.uuid4())
    request = {
        "schema": "secure-sandbox-execution-request-v1", "request_id": request_id,
        "source_id": source_id, "code_b64": base64.b64encode(code.encode()).decode("ascii"),
        "fixtures": fixtures, "timeout_seconds": timeout,
    }
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    audit("execution_accepted", request_id, source_id, code_hash, "accepted")
    started = time.monotonic()
    connection = http.client.HTTPConnection("172.30.20.2", 8080, timeout=timeout + 8)
    connection.request("POST", "/v1/execute", body=json.dumps(request, separators=(",", ":")), headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + config["token"],
    })
    response = connection.getresponse()
    raw = response.read(256 * 1024 + 1)
    connection.close()
    if response.status != 200 or len(raw) > 256 * 1024:
        raise RuntimeError("target_execution_failed")
    result = json.loads(raw)
    if (not isinstance(result, dict) or result.get("schema") != "secure-sandbox-execution-result-v1"
            or result.get("request_id") != request_id or result.get("source_id") != source_id
            or not isinstance(result.get("exit_code"), int) or isinstance(result.get("exit_code"), bool)
            or not -255 <= result["exit_code"] <= 255
            or any(not isinstance(result.get(name), bool) for name in
                   ("timed_out", "output_limit_exceeded", "stdout_truncated", "stderr_truncated"))
            or not isinstance(result.get("duration_ms"), int) or isinstance(result.get("duration_ms"), bool)
            or not 0 <= result["duration_ms"] <= 120_000):
        raise RuntimeError("invalid_target_result")
    for stream in ("stdout", "stderr"):
        try:
            decoded = base64.b64decode(result.pop(stream + "_b64"), validate=True)
        except Exception as error:
            raise RuntimeError("invalid_target_output") from error
        if len(decoded) > MAX_OUTPUT:
            raise RuntimeError("oversized_target_output")
        if hashlib.sha256(decoded).hexdigest() != result.get(stream + "_sha256"):
            raise RuntimeError("target_output_hash_mismatch")
        result[stream] = decoded.decode("utf-8", "backslashreplace")
    result["code_sha256"] = code_hash
    result["fixture_manifest_sha256"] = hashlib.sha256(json.dumps(
        [{"path": item["path"], "sha256": item["sha256"]} for item in fixtures],
        separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    projection = {
        "class":"measured_execution","source_id":source_id,"request_id":request_id,"run_id":run_id,
        "code_sha256":code_hash,"stdout_sha256":result["stdout_sha256"],
        "stderr_sha256":result["stderr_sha256"],"exit_code":result["exit_code"],
        "timed_out":result["timed_out"],"output_limit_exceeded":result["output_limit_exceeded"],
        "stdout_truncated":result["stdout_truncated"],"stderr_truncated":result["stderr_truncated"],
        "timeout_seconds":timeout,"duration_ms":result["duration_ms"],
        "fixture_manifest_sha256":result["fixture_manifest_sha256"],
        "image_digest":result["runtime_image_id"],
    }
    result["run_id"] = run_id
    result["evidence_receipt"] = publish("execution-broker", "run_python_fixture", projection)
    duration = round((time.monotonic() - started) * 1000)
    event = "execution_timed_out" if result.get("timed_out") else "execution_completed"
    audit(event, request_id, source_id, code_hash, "timeout" if result.get("timed_out") else "completed", duration)
    return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    attempts = collections.deque()

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        self._framing_lock = threading.Lock()
        self._framing_state = "open"
        self._deadline_timer = threading.Timer(REQUEST_READ_TIMEOUT_SECONDS, self._expire_framing)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _expire_framing(self) -> None:
        with self._framing_lock:
            if self._framing_state != "open":
                return
            self._framing_state = "expired"
        audit("execution_rejected", status="request_incomplete")
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def _complete_framing(self) -> bool:
        with self._framing_lock:
            if self._framing_state == "expired":
                return False
            self._framing_state = "complete"
        self._deadline_timer.cancel()
        # Socket deadlines apply only while client I/O is pending. Retaining
        # this finite timeout does not shorten Target execution, but prevents a
        # client that stops reading from monopolizing the serialized server.
        self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        return True

    def finish(self) -> None:
        if hasattr(self, "_framing_lock"):
            with self._framing_lock:
                if self._framing_state == "open":
                    self._framing_state = "complete"
        if hasattr(self, "_deadline_timer"):
            self._deadline_timer.cancel()
        super().finish()

    def reply(self, status: int, value: dict) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        try:
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass

    def do_POST(self) -> None:
        now = time.monotonic()
        while self.attempts and self.attempts[0] < now - 60: self.attempts.popleft()
        if len(self.attempts) >= 12:
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(429, {"error": "rate_limited"}); return
        self.attempts.append(now)
        if self.path != "/v1/run-python":
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(404, {"error": "not_found"}); return
        try: length = int(self.headers.get("Content-Length", "-1"))
        except ValueError: length = -1
        if not 0 <= length <= MAX_BODY:
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(413, {"error": "request_too_large"}); return
        source_id = ""; code_hash = ""
        try:
            body = self.rfile.read(length)
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            if len(body) != length:
                raise Rejected("request_incomplete")
            value = json.loads(body); source_id = str(value.get("source_id", "")) if isinstance(value, dict) else ""
            code_hash = hashlib.sha256(str(value.get("code", "")).encode()).hexdigest() if isinstance(value, dict) else ""
            result = validate_and_forward(value, self.server.config)
        except (socket.timeout, TimeoutError):
            self.close_connection = True
            self._expire_framing()
            self.reply(408, {"error": "request_incomplete"}); return
        except (Rejected, IntegrityError, ReceiptError, json.JSONDecodeError) as error:
            token=rejection_token(error)
            audit("execution_rejected", source_id=source_id, code_hash=code_hash, status=token); self.reply(400, {"error": token}); return
        except Exception:
            audit("execution_failed", source_id=source_id, code_hash=code_hash, status="internal_error"); self.reply(502, {"error": "execution_failed"}); return
        self.reply(200, result)

    def log_message(self, *_: object) -> None: return


def main() -> None:
    config = load_config(); server = HTTPServer(("127.0.0.1", 18081), Handler); server.config = config; server.serve_forever()


if __name__ == "__main__": main()
