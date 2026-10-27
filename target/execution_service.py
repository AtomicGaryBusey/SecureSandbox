#!/usr/bin/env python3
"""Authenticated, fixed-policy disposable Python execution service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import selectors
import shutil
import subprocess
import syslog
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler

from shared.bounded_http import AbsoluteFramingHandler, BoundedHTTPServer, RequestIncomplete

CONFIG = "/home/labadmin/.config/secure-sandbox-execution.json"
MAX_BODY = 2 * 1024 * 1024
MAX_CODE = 24 * 1024
MAX_FILES = 16
MAX_FIXTURES = 1024 * 1024
MAX_OUTPUT = 64 * 1024
SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.?(/|$))[A-Za-z0-9_.@+ -]+(?:/[A-Za-z0-9_.@+ -]+)*$")


class Rejected(ValueError):
    pass


def load_config() -> dict:
    info = os.stat(CONFIG, follow_symlinks=False)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("unsafe_config")
    with open(CONFIG, encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schema") != "secure-sandbox-execution-target-v1":
        raise RuntimeError("invalid_config")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("image_id", ""))):
        raise RuntimeError("invalid_image_id")
    if not isinstance(value.get("token"), str) or len(value["token"]) < 40:
        raise RuntimeError("invalid_token")
    return value


def bounded_decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4 + 4:
        raise Rejected("invalid_base64")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise Rejected("invalid_base64") from error
    if len(data) > maximum:
        raise Rejected("content_too_large")
    return data


def validate_request(value: object) -> tuple[bytes, list[tuple[str, bytes]], int, str, str]:
    if not isinstance(value, dict) or set(value) != {"schema", "request_id", "source_id", "code_b64", "fixtures", "timeout_seconds"}:
        raise Rejected("invalid_request")
    if value["schema"] != "secure-sandbox-execution-request-v1":
        raise Rejected("invalid_schema")
    try:
        request_id = str(uuid.UUID(str(value["request_id"])))
        source_id = str(uuid.UUID(str(value["source_id"])))
    except ValueError as error:
        raise Rejected("invalid_identifier") from error
    if request_id != value["request_id"] or source_id != value["source_id"]:
        raise Rejected("invalid_identifier")
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 10:
        raise Rejected("invalid_timeout")
    code = bounded_decode(value["code_b64"], MAX_CODE)
    try:
        code.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise Rejected("code_not_utf8") from error
    fixtures_value = value["fixtures"]
    if not isinstance(fixtures_value, list) or len(fixtures_value) > MAX_FILES:
        raise Rejected("invalid_fixtures")
    fixtures: list[tuple[str, bytes]] = []
    total = 0
    seen: set[str] = set()
    for item in fixtures_value:
        if not isinstance(item, dict) or set(item) != {"path", "content_b64", "sha256"}:
            raise Rejected("invalid_fixture")
        path = item["path"]
        if not isinstance(path, str) or len(path.encode("utf-8")) > 240 or not SAFE_PATH.fullmatch(path) or path in seen or path == "main.py":
            raise Rejected("unsafe_fixture_path")
        data = bounded_decode(item["content_b64"], MAX_FIXTURES)
        digest = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(digest, str(item["sha256"])):
            raise Rejected("fixture_hash_mismatch")
        total += len(data)
        if total > MAX_FIXTURES:
            raise Rejected("fixtures_too_large")
        seen.add(path)
        fixtures.append((path, data))
    return code, fixtures, timeout, request_id, source_id


def bounded_container_output(process: subprocess.Popen, name: str, runtime: str, timeout: int) -> tuple[bytes, bytes, bool, bool]:
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    timed_out = False
    output_limit = False
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        for key, _ in selector.select(min(remaining, 0.25)):
            chunk = os.read(key.fileobj.fileno(), 8192)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            target = buffers[streams[key.fileobj]]
            room = MAX_OUTPUT - len(target)
            target.extend(chunk[:max(0, room)])
            if len(chunk) > room:
                output_limit = True
                break
        if output_limit:
            break
        if process.poll() is not None and not selector.get_map():
            break
    if timed_out or output_limit:
        subprocess.run(["docker", "rm", "-f", name], env={**os.environ, "DOCKER_HOST": runtime}, capture_output=True, timeout=5)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=3)
    selector.close()
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), timed_out, output_limit


def execute(value: object, config: dict) -> dict:
    code, fixtures, timeout, request_id, source_id = validate_request(value)
    runtime = os.environ.get("DOCKER_HOST", "unix:///run/user/1000/docker.sock")
    image_id = config["image_id"]
    inspected = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image_id],
        env={**os.environ, "DOCKER_HOST": runtime}, capture_output=True, text=True, timeout=5, check=True,
    ).stdout.strip()
    if not hmac.compare_digest(inspected, image_id):
        raise RuntimeError("runtime_image_mismatch")
    job_root = "/home/labadmin/.local/share/secure-sandbox-execution/jobs"
    os.makedirs(job_root, mode=0o700, exist_ok=True)
    job = tempfile.mkdtemp(prefix="job-", dir=job_root)
    name = "ssx-" + request_id
    started = time.monotonic()
    timed_out = False
    try:
        os.chmod(job, 0o755)
        main_path = os.path.join(job, "main.py")
        with open(main_path, "xb") as handle:
            handle.write(code)
        os.chmod(main_path, 0o444)
        for relative, data in fixtures:
            destination = os.path.join(job, relative)
            os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
            with open(destination, "xb") as handle:
                handle.write(data)
            os.chmod(destination, 0o444)
        command = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", "256m", "--memory-swap", "256m", "--cpus", "1.0",
            "--user", "65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--mount", f"type=bind,src={job},dst=/work,readonly",
            image_id,
        ]
        process = subprocess.Popen(command, env={**os.environ, "DOCKER_HOST": runtime}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr, timed_out, output_limit = bounded_container_output(process, name, runtime, timeout)
        return {
            "schema": "secure-sandbox-execution-result-v1",
            "request_id": request_id, "source_id": source_id,
            "runtime": "python3.14", "runtime_image_id": image_id,
            "exit_code": process.returncode, "timed_out": timed_out,
            "output_limit_exceeded": output_limit,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout_b64": base64.b64encode(stdout).decode("ascii"), "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_truncated": output_limit,
            "stderr_b64": base64.b64encode(stderr).decode("ascii"), "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "stderr_truncated": output_limit,
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], env={**os.environ, "DOCKER_HOST": runtime}, capture_output=True, timeout=5)
        shutil.rmtree(job, ignore_errors=True)


class Handler(AbsoluteFramingHandler, BaseHTTPRequestHandler):
    server_version = "SecureSandboxExecution/1"
    protocol_version = "HTTP/1.1"

    def reply(self, status: int, value: dict) -> None:
        if not self.complete_framing():
            self.close_connection = True
            return
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        if self.path != "/v1/execute":
            self.reply(404, {"error": "not_found"}); return
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + self.server.config["token"]):
            self.reply(403, {"error": "forbidden"}); return
        if self.headers.get("Transfer-Encoding") is not None:
            self.reply(400, {"error": "transfer_encoding_not_allowed"}); return
        lengths = self.headers.get_all("Content-Length", failobj=[])
        try:
            length = int(lengths[0]) if len(lengths) == 1 else -1
        except (TypeError, ValueError):
            length = -1
        if not 0 <= length <= MAX_BODY:
            self.reply(413, {"error": "request_too_large"}); return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
            self.reply(415, {"error": "json_required"}); return
        try:
            value = json.loads(self.read_exact_body(length))
            result = execute(value, self.server.config)
        except RequestIncomplete:
            self.close_connection = True; return
        except (Rejected, json.JSONDecodeError) as error:
            self.reply(400, {"error": str(error) or "invalid_json"}); return
        except Exception as error:
            syslog.openlog("secure-sandbox-execution-target", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
            syslog.syslog(syslog.LOG_ERR, f"execution_failed:{type(error).__name__}:{str(error)[:160]}")
            self.reply(500, {"error": "execution_failed"}); return
        self.reply(200, result)

    def do_GET(self) -> None:
        self.reply(200, {"status": "ok"}) if self.path == "/healthz" else self.reply(404, {"error": "not_found"})

    def log_message(self, *_: object) -> None:
        return

    def framing_expired(self) -> None:
        syslog.openlog("secure-sandbox-execution-target", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING, "execution_rejected:request_incomplete")


def main() -> None:
    config = load_config()
    server = BoundedHTTPServer(("172.30.20.2", 8080), Handler)
    server.config = config
    server.serve_forever()


if __name__ == "__main__":
    main()
