#!/usr/bin/env python3
"""Resolve and fetch public GitHub source snapshots through pinned endpoints."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}$")
SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def validate_repository(value: str) -> str:
    if not REPOSITORY_RE.fullmatch(value) or value.endswith(".git"):
        raise ValueError("invalid_repository")
    owner, repository = value.split("/", 1)
    if owner in {".", ".."} or repository in {".", ".."}:
        raise ValueError("invalid_repository")
    return value


def validate_ref(value: str) -> str:
    if (
        not REF_RE.fullmatch(value)
        or value.endswith(("/", "."))
        or value.startswith(("/", "."))
        or any(token in value for token in ("..", "//", "@{"))
    ):
        raise ValueError("invalid_ref")
    return value


def validate_npm_package(value: str) -> str:
    if not NPM_PACKAGE_RE.fullmatch(value):
        raise ValueError("invalid_npm_package")
    return value


def validate_npm_version(value: str) -> str:
    if not SEMVER_RE.fullmatch(value):
        raise ValueError("invalid_npm_version")
    return value


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-source-policy-v1":
        raise ValueError("invalid_config")
    for host in ("api.github.com", "codeload.github.com", "registry.npmjs.org"):
        addresses = value.get("endpoint_ipv4", {}).get(host)
        if not isinstance(addresses, list) or not addresses:
            raise ValueError("missing_endpoint_pins")
        for item in addresses:
            address = ipaddress.ip_address(item)
            if address.version != 4 or not address.is_global:
                raise ValueError("invalid_endpoint_pin")
    return value


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(host, 443, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def request(config: dict, host: str, path: str, max_bytes: int) -> tuple[int, dict, bytes]:
    last_error: Exception | None = None
    deadline = time.monotonic() + float(config.get("request_timeout_seconds", 30))
    for address in config["endpoint_ipv4"][host]:
        connection: PinnedHTTPSConnection | None = None
        try:
            remaining = max(1.0, deadline - time.monotonic())
            connection = PinnedHTTPSConnection(host, address, min(remaining, 15.0))
            connection.request("GET", path, headers={
                "Accept": "application/json" if host == "registry.npmjs.org" else ("application/vnd.github+json" if host == "api.github.com" else "application/octet-stream"),
                "User-Agent": "SecureSandboxSourceAcquisition/1",
                "X-GitHub-Api-Version": "2022-11-28",
                "Connection": "close",
            })
            response = connection.getresponse()
            headers = {key.lower(): value for key, value in response.getheaders()}
            length_text = headers.get("content-length", "")
            if length_text:
                length = int(length_text)
                if length < 0 or length > max_bytes:
                    raise ValueError("response_too_large")
            chunks: list[bytes] = []
            total = 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("request_deadline")
                chunk = response.read(min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("response_too_large")
            return response.status, headers, b"".join(chunks)
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as error:
            last_error = error
        finally:
            if connection is not None:
                connection.close()
    raise RuntimeError(type(last_error).__name__ if last_error else "endpoint_unavailable")


def resolve(config: dict, repository: str, requested_ref: str) -> dict:
    repository = validate_repository(repository)
    requested_ref = validate_ref(requested_ref)
    encoded_ref = urllib.parse.quote(requested_ref, safe="")
    status, _, body = request(
        config,
        "api.github.com",
        f"/repos/{repository}/commits/{encoded_ref}",
        int(config.get("max_api_bytes", 2 * 1024 * 1024)),
    )
    if status != 200:
        raise RuntimeError(f"github_status_{status}")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_github_response") from error
    commit = value.get("sha") if isinstance(value, dict) else None
    if not isinstance(commit, str) or not SHA_RE.fullmatch(commit):
        raise ValueError("invalid_commit_sha")
    return {
        "source_kind": "github_archive",
        "repository": repository,
        "requested_ref": requested_ref,
        "resolved_commit": commit,
        "visibility": "public",
        "archive_endpoint_class": "direct_codeload_commit_tarball",
    }


def resolve_npm(config: dict, package: str, version: str) -> dict:
    package = validate_npm_package(package)
    version = validate_npm_version(version)
    encoded = urllib.parse.quote(package, safe="")
    status, _, body = request(config, "registry.npmjs.org", f"/{encoded}/{version}", int(config.get("max_api_bytes", 2 * 1024 * 1024)))
    if status != 200:
        raise RuntimeError(f"npm_status_{status}")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_npm_response") from error
    if not isinstance(value, dict) or value.get("name") != package or value.get("version") != version:
        raise ValueError("invalid_npm_identity")
    dist = value.get("dist")
    if not isinstance(dist, dict):
        raise ValueError("invalid_npm_dist")
    integrity = str(dist.get("integrity", ""))
    shasum = str(dist.get("shasum", ""))
    if not integrity.startswith("sha512-") or not SHA_RE.fullmatch(shasum):
        raise ValueError("invalid_npm_integrity")
    try:
        decoded = base64.b64decode(integrity[7:], validate=True)
    except ValueError as error:
        raise ValueError("invalid_npm_integrity") from error
    if len(decoded) != 64:
        raise ValueError("invalid_npm_integrity")
    parsed = urllib.parse.urlsplit(str(dist.get("tarball", "")))
    if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org" or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid_npm_tarball")
    expected_prefix = f"/{package}/-/"
    if not parsed.path.startswith(expected_prefix) or not parsed.path.endswith(".tgz"):
        raise ValueError("invalid_npm_tarball")
    return {
        "source_kind": "npm_package",
        "repository": f"npm/{package[1:].replace('/', '--') if package.startswith('@') else package}",
        "package_name": package,
        "package_version": version,
        "requested_ref": version,
        "resolved_commit": shasum,
        "npm_integrity": integrity,
        "npm_tarball_path": parsed.path,
        "visibility": "public",
        "archive_endpoint_class": "registry_npm_exact_version_tarball",
    }


def fetch(config: dict, plan_path: str, output_path: str) -> dict:
    with open(plan_path, encoding="utf-8") as handle:
        plan = json.load(handle)
    source_kind = str(plan.get("source_kind", "github_archive"))
    repository = str(plan.get("repository", ""))
    commit = str(plan.get("resolved_commit", ""))
    if not SHA_RE.fullmatch(commit) or plan.get("state") != "claimed":
        raise ValueError("invalid_claimed_plan")
    max_archive = int(config.get("max_archive_bytes", 256 * 1024 * 1024))
    if source_kind == "github_archive":
        repository = validate_repository(repository)
        host, path = "codeload.github.com", f"/{repository}/tar.gz/{commit}"
    elif source_kind == "npm_package":
        validate_npm_package(str(plan.get("package_name", "")))
        validate_npm_version(str(plan.get("package_version", "")))
        path = str(plan.get("npm_tarball_path", ""))
        expected_prefix = f"/{plan['package_name']}/-/"
        if not path.startswith(expected_prefix) or not path.endswith(".tgz") or "?" in path or "#" in path:
            raise ValueError("invalid_npm_tarball")
        host = "registry.npmjs.org"
    else:
        raise ValueError("invalid_source_kind")
    status, headers, body = request(config, host, path, max_archive)
    if status != 200:
        raise RuntimeError(f"source_status_{status}")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/x-gzip", "application/gzip", "application/octet-stream"}:
        raise ValueError("unexpected_content_type")
    if not body.startswith(b"\x1f\x8b"):
        raise ValueError("archive_not_gzip")
    if source_kind == "npm_package":
        expected = str(plan.get("npm_integrity", ""))
        actual = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode("ascii")
        if actual != expected or hashlib.sha1(body).hexdigest() != commit:
            raise ValueError("npm_integrity_mismatch")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(output_path, flags, 0o640)
    try:
        offset = 0
        while offset < len(body):
            offset += os.write(descriptor, body[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(os.path.dirname(output_path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"archive_bytes": len(body), "archive_sha256": hashlib.sha256(body).hexdigest(), "registry_integrity_verified": source_kind == "npm_package"}


def main() -> None:
    for name in list(os.environ):
        if name.lower().endswith("proxy"):
            os.environ.pop(name, None)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/secure-sandbox/source-acquisition.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    resolver = subparsers.add_parser("resolve")
    resolver.add_argument("repository")
    resolver.add_argument("requested_ref")
    npm_resolver = subparsers.add_parser("resolve-npm")
    npm_resolver.add_argument("package")
    npm_resolver.add_argument("version")
    downloader = subparsers.add_parser("fetch")
    downloader.add_argument("plan_path")
    downloader.add_argument("output_path")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.command == "resolve":
        value = resolve(config, args.repository, args.requested_ref)
    elif args.command == "resolve-npm":
        value = resolve_npm(config, args.package, args.version)
    else:
        value = fetch(config, args.plan_path, args.output_path)
    sys.stdout.buffer.write(canonical_json(value) + b"\n")


if __name__ == "__main__":
    main()
