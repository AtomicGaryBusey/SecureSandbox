#!/usr/bin/env python3
"""Validate and safely render a decrypted SecureSandbox artifact envelope."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
import uuid
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:md|txt|json)$")
MAX_FILE_BYTES = 4 * 1024 * 1024
ARCHIVE_NAME_RE = re.compile(
    r"^artifact-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-([0-9]{12})-([0-9a-f]{64})\.age$"
)


def safe_text(value: str) -> str:
    output = []
    for character in value:
        code = ord(character)
        if character in "\n\t":
            output.append(character)
        elif code >= 0x20 and not 0x7F <= code <= 0x9F and unicodedata.category(character) != "Cf":
            output.append(character)
        elif code <= 0xFF:
            output.append(f"\\x{code:02x}")
        else:
            output.append(f"\\u{code:04x}")
    return "".join(output)


def load(path: str) -> tuple[dict, bytes]:
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 8192)
    header_bytes, separator, content = data.partition(b"\n")
    if not separator:
        raise ValueError("missing artifact envelope")
    header = json.loads(header_bytes)
    if not isinstance(header, dict) or header.get("schema") != "secure-sandbox-artifact-v1":
        raise ValueError("unexpected artifact schema")
    uuid.UUID(str(header.get("artifact_id", "")))
    name = str(header.get("file_name", ""))
    if not NAME_RE.fullmatch(name):
        raise ValueError("invalid artifact file name")
    if len(content) != int(header.get("record_bytes", -1)) or len(content) > MAX_FILE_BYTES:
        raise ValueError("artifact size mismatch")
    if hashlib.sha256(content).hexdigest() != header.get("source_sha256"):
        raise ValueError("artifact content hash mismatch")
    content.decode("utf-8")
    return header, content


def metadata_line(header: dict) -> str:
    return "\t".join([
        str(header["captured_at"]),
        str(header["artifact_id"]),
        f"v{int(header['version'])}",
        safe_text(str(header["file_name"])),
        str(header["run_id"]),
        str(header["source_sha256"]),
    ])


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def encrypted_catalog(directory: Path, identity: bytes) -> list[str]:
    if not identity or not directory.is_dir() or directory.is_symlink():
        raise ValueError("invalid encrypted artifact catalog input")
    chunks = sorted(directory.glob("artifact-*.age"))
    if not chunks:
        raise ValueError("no archived artifacts found")
    rows = []
    for chunk in chunks:
        match = ARCHIVE_NAME_RE.fullmatch(chunk.name)
        if match is None or not chunk.is_file() or chunk.is_symlink():
            raise ValueError("invalid encrypted artifact name")
        if file_sha256(chunk) != match.group(3):
            raise ValueError("artifact ciphertext hash mismatch")
        plain = directory / (chunk.name[:-4] + ".plain")
        try:
            result = subprocess.run(
                ["age", "-d", "-i", "-", "-o", str(plain), str(chunk)],
                input=identity, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError("artifact decryption failed")
            os.chmod(plain, 0o600)
            header, _ = load(str(plain))
            if header["artifact_id"] != match.group(1) or int(header["version"]) != int(match.group(2)):
                raise ValueError("artifact filename and envelope disagree")
            rows.append(metadata_line(header))
        finally:
            plain.unlink(missing_ok=True)
    return sorted(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?")
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--encrypted-catalog")
    args = parser.parse_args()
    if args.encrypted_catalog:
        if args.path or args.metadata_only:
            parser.error("--encrypted-catalog cannot be combined with a path or --metadata-only")
        identity = sys.stdin.buffer.read(8193)
        if len(identity) > 8192:
            parser.error("archive identity is too large")
        for row in encrypted_catalog(Path(args.encrypted_catalog), identity):
            print(row)
        return
    if not args.path:
        parser.error("an artifact path is required")
    header, content = load(args.path)
    if args.metadata_only:
        print(metadata_line(header))
        return
    print(f"Artifact: {header['artifact_id']}")
    print(f"Captured: {header['captured_at']}")
    print(f"Source: {safe_text(str(header['file_name']))} (version {int(header['version'])})")
    print(f"Run: {header['run_id']}")
    print(f"SHA-256: {header['source_sha256']}")
    print("---")
    sys.stdout.write(safe_text(content.decode("utf-8")))
    if content and not content.endswith(b"\n"):
        print()


if __name__ == "__main__":
    main()
