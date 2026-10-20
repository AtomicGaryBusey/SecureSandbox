#!/usr/bin/env python3
"""Validate and safely render a decrypted SecureSandbox artifact envelope."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
import uuid

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:md|txt|json)$")
MAX_FILE_BYTES = 4 * 1024 * 1024


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    header, content = load(args.path)
    if args.metadata_only:
        print("\t".join([
            str(header["captured_at"]),
            str(header["artifact_id"]),
            f"v{int(header['version'])}",
            safe_text(str(header["file_name"])),
            str(header["run_id"]),
            str(header["source_sha256"]),
        ]))
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
