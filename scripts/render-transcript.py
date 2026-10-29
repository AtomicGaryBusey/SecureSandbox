#!/usr/bin/env python3
"""Verify a downloaded conversation archive and stream its JSONL records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

UUID4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
NAME_RE = re.compile(rf"^({UUID4})-([0-9]{{12}})-([0-9a-f]{{64}})\.age$")
UUID4_RE = re.compile(rf"^{UUID4}$")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verified_plaintexts(directory: Path, run_id: str, identity: bytes) -> list[Path]:
    if not UUID4_RE.fullmatch(run_id) or not identity or not directory.is_dir() or directory.is_symlink():
        raise ValueError("invalid encrypted transcript input")
    chunks = sorted(directory.glob(f"{run_id}-*.age"))
    if not chunks:
        raise ValueError("no archived chunks found")
    plaintexts: list[Path] = []
    previous = ""
    try:
        for sequence, chunk in enumerate(chunks):
            match = NAME_RE.fullmatch(chunk.name)
            if (match is None or match.group(1) != run_id or
                    int(match.group(2)) != sequence or not chunk.is_file() or chunk.is_symlink()):
                raise ValueError("invalid encrypted transcript chunk")
            digest = match.group(3)
            if file_sha256(chunk) != digest:
                raise ValueError("transcript ciphertext hash mismatch")
            plain = directory / f"chunk-{sequence:012d}.plain"
            result = subprocess.run(
                ["age", "-d", "-i", "-", "-o", str(plain), str(chunk)],
                input=identity, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError("transcript decryption failed")
            os.chmod(plain, 0o600)
            plaintexts.append(plain)
            with plain.open("rb") as handle:
                header_line = handle.readline(8193)
                if not header_line.endswith(b"\n") or len(header_line) > 8192:
                    raise ValueError("archive header missing")
                try:
                    header = json.loads(header_line)
                except (ValueError, UnicodeDecodeError) as error:
                    raise ValueError("invalid archive header") from error
                if (not isinstance(header, dict) or
                        header.get("schema") != "secure-sandbox-conversation-v1" or
                        header.get("run_id") != run_id or
                        type(header.get("sequence")) is not int or
                        header["sequence"] != sequence or
                        header.get("previous_cipher_sha256") != previous):
                    raise ValueError("archive chain gap or header mismatch")
                record_bytes = header.get("record_bytes")
                if (type(record_bytes) is not int or record_bytes < 0 or
                        plain.stat().st_size - len(header_line) != record_bytes):
                    raise ValueError("archive record size mismatch")
            previous = digest
        return plaintexts
    except BaseException:
        for plain in plaintexts:
            plain.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("run_id")
    args = parser.parse_args()
    identity = sys.stdin.buffer.read(8193)
    if len(identity) > 8192:
        parser.error("archive identity is too large")
    plaintexts = verified_plaintexts(args.directory, args.run_id, identity)
    try:
        for plain in plaintexts:
            with plain.open("rb", buffering=0) as handle:
                handle.readline()
                result = subprocess.run(
                    ["jq", "-ce", 'if type == "object" then . else error("invalid transcript record") end'],
                    stdin=handle, stdout=sys.stdout.buffer, check=False,
                )
                if result.returncode != 0:
                    raise ValueError("invalid transcript record")
    finally:
        for plain in plaintexts:
            plain.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Transcript verification failed: {error}", file=sys.stderr)
        sys.exit(1)
