#!/usr/bin/env python3
"""Build a deterministic, content-addressed source release from one Git commit."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_NAME = "SecureSandbox-source.tar.gz"
PROVENANCE_NAME = "SecureSandbox-source.provenance.json"
CHECKSUMS_NAME = "SHA256SUMS"
OUTPUT_NAMES = (ARCHIVE_NAME, PROVENANCE_NAME, CHECKSUMS_NAME)


def git(*arguments: str, cwd: Path = ROOT) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=cwd)


def resolve_commit(ref: str, cwd: Path = ROOT) -> str:
    value = git("rev-parse", "--verify", f"{ref}^{{commit}}", cwd=cwd).decode().strip()
    if len(value) not in (40, 64) or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("Git returned a malformed commit identity")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(ref: str, output_dir: Path, cwd: Path = ROOT) -> dict[str, object]:
    commit = resolve_commit(ref, cwd)
    tree = git("show", "-s", "--format=%T", commit, cwd=cwd).decode().strip()
    source_date_epoch = int(
        git("show", "-s", "--format=%ct", commit, cwd=cwd).decode().strip()
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in OUTPUT_NAMES:
        if (output_dir / name).exists():
            raise FileExistsError(f"refusing to replace existing release output: {name}")

    with tempfile.TemporaryDirectory(prefix="secure-sandbox-release-") as temporary:
        temporary_dir = Path(temporary)
        tar_path = temporary_dir / "source.tar"
        archive_path = temporary_dir / ARCHIVE_NAME
        with tar_path.open("wb") as stream:
            subprocess.run(
                ["git", "archive", "--format=tar", "--prefix=SecureSandbox/", commit],
                cwd=cwd,
                stdout=stream,
                check=True,
            )
        with tar_path.open("rb") as source, archive_path.open("wb") as destination:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=destination, compresslevel=9, mtime=0
            ) as compressed:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    compressed.write(chunk)

        archive_digest = sha256(archive_path)
        provenance = {
            "archive": {
                "name": ARCHIVE_NAME,
                "sha256": archive_digest,
                "size": archive_path.stat().st_size,
            },
            "commit": commit,
            "repository": "SecureSandbox",
            "schema": "secure-sandbox-public-release-provenance-v1",
            "source_date_epoch": source_date_epoch,
            "tree": tree,
        }
        provenance_path = temporary_dir / PROVENANCE_NAME
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksums_path = temporary_dir / CHECKSUMS_NAME
        checksums_path.write_text(
            f"{archive_digest}  {ARCHIVE_NAME}\n"
            f"{sha256(provenance_path)}  {PROVENANCE_NAME}\n",
            encoding="utf-8",
        )

        for name in OUTPUT_NAMES:
            os.replace(temporary_dir / name, output_dir / name)
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="HEAD", help="exact Git commit to package")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    provenance = build(args.ref, args.output_dir)
    print(json.dumps(provenance, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
