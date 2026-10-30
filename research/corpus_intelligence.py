#!/usr/bin/env python3
"""Manifest-bound, read-only corpus search, comparison, and exploration."""

from __future__ import annotations

import hashlib
import argparse
import json
import os
import re
import sqlite3
import stat
import time
import sys
from pathlib import PurePosixPath

from source_integrity import (
    IntegrityError,
    MAX_MANIFEST_BYTES,
    canonical,
    expected_records,
    fixed_tree_path,
    load_control_json,
    registered_source,
    safe_relative,
    verify_source,
)

WORKSPACE = "/home/agent/research-workspace"
INDEX_DIR = f"{WORKSPACE}/corpus-indexes"
INDEX_SCHEMA = "secure-sandbox-corpus-index-v1"
ENGINE_VERSION = "1.2.0"
SUPPORTED_ENGINE_VERSIONS = {"1.0.0", "1.1.0", ENGINE_VERSION}
MAX_INDEX_BYTES = 1536 * 1024 * 1024
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_INDEXED_BYTES = 1024 * 1024 * 1024
MAX_QUERY_CHARS = 256
MAX_PREFIX_CHARS = 240
MAX_EXTENSIONS = 16
MAX_PAGE_RESULTS = 50
MAX_OFFSET = 1_000_000
MAX_CONTEXT_LINES = 2
MAX_SNIPPET_CHARS = 480
MAX_QUERY_SECONDS = 30.0
MAX_LINKS_PER_DOCUMENT = 256
MAX_HEADINGS_PER_DOCUMENT = 512
TEXT_EXTENSIONS = {
    ".adoc", ".bash", ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs",
    ".css", ".csv", ".go", ".h", ".hpp", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".kt", ".lua", ".md", ".markdown", ".mdx",
    ".mjs", ".php", ".properties", ".py", ".rb", ".rs", ".rst", ".sh",
    ".sql", ".swift", ".tf", ".toml", ".ts", ".tsx", ".txt", ".xml",
    ".yaml", ".yml",
}
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.{1,500}?)\s*#*\s*$", re.MULTILINE)
LINK_RE = re.compile(r"(?<!!)\[[^\]\n]{0,300}\]\(([^)\s]+)(?:\s+[\"'][^\n]*[\"'])?\)")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}")

PROFILES = {
    "prompt_injection": [
        ("ignore_instructions", re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.I)),
        ("system_prompt", re.compile(r"\bsystem\s+prompt\b", re.I)),
        ("hidden_instruction", re.compile(r"\b(?:hidden|secret)\s+instructions?\b", re.I)),
        ("role_directive", re.compile(r"\b(?:you are|act as|pretend to be)\b", re.I)),
        ("tool_directive", re.compile(r"\b(?:call|invoke|use|execute|run)\s+(?:the\s+)?(?:tool|command|shell|bash)\b", re.I)),
    ],
    "external_fetch": [
        ("http_url", re.compile(r"https?://[^\s<>()\]\[\"']{1,500}", re.I)),
        ("raw_github", re.compile(r"\braw\.githubusercontent\.com\b", re.I)),
        ("download_command", re.compile(r"\b(?:curl|wget)\b", re.I)),
    ],
    "credential_material": [
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        ("generic_secret_assignment", re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[\"']?[^\s\"']{12,}", re.I)),
    ],
    "agent_directives": [
        ("agent_term", re.compile(r"\b(?:AI agent|LLM|Claude|ChatGPT|copilot)\b", re.I)),
        ("mcp_term", re.compile(r"\bMCP\b|model context protocol", re.I)),
        ("imperative_you", re.compile(r"\byou\s+(?:must|should|need to|will)\b", re.I)),
    ],
    "personnel_identifiers": [
        ("email_address", re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,190}\.[A-Z]{2,24}\b", re.I)),
        ("email_uri", re.compile(r"\bmailto:[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,190}\.[A-Z]{2,24}\b", re.I)),
        ("named_contact_field", re.compile(r"\b(?:author|contact|maintainer|owner|reviewer)\s*[:=]\s*[^\r\n]{2,160}", re.I)),
        ("username_field", re.compile(r"\b(?:user(?:name)?|login|principal|assignee)\s*[:=]\s*[\"']?[A-Z0-9._@\\-]{2,128}", re.I)),
    ],
    "internal_hostnames": [
        ("private_ipv4", re.compile(r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b")),
        ("loopback_host", re.compile(r"\b(?:localhost|127(?:\.\d{1,3}){3}|::1)\b", re.I)),
        ("internal_dns_suffix", re.compile(r"\b[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*\.(?:corp|internal|intranet|lan|local)\b", re.I)),
    ],
    "infrastructure_assets": [
        ("aws_arn", re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^\s\"']{1,256}", re.I)),
        ("azure_resource_id", re.compile(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Z0-9._()\-]+(?:/providers/[^\s\"']+)?", re.I)),
        ("gcp_project_field", re.compile(r"\b(?:gcp[_-]?)?project[_-]?id\s*[:=]\s*[\"']?[a-z][a-z0-9-]{4,61}[a-z0-9]", re.I)),
        ("oauth_client_id_field", re.compile(r"\b(?:oauth[_-]?)?client[_-]?id\s*[:=]\s*[\"']?[A-Z0-9._:\-]{6,256}", re.I)),
        ("cloud_bucket_uri", re.compile(r"\b(?:s3|gs|az)://[A-Z0-9._/\-]{3,512}", re.I)),
    ],
}

# These fixed literal gates are conservative supersets of their corresponding
# regular expressions. They avoid running expensive patterns on lines that
# cannot possibly match, without changing scan semantics or giving the caller
# control over executable matching logic.
RULE_PREFILTERS = {
    "internal_hostnames": {
        "private_ipv4": ("10.", "192.168.", "172."),
        "loopback_host": ("localhost", "127.", "::1"),
        "internal_dns_suffix": (".corp", ".internal", ".intranet", ".lan", ".local"),
    },
}
PROFILE_VERSION = hashlib.sha256(canonical({
    name: [{
        "label": label,
        "pattern": pattern.pattern,
        "flags": pattern.flags,
        "required_literals": list(RULE_PREFILTERS.get(name, {}).get(label, ())),
    } for label, pattern in rules]
    for name, rules in PROFILES.items()
})).hexdigest()


class CorpusError(ValueError):
    pass


class CorpusQueryTimeout(CorpusError):
    def __init__(self, files_examined: int, bytes_examined: int, elapsed_ms: int):
        super().__init__("query_timeout")
        self.safe_metrics = {
            "exhaustive": False,
            "files_examined": files_examined,
            "bytes_examined": bytes_examined,
            "elapsed_ms": elapsed_ms,
            "query_budget_seconds": int(MAX_QUERY_SECONDS),
        }


def index_path(source_id: str) -> str:
    registered_source(source_id)
    return f"{INDEX_DIR}/{source_id}.sqlite3"


def _validate_index_file(path: str) -> os.stat_result:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_size > MAX_INDEX_BYTES
    ):
        raise CorpusError("untrusted_corpus_index")
    return info


def open_index(source_id: str) -> tuple[sqlite3.Connection, int]:
    record = registered_source(source_id)
    path = index_path(source_id)
    _validate_index_file(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        connection = sqlite3.connect(f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        required = {
            "schema": INDEX_SCHEMA,
            "source_id": source_id,
            "repository": str(record.get("repository", "")),
            "resolved_commit": str(record.get("resolved_commit", "")),
            "tree_manifest_sha256": str(record.get("tree_manifest_sha256", "")),
        }
        if any(metadata.get(key) != value for key, value in required.items()):
            connection.close()
            raise CorpusError("corpus_index_binding_mismatch")
        if metadata.get("engine_version") not in SUPPORTED_ENGINE_VERSIONS:
            connection.close()
            raise CorpusError("corpus_index_binding_mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", metadata.get("profile_version", "")):
            connection.close()
            raise CorpusError("corpus_index_binding_mismatch")
        return connection, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_manifest(source_id: str) -> tuple[dict, dict[str, dict], str]:
    record = registered_source(source_id)
    manifest_relative = record.get("integrity_manifest_path")
    if manifest_relative is None:
        raise CorpusError("source_manifest_unavailable")
    manifest_path = fixed_tree_path(manifest_relative, "source-manifests")
    manifest = load_control_json(manifest_path, MAX_MANIFEST_BYTES)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "secure-sandbox-source-integrity-v1"
        or manifest.get("source_id") != source_id
    ):
        raise CorpusError("invalid_integrity_manifest")
    records = expected_records(manifest)
    tree_hash = hashlib.sha256(canonical(manifest.get("entries"))).hexdigest()
    if tree_hash != record.get("tree_manifest_sha256"):
        raise CorpusError("integrity_manifest_hash_mismatch")
    return record, records, tree_hash


def _read_document(path: str, expected: dict) -> str | None:
    if expected.get("type") != "file" or expected.get("bytes", 0) > MAX_DOCUMENT_BYTES:
        return None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected["bytes"]:
            raise CorpusError("source_changed_during_index")
        data = bytearray()
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data.extend(chunk)
            digest.update(chunk)
            if len(data) > MAX_DOCUMENT_BYTES:
                raise CorpusError("document_too_large")
        if digest.hexdigest() != expected.get("sha256"):
            raise CorpusError("source_changed_during_index")
    finally:
        os.close(descriptor)
    if b"\x00" in data[:65536]:
        return None
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _document_structure(relative: str, text: str) -> tuple[str, list[dict], list[str]]:
    headings = [
        {"level": len(match.group(1)), "text": match.group(2).strip()[:500]}
        for match in HEADING_RE.finditer(text)
    ][:MAX_HEADINGS_PER_DOCUMENT]
    title = headings[0]["text"] if headings else PurePosixPath(relative).name
    links = []
    for match in LINK_RE.finditer(text):
        target = match.group(1)[:1000]
        if target not in links:
            links.append(target)
        if len(links) >= MAX_LINKS_PER_DOCUMENT:
            break
    return title, headings, links


def build_index(source_id: str) -> dict:
    """Build a root-owned immutable corpus index after cryptographic verification."""
    if os.geteuid() != 0:
        raise CorpusError("root_required")
    verification = verify_source(source_id, "baseline")
    if verification.get("anchor_status") != "import_validated" or verification.get("baseline", {}).get("status") != "match":
        raise CorpusError("source_not_verified")
    record, records, tree_hash = _read_manifest(source_id)
    baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
    os.makedirs(INDEX_DIR, mode=0o755, exist_ok=True)
    os.chown(INDEX_DIR, 0, 0)
    os.chmod(INDEX_DIR, 0o755)
    destination = index_path(source_id)
    temporary = f"{destination}.tmp-{os.getpid()}"
    if os.path.lexists(temporary):
        raise CorpusError("temporary_index_exists")
    connection = sqlite3.connect(temporary)
    indexed_bytes = 0
    indexed_documents = 0
    skipped_documents = 0
    digest = hashlib.sha256()
    try:
        connection.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            CREATE TABLE documents (
                path TEXT PRIMARY KEY,
                extension TEXT NOT NULL,
                bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                title TEXT NOT NULL,
                headings_json TEXT NOT NULL,
                links_json TEXT NOT NULL,
                content TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE VIRTUAL TABLE docs_fts USING fts5(path UNINDEXED, title, headings, content, tokenize='unicode61');
        """)
        for relative in sorted(records):
            expected = records[relative]
            if expected.get("type") != "file":
                continue
            extension = PurePosixPath(relative).suffix.lower()
            if extension not in TEXT_EXTENSIONS:
                continue
            text = _read_document(os.path.join(baseline, relative), expected)
            if text is None:
                skipped_documents += 1
                continue
            encoded_bytes = len(text.encode("utf-8"))
            indexed_bytes += encoded_bytes
            if indexed_bytes > MAX_INDEXED_BYTES:
                raise CorpusError("indexed_content_too_large")
            title, headings, links = _document_structure(relative, text)
            headings_json = json.dumps(headings, separators=(",", ":"), ensure_ascii=False)
            links_json = json.dumps(links, separators=(",", ":"), ensure_ascii=False)
            headings_text = "\n".join(item["text"] for item in headings)
            connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (relative, extension, expected["bytes"], expected["sha256"], title, headings_json, links_json, text),
            )
            connection.execute(
                "INSERT INTO docs_fts(path, title, headings, content) VALUES (?, ?, ?, ?)",
                (relative, title, headings_text, text),
            )
            digest.update(canonical([relative, expected["sha256"], title, headings, links]))
            indexed_documents += 1
        metadata = {
            "schema": INDEX_SCHEMA,
            "engine_version": ENGINE_VERSION,
            "source_id": source_id,
            "repository": str(record.get("repository", "")),
            "resolved_commit": str(record.get("resolved_commit", "")),
            "tree_manifest_sha256": tree_hash,
            "profile_version": PROFILE_VERSION,
            "index_content_sha256": digest.hexdigest(),
            "indexed_documents": str(indexed_documents),
            "indexed_bytes": str(indexed_bytes),
            "skipped_documents": str(skipped_documents),
        }
        connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", sorted(metadata.items()))
        connection.commit()
        connection.execute("PRAGMA optimize")
        connection.commit()
    except Exception:
        connection.close()
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    connection.close()
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o444)
    os.replace(temporary, destination)
    directory_fd = os.open(INDEX_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {
        "schema": INDEX_SCHEMA,
        "source_id": source_id,
        "repository": record.get("repository"),
        "resolved_commit": record.get("resolved_commit"),
        "tree_manifest_sha256": tree_hash,
        "index_content_sha256": digest.hexdigest(),
        "indexed_documents": indexed_documents,
        "indexed_bytes": indexed_bytes,
        "skipped_documents": skipped_documents,
        "status": "indexed",
    }


def index_status(source_id: str) -> dict:
    """Read back a sealed corpus index without starting another build."""
    registered_source(source_id)
    path = f"{INDEX_DIR}/{source_id}.sqlite3"
    if not os.path.lexists(path):
        return {
            "schema": "secure-sandbox-corpus-index-status-v1",
            "source_id": source_id,
            "status": "not_indexed",
        }
    connection, descriptor = open_index(source_id)
    try:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        numeric = {}
        for key in ("indexed_documents", "indexed_bytes", "skipped_documents"):
            value = metadata.get(key, "")
            if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
                raise CorpusError("corpus_index_metadata_invalid")
            numeric[key] = int(value)
        if re.fullmatch(r"[0-9a-f]{64}", metadata.get("index_content_sha256", "")) is None:
            raise CorpusError("corpus_index_metadata_invalid")
        document_count = int(connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0])
        if document_count != numeric["indexed_documents"]:
            raise CorpusError("corpus_index_document_count_mismatch")
    finally:
        connection.close()
        os.close(descriptor)
    return {
        "schema": "secure-sandbox-corpus-index-status-v1",
        "source_id": source_id,
        "status": "indexed",
        "index_content_sha256": metadata["index_content_sha256"],
        **numeric,
    }


def _validate_page(offset: object, limit: object) -> tuple[int, int]:
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_OFFSET:
        raise CorpusError("invalid_offset")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE_RESULTS:
        raise CorpusError("invalid_limit")
    return offset, limit


def _validate_filters(path_prefix: object, extensions: object) -> tuple[str, set[str]]:
    if path_prefix is None:
        prefix = ""
    elif not isinstance(path_prefix, str) or len(path_prefix) > MAX_PREFIX_CHARS:
        raise CorpusError("invalid_path_prefix")
    else:
        try:
            prefix = safe_relative(path_prefix.rstrip("/"))
        except IntegrityError as failure:
            raise CorpusError("invalid_path_prefix") from failure
    if extensions is None:
        selected = set()
    elif not isinstance(extensions, list) or len(extensions) > MAX_EXTENSIONS:
        raise CorpusError("invalid_extensions")
    else:
        selected = set()
        for value in extensions:
            if not isinstance(value, str):
                raise CorpusError("invalid_extensions")
            normalized = value.lower()
            if not normalized.startswith("."):
                normalized = "." + normalized
            if normalized not in TEXT_EXTENSIONS:
                raise CorpusError("invalid_extension")
            selected.add(normalized)
    return prefix, selected


def _eligible(path: str, extension: str, prefix: str, extensions: set[str]) -> bool:
    return (not prefix or path == prefix or path.startswith(prefix + "/")) and (not extensions or extension in extensions)


def _line_snippet(lines: list[str], line_index: int, context_lines: int) -> str:
    start = max(0, line_index - context_lines)
    end = min(len(lines), line_index + context_lines + 1)
    rendered = "\n".join(f"{number + 1}: {lines[number]}" for number in range(start, end))
    if len(rendered) > MAX_SNIPPET_CHARS:
        rendered = rendered[: MAX_SNIPPET_CHARS - 1] + "…"
    return rendered


def _record_for_output(record: dict) -> dict:
    output = {"type": record["type"]}
    if record["type"] == "file":
        output.update(bytes=record["bytes"], sha256=record["sha256"])
    elif record["type"] == "symlink":
        output["target_sha256"] = hashlib.sha256(record["target"].encode("utf-8", "surrogatepass")).hexdigest()
    return output


def _validate_entry_types(entry_types: object) -> set[str]:
    allowed = {"directory", "file", "symlink"}
    if entry_types is None:
        return allowed
    if not isinstance(entry_types, list) or not 1 <= len(entry_types) <= len(allowed):
        raise CorpusError("invalid_entry_types")
    selected = set(entry_types)
    if len(selected) != len(entry_types) or not selected <= allowed:
        raise CorpusError("invalid_entry_types")
    return selected


def list_source_tree(
    source_id: str,
    path_prefix: str | None = None,
    recursive: bool = False,
    entry_types: list[str] | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """List registered manifest entries without accepting an arbitrary path."""
    if not isinstance(recursive, bool):
        raise CorpusError("invalid_recursive")
    offset, limit = _validate_page(offset, limit)
    prefix, _ = _validate_filters(path_prefix, None)
    selected_types = _validate_entry_types(entry_types)
    record, records, tree_hash = _read_manifest(source_id)
    visible: list[dict] = []
    digest = hashlib.sha256()
    total_entries = 0
    for path in sorted(records):
        item = records[path]
        if item["type"] not in selected_types:
            continue
        if prefix:
            if path == prefix or not path.startswith(prefix + "/"):
                continue
            remainder = path[len(prefix) + 1 :]
        else:
            remainder = path
        if not recursive and "/" in remainder:
            continue
        ordinal = total_entries
        total_entries += 1
        normalized = {"path": path, **_record_for_output(item)}
        digest.update(canonical(normalized))
        if offset <= ordinal < offset + limit:
            visible.append({
                **normalized,
                "path_trust": "validated_registered_path",
            })
    binding = {
        "source_id": source_id,
        "tree_manifest_sha256": tree_hash,
        "path_prefix": prefix,
        "recursive": recursive,
        "entry_types": sorted(selected_types),
    }
    scan_id = hashlib.sha256(canonical(binding)).hexdigest()
    return {
        "schema": "secure-sandbox-source-tree-v1",
        "source_id": source_id,
        "repository": record.get("repository"),
        "resolved_commit": record.get("resolved_commit"),
        "tree_manifest_sha256": tree_hash,
        "scan_id": scan_id,
        "path_prefix": prefix,
        "recursive": recursive,
        "entry_types": sorted(selected_types),
        "exhaustive": True,
        "total_entries": total_entries,
        "result_set_sha256": digest.hexdigest(),
        "offset": offset,
        "returned": len(visible),
        "next_offset": offset + len(visible) if offset + len(visible) < total_entries else None,
        "results": visible,
    }


def diff_sources(
    source_id_a: str,
    source_id_b: str,
    path_prefix: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """Compare two registered immutable manifests without reading source bodies."""
    if source_id_a == source_id_b:
        raise CorpusError("identical_sources")
    offset, limit = _validate_page(offset, limit)
    prefix, _ = _validate_filters(path_prefix, None)
    record_a, records_a, tree_hash_a = _read_manifest(source_id_a)
    record_b, records_b, tree_hash_b = _read_manifest(source_id_b)
    paths = sorted(set(records_a) | set(records_b))
    examined_entries = 0
    total_changes = 0
    categories = {"added": 0, "removed": 0, "modified": 0}
    visible: list[dict] = []
    digest = hashlib.sha256()
    for path in paths:
        if prefix and path != prefix and not path.startswith(prefix + "/"):
            continue
        examined_entries += 1
        before = records_a.get(path)
        after = records_b.get(path)
        if before is None:
            change = "added"
        elif after is None:
            change = "removed"
        elif before != after:
            change = "modified"
        else:
            continue
        normalized = {
            "change": change,
            "path": path,
            "before": _record_for_output(before) if before else None,
            "after": _record_for_output(after) if after else None,
        }
        ordinal = total_changes
        total_changes += 1
        categories[change] += 1
        digest.update(canonical(normalized))
        if offset <= ordinal < offset + limit:
            visible.append({**normalized, "path_trust": "validated_registered_path"})
    binding = {
        "source_id_a": source_id_a,
        "source_id_b": source_id_b,
        "tree_manifest_sha256_a": tree_hash_a,
        "tree_manifest_sha256_b": tree_hash_b,
        "path_prefix": prefix,
    }
    scan_id = hashlib.sha256(canonical(binding)).hexdigest()
    return {
        "schema": "secure-sandbox-source-diff-v1",
        "scan_id": scan_id,
        "source_a": {
            "source_id": source_id_a,
            "repository": record_a.get("repository"),
            "resolved_commit": record_a.get("resolved_commit"),
            "tree_manifest_sha256": tree_hash_a,
        },
        "source_b": {
            "source_id": source_id_b,
            "repository": record_b.get("repository"),
            "resolved_commit": record_b.get("resolved_commit"),
            "tree_manifest_sha256": tree_hash_b,
        },
        "same_repository": record_a.get("repository") == record_b.get("repository"),
        "path_prefix": prefix,
        "exhaustive": True,
        "entries_examined": examined_entries,
        "total_changes": total_changes,
        "categories": categories,
        "result_set_sha256": digest.hexdigest(),
        "offset": offset,
        "returned": len(visible),
        "next_offset": offset + len(visible) if offset + len(visible) < total_changes else None,
        "results": visible,
    }


def search_corpus(
    source_id: str,
    query: str,
    case_sensitive: bool = False,
    path_prefix: str | None = None,
    extensions: list[str] | None = None,
    offset: int = 0,
    limit: int = 25,
    context_lines: int = 1,
) -> dict:
    if not isinstance(query, str) or not query or len(query) > MAX_QUERY_CHARS or "\x00" in query:
        raise CorpusError("invalid_query")
    if not isinstance(case_sensitive, bool):
        raise CorpusError("invalid_case_sensitive")
    if not isinstance(context_lines, int) or isinstance(context_lines, bool) or not 0 <= context_lines <= MAX_CONTEXT_LINES:
        raise CorpusError("invalid_context_lines")
    offset, limit = _validate_page(offset, limit)
    prefix, selected_extensions = _validate_filters(path_prefix, extensions)
    connection, descriptor = open_index(source_id)
    started = time.monotonic()
    needle = query if case_sensitive else query.lower()
    total_matches = 0
    matching_files = 0
    files_examined = 0
    bytes_examined = 0
    visible: list[dict] = []
    result_digest = hashlib.sha256()
    try:
        for row in connection.execute("SELECT path, extension, bytes, content FROM documents ORDER BY path"):
            elapsed = time.monotonic() - started
            if elapsed > MAX_QUERY_SECONDS:
                raise CorpusQueryTimeout(files_examined, bytes_examined, int(elapsed * 1000))
            if not _eligible(row["path"], row["extension"], prefix, selected_extensions):
                continue
            files_examined += 1
            bytes_examined += int(row["bytes"])
            lines = row["content"].splitlines()
            file_matched = False
            for line_index, original in enumerate(lines):
                haystack = original if case_sensitive else original.lower()
                position = 0
                while True:
                    found = haystack.find(needle, position)
                    if found < 0:
                        break
                    ordinal = total_matches
                    total_matches += 1
                    file_matched = True
                    result_digest.update(canonical([row["path"], line_index + 1, found + 1, len(query)]))
                    if offset <= ordinal < offset + limit:
                        visible.append({
                            "path": row["path"],
                            "line": line_index + 1,
                            "column": found + 1,
                            "content_trust": "untrusted_source_content",
                            "snippet": _line_snippet(lines, line_index, context_lines),
                        })
                    position = found + max(1, len(needle))
            if file_matched:
                matching_files += 1
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
        os.close(descriptor)
    query_binding = {
        "source_id": source_id,
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "case_sensitive": case_sensitive,
        "path_prefix": prefix,
        "extensions": sorted(selected_extensions),
    }
    scan_id = hashlib.sha256(canonical(query_binding)).hexdigest()
    return {
        "schema": "secure-sandbox-corpus-search-v1",
        "source_id": source_id,
        "repository": metadata["repository"],
        "resolved_commit": metadata["resolved_commit"],
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "index_content_sha256": metadata["index_content_sha256"],
        "scan_id": scan_id,
        "query_sha256": query_binding["query_sha256"],
        "exhaustive": True,
        "files_examined": files_examined,
        "bytes_examined": bytes_examined,
        "matching_files": matching_files,
        "total_matches": total_matches,
        "result_set_sha256": result_digest.hexdigest(),
        "offset": offset,
        "returned": len(visible),
        "next_offset": offset + len(visible) if offset + len(visible) < total_matches else None,
        "results": visible,
    }


def scan_corpus(
    source_id: str,
    profile: str,
    path_prefix: str | None = None,
    extensions: list[str] | None = None,
    offset: int = 0,
    limit: int = 25,
) -> dict:
    if profile not in PROFILES:
        raise CorpusError("invalid_profile")
    offset, limit = _validate_page(offset, limit)
    prefix, selected_extensions = _validate_filters(path_prefix, extensions)
    connection, descriptor = open_index(source_id)
    started = time.monotonic()
    total_matches = 0
    matching_files_set: set[str] = set()
    files_examined = 0
    bytes_examined = 0
    categories = {label: 0 for label, _ in PROFILES[profile]}
    visible: list[dict] = []
    digest = hashlib.sha256()
    try:
        for row in connection.execute("SELECT path, extension, bytes, content FROM documents ORDER BY path"):
            elapsed = time.monotonic() - started
            if elapsed > MAX_QUERY_SECONDS:
                raise CorpusQueryTimeout(files_examined, bytes_examined, int(elapsed * 1000))
            if not _eligible(row["path"], row["extension"], prefix, selected_extensions):
                continue
            files_examined += 1
            bytes_examined += int(row["bytes"])
            lines = row["content"].splitlines()
            for line_index, line in enumerate(lines):
                folded_line = line.lower()
                for label, pattern in PROFILES[profile]:
                    required = RULE_PREFILTERS.get(profile, {}).get(label)
                    if required and not any(literal in folded_line for literal in required):
                        continue
                    for match in pattern.finditer(line):
                        ordinal = total_matches
                        total_matches += 1
                        categories[label] += 1
                        matching_files_set.add(row["path"])
                        digest.update(canonical([label, row["path"], line_index + 1, match.start() + 1, match.end() - match.start()]))
                        if offset <= ordinal < offset + limit:
                            visible.append({
                                "category": label,
                                "path": row["path"],
                                "line": line_index + 1,
                                "column": match.start() + 1,
                                "content_trust": "untrusted_source_content",
                                "snippet": _line_snippet(lines, line_index, 1),
                            })
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        elapsed_ms = int((time.monotonic() - started) * 1000)
    finally:
        connection.close()
        os.close(descriptor)
    binding = {
        "source_id": source_id,
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "profile": profile,
        "profile_version": PROFILE_VERSION,
        "path_prefix": prefix,
        "extensions": sorted(selected_extensions),
    }
    return {
        "schema": "secure-sandbox-corpus-scan-v1",
        "source_id": source_id,
        "repository": metadata["repository"],
        "resolved_commit": metadata["resolved_commit"],
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "index_content_sha256": metadata["index_content_sha256"],
        "scan_id": hashlib.sha256(canonical(binding)).hexdigest(),
        "profile": profile,
        "profile_version": PROFILE_VERSION,
        "query_budget_seconds": int(MAX_QUERY_SECONDS),
        "elapsed_ms": elapsed_ms,
        "exhaustive": True,
        "files_examined": files_examined,
        "bytes_examined": bytes_examined,
        "matching_files": len(matching_files_set),
        "total_matches": total_matches,
        "categories": categories,
        "result_set_sha256": digest.hexdigest(),
        "offset": offset,
        "returned": len(visible),
        "next_offset": offset + len(visible) if offset + len(visible) < total_matches else None,
        "results": visible,
    }


def explore_corpus(source_id: str, query: str, limit: int = 10) -> dict:
    if not isinstance(query, str) or not query or len(query) > MAX_QUERY_CHARS:
        raise CorpusError("invalid_query")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20:
        raise CorpusError("invalid_limit")
    # CodeGraph is optional and stays behind this source-UUID contract. Its
    # native arbitrary-path, indexing, synchronization, and daemon surfaces
    # are never exposed to the model.
    try:
        from codegraph_adapter import CodeGraphError, explore_graph, graph_available
        if graph_available(source_id):
            try:
                return explore_graph(source_id, query, min(limit, 10))
            except CodeGraphError as failure:
                raise CorpusError(str(failure)) from failure
    except ImportError:
        pass
    tokens = []
    for token in TOKEN_RE.findall(query):
        normalized = token.lower()
        if normalized not in tokens:
            tokens.append(normalized)
    if not tokens:
        raise CorpusError("query_has_no_searchable_terms")
    fts_query = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens[:16])
    connection, descriptor = open_index(source_id)
    try:
        rows = connection.execute(
            """
            SELECT d.path, d.title, d.headings_json, d.links_json,
                   snippet(docs_fts, 3, '[MATCH]', '[/MATCH]', ' … ', 40) AS excerpt,
                   bm25(docs_fts, 8.0, 5.0, 1.0) AS rank
            FROM docs_fts JOIN documents d ON d.path = docs_fts.path
            WHERE docs_fts MATCH ? ORDER BY rank, d.path LIMIT ?
            """,
            (fts_query, limit),
        ).fetchall()
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
        os.close(descriptor)
    results = []
    for row in rows:
        headings = json.loads(row["headings_json"])
        links = json.loads(row["links_json"])
        excerpt = str(row["excerpt"] or "")
        if len(excerpt) > MAX_SNIPPET_CHARS:
            excerpt = excerpt[: MAX_SNIPPET_CHARS - 1] + "…"
        results.append({
            "path": row["path"],
            "title": row["title"],
            "headings": headings[:12],
            "links": links[:20],
            "content_trust": "untrusted_source_content",
            "excerpt": excerpt,
        })
    return {
        "schema": "secure-sandbox-corpus-exploration-v1",
        "source_id": source_id,
        "repository": metadata["repository"],
        "resolved_commit": metadata["resolved_commit"],
        "tree_manifest_sha256": metadata["tree_manifest_sha256"],
        "index_content_sha256": metadata["index_content_sha256"],
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "semantic_backend": "bounded_markdown_fts_link_graph",
        "codegraph_adapter": "not_enabled",
        "returned": len(results),
        "results": results,
    }


def analyze_reachability(
    source_id: str,
    entrypoint_symbol: str,
    entrypoint_file: str,
    target_symbol: str,
    target_file: str,
    max_depth: int = 8,
) -> dict:
    """Trace bounded static flow from an explicitly selected default entrypoint."""
    if not isinstance(entrypoint_symbol, str) or not entrypoint_symbol or len(entrypoint_symbol) > 128 or "\x00" in entrypoint_symbol:
        raise CorpusError("invalid_entrypoint_selector")
    if not isinstance(target_symbol, str) or not target_symbol or len(target_symbol) > 128 or "\x00" in target_symbol:
        raise CorpusError("invalid_target_selector")
    try:
        entrypoint_file = safe_relative(entrypoint_file)
    except (IntegrityError, TypeError, ValueError) as failure:
        raise CorpusError("invalid_entrypoint_selector") from failure
    try:
        target_file = safe_relative(target_file)
    except (IntegrityError, TypeError, ValueError) as failure:
        raise CorpusError("invalid_target_selector") from failure
    if len(entrypoint_file) > 512 or len(target_file) > 512:
        raise CorpusError("invalid_selector_path")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 12:
        raise CorpusError("invalid_max_depth")
    try:
        from codegraph_adapter import CodeGraphError, analyze_reachability as analyze_graph_reachability
        return analyze_graph_reachability(
            source_id, entrypoint_symbol, entrypoint_file,
            target_symbol, target_file, max_depth,
        )
    except ImportError as failure:
        raise CorpusError("codegraph_adapter_unavailable") from failure
    except CodeGraphError as failure:
        raise CorpusError(str(failure)) from failure


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a verified SecureSandbox corpus index")
    parser.add_argument("operation", choices=["index", "status"])
    parser.add_argument("source_id")
    arguments = parser.parse_args()
    try:
        output = (build_index(arguments.source_id) if arguments.operation == "index"
                  else index_status(arguments.source_id))
    except (CorpusError, IntegrityError) as failure:
        print(json.dumps({"status": "rejected", "error": str(failure)}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
