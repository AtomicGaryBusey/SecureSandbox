#!/usr/bin/env python3
"""Content-free live verification of UUID-pointer finding evidence."""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
from pathlib import Path

import corpus_intelligence_mcp
import evidence_receipts
import execution_mcp
import findings_broker
import findings_mcp


UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$"
)
PRODUCERS = {
    "corpus-broker": "exhaustive_corpus_search",
    "execution-broker": "measured_execution",
}


def verified_projection(
    producer: str, sources: dict[str, dict], registry: Path,
    root_uid: int, producer_uid: int, group_gid: int,
) -> dict:
    directory = registry / evidence_receipts.PRODUCERS[producer][0]
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    if len(entries) > evidence_receipts.MAX_RECEIPTS:
        raise RuntimeError("receipt_state_limit_exceeded")
    for path in entries:
        if not UUID4_RE.fullmatch(path.name):
            raise RuntimeError("receipt_state_untrusted")
        receipt_id = path.stem
        try:
            projection = evidence_receipts.load_projection_by_id(
                receipt_id, producer, registry, root_uid, producer_uid, group_gid,
            )
        except evidence_receipts.ReceiptError as error:
            raise RuntimeError(str(error)) from error
        if projection.get("source_id") in sources:
            return projection
    raise RuntimeError(f"live_{producer}_receipt_unavailable")


def verify(
    registry: Path = evidence_receipts.REGISTRY,
    source_index: Path = findings_broker.SOURCE_INDEX,
    root_uid: int = 0,
    producer_uids: dict[str, int] | None = None,
    group_gid: int | None = None,
) -> dict:
    if producer_uids is None:
        producer_uids = {name: pwd.getpwnam(name).pw_uid for name in PRODUCERS}
    if group_gid is None:
        group_gid = grp.getgrnam("evidence-receipts").gr_gid
    sources = findings_broker.load_sources(source_index)
    checked = []
    for producer, evidence_class in PRODUCERS.items():
        projection = verified_projection(
            producer, sources, registry, root_uid, producer_uids[producer], group_gid,
        )
        pointer = {key: projection[key] for key in ("class", "source_id", "receipt_id")}
        resolved = findings_broker.validate_evidence_item(
            pointer, sources, receipt_registry=registry, receipt_root_uid=root_uid,
            receipt_producer_uids=producer_uids, receipt_group_gid=group_gid,
        )
        if (resolved.get("class") != evidence_class
                or resolved.get("receipt_sha256") != projection["receipt_sha256"]):
            raise RuntimeError("receipt_pointer_projection_mismatch")
        forged = dict(projection)
        forged["receipt_sha256"] = (
            "0" * 64 if projection["receipt_sha256"] != "0" * 64 else "1" * 64
        )
        try:
            findings_broker.validate_evidence_item(
                forged, sources, receipt_registry=registry, receipt_root_uid=root_uid,
                receipt_producer_uids=producer_uids, receipt_group_gid=group_gid,
            )
        except findings_broker.FindingError as error:
            if str(error) != "receipt_projection_mismatch_receipt_sha256":
                raise RuntimeError("receipt_field_diagnostic_invalid") from error
        else:
            raise RuntimeError("forged_receipt_projection_accepted")
        checked.append(evidence_class)

    digest = "a" * 64
    displays = (
        corpus_intelligence_mcp.display_json({"result_set_sha256": digest}),
        execution_mcp.display_json({"stdout_sha256": digest}),
        findings_mcp.display_json({"content_sha256": digest}),
    )
    if any("aaaaaaaa aaaaaaaa" not in value for value in displays) or digest != "a" * 64:
        raise RuntimeError("digest_display_invalid")
    return {
        "checked_classes": sorted(checked),
        "schema": "secure-sandbox-receipt-pointer-findings-live-v1",
        "status": "verified",
    }


if __name__ == "__main__":
    print(json.dumps(verify(), separators=(",", ":"), sort_keys=True))
