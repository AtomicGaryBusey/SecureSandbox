#!/usr/bin/env python3
"""Content-free live verification for CodeGraph findings pointers."""

from __future__ import annotations

import argparse
import json
import os
import pwd
from pathlib import Path

import codegraph_adapter
import corpus_intelligence_mcp
import findings_broker
import findings_mcp


def verify(analysis_id: str) -> dict:
    registry = findings_broker.CODEGRAPH_ANALYSES
    owner_uid = pwd.getpwnam("codegraph-query").pw_uid
    record_path = registry / f"{analysis_id}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    projection = record.get("projection")
    if not isinstance(projection, dict):
        raise RuntimeError("analysis_projection_unavailable")
    sources = findings_broker.load_sources(findings_broker.SOURCE_INDEX)
    pointer = {key:projection[key] for key in ("class", "source_id", "analysis_id")}
    resolved = findings_broker.validate_evidence_item(
        pointer, sources, analysis_registry=registry, analysis_owner_uid=owner_uid,
    )
    expected = {**projection, "tree_manifest_sha256":sources[projection["source_id"]]["tree_manifest_sha256"]}
    if resolved != expected:
        raise RuntimeError("analysis_pointer_projection_mismatch")
    forged = {**projection, "codegraph_index_sha256":"0" * 64}
    try:
        findings_broker.validate_evidence_item(
            forged, sources, analysis_registry=registry, analysis_owner_uid=owner_uid,
        )
    except findings_broker.FindingError as error:
        if str(error) != "analysis_projection_mismatch_codegraph_index_sha256":
            raise RuntimeError("analysis_field_diagnostic_invalid") from error
    else:
        raise RuntimeError("forged_analysis_projection_accepted")
    partial = {**pointer, "codegraph_index_sha256":projection["codegraph_index_sha256"]}
    try:
        findings_broker.validate_evidence_item(
            partial, sources, analysis_registry=registry, analysis_owner_uid=owner_uid,
        )
    except findings_broker.FindingError as error:
        if str(error) != "analysis_projection_fields_mismatch":
            raise RuntimeError("analysis_shape_diagnostic_invalid") from error
    else:
        raise RuntimeError("partial_analysis_projection_accepted")
    digest = projection["codegraph_index_sha256"]
    grouped = " ".join(digest[index:index + 8] for index in range(0, 64, 8))
    if codegraph_adapter.grouped_digest(digest) != grouped:
        raise RuntimeError("adapter_digest_display_invalid")
    if grouped not in corpus_intelligence_mcp.display_json({"codegraph_index_sha256":digest}):
        raise RuntimeError("mcp_digest_display_invalid")
    if "finding_evidence_pointer" not in corpus_intelligence_mcp.TOOLS[3]["description"]:
        raise RuntimeError("reachability_guidance_missing")
    if "analysis_id" not in findings_mcp.SUBMIT["description"]:
        raise RuntimeError("findings_guidance_missing")
    return {
        "analysis_id": analysis_id,
        "schema": "secure-sandbox-codegraph-findings-ergonomics-live-v1",
        "status": "verified",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_id")
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.analysis_id), separators=(",", ":"), sort_keys=True))
