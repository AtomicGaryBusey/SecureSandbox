#!/usr/bin/env python3
"""Exercise deployed publisher recovery using content-free temporary state."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from unittest import mock


MODULE_ROOT = os.environ.get("SECURE_SANDBOX_MODULE_ROOT", "/usr/local/libexec/secure-sandbox")
TEMP_ROOT = os.environ.get("SECURE_SANDBOX_LIVE_TMP_ROOT", "/var/lib/secure-sandbox")
__import__("sys").path.insert(0, MODULE_ROOT)


def gateway_gate() -> None:
    import telemetry_receiver
    import update_client_fingerprints

    with tempfile.TemporaryDirectory(prefix="publisher-gateway-", dir=TEMP_ROOT) as directory:
        root = Path(directory)
        spool = root / "current.jsonl"
        spool.write_bytes(b"old\n")
        with mock.patch.object(telemetry_receiver, "SPOOL", str(spool)), \
             mock.patch.object(telemetry_receiver, "SPOOL_LOCK", str(root / ".spool.lock")), \
             mock.patch.object(telemetry_receiver, "MAX_FILE", 1):
            telemetry_receiver.append_events([{"EventType": "publisher_recovery_gate"}])
        if not Path(str(spool) + ".1").is_file() or not spool.is_file():
            raise RuntimeError("telemetry_rotation_recovery_failed")
        config = root / "broker.json"
        config.write_text('{"allowed_client_sha256":[]}\n', encoding="utf-8")
        config.chmod(0o640)
        update_client_fingerprints.update(str(config), "a" * 64, False)
        if json.loads(config.read_text(encoding="utf-8"))["allowed_client_sha256"] != ["a" * 64]:
            raise RuntimeError("fingerprint_publication_failed")


def research_gate() -> None:
    import codegraph_indexer
    import source_importer

    source_id = "11111111-1111-4111-8111-111111111111"
    with tempfile.TemporaryDirectory(prefix="publisher-research-", dir=TEMP_ROOT) as directory:
        root = Path(directory)
        baselines, repos, manifests = root / "baselines", root / "repos", root / "manifests"
        control, staging, markers, builds, indexes = root / "control", root / "control/staging", root / "markers", root / "builds", root / "indexes"
        for path in (baselines, repos, manifests, staging, markers, builds, indexes):
            path.mkdir(parents=True, exist_ok=True)
        (staging / source_id).mkdir()
        prior = {"schema": "secure-sandbox-source-registry-v1", "sources": []}
        record = {"source_id": source_id, "repository": "owner/repo", "worktree_path": f"repos/recovered-{source_id}"}
        updated = {"schema": prior["schema"], "sources": [record]}
        registry, index = control / "registry.json", repos / "INDEX.json"
        registry.write_bytes(source_importer.canonical(prior) + b"\n"); registry.chmod(0o600)
        index.write_bytes(source_importer.canonical(prior) + b"\n"); index.chmod(0o444)
        temporary = [baselines / f".source-{source_id}.new", repos / f".source-{source_id}.new", manifests / f".{source_id}.new"]
        final = [baselines / source_id, repos / f"recovered-{source_id}", manifests / f"{source_id}.json"]
        temporary[0].mkdir(); temporary[1].mkdir(); temporary[2].write_text("{}\n", encoding="utf-8")
        pending = [control / f"registry-{source_id}.pending", repos / f".INDEX-{source_id}.pending"]
        pending[0].write_bytes(source_importer.canonical(updated) + b"\n"); pending[0].chmod(0o600)
        pending[1].write_bytes(source_importer.canonical(updated) + b"\n"); pending[1].chmod(0o444)
        artifacts = [{"temporary": str(a), "final": str(b), "uid": os.geteuid(), "identity": source_importer.publication_identity(str(a))} for a, b in zip(temporary, final)]
        transaction = {"schema": source_importer.PUBLICATION_SCHEMA, "source_id": source_id, "phase": "prepared", "control_uid": os.geteuid(), "record": record, "prior_registry": prior, "updated_registry": updated, "artifacts": artifacts, "pending": [str(path) for path in pending]}
        transaction_path = control / f"publication-{source_id}.transaction.json"
        transaction_path.write_bytes(source_importer.canonical(transaction) + b"\n"); transaction_path.chmod(0o600)
        os.replace(temporary[0], final[0]); os.replace(temporary[1], final[1])
        with mock.patch.multiple(source_importer, ROOT=str(control), STAGING=str(staging), BASELINES=str(baselines), REPOS=str(repos), MANIFESTS=str(manifests), REGISTRY=str(registry)):
            recovered = source_importer.recover_publication(source_id)
        if recovered != record or not all(path.exists() for path in final) or transaction_path.exists():
            raise RuntimeError("source_publication_recovery_failed")

        destination = indexes / source_id
        graph = destination / "project/.codegraph"
        graph.mkdir(parents=True); (graph / "graph.db").write_bytes(b"graph")
        source_record = {"repository": "owner/repo", "resolved_commit": "a" * 40, "tree_manifest_sha256": "b" * 64}
        metadata = {"schema": "secure-sandbox-codegraph-index-v1", "source_id": source_id, **source_record,
                    "corpus_index_content_sha256": "c" * 64, "codegraph_version": "1.6.2",
                    "codegraph_build_commit": codegraph_indexer.BUILD_COMMIT,
                    "codegraph_bundle_sha256": codegraph_indexer.BUNDLE_SHA256,
                    "codegraph_index_sha256": codegraph_indexer.directory_digest(str(graph)),
                    "source_files": 1, "source_bytes": 5, "files_processed": 1,
                    "nodes_created": 1, "edges_created": 0, "index_errors": [], "created_at": "fixed"}
        metadata_path = destination / "project/metadata.json"
        metadata_path.write_bytes(codegraph_indexer.canonical(metadata) + b"\n"); metadata_path.chmod(0o444)
        with mock.patch.multiple(codegraph_indexer, ROOT=str(indexes), MARKER_ROOT=str(markers), BUILD_ROOT=str(builds)):
            observed = codegraph_indexer.validate_recoverable_index(source_id, str(destination), source_record)
        if observed != metadata or not (markers / f"{source_id}.json").is_file():
            raise RuntimeError("codegraph_publication_recovery_failed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("gateway", "research"))
    args = parser.parse_args()
    gateway_gate() if args.role == "gateway" else research_gate()
    print(json.dumps({"role": args.role, "schema": "secure-sandbox-transactional-publisher-live-verification-v1", "status": "verified"}, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
