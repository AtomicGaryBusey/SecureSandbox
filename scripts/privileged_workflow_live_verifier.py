#!/usr/bin/env python3
"""Content-free live acceptance for the privileged workflow engine."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from shared.privileged_workflow import WorkflowError, WorkflowStore, fsync_directory


def action() -> str:
    return str(uuid.uuid4())


def verify(role: str, parent: Path) -> dict[str, object]:
    if role not in {"gateway", "research", "target"}:
        raise WorkflowError("role_invalid")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = Path(tempfile.mkdtemp(prefix="privileged-workflow-live-", dir=parent))
    try:
        store = WorkflowStore(root / "complete", "live-acceptance")
        transaction_id = str(uuid.uuid4())
        now = int(time.time())
        identities = {"role": role, "release": "a" * 64}
        with store.locked():
            store.create(transaction_id, action(), identities, now + 300, now=now)
            authorized_action = action()
            store.advance(transaction_id, "authorized", authorized_action, identities,
                          authorization_sha256="b" * 64,
                          authorization_expires_at=now + 120, now=now + 1)
            transaction = store.transactions / transaction_id
            (transaction / "head.json").unlink()
            fsync_directory(transaction)
            recovered = store.advance(
                transaction_id, "authorized", authorized_action, identities,
                authorization_sha256="b" * 64,
                authorization_expires_at=now + 120, now=now + 1,
            )
            if recovered["phase"] != "authorized":
                raise WorkflowError("lost_response_recovery_failed")
            store.advance(transaction_id, "activated", action(), identities,
                          evidence_sha256="c" * 64, now=now + 2)
            store.advance(transaction_id, "verified", action(), identities,
                          evidence_sha256="d" * 64, now=now + 3)
            committed = store.advance(transaction_id, "committed", action(), identities,
                                      evidence_sha256="e" * 64, now=now + 4)
            if committed["phase"] != "committed" or len(store.event_history(transaction_id, identities)) != 5:
                raise WorkflowError("commit_recovery_failed")

        rollback = WorkflowStore(root / "rollback", "live-rollback")
        rollback_id = str(uuid.uuid4())
        with rollback.locked():
            rollback.create(rollback_id, action(), identities, now + 300, now=now)
            if rollback.advance(rollback_id, "rolled_back", action(), identities,
                                evidence_sha256="f" * 64, now=now + 1)["phase"] != "rolled_back":
                raise WorkflowError("rollback_failed")

        expiry = WorkflowStore(root / "expiry", "live-expiry")
        expiry_id = str(uuid.uuid4())
        with expiry.locked():
            expiry.create(expiry_id, action(), identities, now + 1, now=now)
            if expiry.advance(expiry_id, "expired", action(), identities, now=now + 2)["phase"] != "expired":
                raise WorkflowError("expiry_failed")
        return {
            "schema": "secure-sandbox-privileged-workflow-live-verification-v1",
            "role": role,
            "status": "verified",
            "append_only": True,
            "lost_response_recovered": True,
            "rollback_verified": True,
            "expiry_verified": True,
        }
    finally:
        shutil.rmtree(root)
        fsync_directory(parent)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("gateway", "research", "target"))
    parser.add_argument("--state-parent", default="/var/lib/secure-sandbox")
    args = parser.parse_args()
    try:
        result = verify(args.role, Path(args.state_parent))
    except (WorkflowError, OSError) as error:
        print(json.dumps({"error": str(error), "status": "rejected"}, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
