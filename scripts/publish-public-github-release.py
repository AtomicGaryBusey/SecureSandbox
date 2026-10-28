#!/usr/bin/env python3
"""Publish one reviewed fast-forward commit through the frozen GitHub ref."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SEAL_PATH = Path(__file__).with_name("seal-public-github-release.py")
SPEC = importlib.util.spec_from_file_location("secure_sandbox_github_seal", SEAL_PATH)
SEAL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SEAL)


def git(*arguments: str, capture: bool = True) -> str:
    result = subprocess.run(
        ["git", "--no-replace-objects", *arguments], cwd=ROOT,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Git publication result is ambiguous; inspect local and remote refs")
    return result.stdout.strip() if capture else ""


def exact_ruleset(repository: str, name: str) -> dict[str, object]:
    matches = [item for item in SEAL.rulesets(repository) if item.get("name") == name]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
        raise RuntimeError("required publication ruleset is absent or ambiguous")
    actual = SEAL.gh_json(f"repos/{repository}/rulesets/{matches[0]['id']}")
    if not isinstance(actual, dict):
        raise RuntimeError("invalid publication ruleset response")
    return actual


def verify_ruleset_enforcement(
    repository: str, expected: dict[str, object], enforcement: str,
) -> None:
    actual = exact_ruleset(repository, str(expected["name"]))
    for key in ("name", "target", "bypass_actors", "conditions"):
        if actual.get(key) != expected[key]:
            raise RuntimeError(f"publication ruleset differs at {key}")
    if actual.get("enforcement") != enforcement:
        raise RuntimeError("publication ruleset enforcement differs")
    actual_rules = actual.get("rules")
    expected_rules = expected.get("rules")
    if not isinstance(actual_rules, list) or not isinstance(expected_rules, list):
        raise RuntimeError("publication ruleset differs at rules")
    actual_types = sorted(rule.get("type") for rule in actual_rules if isinstance(rule, dict))
    expected_types = sorted(rule.get("type") for rule in expected_rules if isinstance(rule, dict))
    if actual_types != expected_types or len(actual_types) != len(actual_rules):
        raise RuntimeError("publication ruleset differs at rules")


def remote_tip(repository: str) -> str:
    value = SEAL.gh_json(f"repos/{repository}/git/ref/heads/public-release")
    if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
        raise RuntimeError("invalid GitHub public-release ref")
    tip = value["object"].get("sha")
    if not isinstance(tip, str) or len(tip) != 40:
        raise RuntimeError("invalid GitHub public-release tip")
    return tip


def verify_prepublication(repository: str, head: str, parent: str) -> None:
    if git("status", "--porcelain"):
        raise RuntimeError("publication requires a clean worktree and index")
    if git("symbolic-ref", "--short", "HEAD") != "public-release":
        raise RuntimeError("publication requires the public-release branch")
    if git("merge-base", "--is-ancestor", parent, head) != "":
        raise RuntimeError("unexpected merge-base output")
    metadata = SEAL.gh_json(f"repos/{repository}")
    if not isinstance(metadata, dict):
        raise RuntimeError("invalid GitHub repository response")
    if metadata.get("visibility") != "public" or metadata.get("default_branch") != "public-release":
        raise RuntimeError("GitHub repository is not public with public-release as default")
    if SEAL.ref_names(repository, "branches") != ["public-release"] or SEAL.ref_names(repository, "tags"):
        raise RuntimeError("GitHub ref inventory is not publication-safe")
    if remote_tip(repository) != parent:
        raise RuntimeError("GitHub public-release moved after local review")
    if SEAL.gh_json(f"repos/{repository}/private-vulnerability-reporting") != {"enabled": True}:
        raise RuntimeError("GitHub private vulnerability reporting is not enabled")
    SEAL.verify_ruleset(repository, SEAL.ruleset_payload(SEAL.BRANCH_RULESET, "branch"))
    SEAL.verify_ruleset(repository, SEAL.ruleset_payload(SEAL.TAG_RULESET, "tag"))


def publish(repository: str) -> dict[str, str]:
    head = git("rev-parse", "HEAD")
    branch_ref = "refs/heads/public-release"
    if git("rev-parse", branch_ref) != head:
        raise RuntimeError("public-release does not name the reviewed local HEAD")
    parent = git("rev-parse", "origin/public-release")
    verify_prepublication(repository, head, parent)
    subprocess.run(
        [str(ROOT / "scripts/run-public-release-checks.sh"), head],
        cwd=ROOT, check=True,
    )

    active = SEAL.ruleset_payload(SEAL.BRANCH_RULESET, "branch")
    disabled = {**active, "enforcement": "disabled"}
    SEAL.put_ruleset(repository, disabled)
    verify_ruleset_enforcement(repository, disabled, "disabled")
    push_error: BaseException | None = None
    try:
        if git("rev-parse", branch_ref) != head:
            raise RuntimeError("public-release moved after review")
        git("push", "origin", f"{branch_ref}:{branch_ref}", capture=False)
        if remote_tip(repository) != head:
            raise RuntimeError("GitHub push completed without the expected remote tip")
    except BaseException as error:
        push_error = error
    finally:
        SEAL.put_ruleset(repository, active)
        SEAL.verify_ruleset(repository, active)
    if push_error is not None:
        raise RuntimeError("GitHub publication failed; immutable ruleset was restored") from push_error
    SEAL.verify_repository(repository)
    return {
        "commit": head,
        "repository": repository,
        "schema": "secure-sandbox-public-github-publication-v1",
        "status": "published-and-resealed",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=SEAL.DEFAULT_REPOSITORY)
    arguments = parser.parse_args()
    print(json.dumps(publish(arguments.repository), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
