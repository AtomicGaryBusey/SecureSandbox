#!/usr/bin/env python3
"""Freeze all public GitHub refs after the reviewed visibility transition."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPOSITORY = "AtomicGaryBusey/SecureSandbox"
BRANCH_RULESET = "SecureSandbox immutable public branches"
TAG_RULESET = "SecureSandbox immutable public tags"


def gh_json(endpoint: str, *, method: str = "GET", payload: object | None = None) -> object:
    command = [
        "gh", "api", "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28", "--method", method, endpoint,
    ]
    encoded = None
    if payload is not None:
        command.extend(["--input", "-"])
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    result = subprocess.run(
        command, input=encoded, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=ROOT, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("GitHub API result is ambiguous; inspect remote state before retrying")
    return json.loads(result.stdout) if result.stdout.strip() else None


def local_head() -> str:
    return subprocess.check_output(
        ["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=ROOT, text=True,
    ).strip()


def ruleset_payload(name: str, target: str) -> dict[str, object]:
    rules: list[dict[str, object]] = [
        {"type": "creation"},
        {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}},
        {"type": "deletion"},
    ]
    if target == "branch":
        rules.append({"type": "non_fast_forward"})
    return {
        "name": name,
        "target": target,
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
        "rules": rules,
    }


def ref_names(repository: str, kind: str) -> list[str]:
    values = gh_json(f"repos/{repository}/{kind}?per_page=100")
    if not isinstance(values, list):
        raise RuntimeError(f"unexpected GitHub {kind} response")
    if len(values) == 100:
        raise RuntimeError(f"GitHub {kind} inventory reached the verification page bound")
    names = [value.get("name") for value in values if isinstance(value, dict)]
    if len(names) != len(values) or not all(isinstance(name, str) for name in names):
        raise RuntimeError(f"invalid GitHub {kind} inventory")
    return sorted(names)


def rulesets(repository: str) -> list[dict[str, object]]:
    values = gh_json(f"repos/{repository}/rulesets?includes_parents=false&per_page=100")
    if not isinstance(values, list) or len(values) >= 100:
        raise RuntimeError("unexpected or incomplete GitHub ruleset inventory")
    return [value for value in values if isinstance(value, dict)]


def put_ruleset(repository: str, payload: dict[str, object]) -> None:
    matches = [item for item in rulesets(repository) if item.get("name") == payload["name"]]
    if len(matches) > 1:
        raise RuntimeError("duplicate publication rulesets require manual review")
    if matches:
        identifier = matches[0].get("id")
        if not isinstance(identifier, int):
            raise RuntimeError("publication ruleset has no stable identifier")
        gh_json(f"repos/{repository}/rulesets/{identifier}", method="PUT", payload=payload)
    else:
        gh_json(f"repos/{repository}/rulesets", method="POST", payload=payload)


def verify_ruleset(repository: str, expected: dict[str, object]) -> None:
    matches = [item for item in rulesets(repository) if item.get("name") == expected["name"]]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
        raise RuntimeError("required publication ruleset is absent or ambiguous")
    actual = gh_json(f"repos/{repository}/rulesets/{matches[0]['id']}")
    if not isinstance(actual, dict):
        raise RuntimeError("invalid publication ruleset response")
    for key in ("name", "target", "enforcement", "bypass_actors", "conditions", "rules"):
        if actual.get(key) != expected[key]:
            raise RuntimeError(f"publication ruleset differs at {key}")


def verify_repository(repository: str) -> None:
    metadata = gh_json(f"repos/{repository}")
    if not isinstance(metadata, dict):
        raise RuntimeError("invalid GitHub repository response")
    if metadata.get("visibility") != "public" or metadata.get("default_branch") != "public-release":
        raise RuntimeError("GitHub repository is not public with public-release as default")
    if ref_names(repository, "branches") != ["public-release"]:
        raise RuntimeError("GitHub repository has an unexpected branch inventory")
    if ref_names(repository, "tags"):
        raise RuntimeError("GitHub repository has unexpected tags")
    remote_ref = gh_json(f"repos/{repository}/git/ref/heads/public-release")
    if (not isinstance(remote_ref, dict) or not isinstance(remote_ref.get("object"), dict)
            or remote_ref["object"].get("sha") != local_head()):
        raise RuntimeError("GitHub public-release does not equal the reviewed local HEAD")
    reporting = gh_json(f"repos/{repository}/private-vulnerability-reporting")
    if reporting != {"enabled": True}:
        raise RuntimeError("GitHub private vulnerability reporting is not enabled")
    verify_ruleset(repository, ruleset_payload(BRANCH_RULESET, "branch"))
    verify_ruleset(repository, ruleset_payload(TAG_RULESET, "tag"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--apply", action="store_true",
                        help="create/update the immutable ref rulesets and reporting channel")
    args = parser.parse_args()
    if args.apply:
        metadata = gh_json(f"repos/{args.repository}")
        if not isinstance(metadata, dict) or metadata.get("visibility") != "public":
            raise SystemExit("repository must already be public before applying public rulesets")
        put_ruleset(args.repository, ruleset_payload(BRANCH_RULESET, "branch"))
        put_ruleset(args.repository, ruleset_payload(TAG_RULESET, "tag"))
        gh_json(
            f"repos/{args.repository}/private-vulnerability-reporting", method="PUT",
        )
    verify_repository(args.repository)
    print(json.dumps({
        "repository": args.repository,
        "schema": "secure-sandbox-public-github-seal-v1",
        "status": "verified",
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
