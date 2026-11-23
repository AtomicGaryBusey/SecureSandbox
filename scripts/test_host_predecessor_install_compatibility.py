#!/usr/bin/env python3
"""Prove the current Host install contract remains predecessor-admissible."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
BROKER = REPO / "scripts/operator-authorization.py"
RELEASE_MANAGER = REPO / "scripts/host-controller-release.py"
PREDECESSOR_COMMIT = "1965de0a062b5f0c960ff5442df638cacdbb4713"
PREDECESSOR_BROKER_SHA256 = (
    "4a286ebb79b5808e570f7c0ff81f72f8868751ada3912aa04985fe2b9933b3ce"
)


def literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    matches: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            ):
                matches.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            matches.append(node.value)
    if len(matches) != 1:
        raise AssertionError(f"expected one assignment for {name}, got {len(matches)}")
    return ast.literal_eval(matches[0])


def dictionary_keys(path: Path, name: str) -> set[str]:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    matches: list[ast.Dict] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Dict):
            raise AssertionError(f"{name} is not a dictionary literal")
        matches.append(node.value)
    if len(matches) != 1:
        raise AssertionError(f"expected one assignment for {name}, got {len(matches)}")
    keys: set[str] = set()
    for key in matches[0].keys:
        value = ast.literal_eval(key)
        if not isinstance(value, str):
            raise AssertionError(f"{name} contains a non-string key")
        keys.add(value)
    return keys


def extract_predecessor(root: Path) -> None:
    archive = subprocess.run(
        [
            "git", "archive", "--format=tar", PREDECESSOR_COMMIT,
            "scripts/operator-authorization.py", "shared",
        ],
        cwd=REPO,
        check=True,
        capture_output=True,
    ).stdout
    resolved_root = root.resolve(strict=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            destination = (root / member.name).resolve()
            if not destination.is_relative_to(resolved_root):
                raise AssertionError("predecessor archive escaped extraction root")
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(member.mode & 0o777)
                continue
            if not member.isfile():
                raise AssertionError(
                    f"unexpected predecessor archive member: {member.name}"
                )
            source = bundle.extractfile(member)
            if source is None:
                raise AssertionError(f"unable to read archive member: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
            destination.chmod(member.mode & 0o777)


PREDECESSOR_RUNNER = r"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

archive_root = Path(sys.argv[1])
home = Path(sys.argv[2])
current = json.loads(sys.argv[3])
broker_path = archive_root / "scripts/operator-authorization.py"
spec = importlib.util.spec_from_file_location("exact_predecessor_broker", broker_path)
broker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(broker)

if broker.EXPECTED_RELEASE_MODES != current["release_modes"]:
    raise AssertionError("predecessor/current release inventory mismatch")
for name, value in current["schemas"].items():
    if getattr(broker, name) != value:
        raise AssertionError(f"predecessor/current schema mismatch: {name}")

home.mkdir(mode=0o700)
repo = home / "SecureSandbox"
repo.mkdir()
release_commit = "c" * 40
candidate_root = (
    repo / ".private/native-host-product-candidates"
    / (release_commit + "-12345678-1234-4123-8123-123456789abc")
)
generation = candidate_root / "generation"
generation.mkdir(parents=True)
evidence = candidate_root / "evidence"
evidence.mkdir(mode=0o700)
preimage = evidence / broker.NATIVE_HOST_RELEASE_PREIMAGE_ARCHIVE_NAME
preimage.write_bytes(b"predecessor-compatibility-preimage\n" + b"p" * 1024)
preimage.chmod(0o400)
generation_info = generation.lstat()
preimage_info = preimage.lstat()
candidate = {
    "schema": current["schemas"]["NATIVE_HOST_CANDIDATE_SCHEMA"],
    "build_custody": "trusted-login-principal-v1",
    "generation_path": str(generation),
    "generation_device": generation_info.st_dev,
    "generation_inode": generation_info.st_ino,
    "generation_tree_sha256": "1" * 64,
    "release_commit": release_commit,
    "host_release_preimage_path": str(preimage),
    "host_release_preimage_device": preimage_info.st_dev,
    "host_release_preimage_inode": preimage_info.st_ino,
    "host_release_preimage_size": preimage_info.st_size,
    "host_release_preimage_sha256": "2" * 64,
    "host_release_preimage_schema": current["schemas"][
        "NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA"
    ],
    "signing_config_sha256": "3" * 64,
    "source_archive_sha256": "4" * 64,
    "source_tree_sha256": "5" * 64,
    "developer_id_certificate_sha1": "6" * 40,
    "notary_submission_id": "12345678-1234-4123-8123-123456789abc",
}
# Payload digests are intentionally opaque fixture values: the predecessor
# validator admits the signed candidate record and exact inventory contract;
# notarized-product byte verification remains the release manager's boundary.
payloads = {
    name: hashlib.sha256(
        f"repaired-candidate:{name}:{mode:o}".encode("ascii")
    ).hexdigest()
    for name, mode in current["release_modes"].items()
}
plan = {
    "candidate_record_sha256": hashlib.sha256(
        broker.canonical_v2(candidate)
    ).hexdigest(),
    "payloads": payloads,
    "release_id": broker.host_release_identity(payloads),
    "schema": current["schemas"]["HOST_RELEASE_TARGET_PLAN_SCHEMA"],
    "source_stable_sha256": "7" * 64,
    "target_launcher_sha256": "8" * 64,
}
parameters = {
    "repo": str(repo),
    "state_root": str(
        home / "Library/Application Support/SecureSandbox/controller-state"
    ),
    "authorized_target_plan": plan,
    "authorized_target_plan_sha256": hashlib.sha256(
        broker.canonical(plan)
    ).hexdigest(),
    "native_host_candidate": candidate,
}
broker.validate_parameters("host-controller-install", parameters, home)

request = {
    "operation": "host-controller-install",
    "parameters": parameters,
    "request_id": "11111111-1111-4111-8111-111111111111",
}
release = Path("/exact-predecessor-release")
command = broker.operation_command(request, release)
if command[:4] != [
    "/usr/bin/python3", "-I", str(release / "release_manager"), "install",
]:
    raise AssertionError("predecessor install command prefix changed")

def argument(flag):
    position = command.index(flag)
    return command[position + 1]

if argument("--repo") != str(repo):
    raise AssertionError("repository argument was not preserved")
if argument("--state-root") != parameters["state_root"]:
    raise AssertionError("state-root argument was not preserved")
if argument("--authorized-target-plan-sha256") != parameters[
    "authorized_target_plan_sha256"
]:
    raise AssertionError("authorized plan digest was not preserved")
if argument("--expected-source-release-id") != plan["release_id"]:
    raise AssertionError("candidate release identity was not preserved")
if json.loads(argument("--native-host-candidate-json")) != candidate:
    raise AssertionError("candidate record was not preserved")
if "--json" not in command:
    raise AssertionError("machine-readable manager result was not requested")

result = {
    "schema": "secure-sandbox-host-controller-release-v1",
    "status": "deployed",
    "release_id": plan["release_id"],
    "transition_id": "12345678-1234-4123-8123-123456789abc",
    "transition_sha256": "9" * 64,
    "host_release_launcher_pair_sha256": "a" * 64,
    "candidate_authority_sha256": "b" * 64,
    "release_tree_identity_sha256": "c" * 64,
    "developer_id_team_id": "389K3H8Y32",
    "developer_id_team_floor_sha256": "d" * 64,
    "developer_id_team_floor_release_id": "e" * 64,
    "launcher_sha256": plan["target_launcher_sha256"],
    "payloads": payloads,
}
if broker.validate_host_pair_manager_result(
    result, "host-controller-install", parameters
) != result:
    raise AssertionError("predecessor rejected the deployed result schema")

# Ensure this proof is sensitive to a future uncoordinated payload addition.
changed_payloads = dict(payloads)
changed_payloads["uncoordinated_payload"] = "f" * 64
changed_plan = dict(plan)
changed_plan["payloads"] = changed_payloads
changed_plan["release_id"] = broker.host_release_identity(changed_payloads)
try:
    broker.validate_host_release_authorized_target_plan(
        "host-controller-install",
        changed_plan,
        hashlib.sha256(broker.canonical(changed_plan)).hexdigest(),
        candidate=candidate,
    )
except broker.AuthorizationError:
    pass
else:
    raise AssertionError("predecessor accepted an uncoordinated inventory change")

print(json.dumps({
    "accepted": True,
    "payload_count": len(payloads),
    "release_id": plan["release_id"],
}, sort_keys=True))
"""


class HostPredecessorInstallCompatibilityTests(unittest.TestCase):
    def test_exact_predecessor_accepts_current_install_contract(self) -> None:
        current_modes = literal_assignment(BROKER, "EXPECTED_RELEASE_MODES")
        self.assertIsInstance(current_modes, dict)
        manager_modes = literal_assignment(RELEASE_MANAGER, "EXPECTED_MODES")
        self.assertIsInstance(manager_modes, dict)
        candidate_payloads = dictionary_keys(RELEASE_MANAGER, "PAYLOAD_SOURCES") | {
            "gpgv", "native_stack_support", "native_deployment_payloads",
        }
        self.assertEqual(set(current_modes), candidate_payloads)
        self.assertEqual(
            current_modes,
            {name: manager_modes[name] for name in candidate_payloads},
        )
        current = {
            "release_modes": current_modes,
            "schemas": {
                name: literal_assignment(BROKER, name)
                for name in (
                    "NATIVE_HOST_CANDIDATE_SCHEMA",
                    "NATIVE_HOST_RELEASE_PREIMAGE_SCHEMA",
                    "HOST_RELEASE_TARGET_PLAN_SCHEMA",
                )
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_root = root / "predecessor"
            archive_root.mkdir()
            extract_predecessor(archive_root)
            archived_broker = archive_root / "scripts/operator-authorization.py"
            self.assertEqual(
                hashlib.sha256(archived_broker.read_bytes()).hexdigest(),
                PREDECESSOR_BROKER_SHA256,
            )
            process = subprocess.run(
                [
                    sys.executable, "-I", "-c", PREDECESSOR_RUNNER,
                    str(archive_root), str(root / "home"),
                    json.dumps(current, separators=(",", ":"), sort_keys=True),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(process.returncode, 0, process.stderr)
        outcome = json.loads(process.stdout)
        self.assertTrue(outcome["accepted"])
        self.assertEqual(outcome["payload_count"], len(current_modes))
        self.assertRegex(outcome["release_id"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
