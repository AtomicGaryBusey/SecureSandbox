#!/usr/bin/env python3
"""Operator-attributed coordination wrapper for host-controller mutations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from typing import NamedTuple
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("secure-sandbox-claude-launcher.py")
SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher", MODULE_PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(LAUNCHER)
MANAGER_PATH = Path(__file__).with_name("host-controller-release.py")
MANAGER_SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(MANAGER_SPEC)
assert MANAGER_SPEC.loader is not None
MANAGER_SPEC.loader.exec_module(MANAGER)
BROKER_PATH = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
TOUCHID_BUILD = Path(__file__).with_name("build-touchid-authorization-ui.sh")
NATIVE_COMPONENT_BUILD = Path(__file__).with_name(
    "build-native-credential-components.sh"
)
NATIVE_HOST_PRODUCTS_BUILD = Path(__file__).with_name(
    "build-native-host-products.sh"
)
INSTALL_ROOT = Path("/usr/local/libexec/secure-sandbox-host")
STABLE_LAUNCHER = Path("/usr/local/bin/secure-sandbox-claude")
INSTALL_TRANSITION_DIRECTORY = INSTALL_ROOT / "install-transitions"
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}$")
SAFE_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
BOOTSTRAP_NOTICE_SCRIPT = r'''
on run argv
  tell application "System Events"
    activate
    set answer to display dialog (item 1 of argv) with title "SecureSandbox Bootstrap Authorization" buttons {"Cancel", "Continue"} default button "Cancel" cancel button "Cancel" with icon caution giving up after 90
    if gave up of answer then error number -128
    return button returned of answer
  end tell
end run
'''
BOOTSTRAP_LOADER = r'''
import hashlib, os, stat, sys
path, expected = sys.argv[1], sys.argv[2]
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(descriptor)
    sudo_uid = int(os.environ.get("SUDO_UID", "-1"))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != sudo_uid:
        raise SystemExit("bootstrap_manager_untrusted")
    data = os.read(descriptor, 2 * 1024 * 1024 + 1)
finally:
    os.close(descriptor)
if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit("bootstrap_manager_digest_mismatch")
sys.argv = [path] + sys.argv[3:]
namespace = {"__name__": "__main__", "__file__": path, "__package__": None}
exec(compile(data, path, "exec"), namespace, namespace)
'''


class BootstrapBinding(NamedTuple):
    release_id: str
    manager_sha256: str
    broker_sha256: str
    installed_launcher_sha256: str
    replacement_launcher_sha256: str
    touchid_ui_previous_sha256: str = ""
    touchid_ui_replacement_sha256: str = ""
    touchid_sources_previous_sha256: str = ""
    touchid_sources_replacement_sha256: str = ""
    archive_current_release_id: str = ""
    archive_previous_release_id: str = ""
    archive_plan_sha256: str = ""
    archive_release_ids: tuple[str, ...] = ()
    schema_current_release_id: str = ""
    developer_id_team_id: str = ""
    current_authorization_manifest_sha256: str = ""
    candidate_authorization_manifest_sha256: str = ""


def prepare_touchid_ui(*, require_developer_id: bool = False) -> None:
    if require_developer_id and not os.environ.get(
        "SECURE_SANDBOX_DEVELOPER_ID"
    ):
        raise RuntimeError("SECURE_SANDBOX_DEVELOPER_ID_is_required")
    result = subprocess.run(
        [str(TOUCHID_BUILD)], check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("touchid_ui_build_failed:" + detail[-1000:])


def prepare_native_credential_components() -> None:
    if not os.environ.get("SECURE_SANDBOX_DEVELOPER_ID"):
        raise RuntimeError("SECURE_SANDBOX_DEVELOPER_ID_is_required")
    result = subprocess.run(
        [str(NATIVE_COMPONENT_BUILD)], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=900,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("native_component_build_failed:" + detail[-1000:])


def prepare_native_host_products() -> None:
    if (not os.environ.get("SECURE_SANDBOX_DEVELOPER_ID")
            or not os.environ.get(
                "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE"
            )):
        raise RuntimeError(
            "Developer_ID_and_notary_profile_are_required"
        )
    result = subprocess.run(
        [str(NATIVE_HOST_PRODUCTS_BUILD)], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=1800,
        env={**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError("native_host_products_build_failed:" + detail[-2000:])


def protected_broker_available(broker_path: Path | None = None) -> bool:
    broker_path = BROKER_PATH if broker_path is None else broker_path
    try:
        return (
            broker_path.is_file() and not broker_path.is_symlink()
            and os.access(broker_path, os.X_OK)
        )
    except OSError:
        return False


def wait_for_install_terminal(
    pending: dict[str, object], *, timeout: float = 605.0,
) -> dict[str, object]:
    transition_id = pending.get("transition_id")
    transition_sha256 = pending.get("transition_sha256")
    candidate = pending.get("candidate_release_id")
    expires_at = pending.get("expires_at")
    if (not isinstance(transition_id, str)
            or not isinstance(transition_sha256, str)
            or MANAGER.SHA256.fullmatch(transition_sha256) is None
            or not isinstance(candidate, str)
            or MANAGER.SHA256.fullmatch(candidate) is None
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)):
        raise RuntimeError("host_install_activation_pending_invalid")
    MANAGER._validated_uuid4(transition_id, "install_transition_id")
    deadline = time.monotonic() + min(
        timeout, max(1.0, float(expires_at - int(time.time()) + 5)),
    )
    filename = f"{transition_id}.json"
    while time.monotonic() < deadline:
        descriptor = -1
        try:
            descriptor = MANAGER.open_trusted_absolute_directory(
                INSTALL_TRANSITION_DIRECTORY, 0, final_mode=0o755,
            )
            try:
                publication = os.stat(
                    filename, dir_fd=descriptor, follow_symlinks=False,
                )
            except FileNotFoundError:
                terminal = None
                time.sleep(0.05)
                continue
            if publication.st_nlink == 2:
                # The publisher first hard-links the canonical pending inode to
                # its final name, fsyncs, then unlinks pending.  nlink=2 is the
                # intentional crash-recoverable publication window, not an
                # untrusted terminal record.
                terminal = None
                time.sleep(0.05)
                continue
            value, _raw, _ = MANAGER.read_state_record_at(
                descriptor, filename, 0, 0o444,
            )
            terminal = MANAGER.validate_terminal_transition(value)
        except FileNotFoundError:
            terminal = None
        except MANAGER.ReleaseFailure as error:
            if "install_transition_parent_untrusted" in str(error):
                terminal = None
            else:
                raise RuntimeError("host_install_terminal_untrusted") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if terminal is not None:
            if (terminal["transition_id"] != transition_id
                    or terminal["transition_sha256"] != transition_sha256
                    or terminal["candidate_release_id"] != candidate):
                raise RuntimeError("host_install_terminal_mismatch")
            return terminal
        time.sleep(0.05)
    raise RuntimeError("host_install_activation_timeout")


def selector_recovery_required(
    install_root: Path = INSTALL_ROOT, expected_uid: int = 0
) -> bool:
    selector = install_root / "current"
    try:
        root_info = install_root.lstat()
        releases_info = (install_root / "releases").lstat()
        selector_info = selector.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode)
        and root_info.st_uid == expected_uid and stat.S_IMODE(root_info.st_mode) == 0o755
        and stat.S_ISDIR(releases_info.st_mode) and not stat.S_ISLNK(releases_info.st_mode)
        and releases_info.st_uid == expected_uid and stat.S_IMODE(releases_info.st_mode) == 0o755
        and stat.S_ISLNK(selector_info.st_mode) and selector_info.st_uid == expected_uid
        and stat.S_IMODE(selector_info.st_mode) != 0o755
    )


def postactivation_current_release(
    allow_legacy: bool = False, expected_uid: int = 0,
    allow_migration_predecessor_anchor: bool = False,
) -> Path:
    """Verify the current selector without reading the root-only v2 floor."""
    enforce_floor = MANAGER.enforce_execution_approval_floor
    developer_floor = MANAGER.developer_id_team_floor
    floor_path = INSTALL_ROOT / MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
    floor_present = False
    selected_link = INSTALL_ROOT / "current"
    if (allow_migration_predecessor_anchor
            and not selected_link.is_symlink()):
        selected_link = (
            INSTALL_ROOT / MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
        )
    try:
        floor_info = floor_path.lstat()
        if (not stat.S_ISREG(floor_info.st_mode)
                or stat.S_ISLNK(floor_info.st_mode)
                or floor_info.st_uid != expected_uid or floor_info.st_nlink != 1
                or stat.S_IMODE(floor_info.st_mode) != 0o600):
            raise RuntimeError("developer_id_team_floor_untrusted")
        floor_present = True
    except FileNotFoundError:
        pass
    try:
        MANAGER.enforce_execution_approval_floor = lambda _broker, _uid=0: None
        MANAGER.developer_id_team_floor = lambda *_args, **_kwargs: None
        current_path, _manifest = MANAGER.verified_release(
            INSTALL_ROOT, selected_link, expected_uid,
            allow_legacy=allow_legacy,
        )
    finally:
        MANAGER.enforce_execution_approval_floor = enforce_floor
        MANAGER.developer_id_team_floor = developer_floor
    if floor_present or allow_migration_predecessor_anchor:
        authorization_manifest = MANAGER.read_regular(
            current_path / "authorization_ui_bundle"
        )
        if allow_migration_predecessor_anchor:
            # This is only a non-authoritative preflight for the one-time,
            # terminal-bound Development -> Developer ID migration.  The root
            # manager re-reads and binds the protected floor, exact immutable
            # predecessor release, signer team, and both manifests before it
            # mutates anything.  Permitting the exact pre-migration anchor here
            # keeps a floor-created/install-failed ceremony retryable without
            # weakening ordinary post-activation verification.
            MANAGER.verified_existing_authorization_ui_anchor_policy(
                current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                authorization_manifest,
                expected_uid,
            )
        else:
            MANAGER.verified_authorization_ui_signing_policy(
                current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
                authorization_manifest,
                expected_uid,
            )
    broker = MANAGER.read_regular(current_path / "authorization_broker")
    if MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
        raise RuntimeError("current_selector_below_execution_approval_floor")
    completed = subprocess.run(
        [str(current_path / "authorization_broker"),
         "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"
            or MANAGER.SHA256.fullmatch(identity.get("public_key_sha256", "")) is None
            or not isinstance(identity.get("generation_epoch"), int)
            or isinstance(identity.get("generation_epoch"), bool)
            or identity["generation_epoch"] < 1):
        raise RuntimeError("active_execution_approval_identity_invalid")
    return current_path


def postactivation_release_archive_plan(current_path: Path) -> dict[str, object]:
    """Build the public recovery plan without reading the root-only floor."""
    enforce_floor = MANAGER.enforce_execution_approval_floor
    try:
        MANAGER.enforce_execution_approval_floor = lambda _broker, _uid=0: None
        plan = MANAGER.release_archive_plan(INSTALL_ROOT, 0)
    finally:
        MANAGER.enforce_execution_approval_floor = enforce_floor
    if plan.get("current_release_id") != current_path.name:
        raise RuntimeError("release_archive_plan_current_changed")
    retained = [plan.get("current_release_id"), plan.get("previous_release_id")]
    for release_id in retained:
        if release_id is None:
            continue
        if not isinstance(release_id, str) or MANAGER.SHA256.fullmatch(release_id) is None:
            raise RuntimeError("release_archive_plan_retained_release_invalid")
        broker = MANAGER.read_regular(
            INSTALL_ROOT / "releases" / release_id / "authorization_broker"
        )
        if MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
            raise RuntimeError("retained_release_below_execution_approval_floor")
    return plan


def identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    parser.add_argument("--purpose")


def require_identity(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.requesting_agent or not args.requesting_session:
        parser.error(
            "--requesting-agent and --requesting-session are required so the authorization prompt "
            "can be attributed to the correct agent conversation"
        )
    if not SAFE_AGENT.fullmatch(args.requesting_agent):
        parser.error("--requesting-agent must be 1-80 printable allowlisted ASCII characters")
    if not SAFE_SESSION.fullmatch(args.requesting_session):
        parser.error("--requesting-session must be 1-128 printable allowlisted ASCII characters")


def bootstrap_binding(touchid_recovery: bool = False,
                      capacity_recovery: bool = False,
                      secure_enclave_schema: bool = False,
                      profiled_touchid_schema: bool = False,
                      touchid_bundle_v2_schema: bool = False,
                      model_profile_schema: bool = False,
                      native_stack_schema: bool = False,
                      native_vendor_developer_id_schema: bool = False,
                      authorization_icon_schema: bool = False,
                      operator_ceremony_broker_recovery: bool = False) -> BootstrapBinding:
    if capacity_recovery:
        # The monotonic execution-approval floor is intentionally root-only.
        # Capacity recovery begins as the operator, so validate the selected
        # release through the same public v2-capability and active-identity
        # checks used by post-activation schema recovery instead of trying to
        # read that protected floor directly.
        current_path = postactivation_current_release()
        release_id = current_path.name
        manager_sha256 = hashlib.sha256(MANAGER.read_regular(MANAGER_PATH)).hexdigest()
        broker_sha256 = hashlib.sha256(
            MANAGER.read_regular(current_path / "authorization_broker")
        ).hexdigest()
        hashes: dict[str, str] = {}
        previous_ui = previous_sources = ""
    elif touchid_recovery:
        values, hashes, release_id = MANAGER.touchid_ui_recovery_payload(
            MANAGER_PATH.parent.parent, INSTALL_ROOT, 0,
        )
        current_path, current_manifest = MANAGER.verified_release(
            INSTALL_ROOT, INSTALL_ROOT / "current", 0,
        )
        manager_sha256 = hashlib.sha256(MANAGER.read_regular(MANAGER_PATH)).hexdigest()
        broker_sha256 = hashlib.sha256(values["authorization_broker"]).hexdigest()
        previous_ui = current_manifest["payloads"]["authorization_ui"]
        previous_sources = current_manifest["payloads"]["authorization_ui_sources"]
    else:
        if native_vendor_developer_id_schema:
            prepare_native_host_products()
        else:
            prepare_touchid_ui()
        values, hashes, release_id = MANAGER.source_payload(MANAGER_PATH.parent.parent)
        manager_sha256 = hashlib.sha256(values["release_manager"]).hexdigest()
        broker_sha256 = hashlib.sha256(values["authorization_broker"]).hexdigest()
        previous_ui = previous_sources = ""
    schema_current_release_id = ""
    if (secure_enclave_schema or profiled_touchid_schema or touchid_bundle_v2_schema
            or model_profile_schema or native_stack_schema
            or native_vendor_developer_id_schema or authorization_icon_schema
            or operator_ceremony_broker_recovery):
        if (touchid_bundle_v2_schema or model_profile_schema or native_stack_schema
                or native_vendor_developer_id_schema
                or authorization_icon_schema
                or operator_ceremony_broker_recovery):
            if native_vendor_developer_id_schema:
                current_path = postactivation_current_release(
                    allow_legacy=True,
                    allow_migration_predecessor_anchor=True,
                )
            else:
                current_path = postactivation_current_release(
                    allow_legacy=(model_profile_schema or native_stack_schema),
                )
        else:
            current_path, _current_manifest = MANAGER.verified_release(
                INSTALL_ROOT, INSTALL_ROOT / "current", 0,
                allow_legacy=profiled_touchid_schema or model_profile_schema,
            )
        schema_current_release_id = current_path.name
    developer_id_team_id = ""
    current_authorization_manifest_sha256 = ""
    candidate_authorization_manifest_sha256 = ""
    if native_vendor_developer_id_schema:
        current_manifest_data = MANAGER.read_regular(
            current_path / "authorization_ui_bundle"
        )
        candidate_manifest_data = values["authorization_ui_bundle"]
        current_policy = MANAGER.verified_existing_authorization_ui_anchor_policy(
            current_path / MANAGER.AUTHORIZATION_UI_APP_NAME,
            current_manifest_data,
            0,
        )
        candidate_policy = MANAGER.verified_authorization_ui_signing_policy(
            MANAGER_PATH.parent.parent / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            candidate_manifest_data,
        )
        if current_policy["team_id"] != candidate_policy["team_id"]:
            raise RuntimeError("developer_id_team_mismatch")
        developer_id_team_id = candidate_policy["team_id"]
        current_authorization_manifest_sha256 = hashlib.sha256(
            current_manifest_data
        ).hexdigest()
        candidate_authorization_manifest_sha256 = hashlib.sha256(
            candidate_manifest_data
        ).hexdigest()
    installed_launcher = MANAGER.read_regular(STABLE_LAUNCHER)
    replacement_launcher = MANAGER.read_regular(MODULE_PATH)
    archive_plan = (
        postactivation_release_archive_plan(current_path) if capacity_recovery else None
    )
    return BootstrapBinding(
        release_id=release_id,
        manager_sha256=manager_sha256,
        broker_sha256=broker_sha256,
        installed_launcher_sha256=hashlib.sha256(installed_launcher).hexdigest(),
        replacement_launcher_sha256=hashlib.sha256(replacement_launcher).hexdigest(),
        touchid_ui_previous_sha256=previous_ui,
        touchid_ui_replacement_sha256=hashes["authorization_ui"] if touchid_recovery else "",
        touchid_sources_previous_sha256=previous_sources,
        touchid_sources_replacement_sha256=(
            hashes["authorization_ui_sources"] if touchid_recovery else ""
        ),
        archive_current_release_id=(
            archive_plan["current_release_id"] if archive_plan else ""
        ),
        archive_previous_release_id=(
            (archive_plan["previous_release_id"] or "none") if archive_plan else ""
        ),
        archive_plan_sha256=archive_plan["plan_sha256"] if archive_plan else "",
        archive_release_ids=tuple(archive_plan["archive_release_ids"]) if archive_plan else (),
        schema_current_release_id=schema_current_release_id,
        developer_id_team_id=developer_id_team_id,
        current_authorization_manifest_sha256=(
            current_authorization_manifest_sha256
        ),
        candidate_authorization_manifest_sha256=(
            candidate_authorization_manifest_sha256
        ),
    )


def bootstrap_notice(agent: str, session: str, binding: BootstrapBinding,
                     operation: str = "bootstrap-authorization") -> bool:
    maintenance = operation == "bootstrap-maintenance-schema"
    touchid = operation == "bootstrap-touchid-schema"
    secure_enclave = operation == "bootstrap-secure-enclave-schema"
    profiled_touchid = operation == "bootstrap-profiled-touchid-schema"
    touchid_bundle_v2 = operation == "bootstrap-touchid-bundle-v2-schema"
    model_profile = operation == "bootstrap-model-profile-schema"
    native_stack = operation == "bootstrap-native-stack-schema"
    native_vendor_developer_id = (
        operation == "bootstrap-native-vendor-developer-id-schema"
    )
    authorization_icon = operation == "bootstrap-authorization-icon-schema"
    operator_ceremony_recovery = operation == "recover-operator-ceremony-broker"
    selector_recovery = operation == "recover-release-selector"
    touchid_recovery = operation == "recover-touchid-ui"
    capacity_recovery = operation == "recover-release-capacity"
    purpose = (
        "archive inactive immutable releases while retaining active and rollback releases"
        if capacity_recovery else
        "replace the known no-window signed Touch ID UI with the reviewed corrected release"
        if touchid_recovery else
        "repair the protected release selector and install the reviewed release"
        if selector_recovery else
        "migrate the protected release to the provisioned Touch ID app-bundle schema"
        if profiled_touchid else
        "migrate the protected Touch ID bundle manifest to the signing-policy-bound v2 schema"
        if touchid_bundle_v2 else
        "migrate the protected authorization UI to the attested icon source schema"
        if authorization_icon else
        "migrate the protected release to the model-profile manager schema"
        if model_profile else
        "migrate the protected release to the native-stack manager schema"
        if native_stack else
        "enroll the existing Apple team as the permanent Developer ID floor and migrate to the complete native-vendor release"
        if native_vendor_developer_id else
        "replace the exact immutable pre-execution ceremony-broker defect"
        if operator_ceremony_recovery else
        "migrate the protected release to the Secure Enclave authorization schema"
        if secure_enclave else
        "migrate the protected release to the signed Touch ID authorization schema"
        if touchid else
        "migrate the protected release to the maintenance-coordinator schema"
        if maintenance else "install the first protected authorization broker"
    )
    message = "\n".join([
        "SecureSandbox one-time release-capacity recovery" if capacity_recovery else
        "SecureSandbox one-time Touch ID UI recovery" if touchid_recovery else
        "SecureSandbox one-time release-selector recovery" if selector_recovery else
        "SecureSandbox one-time release-schema bootstrap"
        if (maintenance or touchid or secure_enclave or profiled_touchid
            or touchid_bundle_v2 or model_profile or native_stack
            or native_vendor_developer_id or authorization_icon)
        else "SecureSandbox one-time operator-ceremony broker recovery"
        if operator_ceremony_recovery
        else "SecureSandbox one-time authorization bootstrap",
        "",
        f"Declared agent: {agent}",
        f"Declared session: {session}",
        f"Purpose: {purpose}",
        f"Operation: {operation}",
        "Resource: /usr/local/libexec/secure-sandbox-host",
        f"Expected release: {binding.release_id}",
        f"Release manager SHA-256: {binding.manager_sha256}",
        f"Authorization broker SHA-256: {binding.broker_sha256}",
        f"Installed launcher SHA-256: {binding.installed_launcher_sha256}",
        f"Replacement launcher SHA-256: {binding.replacement_launcher_sha256}",
        *([f"Exact current release: {binding.schema_current_release_id}"]
          if (secure_enclave or profiled_touchid or touchid_bundle_v2 or model_profile
              or native_stack or native_vendor_developer_id
              or authorization_icon
              or operator_ceremony_recovery) else []),
        *([
            "Permitted payload changes: authorization_ui, authorization_ui_sources",
            f"Authorization UI: {binding.touchid_ui_previous_sha256} -> {binding.touchid_ui_replacement_sha256}",
            f"Authorization UI sources: {binding.touchid_sources_previous_sha256} -> {binding.touchid_sources_replacement_sha256}",
            "All other protected payload hashes remain identical to the installed release.",
        ] if touchid_recovery else []),
        *([
            f"Expected Apple Developer Team: {binding.developer_id_team_id}",
            f"Current authorization manifest SHA-256: {binding.current_authorization_manifest_sha256}",
            f"Candidate authorization manifest SHA-256: {binding.candidate_authorization_manifest_sha256}",
            "The current immutable Apple Development-signed release is the only bootstrap anchor.",
            "The candidate must carry a valid Developer ID Application signature for the same team.",
            "This one-time operation creates a non-replaceable team floor before the candidate becomes ordinary update authority.",
        ] if native_vendor_developer_id else []),
        *([
            f"Current release retained: {binding.archive_current_release_id}",
            f"Rollback release retained: {binding.archive_previous_release_id}",
            f"Inactive releases archived: {len(binding.archive_release_ids)}",
            f"Archive plan SHA-256: {binding.archive_plan_sha256}",
            "Archive targets: " + ", ".join(binding.archive_release_ids),
            "No release is deleted; inactive releases move to the protected release archive.",
        ] if capacity_recovery else []),
        "",
        "Continue only if this matches the agent conversation you intend to authorize.",
    ])
    print(message, file=sys.stderr, flush=True)
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", BOOTSTRAP_NOTICE_SCRIPT, "--", message],
            check=False, stdin=subprocess.DEVNULL, timeout=90,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def expected_source_release_id() -> str:
    prepare_native_host_products()
    _values, _hashes, release_id = MANAGER.source_payload(MANAGER_PATH.parent.parent)
    return release_id


def previous_release_id() -> str:
    path, _manifest = MANAGER.verified_release(INSTALL_ROOT, INSTALL_ROOT / "previous", 0)
    return path.name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("deploy", "rollback", "migrate-launcher", "bootstrap-authorization",
                            "bootstrap-maintenance-schema", "bootstrap-touchid-schema",
                            "bootstrap-secure-enclave-schema", "bootstrap-profiled-touchid-schema",
                            "bootstrap-touchid-bundle-v2-schema",
                            "bootstrap-model-profile-schema",
                            "bootstrap-native-stack-schema",
                            "bootstrap-native-vendor-developer-id-schema",
                            "bootstrap-authorization-icon-schema",
                            "recover-operator-ceremony-broker",
                            "recover-touchid-ui", "recover-release-capacity")
    )
    parser.add_argument("identity", nargs="?")
    identity_arguments(parser)
    args = parser.parse_args()
    if args.command in {"deploy", "bootstrap-authorization", "bootstrap-maintenance-schema",
                        "bootstrap-touchid-schema", "bootstrap-secure-enclave-schema",
                        "bootstrap-profiled-touchid-schema",
                        "bootstrap-touchid-bundle-v2-schema",
                        "bootstrap-model-profile-schema",
                        "bootstrap-native-stack-schema",
                        "bootstrap-native-vendor-developer-id-schema",
                        "bootstrap-authorization-icon-schema",
                        "recover-operator-ceremony-broker",
                        "recover-touchid-ui",
                        "recover-release-capacity"} and args.identity:
        parser.error("deploy does not accept a release ID")
    if args.command == "migrate-launcher" and not args.identity:
        parser.error("migrate-launcher requires the expected installed launcher SHA-256")
    require_identity(parser, args)
    state_root = LAUNCHER.STATE_ROOT
    lock = LAUNCHER.acquire_lock(state_root, timeout=10.0)
    try:
        live = MANAGER.active_markers(state_root)
        if live:
            print("active_controller_invocations:" + ",".join(live), file=sys.stderr)
            return 1
        if args.command == "bootstrap-authorization":
            if BROKER_PATH.is_file() and not BROKER_PATH.is_symlink():
                print("authorization_broker_already_deployed", file=sys.stderr)
                return 1
            binding = bootstrap_binding()
            if not bootstrap_notice(args.requesting_agent, args.requesting_session, binding):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time bootstrap.", file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-authorization",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-maintenance-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding()
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-maintenance-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time schema migration.", file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-maintenance-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-touchid-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding()
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-touchid-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Touch ID schema migration.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "bootstrap-touchid-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-secure-enclave-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(secure_enclave_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-secure-enclave-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Secure Enclave schema migration.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-secure-enclave-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-profiled-touchid-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(profiled_touchid_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-profiled-touchid-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time provisioned UI schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-profiled-touchid-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-touchid-bundle-v2-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(touchid_bundle_v2_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-touchid-bundle-v2-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time Touch ID bundle v2 schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-touchid-bundle-v2-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-model-profile-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(model_profile_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-model-profile-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time model-profile schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-model-profile-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-stack-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(native_stack_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-stack-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time native-stack schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-stack-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "bootstrap-native-vendor-developer-id-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(
                native_vendor_developer_id_schema=True
            )
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-native-vendor-developer-id-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time Developer ID team-floor and native-vendor schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-native-vendor-developer-id-schema",
                "--state-root", str(state_root),
                "--expected-source-release-id", binding.release_id,
                "--expected-current-release-id",
                binding.schema_current_release_id,
                "--expected-launcher-sha256",
                binding.installed_launcher_sha256,
                "--expected-replacement-sha256",
                binding.replacement_launcher_sha256,
                "--expected-developer-id-team-id",
                binding.developer_id_team_id,
                "--expected-current-authorization-manifest-sha256",
                binding.current_authorization_manifest_sha256,
                "--expected-candidate-authorization-manifest-sha256",
                binding.candidate_authorization_manifest_sha256,
                "--json",
            ], check=False).returncode
        if args.command == "bootstrap-authorization-icon-schema":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(authorization_icon_schema=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "bootstrap-authorization-icon-schema",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time authorization icon schema migration.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "bootstrap-authorization-icon-schema",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-operator-ceremony-broker":
            binding = bootstrap_binding(operator_ceremony_broker_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-operator-ceremony-broker",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time operator-ceremony broker recovery.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256,
                "recover-operator-ceremony-broker",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-current-release-id",
                binding.schema_current_release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-touchid-ui":
            if not BROKER_PATH.is_file():
                print("protected_authorization_broker_unavailable", file=sys.stderr)
                return 1
            binding = bootstrap_binding(touchid_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-touchid-ui",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print("The next password request is the terminal-bound one-time Touch ID UI recovery.",
                  file=sys.stderr)
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "recover-touchid-ui",
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--expected-launcher-sha256",
                binding.installed_launcher_sha256, "--expected-replacement-sha256",
                binding.replacement_launcher_sha256, "--json",
            ], check=False).returncode
        if args.command == "recover-release-capacity":
            binding = bootstrap_binding(capacity_recovery=True)
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-release-capacity",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time release-capacity recovery.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "archive-inactive-releases",
                "--state-root", str(state_root),
                "--expected-current-release-id", binding.archive_current_release_id,
                "--expected-previous-release-id", binding.archive_previous_release_id,
                "--expected-plan-sha256", binding.archive_plan_sha256,
                "--json",
            ], check=False).returncode
        # A 0700 selector created by an older manager may still resolve on macOS,
        # but routing deployment through that broker would run the old manager
        # and reproduce the defect. Repair this narrowly validated state first.
        if args.command == "deploy" and selector_recovery_required():
            binding = bootstrap_binding()
            if not bootstrap_notice(
                args.requesting_agent, args.requesting_session, binding,
                "recover-release-selector",
            ):
                print("operator_cancelled", file=sys.stderr)
                return 1
            print(
                "The next password request is the terminal-bound one-time release-selector recovery.",
                file=sys.stderr,
            )
            return subprocess.run([
                "sudo", "/usr/bin/python3", "-I", "-c", BOOTSTRAP_LOADER,
                str(MANAGER_PATH), binding.manager_sha256, "install",
                "--repo", str(MANAGER_PATH.parent.parent),
                "--state-root", str(state_root), "--expected-source-release-id",
                binding.release_id, "--json",
            ], check=False).returncode
        if not protected_broker_available():
            print(
                "protected_authorization_broker_unavailable; run bootstrap-authorization once",
                file=sys.stderr,
            )
            return 1
        operation = {
            "deploy": "host-controller-install",
            "rollback": "host-controller-rollback",
            "migrate-launcher": "host-controller-migrate-launcher",
        }[args.command]
        parameters = {"repo": str(MANAGER_PATH.parent.parent), "state_root": str(state_root)}
        if args.command == "deploy":
            parameters["expected_source_release_id"] = expected_source_release_id()
        if args.command == "rollback":
            parameters["release_id"] = args.identity or previous_release_id()
        if args.command == "migrate-launcher":
            replacement = MANAGER.read_regular(MODULE_PATH)
            parameters.update({
                "expected_installed_sha256": args.identity,
                "expected_replacement_sha256": hashlib.sha256(replacement).hexdigest(),
            })
        purpose = args.purpose or {
            "deploy": "Publish the reviewed host-controller release",
            "rollback": "Roll back the host-controller release",
            "migrate-launcher": "Migrate the stable host-controller launcher",
        }[args.command]
        command = [
            str(BROKER_PATH), "request", "--agent", args.requesting_agent,
            "--session", args.requesting_session, "--purpose", purpose,
            "--resource", {
                "deploy": "/usr/local/libexec/secure-sandbox-host",
                "rollback": "/usr/local/libexec/secure-sandbox-host",
                "migrate-launcher": "/usr/local/bin/secure-sandbox-claude",
            }[args.command],
            "--operation", operation, "--parameters-json",
            json.dumps(parameters, separators=(",", ":"), sort_keys=True),
        ]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True,
        )
        if completed.returncode != 0:
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)
            print(
                f"protected_authorization_failed:{completed.returncode}",
                file=sys.stderr,
            )
            return completed.returncode
        if args.command != "deploy":
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)
            return 0
        try:
            pending = json.loads(completed.stdout)
        except json.JSONDecodeError:
            print("host_install_activation_result_invalid", file=sys.stderr)
            return 1
        if (not isinstance(pending, dict)
                or pending.get("schema") != MANAGER.SCHEMA
                or pending.get("status") != "activation_pending"):
            print("host_install_activation_result_invalid", file=sys.stderr)
            return 1
        try:
            terminal = wait_for_install_terminal(pending)
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
            return 1
        if terminal["status"] != "deployed_verified":
            print(
                "host_install_activation_failed:" + str(terminal["status"]),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(terminal, separators=(",", ":"), sort_keys=True))
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        return 0
    finally:
        LAUNCHER.release_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
