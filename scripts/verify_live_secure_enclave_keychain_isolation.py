#!/usr/bin/env python3
"""Prove an ad-hoc helper cannot query the protected Secure Enclave key."""

from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import tempfile
from pathlib import Path


DEFAULT_RELEASE = Path("/usr/local/libexec/secure-sandbox-host/current")
GENERATION = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SOURCE = r'''
import Foundation
import Security

guard CommandLine.arguments.count == 3 else { exit(64) }
let tag = CommandLine.arguments[1]
let accessGroup = CommandLine.arguments[2]
let query: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecAttrApplicationTag as String: Data(tag.utf8),
    kSecAttrAccessGroup as String: accessGroup,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecUseDataProtectionKeychain as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnRef as String: true,
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
exit(status == errSecMissingEntitlement && result == nil ? 0 : 1)
'''


class ProbeError(RuntimeError):
    pass


def signing_identity(release: Path = DEFAULT_RELEASE) -> tuple[str, str]:
    try:
        manifest = json.loads((release / "authorization_ui_bundle").read_text("utf-8"))
        policy = manifest.get("signing_policy")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError("authorization_ui_signing_policy_invalid") from error
    schema = manifest.get("schema") if isinstance(manifest, dict) else None
    if (schema != "secure-sandbox-touchid-ui-bundle-v2"
            or set(manifest) != {"bundle", "files", "schema", "signing_policy"}
            or manifest.get("bundle") != "SecureSandboxAuthorizationUI.app"
            or not isinstance(manifest.get("files"), dict)
            or not isinstance(policy, dict)
            or set(policy) != {
                "access_group", "application_identifier", "bundle_id", "team_id",
            }):
        raise ProbeError("authorization_ui_signing_policy_invalid")
    team_id = policy.get("team_id")
    access_group = policy.get("access_group")
    bundle_id = policy.get("bundle_id")
    application_identifier = policy.get("application_identifier")
    if (not isinstance(team_id, str)
            or re.fullmatch(r"[A-Z0-9]{10}", team_id) is None
            or bundle_id != "org.zebeth.SecureSandbox.AuthorizationUI"
            or application_identifier != team_id + "." + bundle_id
            or access_group != application_identifier):
        raise ProbeError("authorization_ui_signing_policy_invalid")
    if (not isinstance(team_id, str) or re.fullmatch(r"[A-Z0-9]{10}", team_id) is None
            or not isinstance(access_group, str)
            or not access_group.startswith(team_id + ".")):
        raise ProbeError("authorization_ui_signing_policy_invalid")
    return team_id, access_group


def probe(generation_id: str, team_id: str | None = None,
          access_group: str | None = None) -> dict[str, object]:
    if GENERATION.fullmatch(generation_id) is None:
        raise ProbeError("generation_id_invalid")
    if team_id is None or access_group is None:
        team_id, access_group = signing_identity()
    application_tag = "org.zebeth.SecureSandbox.execution-approval." + generation_id
    environment = {
        "PATH":"/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG":"C.UTF-8", "LC_ALL":"C.UTF-8", "HOME":str(Path.home()),
    }
    with tempfile.TemporaryDirectory(prefix="secure-enclave-keychain-negative-") as name:
        root = Path(name)
        source = root / "DifferentSignerProbe.swift"
        binary = root / "DifferentSignerProbe"
        entitlements_path = root / "forged-entitlements.plist"
        source.write_text(SOURCE, encoding="utf-8")
        source.chmod(0o600)
        subprocess.run(
            ["/usr/bin/swiftc", str(source), "-o", str(binary)], check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60, env=environment,
        )
        signature = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(binary)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=10, env=environment,
        )
        details = signature.stdout + signature.stderr
        if (signature.returncode != 0 or f"TeamIdentifier={team_id}" in details
                or "Signature=adhoc" not in details):
            raise ProbeError("different_signer_identity_invalid")
        unentitled = subprocess.run(
            [str(binary), application_tag, access_group], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=10, env=environment,
        )
        if (unentitled.returncode != 0
                or unentitled.stdout.strip() != "-34018"
                or unentitled.stderr):
            raise ProbeError("unentitled_keychain_lookup_not_rejected")
        entitlements_path.write_bytes(plistlib.dumps({
            "keychain-access-groups":[access_group],
        }, fmt=plistlib.FMT_XML, sort_keys=True))
        entitlements_path.chmod(0o600)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", "--entitlements",
             str(entitlements_path), str(binary)], check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15, env=environment,
        )
        forged_signature = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(binary)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=10, env=environment,
        )
        forged_details = forged_signature.stdout + forged_signature.stderr
        if (forged_signature.returncode != 0
                or f"TeamIdentifier={team_id}" in forged_details
                or "Signature=adhoc" not in forged_details):
            raise ProbeError("forged_signer_identity_invalid")
        entitlement_result = subprocess.run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, env=environment,
        )
        try:
            entitlements = plistlib.loads(entitlement_result.stdout)
        except plistlib.InvalidFileException as error:
            raise ProbeError("forged_entitlement_unavailable") from error
        if (entitlement_result.returncode != 0 or entitlements != {
                "keychain-access-groups":[access_group]
            }):
            raise ProbeError("forged_entitlement_unavailable")
        forged = subprocess.run(
            [str(binary), application_tag, access_group], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=10, env=environment,
        )
    if (forged.returncode != -9 or forged.stdout or forged.stderr):
        raise ProbeError("forged_entitlement_launch_not_rejected")
    return {
        "schema":"secure-sandbox-live-keychain-isolation-v1",
        "status":"verified", "generation_id":generation_id,
        "application_tag":application_tag, "access_group":access_group,
        "helper_signature":"adhoc", "unentitled_lookup_status":-34018,
        "forged_access_group_present":True, "forged_launch_signal":9,
        "lookup_status":-34018,
        "lookup_result_absent":True, "authentication_ui":"fail",
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--generation-id", required=True)
    args = parser.parse_args()
    try:
        result = probe(args.generation_id)
    except (ProbeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({
            "schema":"secure-sandbox-live-keychain-isolation-v1",
            "status":"rejected", "error":str(error),
        }, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
