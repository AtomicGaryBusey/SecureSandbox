#!/bin/bash
set -euo pipefail

role="${1:-}"
case "$role" in
  research)
    config=/etc/secure-sandbox/execution-broker.json
    [[ -f "$config" && ! -L "$config" \
        && "$(stat -c '%U:%G:%a' "$config")" == root:execution-broker:640 ]] \
      || { echo execution_runtime_config_untrusted >&2; exit 1; }
    jq -e '
      type == "object"
      and (keys | sort) == ["approval","runtime_image_id","schema","token"]
      and .schema == "secure-sandbox-execution-broker-v3"
      and (.token | type == "string" and test("^[A-Za-z0-9]{64}$"))
      and (.runtime_image_id | type == "string"
           and test("^sha256:[0-9a-f]{64}$"))
      and (.approval | type == "object")
      and .approval.mode == "active-v2"
      and .approval.minimum_protocol == 2
      and (.approval.generation_id | type == "string")
      and (.approval.generation_epoch | type == "number")
      and .approval.generation_epoch >= .approval.minimum_epoch
      and .approval.algorithm == "ecdsa-p256-sha256-x962-low-s"
      and (.approval.public_key_sha256 | test("^[0-9a-f]{64}$"))
    ' "$config" >/dev/null || { echo execution_runtime_config_invalid >&2; exit 1; }
    jq -cS '
      {schema:"secure-sandbox-execution-runtime-identity-v1",role:"research",
       runtime_image_id:.runtime_image_id,generation_id:.approval.generation_id,
       generation_epoch:.approval.generation_epoch,
       public_key_sha256:.approval.public_key_sha256}
    ' "$config"
    ;;
  target)
    config=/home/labadmin/.config/secure-sandbox-execution.json
    [[ -f "$config" && ! -L "$config" \
        && "$(stat -c '%U:%G:%a' "$config")" == labadmin:labadmin:600 ]] \
      || { echo execution_runtime_config_untrusted >&2; exit 1; }
    jq -e '
      type == "object"
      and (keys | sort) == ["image_id","schema","token"]
      and .schema == "secure-sandbox-execution-target-v1"
      and (.token | type == "string" and test("^[A-Za-z0-9]{64}$"))
      and (.image_id | type == "string" and test("^sha256:[0-9a-f]{64}$"))
    ' "$config" >/dev/null || { echo execution_runtime_config_invalid >&2; exit 1; }
    jq -cS '
      {schema:"secure-sandbox-execution-runtime-identity-v1",role:"target",
       runtime_image_id:.image_id}
    ' "$config"
    ;;
  *)
    echo execution_runtime_role_invalid >&2
    exit 2
    ;;
esac
