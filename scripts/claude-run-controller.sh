#!/bin/bash
set -euo pipefail

release_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
ssh_config="$release_dir/ssh_config"
control_client="$release_dir/control_client"
active_marker="${SECURE_SANDBOX_ACTIVE_MARKER:-}"
release_id="${SECURE_SANDBOX_RELEASE_ID:-}"
state_root="${SECURE_SANDBOX_STATE_ROOT:-}"
run_interrupted=false
session_failed=false
approval_relay_pid=""
lifecycle_armed=false
session_pid=""
gateway_issue_pending=false
watchdog_arm_pending=false

control() {
  local host="$1"
  shift
  "$control_client" client --ssh-config "$ssh_config" "$host" run "$@"
}

control_pipe() {
  local host="$1"
  shift
  "$control_client" client --ssh-config "$ssh_config" "$host" pipe "$@"
}

cleanup_marker() {
  if [[ -n "$state_root" && "$state_root" == /* && -n "$active_marker" \
      && "$active_marker" == "$state_root/active/"* ]]; then
    /bin/rm -f -- "$active_marker"
  fi
}
trap cleanup_marker EXIT

expected_marker_root="$state_root/active/"
[[ -n "$state_root" && "$state_root" == /* && ! -L "$state_root" ]] || {
  echo "controller_state_directory_invalid" >&2
  exit 1
}
[[ -n "$active_marker" && "$active_marker" == "$expected_marker_root"* && -f "$active_marker" && ! -L "$active_marker" ]] || {
  echo "controller_active_marker_missing" >&2
  exit 1
}
[[ "$release_id" =~ ^[0-9a-f]{64}$ ]] || {
  echo "controller_release_id_invalid" >&2
  exit 1
}
[[ "$(/usr/bin/jq -er .pid "$active_marker")" == "$$" && "$(/usr/bin/jq -er .release_id "$active_marker")" == "$release_id" ]] || {
  echo "controller_active_marker_invalid" >&2
  exit 1
}

interrupt_run() {
  local exit_status="$1"
  run_interrupted=true
  if [[ -n "$session_pid" ]]; then
    /bin/kill -HUP "$session_pid" 2>/dev/null || true
  fi
  exit "$exit_status"
}
trap 'interrupt_run 129' HUP
trap 'interrupt_run 130' INT
trap 'interrupt_run 143' TERM

claude_args=()
resume_requested=false
lease_profile=standard
lease_profile_given=false
source_id=""
acceptance_run_id="${SECURE_SANDBOX_ACCEPTANCE_RUN_ID:-}"
acceptance_session_id="${SECURE_SANDBOX_ACCEPTANCE_SESSION_ID:-}"
if [[ -n "$acceptance_run_id" || -n "$acceptance_session_id" ]]; then
  [[ "$acceptance_run_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ \
      && "$acceptance_session_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || { echo "Invalid bounded acceptance context." >&2; exit 2; }
fi
usage_error() { echo "Usage: secure-sandbox-claude [--lease-profile short|standard|extended] [--resume SESSION_UUID | --source SOURCE_UUID]" >&2; exit 2; }
while (( $# )); do
  (( $# >= 2 )) || usage_error
  case "$1" in
    --resume)
      [[ "$resume_requested" == false && -z "$source_id" && "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || usage_error
      claude_args=(--resume "$2"); resume_requested=true;;
    --source)
      [[ -z "$source_id" && "$resume_requested" == false && "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || usage_error
      source_id="$2";;
    --lease-profile)
      [[ "$lease_profile_given" == false ]] || usage_error
      lease_profile="$2"; lease_profile_given=true;;
    *) usage_error;;
  esac
  shift 2
done
case "$lease_profile" in short|standard|extended) ;; *) echo "Unknown lease profile: $lease_profile" >&2; exit 2;; esac

read_epoch() {
  local host="$1"
  local value
  value="$(/usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$host" 'date -u +%s')"
  [[ "$value" =~ ^[0-9]{10,}$ ]] || { echo "Invalid UTC epoch returned by $host." >&2; return 1; }
  printf '%s\n' "$value"
}

parse_lease_response() {
  local payload="$1"
  local now maximum
  now="$(/bin/date -u +%s)"
  maximum=$((now + 86400))
  /usr/bin/jq -er --argjson minimum "$((now - 60))" --argjson maximum "$maximum" '
    if type == "object"
       and (.lease_id | type) == "string"
       and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
       and (.expires_at | type) == "number"
       and (.expires_at | floor == .)
       and .expires_at >= $minimum
       and .expires_at <= $maximum
    then [.lease_id, (.expires_at | tostring)] | @tsv
    else error("invalid lease response")
    end
  ' <<<"$payload"
}

canonicalize_issued_lease() {
  local payload="$1" expected_run_id="$2" expected_session_id="$3" expected_profile="$4"
  local model_profile="$5" session_policy="$6" harness_binding="$7"
  /usr/bin/python3 -I - "$payload" "$expected_run_id" "$expected_session_id" \
    "$expected_profile" "$model_profile" "$session_policy" "$harness_binding" <<'PY'
import hashlib, hmac, json, re, sys

lease = json.loads(sys.argv[1])
run_id, session_id, profile = sys.argv[2:5]
model_profile, policy, expected_harness = map(json.loads, sys.argv[5:8])
sha = re.compile(r"[0-9a-f]{64}")
name = re.compile(r"[a-z][a-z0-9-]{0,62}")
profile_name = re.compile(r"[a-z][a-z0-9-]{0,47}")
model_id = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+\-\[\]]{0,191}")
uuid4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

def canonical(value):
    return (json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")

def integer(value, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def validate_harness(value):
    body_fields = (
        "harness_id", "harness_generation_id", "harness_manifest_sha256",
        "harness_executable_sha256", "harness_inventory_sha256",
        "harness_adapter_id", "harness_adapter_sha256",
    )
    if (not isinstance(value, dict)
            or set(value) != {"schema", *body_fields, "binding_sha256"}
            or value.get("schema") != "secure-sandbox-harness-runtime-binding-v1"
            or name.fullmatch(str(value.get("harness_id"))) is None
            or name.fullmatch(str(value.get("harness_adapter_id"))) is None
            or any(sha.fullmatch(str(value.get(field))) is None
                   for field in body_fields if field not in {"harness_id", "harness_adapter_id"})):
        raise ValueError("harness")
    body = {field:value[field] for field in body_fields}
    if not hmac.compare_digest(str(value.get("binding_sha256")), digest(body)):
        raise ValueError("harness_digest")
    return value

def validate_context(value):
    fields = (
        "session_id", "source_id", "source_manifest_sha256", "persona_sha256",
        "tool_catalog_sha256", "extension_set_sha256",
    )
    if (not isinstance(value, dict)
            or set(value) != {"schema", *fields, "binding_sha256"}
            or value.get("schema") != "secure-sandbox-session-context-binding-v1"
            or uuid4.fullmatch(str(value.get("session_id"))) is None
            or (value.get("source_id") is None) != (value.get("source_manifest_sha256") is None)
            or (value.get("source_id") is not None
                and (uuid4.fullmatch(str(value["source_id"])) is None
                     or sha.fullmatch(str(value["source_manifest_sha256"])) is None))
            or any(sha.fullmatch(str(value.get(field))) is None for field in (
                "persona_sha256", "tool_catalog_sha256", "extension_set_sha256"))):
        raise ValueError("context")
    body = {field:value[field] for field in fields}
    if not hmac.compare_digest(str(value.get("binding_sha256")), digest(body)):
        raise ValueError("context_digest")
    return value

def validate_model_stack(value):
    if (not isinstance(value, dict)
            or set(value) != {"schema", "mode", "authority", "binding_sha256"}
            or value.get("schema") != "secure-sandbox-model-stack-runtime-binding-v1"
            or value.get("mode") != "brokered-model-profile"):
        raise ValueError("model_stack")
    brokered = value.get("authority")
    fields = ("adapter", "model", "profile_id", "profile_sha256", "provider_mode", "vendor_id")
    if (not isinstance(brokered, dict)
            or set(brokered) != {"schema", *fields, "binding_sha256"}
            or brokered.get("schema") != "secure-sandbox-brokered-model-runtime-binding-v1"
            or brokered.get("adapter") not in {
                "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
            or not isinstance(brokered.get("model"), str)
            or model_id.fullmatch(brokered["model"]) is None
            or profile_name.fullmatch(str(brokered.get("profile_id"))) is None
            or profile_name.fullmatch(str(brokered.get("vendor_id"))) is None
            or sha.fullmatch(str(brokered.get("profile_sha256"))) is None
            or brokered.get("provider_mode") not in {"mock", "production"}):
        raise ValueError("brokered")
    brokered_body = {field:brokered[field] for field in fields}
    if not hmac.compare_digest(str(brokered.get("binding_sha256")), digest(brokered_body)):
        raise ValueError("brokered_digest")
    body = {"authority":brokered, "mode":value["mode"]}
    if not hmac.compare_digest(str(value.get("binding_sha256")), digest(body)):
        raise ValueError("model_stack_digest")
    return value

def validate_authority(value):
    if (not isinstance(value, dict)
            or set(value) != {"schema", "model_stack_binding", "session_context_binding",
                              "harness_binding", "binding_sha256"}
            or value.get("schema") != "secure-sandbox-runtime-authority-v1"):
        raise ValueError("authority")
    model = validate_model_stack(value["model_stack_binding"])
    context = validate_context(value["session_context_binding"])
    harness = validate_harness(value["harness_binding"])
    body = {"model_stack_binding":model, "session_context_binding":context,
            "harness_binding":harness}
    if not hmac.compare_digest(str(value.get("binding_sha256")), digest(body)):
        raise ValueError("authority_digest")
    return value

lease_fields = {
    "schema", "lease_id", "run_id", "profile", "issued_at", "expires_at",
    "maximum_expires_at", "runtime_authority", "brokered_transport", "limits",
    "pricing", "renewals",
}
if (not isinstance(lease, dict) or set(lease) != lease_fields
        or lease.get("schema") != "secure-sandbox-run-lease-v3"
        or lease.get("run_id") != run_id or lease.get("profile") != profile
        or uuid4.fullmatch(str(lease.get("lease_id"))) is None
        or any(not integer(lease.get(field)) for field in (
            "issued_at", "expires_at", "maximum_expires_at", "renewals"))
        or not lease["issued_at"] <= lease["expires_at"] <= lease["maximum_expires_at"]):
    raise SystemExit("invalid issued lease")
authority = validate_authority(lease.get("runtime_authority"))
context = authority["session_context_binding"]
expected_policy_fields = {
    "schema", "source_id", "source_manifest_sha256", "persona_sha256",
    "tool_catalog_sha256", "extension_set_sha256",
}
if (not isinstance(policy, dict) or set(policy) != expected_policy_fields
        or policy.get("schema") != "secure-sandbox-session-policy-runtime-v1"):
    raise SystemExit("invalid Research session policy")
expected_context = {field:policy[field] for field in expected_policy_fields if field != "schema"}
expected_context["session_id"] = session_id
if (context["session_id"] != session_id
        or any(context.get(field) != value for field, value in expected_context.items())):
    raise SystemExit("Gateway lease session context mismatch")
if authority["harness_binding"] != validate_harness(expected_harness):
    raise SystemExit("Gateway lease harness binding mismatch")
brokered = authority["model_stack_binding"]["authority"]
expected_brokered = {
    "adapter": model_profile.get("adapter"), "model": model_profile.get("model"),
    "profile_id": model_profile.get("profile_id"),
    "profile_sha256": model_profile.get("profile_sha256"),
    "provider_mode": model_profile.get("mode"), "vendor_id": model_profile.get("vendor_id"),
}
if any(brokered.get(field) != value for field, value in expected_brokered.items()):
    raise SystemExit("Gateway lease model profile mismatch")
transport = lease.get("brokered_transport")
if (not isinstance(transport, dict)
        or set(transport) != {"schema", "relay_sha256", "policy_sha256"}
        or transport.get("schema") != "secure-sandbox-brokered-run-transport-v1"
        or any(sha.fullmatch(str(transport.get(field))) is None
               for field in ("relay_sha256", "policy_sha256"))):
    raise SystemExit("invalid Gateway brokered transport")
limit_fields = {"max_requests", "max_input_tokens", "max_output_tokens", "max_cost_microusd"}
price_fields = {"input_microusd_per_million_tokens", "output_microusd_per_million_tokens"}
if (not isinstance(lease.get("limits"), dict) or set(lease["limits"]) != limit_fields
        or any(not integer(lease["limits"].get(field), 1) for field in limit_fields)
        or not isinstance(lease.get("pricing"), dict) or set(lease["pricing"]) != price_fields
        or any(not integer(lease["pricing"].get(field), 1) for field in price_fields)):
    raise SystemExit("invalid Gateway lease bounds")
print(json.dumps(lease, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
PY
}

canonicalize_gateway_active_status() {
  local payload="$1" expected_run_id="$2" expected_session_id="$3" expected_profile="$4"
  local model_profile="$5" session_policy="$6" harness_binding="$7" lease
  lease="$(/usr/bin/jq -ceS --arg run_id "$expected_run_id" '
    def nonnegative_integer: type == "number" and floor == . and . >= 0;
    if type == "object" and keys == ["counters","lease","summary"]
       and .summary == null and (.lease | type) == "object"
       and (.counters | type) == "object"
       and (.counters | keys) == ["cost_microusd","input_tokens","lease_id",
            "output_tokens","requests","reservations","run_id","schema",
            "settled_reservations","updated_at"]
       and .counters.schema == "secure-sandbox-run-lease-counter-v1"
       and .counters.run_id == $run_id
       and .counters.lease_id == .lease.lease_id
       and all(.counters.requests,.counters.input_tokens,.counters.output_tokens,
               .counters.cost_microusd,.counters.updated_at; nonnegative_integer)
       and (.counters.reservations | type) == "object"
       and (.counters.settled_reservations | type) == "array"
    then .lease else error("invalid active Gateway lease status") end
  ' <<<"$payload")" || return 1
  canonicalize_issued_lease "$lease" "$expected_run_id" "$expected_session_id" \
    "$expected_profile" "$model_profile" "$session_policy" "$harness_binding"
}

canonicalize_gateway_finalized_status() {
  local payload="$1" expected_run_id="$2" expected_lease_id="$3"
  local expected_reason="$4" issued_lease="$5" summary
  summary="$(/usr/bin/jq -ceS '
    if type == "object" and keys == ["counters","lease","summary"]
       and (.summary | type) == "object"
       and .lease == .summary.lease
       and .counters == .summary.final_counters
    then .summary else error("invalid finalized Gateway lease status") end
  ' <<<"$payload")" || return 1
  canonicalize_gateway_summary "$summary" "$expected_run_id" "$expected_lease_id" \
    "$expected_reason" "$issued_lease"
}

canonicalize_gateway_resolved_status() {
  local payload="$1" expected_run_id="$2" expected_session_id="$3" expected_profile="$4"
  local model_profile="$5" session_policy="$6" harness_binding="$7"
  local lease_raw lease lease_id reason
  lease_raw="$(/usr/bin/jq -ceS '
    if type == "object" and keys == ["counters","lease","summary"]
       and (.summary | type) == "object" and .lease == .summary.lease
       and .counters == .summary.final_counters
    then .lease else error("invalid resolved Gateway lease status") end
  ' <<<"$payload")" || return 1
  lease="$(canonicalize_issued_lease "$lease_raw" "$expected_run_id" \
    "$expected_session_id" "$expected_profile" "$model_profile" \
    "$session_policy" "$harness_binding")" || return 1
  lease_id="$(/usr/bin/jq -er '.lease_id' <<<"$lease")" || return 1
  reason="$(/usr/bin/jq -er '
    .summary.reason
    | select(. == "completed" or . == "expired" or . == "operator_closed"
             or . == "launch_failed" or . == "session_failed")
  ' <<<"$payload")" || return 1
  canonicalize_gateway_finalized_status "$payload" "$expected_run_id" "$lease_id" \
    "$reason" "$lease"
}

canonicalize_research_lease() {
  /usr/bin/python3 -I - "$1" "$2" <<'PY'
import hashlib, json, sys
research, gateway = map(json.loads, sys.argv[1:3])
def canonical(value):
    return (json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
fields = {"schema", "run_id", "lease_id", "expires_at", "maximum_expires_at",
          "runtime_authority", "gateway_lease", "gateway_lease_sha256"}
if (not isinstance(research, dict) or set(research) != fields
        or research.get("schema") != "secure-sandbox-research-run-lease-v3"
        or research.get("run_id") != gateway.get("run_id")
        or research.get("lease_id") != gateway.get("lease_id")
        or research.get("expires_at") != gateway.get("expires_at")
        or research.get("maximum_expires_at") != gateway.get("maximum_expires_at")
        or research.get("runtime_authority") != gateway.get("runtime_authority")
        or research.get("gateway_lease") != gateway
        or research.get("gateway_lease_sha256") != hashlib.sha256(canonical(gateway)).hexdigest()):
    raise SystemExit(1)
print(json.dumps(research, allow_nan=False, ensure_ascii=True,
                 separators=(",", ":"), sort_keys=True))
PY
}

canonicalize_watchdog_status() {
  /usr/bin/python3 -I - "$1" "$2" <<'PY'
import hashlib, json, re, sys
state, gateway = map(json.loads, sys.argv[1:3])
def canonical(value):
    return (json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
authority = gateway.get("runtime_authority")
context = authority.get("session_context_binding") if isinstance(authority, dict) else None
phase = state.get("phase") if isinstance(state, dict) else None
if (not isinstance(state, dict)
        or state.get("schema") != "secure-sandbox-run-lifecycle-v3"
        or phase not in {"preparing", "active", "closing", "local_closed", "failure_latched"}
        or state.get("run_id") != gateway.get("run_id")
        or state.get("lease_id") != gateway.get("lease_id")
        or not isinstance(context, dict) or state.get("session_id") != context.get("session_id")
        or state.get("expires_at") != gateway.get("expires_at")
        or state.get("unit") != "secure-sandbox-run-" + str(gateway.get("run_id")) + ".scope"
        or state.get("runtime_authority_sha256") != authority.get("binding_sha256")
        or state.get("gateway_lease_sha256") != hashlib.sha256(canonical(gateway)).hexdigest()):
    raise SystemExit(1)
print(phase)
PY
}

research_status_proves_absence() {
  /usr/bin/python3 -I - "$1" <<'PY'
import json, re, sys
lines = [line for line in sys.argv[1].splitlines() if line]
uuid4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
missing = "FileNotFoundError: [Errno 2] No such file or directory: '/var/lib/secure-sandbox/run-lifecycle/active.json'"
if len(lines) < 2 or lines[-2] != missing:
    raise SystemExit(1)
try:
    client = json.loads(lines[-1])
except json.JSONDecodeError:
    raise SystemExit(1)
if (not isinstance(client, dict)
        or set(client) != {"request_id", "schema", "status"}
        or client.get("schema") != "secure-sandbox-control-client-failure-v1"
        or client.get("status") != 1
        or uuid4.fullmatch(str(client.get("request_id"))) is None):
    raise SystemExit(1)
PY
}

finalize_reconciled_gateway_lease() {
  local lease="$1" lease_id reply observed active retry_observed
  lease_id="$(/usr/bin/jq -er '.lease_id' <<<"$lease")" || return 70
  if reply="$(control sandbox-gateway-control lease-finalize "$run_id" launch_failed 2>&1)"; then
    if canonicalize_gateway_summary "$reply" "$run_id" "$lease_id" launch_failed "$lease" >/dev/null; then
      return 0
    fi
  fi
  if observed="$(control sandbox-gateway-control lease-status "$run_id" 2>&1)"; then
    if canonicalize_gateway_finalized_status "$observed" "$run_id" "$lease_id" \
        launch_failed "$lease" >/dev/null; then
      return 0
    fi
    if canonicalize_gateway_resolved_status "$observed" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" >/dev/null 2>&1; then
      return 0
    fi
    active="$(canonicalize_gateway_active_status "$observed" "$run_id" \
      "$session_binding_id" "$lease_profile" "$active_model_profile" \
      "$session_policy" "$harness_runtime")" || active=""
    if [[ -n "$active" && "$active" == "$lease" ]]; then
      if reply="$(control sandbox-gateway-control lease-finalize "$run_id" launch_failed 2>&1)"; then
        if canonicalize_gateway_summary "$reply" "$run_id" "$lease_id" \
            launch_failed "$lease" >/dev/null; then
          return 0
        fi
      fi
      if retry_observed="$(control sandbox-gateway-control lease-status "$run_id" 2>&1)" \
          && canonicalize_gateway_finalized_status "$retry_observed" "$run_id" \
            "$lease_id" launch_failed "$lease" >/dev/null; then
        return 0
      fi
      if [[ -n "${retry_observed:-}" ]] \
          && canonicalize_gateway_resolved_status "$retry_observed" "$run_id" \
            "$session_binding_id" "$lease_profile" "$active_model_profile" \
            "$session_policy" "$harness_runtime" >/dev/null 2>&1; then
        return 0
      fi
    fi
  fi
  echo "Gateway lease finalization outcome is unresolved; recovery is required." >&2
  return 70
}

reconcile_gateway_issue() {
  local observed lease replay_reply
  if observed="$(control sandbox-gateway-control lease-status "$run_id" 2>&1)"; then
    if lease="$(canonicalize_gateway_active_status "$observed" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" 2>/dev/null)"; then
      finalize_reconciled_gateway_lease "$lease"
      return $?
    fi
    if canonicalize_gateway_resolved_status "$observed" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" >/dev/null 2>&1; then
      return 0
    fi
    echo "Gateway lease status did not match the attempted issuance." >&2
    return 70
  fi

  # A missing counter and a wholly absent run both make lease-status surface
  # FileNotFoundError.  Never treat that generic error as proof of absence.
  # Replaying the same content-bound issue is idempotent: an absent run becomes
  # a complete matching lease, a complete run is returned unchanged, and a
  # partial publication remains rejected for explicit recovery.
  if replay_reply="$(/usr/bin/printf '%s\n' "$issue_payload" \
      | control_pipe sandbox-gateway-control lease-issue-v3 "$run_id" "$lease_profile" 2>&1)"; then
    if lease="$(canonicalize_issued_lease "$replay_reply" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" 2>/dev/null)"; then
      finalize_reconciled_gateway_lease "$lease"
      return $?
    fi
  fi

  if observed="$(control sandbox-gateway-control lease-status "$run_id" 2>&1)"; then
    if lease="$(canonicalize_gateway_active_status "$observed" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" 2>/dev/null)"; then
      finalize_reconciled_gateway_lease "$lease"
      return $?
    fi
    if canonicalize_gateway_resolved_status "$observed" "$run_id" \
        "$session_binding_id" "$lease_profile" "$active_model_profile" \
        "$session_policy" "$harness_runtime" >/dev/null 2>&1; then
      return 0
    fi
  fi
  echo "Gateway lease issuance outcome is unresolved; recovery is required." >&2
  return 70
}

early_controller_exit() {
  local original_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [[ "$gateway_issue_pending" == true ]] && ! reconcile_gateway_issue; then
    original_status=70
  fi
  cleanup_marker
  exit "$original_status"
}

reconcile_watchdog_arm() {
  local observed phase
  if observed="$(control sandbox-research-control watchdog-status "$run_id" 2>&1)"; then
    phase="$(canonicalize_watchdog_status "$observed" "$issued_lease")" || {
      echo "Research watchdog status did not match the attempted arm." >&2
      return 70
    }
    lifecycle_armed=true
    if [[ "$phase" != local_closed ]]; then
      if ! control sandbox-research-control watchdog-close "$run_id" >/dev/null; then
        echo "Research watchdog reconciliation close failed; recovery is required." >&2
        return 70
      fi
    fi
    watchdog_arm_pending=false
    return 0
  fi
  if research_status_proves_absence "$observed"; then
    watchdog_arm_pending=false
    return 0
  fi
  echo "Research watchdog arm outcome is unresolved; recovery is required." >&2
  return 70
}

canonicalize_gateway_summary() {
  local payload="$1" expected_run_id="$2" expected_lease_id="$3" expected_reason="$4" issued_lease="$5"
  /usr/bin/jq -ceS --arg run_id "$expected_run_id" --arg lease_id "$expected_lease_id" --arg reason "$expected_reason" --argjson issued "$issued_lease" '
    def nonnegative_integer: type == "number" and floor == . and . >= 0;
    if type == "object"
       and keys == ["final_counters","finalized_at","lease","reason","schema"]
       and .schema == "secure-sandbox-run-lease-summary-v2"
       and .reason == $reason
       and (.finalized_at | nonnegative_integer)
       and (.lease | type) == "object"
       and .lease.schema == "secure-sandbox-run-lease-v3"
       and .lease.run_id == $run_id and .lease.lease_id == $lease_id
       and (.lease | del(.expires_at, .renewals)) == ($issued | del(.expires_at, .renewals))
       and (.lease.expires_at | nonnegative_integer)
       and .lease.expires_at >= $issued.expires_at
       and .lease.expires_at <= $issued.maximum_expires_at
       and (.lease.renewals | nonnegative_integer)
       and .lease.renewals >= $issued.renewals
       and (.lease.runtime_authority | type) == "object"
       and (.lease.brokered_transport | type) == "object"
       and (.lease.profile | type) == "string" and (.lease.profile | length) > 0
       and (.final_counters | type) == "object"
       and (.final_counters | keys) == ["cost_microusd","input_tokens","lease_id",
            "output_tokens","requests","reservations","run_id","schema",
            "settled_reservations","updated_at"]
       and .final_counters.schema == "secure-sandbox-run-lease-counter-v1"
       and .final_counters.run_id == $run_id and .final_counters.lease_id == $lease_id
       and all(.final_counters.requests, .final_counters.input_tokens,
               .final_counters.output_tokens, .final_counters.cost_microusd,
               .final_counters.updated_at; nonnegative_integer)
       and (.final_counters.reservations | type) == "object"
       and (.final_counters.settled_reservations | type) == "array"
    then . else error("invalid Gateway summary") end
  ' <<<"$payload"
}

record_session_run() {
  /usr/bin/python3 -I - "$state_root/session-runs.json" "$session_binding_id" "$run_id" \
    "$runtime_authority" <<'PY'
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

path = Path(sys.argv[1])
session_id = sys.argv[2]
run_id = sys.argv[3]
authority = json.loads(sys.argv[4])
uuid = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
run_uuid = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
name = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
sha256 = re.compile(r"^[0-9a-f]{64}$")
def canonical(item):
    return (json.dumps(item, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
def checked(item, schema, fields):
    if (not isinstance(item, dict) or set(item) != {"schema", *fields, "binding_sha256"}
            or item.get("schema") != schema
            or sha256.fullmatch(str(item.get("binding_sha256"))) is None):
        raise SystemExit("session_runtime_authority_invalid")
    body = {field:item[field] for field in fields}
    expected = hashlib.sha256(canonical(body)).hexdigest()
    if not hmac.compare_digest(item["binding_sha256"], expected):
        raise SystemExit("session_runtime_authority_invalid")
    return item
def validate_authority(item, expected_session_id):
    fields = ("model_stack_binding", "session_context_binding", "harness_binding")
    checked(item, "secure-sandbox-runtime-authority-v1", fields)
    context_fields = ("session_id", "source_id", "source_manifest_sha256", "persona_sha256",
                      "tool_catalog_sha256", "extension_set_sha256")
    context = checked(item["session_context_binding"],
                      "secure-sandbox-session-context-binding-v1", context_fields)
    harness_fields = ("harness_id", "harness_generation_id", "harness_manifest_sha256",
                      "harness_executable_sha256", "harness_inventory_sha256",
                      "harness_adapter_id", "harness_adapter_sha256")
    checked(item["harness_binding"], "secure-sandbox-harness-runtime-binding-v1", harness_fields)
    stack = checked(item["model_stack_binding"],
                    "secure-sandbox-model-stack-runtime-binding-v1", ("authority", "mode"))
    if stack.get("mode") != "brokered-model-profile":
        raise SystemExit("session_runtime_authority_invalid")
    brokered_fields = ("adapter", "model", "profile_id", "profile_sha256",
                       "provider_mode", "vendor_id")
    brokered = checked(stack["authority"],
                       "secure-sandbox-brokered-model-runtime-binding-v1", brokered_fields)
    if context.get("session_id") != expected_session_id:
        raise SystemExit("session_runtime_authority_invalid")
    return item, brokered
authority, identity = validate_authority(authority, session_id)
harness = authority["harness_binding"]
if (not isinstance(identity.get("adapter"), str) or not identity["adapter"]
        or not isinstance(identity.get("model"), str) or not identity["model"]
        or name.fullmatch(str(identity.get("vendor_id"))) is None):
    raise SystemExit("session_model_profile_invalid")
harness_fields = {
    "harness_id", "harness_generation_id", "harness_manifest_sha256",
    "harness_executable_sha256", "harness_inventory_sha256",
    "harness_adapter_id", "harness_adapter_sha256", "binding_sha256", "schema",
}
if (not isinstance(harness, dict) or set(harness) != harness_fields
        or harness.get("schema") != "secure-sandbox-harness-runtime-binding-v1"
        or name.fullmatch(str(harness.get("harness_id"))) is None
        or name.fullmatch(str(harness.get("harness_adapter_id"))) is None
        or any(sha256.fullmatch(str(harness.get(field))) is None for field in (
            "harness_generation_id", "harness_manifest_sha256",
            "harness_executable_sha256", "harness_inventory_sha256",
            "harness_adapter_sha256", "binding_sha256"))):
    raise SystemExit("session_harness_binding_invalid")
if uuid.fullmatch(session_id) is None or run_uuid.fullmatch(run_id) is None:
    raise SystemExit("session_run_id_invalid")
parent = path.parent
parent_info = parent.lstat()
if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700):
    raise SystemExit("session_run_directory_untrusted")
lock_path = parent / ".session-runs.lock"
lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
temporary = None
try:
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
            or lock_info.st_uid != os.geteuid() or stat.S_IMODE(lock_info.st_mode) != 0o600):
        raise SystemExit("session_run_lock_untrusted")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        value = {"schema": "secure-sandbox-session-runs-v5", "sessions": {}}
    else:
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 1024 * 1024):
                raise SystemExit("session_run_catalog_untrusted")
            raw = handle.read(1024 * 1024 + 1)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SystemExit("session_run_catalog_invalid") from error
    if not isinstance(value, dict) or value.get("schema") not in {
            "secure-sandbox-session-runs-v1", "secure-sandbox-session-runs-v2",
            "secure-sandbox-session-runs-v3", "secure-sandbox-session-runs-v4",
            "secure-sandbox-session-runs-v5"}:
        raise SystemExit("session_run_catalog_invalid")
    legacy = value["schema"] == "secure-sandbox-session-runs-v1"
    sessions = value.get("sessions")
    if not isinstance(sessions, dict) or len(sessions) > 10_000:
        raise SystemExit("session_run_catalog_invalid")
    for key, record in sessions.items():
        if (not isinstance(key, str) or uuid.fullmatch(key) is None
                or not isinstance(record, dict)
                or set(record) not in ({"last_started_at", "runs"},
                                       {"last_started_at", "runs", "run_ids"},
                                       {"adapter", "last_started_at", "model",
                                        "model_profile_id", "model_profile_sha256",
                                        "run_ids", "runs", "vendor_id"},
                                       {"adapter", "last_started_at", "model",
                                        "model_profile_id", "model_profile_sha256",
                                        "run_ids", "runs", "vendor_id",
                                        "harness_id", "harness_generation_id",
                                        "harness_manifest_sha256",
                                        "harness_executable_sha256",
                                        "harness_inventory_sha256",
                                        "harness_adapter_id", "harness_adapter_sha256",
                                        "harness_binding_sha256"},
                                       {"adapter", "last_started_at", "model",
                                        "run_ids", "runs", "runtime_authority",
                                        "vendor_id"})
                or (legacy and "run_ids" in record)
                or not isinstance(record["last_started_at"], int)
                or isinstance(record["last_started_at"], bool) or record["last_started_at"] < 0
                or not isinstance(record["runs"], int) or isinstance(record["runs"], bool)
                or not 1 <= record["runs"] <= 1_000_000
                or ("run_ids" in record and (not isinstance(record["run_ids"], list)
                    or len(record["run_ids"]) > 1000
                    or len(record["run_ids"]) > record["runs"]
                    or any(not isinstance(item, str) or run_uuid.fullmatch(item) is None
                           for item in record["run_ids"])
                    or len(set(record["run_ids"])) != len(record["run_ids"])))
                or ("model_profile_id" in record and (
                    name.fullmatch(str(record["model_profile_id"])) is None
                    or name.fullmatch(str(record["vendor_id"])) is None
                    or sha256.fullmatch(str(record["model_profile_sha256"])) is None
                    or not isinstance(record["adapter"], str)
                    or not isinstance(record["model"], str)))
                or ("harness_generation_id" in record and (
                    name.fullmatch(str(record["harness_id"])) is None
                    or name.fullmatch(str(record["harness_adapter_id"])) is None
                    or any(sha256.fullmatch(str(record[field])) is None for field in (
                        "harness_generation_id", "harness_manifest_sha256",
                        "harness_executable_sha256", "harness_inventory_sha256",
                        "harness_adapter_sha256", "harness_binding_sha256"))))):
            raise SystemExit("session_run_catalog_invalid")
        if "runtime_authority" in record:
            carried = record["runtime_authority"]
            try:
                _, carried_identity = validate_authority(carried, key)
            except SystemExit:
                raise SystemExit("session_run_catalog_invalid")
            if (record.get("adapter") != carried_identity.get("adapter")
                    or record.get("model") != carried_identity.get("model")
                    or record.get("vendor_id") != carried_identity.get("vendor_id")):
                raise SystemExit("session_run_catalog_invalid")
    for record in sessions.values():
        record.setdefault("run_ids", [])
    if session_id not in sessions and len(sessions) >= 10_000:
        raise SystemExit("session_run_catalog_full")
    prior = sessions.get(session_id, {"runs": 0})["runs"]
    if prior >= 1_000_000:
        raise SystemExit("session_run_counter_exhausted")
    prior_ids = sessions[session_id]["run_ids"] if session_id in sessions else []
    expected = {"adapter": identity["adapter"], "model": identity["model"],
                "vendor_id": identity["vendor_id"], "runtime_authority": authority}
    if session_id in sessions:
        if "runtime_authority" not in sessions[session_id]:
            raise SystemExit("session_runtime_authority_legacy_unbound")
        if any(sessions[session_id].get(key) != value for key, value in expected.items()):
            raise SystemExit("session_model_profile_mismatch")
    if run_id in prior_ids:
        raise SystemExit("session_run_duplicate")
    sessions[session_id] = {**expected, "last_started_at": int(time.time()),
                            "runs": prior + 1,
                            "run_ids": (prior_ids + [run_id])[-1000:]}
    value["schema"] = "secure-sandbox-session-runs-v5"
    payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(payload) > 1024 * 1024:
        for old_id, old_record in sorted(sessions.items(), key=lambda item: item[1]["last_started_at"]):
            if old_id == session_id:
                continue
            old_record["run_ids"] = []
            payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
            if len(payload) <= 1024 * 1024:
                break
    if len(payload) > 1024 * 1024:
        sessions[session_id]["run_ids"] = sessions[session_id]["run_ids"][-100:]
        payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(payload) > 1024 * 1024:
        raise SystemExit("session_run_catalog_full")
    descriptor, name = tempfile.mkstemp(prefix=".session-runs.", dir=parent)
    temporary = Path(name)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    temporary = None
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if temporary is not None:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    os.close(lock_fd)
PY
}

session_runtime_authority() {
  /usr/bin/python3 -I - "$state_root/session-runs.json" "$session_binding_id" <<'PY'
import hashlib, hmac, json, os, re, stat, sys
from pathlib import Path

path, session_id = Path(sys.argv[1]), sys.argv[2]
info = path.lstat()
if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1 or not 0 < info.st_size <= 1024 * 1024):
    raise SystemExit("session_run_catalog_untrusted")
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
with os.fdopen(descriptor, "rb") as handle:
    opened = os.fstat(handle.fileno())
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        raise SystemExit("session_run_catalog_untrusted")
    raw = handle.read(1024 * 1024 + 1)
try:
    value = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("session_run_catalog_invalid") from error
sessions = value.get("sessions") if isinstance(value, dict) else None
record = sessions.get(session_id) if isinstance(sessions, dict) else None
record_fields = {"adapter", "last_started_at", "model", "run_ids", "runs",
                 "runtime_authority", "vendor_id"}
run_uuid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
if (not isinstance(value, dict) or set(value) != {"schema", "sessions"}
        or value.get("schema") != "secure-sandbox-session-runs-v5"
        or not isinstance(sessions, dict) or len(sessions) > 10_000
        or not isinstance(record, dict) or set(record) != record_fields):
    raise SystemExit("session_runtime_authority_legacy_unbound")
if (not isinstance(record.get("last_started_at"), int)
        or isinstance(record.get("last_started_at"), bool)
        or record["last_started_at"] < 0
        or not isinstance(record.get("runs"), int) or isinstance(record.get("runs"), bool)
        or not 1 <= record["runs"] <= 1_000_000
        or not isinstance(record.get("run_ids"), list)
        or len(record["run_ids"]) > min(record["runs"], 1000)
        or any(not isinstance(item, str) or run_uuid.fullmatch(item) is None
               for item in record["run_ids"])
        or len(set(record["run_ids"])) != len(record["run_ids"])):
    raise SystemExit("session_runtime_authority_invalid")

sha = re.compile(r"[0-9a-f]{64}")
name = re.compile(r"[a-z][a-z0-9-]{0,62}")
profile_name = re.compile(r"[a-z][a-z0-9-]{0,47}")
uuid4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
def canonical(item):
    return (json.dumps(item, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
def digest(item):
    return hashlib.sha256(canonical(item)).hexdigest()
def checked(item, schema, fields):
    if (not isinstance(item, dict) or set(item) != {"schema", *fields, "binding_sha256"}
            or item.get("schema") != schema
            or sha.fullmatch(str(item.get("binding_sha256"))) is None):
        raise SystemExit("session_runtime_authority_invalid")
    body = {field:item[field] for field in fields}
    if not hmac.compare_digest(item["binding_sha256"], digest(body)):
        raise SystemExit("session_runtime_authority_invalid")
    return item

authority = record["runtime_authority"]
authority_fields = ("model_stack_binding", "session_context_binding", "harness_binding")
checked(authority, "secure-sandbox-runtime-authority-v1", authority_fields)
context_fields = ("session_id", "source_id", "source_manifest_sha256", "persona_sha256",
                  "tool_catalog_sha256", "extension_set_sha256")
context = checked(authority["session_context_binding"],
                  "secure-sandbox-session-context-binding-v1", context_fields)
if (context.get("session_id") != session_id or uuid4.fullmatch(session_id) is None
        or (context.get("source_id") is None) != (context.get("source_manifest_sha256") is None)
        or (context.get("source_id") is not None
            and (uuid4.fullmatch(str(context["source_id"])) is None
                 or sha.fullmatch(str(context["source_manifest_sha256"])) is None))
        or any(sha.fullmatch(str(context.get(field))) is None for field in (
            "persona_sha256", "tool_catalog_sha256", "extension_set_sha256"))):
    raise SystemExit("session_runtime_authority_invalid")
harness_fields = ("harness_id", "harness_generation_id", "harness_manifest_sha256",
                  "harness_executable_sha256", "harness_inventory_sha256",
                  "harness_adapter_id", "harness_adapter_sha256")
harness = checked(authority["harness_binding"],
                  "secure-sandbox-harness-runtime-binding-v1", harness_fields)
if (name.fullmatch(str(harness.get("harness_id"))) is None
        or name.fullmatch(str(harness.get("harness_adapter_id"))) is None
        or any(sha.fullmatch(str(harness.get(field))) is None for field in harness_fields
               if field not in {"harness_id", "harness_adapter_id"})):
    raise SystemExit("session_runtime_authority_invalid")
stack = checked(authority["model_stack_binding"],
                "secure-sandbox-model-stack-runtime-binding-v1", ("authority", "mode"))
if stack.get("mode") != "brokered-model-profile":
    raise SystemExit("session_native_runtime_requires_native_controller")
brokered_fields = ("adapter", "model", "profile_id", "profile_sha256", "provider_mode", "vendor_id")
brokered = checked(stack["authority"], "secure-sandbox-brokered-model-runtime-binding-v1",
                   brokered_fields)
if (brokered.get("adapter") not in {
        "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
        or not isinstance(brokered.get("model"), str) or not brokered["model"]
        or profile_name.fullmatch(str(brokered.get("profile_id"))) is None
        or profile_name.fullmatch(str(brokered.get("vendor_id"))) is None
        or sha.fullmatch(str(brokered.get("profile_sha256"))) is None
        or brokered.get("provider_mode") not in {"mock", "production"}
        or record.get("adapter") != brokered.get("adapter")
        or record.get("model") != brokered.get("model")
        or record.get("vendor_id") != brokered.get("vendor_id")):
    raise SystemExit("session_runtime_authority_invalid")
print(json.dumps(authority, allow_nan=False, ensure_ascii=True,
                 separators=(",", ":"), sort_keys=True))
PY
}

for guest in sandbox-gateway sandbox-research-admin sandbox-target-admin; do
  host_epoch="$(/bin/date -u +%s)"
  guest_epoch="$(read_epoch "$guest")"
  skew=$((host_epoch - guest_epoch)); (( skew < 0 )) && skew=$((-skew))
  if (( skew > 5 )); then
    echo "$guest exceeds the 5s clock-skew limit." >&2
    echo "Refusing to launch with stale guest clocks." >&2
    exit 1
  fi
done

if [[ "$resume_requested" == true ]]; then
  session_uuid="${claude_args[1]}"
  set +e
  control sandbox-research-control session-refresh-contains "$session_uuid"
  registry_status=$?
  set -e
  case "$registry_status" in
    0) ;;
    1) echo "Refusing to resume an unregistered Claude session UUID: $session_uuid" >&2; exit 2;;
    *) echo "Unable to verify the Claude session registry on Research (status $registry_status)." >&2; exit 1;;
  esac
fi

run_id="${acceptance_run_id:-$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')}"
if [[ -n "$acceptance_session_id" ]]; then
  [[ "$resume_requested" == false ]] || { echo "Acceptance cannot resume an existing session." >&2; exit 2; }
  session_binding_id="$acceptance_session_id"
elif [[ "$resume_requested" == true ]]; then
  session_binding_id="$session_uuid"
else
  session_binding_id="$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')"
fi
resume_runtime_authority=""
session_policy_source="${source_id:-none}"
if [[ "$resume_requested" == true ]]; then
  resume_runtime_authority="$(session_runtime_authority)" || {
    echo "Session has no current attested runtime authority; explicit migration is required." >&2
    exit 1
  }
  session_generation="$(/usr/bin/jq -er '.harness_binding.harness_generation_id' \
    <<<"$resume_runtime_authority")"
  session_policy_source="$(/usr/bin/jq -er '.session_context_binding.source_id // "none"' \
    <<<"$resume_runtime_authority")"
fi

active_model_profile="$(control sandbox-gateway-control model-profile-status)"
active_model_profile="$(/usr/bin/jq -ceS '
  def base_keys:
    ["adapter","mode","model","profile_id","profile_sha256","schema",
     "upstream_origin","vendor_id"];
  def attested_keys:
    ["activation_id","adapter","mode","model","plan_sha256","profile_id",
     "profile_sha256","schema","upstream_origin","vendor_id"];
  if type == "object"
     and ((keys == base_keys)
          or (keys == attested_keys
              and (.activation_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
              and (.plan_sha256 | test("^[0-9a-f]{64}$"))))
     and .schema == "secure-sandbox-active-model-profile-v1"
     and (.mode == "mock" or .mode == "production")
     and (.profile_id | test("^[a-z][a-z0-9-]{0,47}$"))
     and (.profile_sha256 | test("^[0-9a-f]{64}$"))
     and (.vendor_id | test("^[a-z][a-z0-9-]{0,47}$"))
     and (.adapter == "anthropic-messages-v1"
          or .adapter == "openai-responses-v1"
          or .adapter == "google-openai-chat-v1")
     and (.model | test("^[A-Za-z0-9][A-Za-z0-9._:/+\\[\\]-]{0,191}$"))
     and (.upstream_origin | type) == "string"
  then . else error("invalid active model profile") end
' <<<"$active_model_profile")" || { echo "Invalid Gateway model profile status." >&2; exit 1; }
if [[ "$resume_requested" == true ]]; then
  harness_runtime="$(control sandbox-research-control harness-generation-runtime "$session_generation")"
else
  harness_runtime="$(control sandbox-research-control harness-active-runtime)"
fi
harness_runtime="$(/usr/bin/jq -ceS '
  if type == "object"
     and keys == ["binding_sha256","harness_adapter_id","harness_adapter_sha256",
                  "harness_executable_sha256","harness_generation_id","harness_id",
                  "harness_inventory_sha256","harness_manifest_sha256","schema"]
     and .schema == "secure-sandbox-harness-runtime-binding-v1"
     and (.harness_id | test("^[a-z][a-z0-9-]{0,62}$"))
     and (.harness_adapter_id | test("^[a-z][a-z0-9-]{0,62}$"))
     and all(.binding_sha256, .harness_adapter_sha256, .harness_executable_sha256,
             .harness_generation_id, .harness_inventory_sha256,
             .harness_manifest_sha256; test("^[0-9a-f]{64}$"))
  then . else error("invalid harness runtime binding") end
' <<<"$harness_runtime")" || { echo "Invalid Research harness runtime binding." >&2; exit 1; }
if [[ "$resume_requested" == true ]]; then
  expected_harness_runtime="$(/usr/bin/jq -ceS '.harness_binding' \
    <<<"$resume_runtime_authority")"
  [[ "$harness_runtime" == "$expected_harness_runtime" ]] || {
    echo "Research harness generation does not preserve the session runtime authority." >&2
    exit 1
  }
fi

session_policy="$(control sandbox-research-control session-policy-runtime "$session_policy_source")"
session_policy="$(/usr/bin/jq -ceS --arg expected_source "$session_policy_source" '
  if type == "object"
     and keys == ["extension_set_sha256","persona_sha256","schema","source_id",
                  "source_manifest_sha256","tool_catalog_sha256"]
     and .schema == "secure-sandbox-session-policy-runtime-v1"
     and ((.source_id == null and .source_manifest_sha256 == null)
          or ((.source_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
              and (.source_manifest_sha256 | test("^[0-9a-f]{64}$"))))
     and (if $expected_source == "none"
          then .source_id == null and .source_manifest_sha256 == null
          else .source_id == $expected_source
          end)
     and all(.persona_sha256,.tool_catalog_sha256,.extension_set_sha256;
             test("^[0-9a-f]{64}$"))
  then . else error("invalid session policy") end
' <<<"$session_policy")" || { echo "Invalid Research session policy." >&2; exit 1; }
if [[ "$resume_requested" == true ]]; then
  expected_session_policy="$(/usr/bin/jq -ceS '
    .session_context_binding
    | {schema:"secure-sandbox-session-policy-runtime-v1",source_id,
       source_manifest_sha256,persona_sha256,tool_catalog_sha256,
       extension_set_sha256}
  ' <<<"$resume_runtime_authority")"
  [[ "$session_policy" == "$expected_session_policy" ]] || {
    echo "Research session policy does not preserve the session runtime authority." >&2
    exit 1
  }
fi

issue_payload="$(/usr/bin/jq -ncS --arg session_id "$session_binding_id" \
  --argjson session_policy "$session_policy" --argjson harness_binding "$harness_runtime" \
  '{schema:"secure-sandbox-run-lease-issue-v3",session_id:$session_id,
    session_policy:$session_policy,harness_binding:$harness_binding}')"
gateway_issue_pending=true
trap early_controller_exit EXIT
if lease_json="$(/usr/bin/printf '%s\n' "$issue_payload" \
    | control_pipe sandbox-gateway-control lease-issue-v3 "$run_id" "$lease_profile" 2>&1)"; then
  issue_status=0
else
  issue_status=$?
fi
if (( issue_status != 0 )); then
  echo "Gateway lease issuance did not return success; reconciling the exact run ID." >&2
  exit 1
fi
if ! issued_lease="$(canonicalize_issued_lease "$lease_json" "$run_id" "$session_binding_id" \
    "$lease_profile" "$active_model_profile" "$session_policy" "$harness_runtime")"; then
  echo "Invalid Gateway lease; reconciling the exact run ID." >&2
  exit 1
fi
runtime_authority="$(/usr/bin/jq -ceS '.runtime_authority' <<<"$issued_lease")"
lease_fields="$(parse_lease_response "$issued_lease")"
IFS=$'\t' read -r lease_id lease_expires_at <<<"$lease_fields"
[[ "$lease_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ \
    && "$lease_expires_at" =~ ^[0-9]{10}$ ]] || { echo "Invalid lease response." >&2; exit 1; }
run_started=false

cleanup_run() {
  cleanup_status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [[ -n "$session_pid" ]]; then
    /bin/kill -HUP "$session_pid" 2>/dev/null || true
    wait "$session_pid" 2>/dev/null || true
    session_pid=""
  fi
  if [[ -n "$approval_relay_pid" ]]; then
    /bin/kill "$approval_relay_pid" 2>/dev/null || true
    wait "$approval_relay_pid" 2>/dev/null || true
    approval_relay_pid=""
  fi
  now="$(/bin/date -u +%s)"
  if (( now >= lease_expires_at )); then lease_reason=expired
  elif [[ "$run_interrupted" == true ]]; then lease_reason=operator_closed
  elif [[ "$session_failed" == true ]]; then lease_reason=session_failed
  elif [[ "$run_started" == true ]]; then lease_reason=completed
  else lease_reason=launch_failed
  fi
  cleanup_failed=false
  if [[ "$watchdog_arm_pending" == true ]]; then
    if ! reconcile_watchdog_arm && [[ "$lifecycle_armed" != true ]]; then
      cleanup_failed=true
    fi
  fi
  if [[ "$lifecycle_armed" == true ]]; then
    if ! control sandbox-research-control watchdog-close "$run_id" >/dev/null; then
      echo "Research lifecycle close failed; admission remains closed and recovery is required." >&2
      cleanup_failed=true
    else
      watchdog_arm_pending=false
    fi
  fi
  gateway_summary=""
  if [[ "$cleanup_failed" == false ]]; then
    if ! gateway_summary="$(control sandbox-gateway-control lease-finalize "$run_id" "$lease_reason")"; then
      echo "Gateway lease finalization failed; Research lifecycle was not committed." >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false ]]; then
    gateway_summary="$(canonicalize_gateway_summary "$gateway_summary" "$run_id" "$lease_id" "$lease_reason" "$issued_lease")" || cleanup_failed=true
    if [[ "$cleanup_failed" == true ]]; then
      echo "Gateway returned an invalid final summary; Research lifecycle was not committed." >&2
    fi
  fi
  if [[ "$cleanup_failed" == false && "$lifecycle_armed" == true ]]; then
    # Gateway atomic_json persists canonical JSON followed by exactly one LF.
    # Bind Research's commit to those exact durable bytes, not merely to an
    # equivalent JSON value transported through command substitution.
    gateway_summary_sha256="$(/usr/bin/printf '%s\n' "$gateway_summary" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    if ! control sandbox-research-control watchdog-commit "$run_id" "$gateway_summary_sha256" >/dev/null; then
      echo "Research lifecycle commit failed; recovery is required." >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false && "$lifecycle_armed" == true ]]; then
    if ! control sandbox-research-control session-refresh >/dev/null; then
      echo "Session registry refresh failed after committed teardown." >&2
      cleanup_failed=true
    fi
  fi
  cleanup_marker
  if [[ "$cleanup_failed" == true ]]; then
    return 70
  fi
  return "$cleanup_status"
}
trap cleanup_run EXIT
gateway_issue_pending=false

if [[ "$resume_requested" == true && "$runtime_authority" != "$resume_runtime_authority" ]]; then
  echo "Gateway lease does not preserve the session runtime authority." >&2
  exit 1
fi

arm_payload="$(/usr/bin/jq -ncS --argjson gateway_lease "$issued_lease" \
  '{schema:"secure-sandbox-research-run-arm-v3",gateway_lease:$gateway_lease}')"
watchdog_arm_pending=true
if arm_reply="$(/usr/bin/printf '%s\n' "$arm_payload" \
    | control_pipe sandbox-research-control watchdog-arm-v3 2>&1)"; then
  arm_status=0
else
  arm_status=$?
fi
if (( arm_status == 0 )) \
    && canonicalize_research_lease "$arm_reply" "$issued_lease" >/dev/null; then
  lifecycle_armed=true
  watchdog_arm_pending=false
else
  echo "Research watchdog arm did not return a valid success; reconciling the exact run ID." >&2
  if reconcile_watchdog_arm; then
    exit 1
  else
    exit 70
  fi
fi
control sandbox-research-control capture-ready

approval_relay() {
  local pending status signed response approval_id broker_stderr broker_error failures=0
  relay_event() {
    local stage="$1" result="$2" request_id="${3:-}" event_path
    [[ "$stage" =~ ^[a-z_]{1,48}$ && "$result" =~ ^[a-z0-9_]{1,80}$ ]] || return 1
    [[ -z "$request_id" || "$request_id" =~ ^[0-9a-f-]{36}$ ]] || return 1
    event_path="$state_root/approval-relay-last.json"
    /usr/bin/python3 -I -c '
import json, os, sys, time

path, stage, result, approval_id, run_id, session_id = sys.argv[1:]
record = {
    "approval_id": approval_id,
    "created_at": int(time.time()),
    "result": result,
    "run_id": run_id,
    "schema": "secure-sandbox-approval-relay-event-v1",
    "session_id": session_id,
    "stage": stage,
}
payload = (json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
temporary = path + "." + str(os.getpid()) + ".new"
descriptor = None
try:
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = None
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
except Exception:
    if descriptor is not None:
        os.close(descriptor)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
' "$event_path" "$stage" "$result" "${request_id:-none}" "$run_id" "$session_binding_id" || return 1
    /usr/bin/logger -p user.notice -t secure-sandbox-approval-relay \
      "stage=$stage result=$result approval_id=${request_id:-none} run_id=$run_id session_id=$session_binding_id"
  }
  while true; do
    set +e
    pending="$(control sandbox-research-control execution-approval-next "$run_id" "$session_binding_id" 2>/dev/null)"
    status=$?
    set -e
    if (( status == 3 )); then
      failures=0
      continue
    fi
    if (( status != 0 )); then
      failures=$((failures + 1))
      if (( failures >= 3 )); then
        relay_event poll transport_failed || true
        echo "Execution approval relay failed closed after repeated polling errors." >&2
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return "$status"
      fi
      /bin/sleep 1
      continue
    fi
    failures=0
    if ! approval_id="$(/usr/bin/jq -er '.approval_id' <<<"$pending")"; then
      relay_event request invalid || true
      echo "Execution approval relay received an invalid pending request." >&2
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    fi
    relay_event claim acquired "$approval_id" || true
    broker_stderr="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/secure-sandbox-approval.XXXXXX")" || {
      relay_event authorization stderr_capture_failed "$approval_id" || true
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    }
    set +e
    signed="$("$release_dir/authorization_broker" request \
      --agent "Claude Code" --session "$session_binding_id" \
      --purpose "Authorize this exact disposable execution request" \
      --resource "Disposable execution in SecureSandbox-Target" \
      --operation execution-approval-sign --parameters-json "$pending" 2>"$broker_stderr")"
    status=$?
    set -e
    if (( status == 0 )); then
      relay_event authorization approved "$approval_id" || true
      if ! response="$(/usr/bin/jq -ncS --arg approval_id "$approval_id" --argjson envelope "$signed" \
          '{schema:"secure-sandbox-execution-approval-response-v1",approval_id:$approval_id,status:"approved",envelope:$envelope}')"; then
        /bin/rm -f -- "$broker_stderr"
        relay_event response invalid_signed_envelope "$approval_id" || true
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return 1
      fi
    else
      broker_error="$(/usr/bin/tail -n 1 "$broker_stderr" \
        | /usr/bin/jq -er '.error | select(type == "string" and test("^[a-z0-9_]{1,80}$"))' 2>/dev/null \
        || /usr/bin/printf '%s' authorization_failed)"
      relay_event authorization "$broker_error" "$approval_id" || true
      if ! response="$(/usr/bin/jq -ncS --arg approval_id "$approval_id" \
          '{schema:"secure-sandbox-execution-approval-response-v1",approval_id:$approval_id,status:"cancelled"}')"; then
        /bin/rm -f -- "$broker_stderr"
        relay_event response cancellation_encoding_failed "$approval_id" || true
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return 1
      fi
    fi
    /bin/rm -f -- "$broker_stderr"
    relay_event response delivering "$approval_id" || true
    if ! /usr/bin/printf '%s\n' "$response" \
      | control_pipe sandbox-research-control execution-approval-deliver >/dev/null; then
      relay_event response delivery_failed "$approval_id" || true
      echo "Execution approval relay failed closed while delivering a response." >&2
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    fi
    relay_event response delivered "$approval_id" || true
  done
}

controller_pid="$$"
approval_relay &
approval_relay_pid=$!
host_pki="$($release_dir/pki_anchor verify)"
gateway_pki="$(control sandbox-gateway-control pki-verify)"
research_pki="$(control sandbox-research-control pki-verify)"
host_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$host_pki")"
gateway_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$gateway_pki")"
research_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$research_pki")"
[[ "$host_generation" == "$gateway_generation" && "$host_generation" == "$research_generation" ]] || {
  echo "pki_generation_boundary_mismatch" >&2
  exit 1
}
echo "SecureSandbox controller release: $release_id"
echo "SecureSandbox run ID: $run_id"
echo "SecureSandbox session binding: $session_binding_id"
echo "Run lease: $lease_id ($lease_profile; expires $(/bin/date -r "$lease_expires_at" -u '+%Y-%m-%dT%H:%M:%SZ'))"
record_session_run
run_started=true
set +e
if [[ "$resume_requested" == true ]]; then
  /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --resume "$session_uuid" <&0 &
else
  if [[ -n "$source_id" ]]; then
    /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --session-id "$session_binding_id" --source "$source_id" <&0 &
  else
    /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --session-id "$session_binding_id" <&0 &
  fi
fi
session_pid=$!
wait "$session_pid"
session_status=$?
session_pid=""
set -e
if (( session_status != 0 )); then
  session_failed=true
  exit "$session_status"
fi

