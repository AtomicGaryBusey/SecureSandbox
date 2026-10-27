#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if /usr/bin/pgrep -x prl_client_app >/dev/null 2>&1; then
  echo parallels_gui_must_be_closed_before_vm_lifecycle_transition >&2
  exit 1
fi

temporary="$(mktemp -d /tmp/secure-sandbox-lifecycle-ddd.XXXXXX)"
cleanup() {
  local status="$?"
  trap - EXIT
  if (( status != 0 )); then
    echo "Lifecycle acceptance stopped before completion; performing read-only state recovery." >&2
    scripts/labctl status || true
  fi
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

capture() {
  local name="$1"
  shift
  set +e
  "$@" 2>&1 | tee "$temporary/$name.log"
  local status="${PIPESTATUS[0]}"
  set -e
  (( status == 0 )) || return "$status"
  tail -n 1 "$temporary/$name.log" > "$temporary/$name.json"
}

states_known='(.observed.gateway | IN("running","stopped")) and
  (.observed.research | IN("running","stopped")) and
  (.observed.target | IN("running","stopped")) and
  (.observed.gateway_net0 | IN("connected","disconnected"))'
all_stopped='.observed.gateway == "stopped" and
  .observed.research == "stopped" and .observed.target == "stopped"'
all_running='.observed.gateway == "running" and
  .observed.research == "running" and .observed.target == "running" and
  .observed.gateway_net0 == "connected"'

echo "DDD 1/6  Read the exact VM and guest-control state without mutation"
capture status scripts/labctl status
jq -e ".schema == \"secure-sandbox-host-lifecycle-v1\" and
  .operation == \"status\" and .status == \"verified\" and ($states_known)" \
  "$temporary/status.json" >/dev/null

echo "DDD 2/6  Converge the stack to independently verified stopped state"
capture stop scripts/labctl stop
jq -e ".schema == \"secure-sandbox-host-lifecycle-v1\" and
  .operation == \"stop\" and .status == \"verified\" and ($all_stopped)" \
  "$temporary/stop.json" >/dev/null

echo "DDD 3/6  Prove stopped-state replay is idempotent and action-free"
capture stop-idempotent scripts/labctl stop
jq -e ".status == \"verified\" and ($all_stopped) and
  (.action_outcomes | length == 3) and
  all(.action_outcomes[]; .result == \"already_satisfied\")" \
  "$temporary/stop-idempotent.json" >/dev/null

echo "DDD 4/6  Converge the stack to verified running state with trusted time"
capture start scripts/labctl start
jq -e ".schema == \"secure-sandbox-host-lifecycle-v1\" and
  .operation == \"start\" and .status == \"verified\" and ($all_running) and
  all(.reachability[]; . == \"reachable\")" "$temporary/start.json" >/dev/null

echo "DDD 5/6  Prove running-state replay performs no duplicate VM start"
capture start-idempotent scripts/labctl start
jq -e ".status == \"verified\" and ($all_running) and
  ([.action_outcomes[] | select(.action == \"vm_start\")] | length == 3) and
  all(.action_outcomes[] | select(.action == \"vm_start\");
      .result == \"already_satisfied\")" "$temporary/start-idempotent.json" >/dev/null

echo "DDD 6/6  Verify the complete live containment boundary"
scripts/verify-boundaries.sh
echo parallels-lifecycle-resilience-ddd:deployed-and-boundary-verified
