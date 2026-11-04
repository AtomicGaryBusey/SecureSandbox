#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }

guest_control="${1:-/tmp/native_guest_control.py}"
native_egress="${2:-/tmp/native_egress.py}"
shared_init="${3:-/tmp/shared_init.py}"
renderer="${4:-/tmp/render_gateway_firewall.py}"
tunnel="${5:-/tmp/native_opaque_tunnel.py}"
unit="${6:-/tmp/native-opaque-tunnel.service}"
policy_hash="${7:-/tmp/update-policy-hash.sh}"
native_vendor_stack="${8:-/tmp/native_vendor_stack.py}"
native_stack_binding="${9:-/tmp/native_stack_runtime_binding.py}"
model_stack_binding="${10:-/tmp/model_stack_runtime_binding.py}"
runtime_authority="${11:-/tmp/runtime_authority.py}"
harness_binding="${12:-/tmp/harness_runtime_binding.py}"
session_binding="${13:-/tmp/session_context_binding.py}"
install_transaction="${14:-/tmp/native_install_transaction.py}"

sources=(
  "$guest_control" "$native_egress" "$shared_init" "$renderer" "$tunnel"
  "$unit" "$policy_hash" "$native_vendor_stack" "$native_stack_binding"
  "$model_stack_binding" "$runtime_authority" "$harness_binding"
  "$session_binding" "$install_transaction"
)

# Protected deployment bind-mounts a root-created bundle over /tmp. Require
# that exact ownership and sticky-parent shape, so direct sudo execution over a
# same-UID staging tree fails before any mutation.
python3 - "${sources[@]}" <<'PY'
import os,stat,sys
for name in sys.argv[1:]:
    try:
        parent=os.lstat(os.path.dirname(name) or ".")
        before=os.lstat(name)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        opened=os.fstat(fd)
        os.close(fd)
    except OSError as error:
        raise SystemExit(f"native_source_unavailable:{name}") from error
    parent_safe=(stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode)
                 and parent.st_uid == 0
                 and (not (parent.st_mode & 0o022) or parent.st_mode & stat.S_ISVTX))
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,
                           value.st_mtime_ns,value.st_ctime_ns)
    if (not parent_safe or not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode) or before.st_uid != 0
            or before.st_nlink != 1 or before.st_mode & 0o022
            or identity(before) != identity(opened)):
        raise SystemExit(f"native_source_untrusted:{name}")
PY

python3 -m py_compile \
  "$guest_control" "$native_egress" "$renderer" "$tunnel" \
  "$native_vendor_stack" "$native_stack_binding" "$model_stack_binding" \
  "$runtime_authority" "$harness_binding" "$session_binding" \
  "$install_transaction"
systemd-analyze verify "$unit" >/dev/null

install -d -o root -g root -m 755 \
  /usr/local/libexec/secure-sandbox \
  /usr/local/libexec/secure-sandbox/shared \
  /etc/secure-sandbox
install -d -o root -g root -m 700 \
  /var/lib/secure-sandbox/native-egress-control \
  /var/lib/secure-sandbox/policy-backups

lock=/var/lib/secure-sandbox/native-egress-control/install.lock
pending=/var/lib/secure-sandbox/native-egress-control/gateway-install.pending.json
exec 9>"$lock"
chmod 600 "$lock"
flock -x 9

service_is_active() {
  systemctl is-active --quiet native-opaque-tunnel.service
}

service_is_exactly_stopped() {
  local values load active sub pid
  values="$(systemctl show native-opaque-tunnel.service \
    --property=LoadState --property=ActiveState --property=SubState \
    --property=MainPID 2>/dev/null || true)"
  load="$(printf '%s\n' "$values" | awk -F= '$1=="LoadState"{print $2}')"
  active="$(printf '%s\n' "$values" | awk -F= '$1=="ActiveState"{print $2}')"
  sub="$(printf '%s\n' "$values" | awk -F= '$1=="SubState"{print $2}')"
  pid="$(printf '%s\n' "$values" | awk -F= '$1=="MainPID"{print $2}')"
  [[ "$load" == loaded && "$active" == inactive \
    && "$sub" == dead && "$pid" == 0 ]]
}

apply_restored_firewall() {
  [[ -f /etc/nftables.conf && ! -L /etc/nftables.conf ]] || return 1
  nft -c -f /etc/nftables.conf >/dev/null
  nft -f /etc/nftables.conf >/dev/null
  nft -j list ruleset >/dev/null
}

verify_closed_live_firewall() {
  local native_uid
  native_uid="$(id -u native-tunnel)"
  nft -j list ruleset | python3 -c '
import json,sys
uid=int(sys.argv[1]); value=json.load(sys.stdin)
items=value.get("nftables") if isinstance(value,dict) else None
if not isinstance(items,list): raise SystemExit("native_nft_readback_invalid")
tables=[item.get("table") for item in items if isinstance(item,dict)
        and isinstance(item.get("table"),dict)]
if not any(t.get("family")=="inet" and t.get("name")=="filter" for t in tables):
    raise SystemExit("native_nft_filter_table_missing")
chains={c.get("name") for item in items if isinstance(item,dict)
        for c in [item.get("chain")] if isinstance(c,dict)
        and c.get("family")=="inet" and c.get("table")=="filter"}
if not {"input","forward","output"}.issubset(chains):
    raise SystemExit("native_nft_filter_chains_missing")
sets=[item.get("set",{}).get("name") for item in items if isinstance(item,dict)
      and isinstance(item.get("set"),dict)]
if "native_provider_ipv4" in sets:
    raise SystemExit("native_nft_open_set_present")
def contains_key(value,name):
    if isinstance(value,dict):
        return name in value or any(contains_key(v,name) for v in value.values())
    if isinstance(value,list): return any(contains_key(v,name) for v in value)
    return False
def text(value): return json.dumps(value,sort_keys=True,separators=(",",":"))
native_rules=[]; marked_drop=False
for item in items:
    rule=item.get("rule") if isinstance(item,dict) else None
    if not isinstance(rule,dict) or rule.get("family")!="inet" or rule.get("table")!="filter":
        continue
    raw=text(rule)
    if "skuid" in raw and str(uid) in raw: native_rules.append(rule)
    if "ct" in raw and "mark" in raw and contains_key(rule,"drop"): marked_drop=True
if not native_rules or not any(contains_key(rule,"drop") for rule in native_rules):
    raise SystemExit("native_nft_owner_drop_missing")
if any(contains_key(rule,"accept") for rule in native_rules):
    raise SystemExit("native_nft_owner_accept_present")
if not marked_drop: raise SystemExit("native_nft_mark_drop_missing")
' "$native_uid"
}

if [[ -e "$pending" || -L "$pending" ]]; then
  systemctl stop native-opaque-tunnel.service >/dev/null 2>&1 || true
  python3 "$install_transaction" recover --pending "$pending"
  systemctl daemon-reload
  apply_restored_firewall
  service_is_active && { echo "native tunnel active after recovery" >&2; exit 75; }
  python3 "$install_transaction" finalize-recovery --pending "$pending" >/dev/null
  echo "native-egress-gateway:recovered; run deployment again" >&2
  exit 75
fi

[[ ! -e /var/lib/secure-sandbox/native-egress/active.json ]] || {
  echo "An active native-egress grant blocks installation." >&2
  exit 1
}
if service_is_active; then
  echo "native tunnel unexpectedly active before installation" >&2
  exit 1
fi

if ! getent group native-tunnel >/dev/null; then groupadd --system native-tunnel; fi
if ! getent passwd native-tunnel >/dev/null; then
  useradd --system --gid native-tunnel --home-dir /var/empty \
    --shell /usr/sbin/nologin native-tunnel
fi
account="$(getent passwd native-tunnel)"
group="$(getent group native-tunnel)"
IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell <<< "$account"
IFS=: read -r group_name _ group_gid group_members <<< "$group"
identity_groups="$(id -G native-tunnel)"
[[ "$account_name" == native-tunnel && "$group_name" == native-tunnel \
  && "$account_uid" -ne 0 && "$account_gid" == "$group_gid" && "$group_gid" -ne 0 \
  && "$account_home" == /var/empty && "$account_shell" == /usr/sbin/nologin \
  && -z "$group_members" && "$identity_groups" == "$group_gid" ]] || {
  echo "native-tunnel identity is untrusted" >&2
  exit 2
}

install -d -o root -g native-tunnel -m 750 /var/lib/secure-sandbox/native-egress

destinations=(
  /usr/local/libexec/secure-sandbox/native_guest_control.py
  /usr/local/libexec/secure-sandbox/shared/native_egress.py
  /usr/local/libexec/secure-sandbox/shared/__init__.py
  /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py
  /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py
  /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py
  /usr/local/libexec/secure-sandbox/shared/runtime_authority.py
  /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py
  /usr/local/libexec/secure-sandbox/shared/session_context_binding.py
  /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
  /usr/local/libexec/secure-sandbox/native_opaque_tunnel.py
  /etc/systemd/system/native-opaque-tunnel.service
  /etc/secure-sandbox/native-egress-installed
  /etc/secure-sandbox/native-egress-role
  /etc/secure-sandbox/policy.sha256
  /etc/nftables.conf
)
backup_id="native-egress-gateway-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
python3 "$install_transaction" begin --pending "$pending" --backup "$backup" \
  "${destinations[@]}" >/dev/null

rollback_install() {
  trap - ERR HUP INT TERM
  set +e
  local failed=0
  systemctl stop native-opaque-tunnel.service >/dev/null 2>&1 || failed=1
  python3 "$install_transaction" recover --pending "$pending" >/dev/null || failed=1
  systemctl daemon-reload >/dev/null 2>&1 || failed=1
  apply_restored_firewall || failed=1
  service_is_active && failed=1
  if [[ "$failed" -eq 0 ]]; then
    python3 "$install_transaction" finalize-recovery --pending "$pending" >/dev/null || failed=1
  fi
  if [[ "$failed" -ne 0 ]]; then
    echo "native gateway rollback is fenced; durable recovery remains pending" >&2
    return 75
  fi
  return 0
}

trap 'rollback_install' ERR
trap 'rollback_install; exit 70' HUP INT TERM

install -o root -g root -m 755 "$guest_control" /usr/local/libexec/secure-sandbox/native_guest_control.py
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 644 "$native_egress" /usr/local/libexec/secure-sandbox/shared/native_egress.py
install -o root -g root -m 644 "$native_vendor_stack" /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py
install -o root -g root -m 644 "$native_stack_binding" /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py
install -o root -g root -m 644 "$model_stack_binding" /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py
install -o root -g root -m 644 "$runtime_authority" /usr/local/libexec/secure-sandbox/shared/runtime_authority.py
install -o root -g root -m 644 "$harness_binding" /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py
install -o root -g root -m 644 "$session_binding" /usr/local/libexec/secure-sandbox/shared/session_context_binding.py
install -o root -g root -m 755 "$renderer" /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
install -o root -g root -m 755 "$tunnel" /usr/local/libexec/secure-sandbox/native_opaque_tunnel.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/native-opaque-tunnel.service
install -o root -g root -m 600 /dev/null /etc/secure-sandbox/native-egress-role
printf '%s\n' gateway > /etc/secure-sandbox/native-egress-role
install -o root -g root -m 600 /dev/null /etc/secure-sandbox/native-egress-installed
printf '%s\n' secure-sandbox-native-egress-installed-v1 \
  > /etc/secure-sandbox/native-egress-installed

python3 -m py_compile \
  /usr/local/libexec/secure-sandbox/native_guest_control.py \
  /usr/local/libexec/secure-sandbox/shared/native_egress.py \
  /usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py \
  /usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/runtime_authority.py \
  /usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py \
  /usr/local/libexec/secure-sandbox/shared/session_context_binding.py \
  /usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  /usr/local/libexec/secure-sandbox/native_opaque_tunnel.py

systemctl daemon-reload
systemctl disable native-opaque-tunnel.service >/dev/null 2>&1 || true
systemctl stop native-opaque-tunnel.service

policy_temporary="$(mktemp /etc/.nftables.conf.native.XXXXXX)"
trap 'rm -f -- "$policy_temporary"; rollback_install' ERR
/usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  --broker-config /etc/secure-sandbox/broker.json \
  --azure-config /etc/secure-sandbox/azure-shipper.json \
  --archive-config /etc/secure-sandbox/conversation-azure.json \
  --source-config /etc/secure-sandbox/source-acquisition.json \
  --output "$policy_temporary"
chown root:root "$policy_temporary"
chmod 600 "$policy_temporary"
nft -c -f "$policy_temporary"
mv -f -- "$policy_temporary" /etc/nftables.conf
python3 -c 'import os; fd=os.open("/etc",os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)'
nft -f /etc/nftables.conf
verify_closed_live_firewall

service_is_exactly_stopped || {
  echo "native tunnel service readback is not exactly stopped" >&2
  false
}
python3 - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "/usr/local/libexec/secure-sandbox")
from shared import native_egress
assert native_egress.load_install_state(Path("/etc/secure-sandbox/native-egress-installed"))
PY
if [[ -x "$policy_hash" ]]; then "$policy_hash" gateway >/dev/null; fi

python3 "$install_transaction" commit --pending "$pending" >/dev/null
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/native-egress-gateway-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/native-egress-gateway-latest
python3 -c 'import os; fd=os.open("/var/lib/secure-sandbox/policy-backups",os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)'
trap - ERR HUP INT TERM
echo "native-egress-gateway:installed:$backup_id"
