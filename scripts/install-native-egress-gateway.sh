#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

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

# Transaction infrastructure is a permanent bootstrap surface. Existing
# objects are never repaired in place: any ownership, mode, or symlink mismatch
# fails before the lock is opened or a deployment source is read.
python3 - <<'PY'
import os,stat
spec=(
 ("/usr/local/libexec/secure-sandbox",0o755),
 ("/usr/local/libexec/secure-sandbox/shared",0o755),
 ("/etc/secure-sandbox",0o755),
 ("/var/lib/secure-sandbox/native-egress-control",0o700),
 ("/var/lib/secure-sandbox/policy-backups",0o700),
 ("/usr/local/libexec/secure-sandbox/native-install-recovery",0o755),
)
for name,mode in spec:
    parent=os.path.dirname(name)
    p=os.lstat(parent)
    if (not stat.S_ISDIR(p.st_mode) or stat.S_ISLNK(p.st_mode)
            or p.st_uid != 0 or p.st_mode & 0o022):
        raise SystemExit(f"native_install_parent_untrusted:{parent}")
    try: os.mkdir(name,mode)
    except FileExistsError: pass
    value=os.lstat(name)
    if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode)
            or value.st_uid != 0 or value.st_gid != 0
            or stat.S_IMODE(value.st_mode) != mode):
        raise SystemExit(f"native_install_directory_untrusted:{name}")
PY

lock=/var/lib/secure-sandbox/native-egress-control/install.lock
guest_lock=/var/lib/secure-sandbox/native-egress-control/.lock
pending=/var/lib/secure-sandbox/native-egress-control/gateway-install.pending.json
if [[ -z "${SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD:-}" ]]; then
  # Bash cannot open a path with O_NOFOLLOW.  Re-exec the installer with a
  # validated, inherited descriptor so the pathname is never reopened.
  exec python3 - "$0" "$lock" "$guest_lock" "$@" <<'PY'
import os,stat,sys
script,install_lock,guest_lock,*arguments=sys.argv[1:]
for path,target in ((guest_lock,8),(install_lock,9)):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    value=os.fstat(fd)
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_gid != 0
            or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o600):
        raise SystemExit("native_install_lock_untrusted")
    if fd != target:
        os.dup2(fd,target,inheritable=True); os.close(fd)
    else:
        os.set_inheritable(fd,True)
environment=dict(os.environ)
environment["SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD"]="9"
environment["SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD"]="8"
os.execve("/bin/bash",["bash",os.path.realpath(script),*arguments],environment)
PY
fi
[[ "$SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD" == 9 \
  && "${SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD:-}" == 8 ]] || {
  echo "native install lock descriptor is invalid" >&2; exit 2;
}
flock -x "$SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD"
flock -x "$SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD"
python3 - "$lock" "$SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD" \
  "$guest_lock" "$SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD" <<'PY'
import os,stat,sys
for index in (1,3):
    path=sys.argv[index]; fd=int(sys.argv[index+1]); opened=os.fstat(fd); current=os.lstat(path)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=0 or opened.st_gid!=0
            or opened.st_nlink!=1 or stat.S_IMODE(opened.st_mode)!=0o600
            or stat.S_ISLNK(current.st_mode)
            or (current.st_dev,current.st_ino)!=(opened.st_dev,opened.st_ino)):
        raise SystemExit("native_install_lock_identity_changed")
PY

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

service_is_quiescent_or_absent() {
  local values load active sub pid
  values="$(systemctl show native-opaque-tunnel.service \
    --property=LoadState --property=ActiveState --property=SubState \
    --property=MainPID 2>/dev/null || true)"
  load="$(printf '%s\n' "$values" | awk -F= '$1=="LoadState"{print $2}')"
  active="$(printf '%s\n' "$values" | awk -F= '$1=="ActiveState"{print $2}')"
  sub="$(printf '%s\n' "$values" | awk -F= '$1=="SubState"{print $2}')"
  pid="$(printf '%s\n' "$values" | awk -F= '$1=="MainPID"{print $2}')"
  [[ "$load" == not-found ]] || {
    [[ "$load" == loaded && "$active" == inactive \
      && "$sub" == dead && "$pid" == 0 ]]
  }
}

service_enabled_state() {
  local value
  value="$(systemctl is-enabled native-opaque-tunnel.service 2>/dev/null || true)"
  case "$value" in
    enabled|disabled|static|not-found) printf '%s\n' "$value" ;;
    *) return 1 ;;
  esac
}

restore_service_enablement() {
  local load="$1" enabled="$2"
  if [[ "$load" == not-found ]]; then
    [[ "$enabled" == not-found ]]
    return
  fi
  [[ "$load" == loaded ]] || return 1
  case "$enabled" in
    enabled) systemctl enable native-opaque-tunnel.service >/dev/null ;;
    disabled) systemctl disable native-opaque-tunnel.service >/dev/null ;;
    static) : ;;
    *) return 1 ;;
  esac
}

verify_service_prestate() {
  local load="$1" enabled="$2" observed
  observed="$(systemctl show native-opaque-tunnel.service \
    --property=LoadState --value 2>/dev/null || true)"
  [[ "$observed" == "$load" ]] || return 1
  if [[ "$load" == loaded ]]; then
    service_is_exactly_stopped && [[ "$(service_enabled_state)" == "$enabled" ]]
  else
    [[ "$load" == not-found && "$enabled" == not-found ]]
  fi
}

restore_identity_prestate() {
  local user_existed="$1" group_existed="$2" directory_existed="$3"
  case "$directory_existed" in
    true)
      [[ -d /var/lib/secure-sandbox/native-egress \
        && ! -L /var/lib/secure-sandbox/native-egress \
        && "$(stat -c %U:%G:%a /var/lib/secure-sandbox/native-egress)" \
          == root:native-tunnel:750 ]] || return 1
      ;;
    false)
      if [[ -e /var/lib/secure-sandbox/native-egress \
        || -L /var/lib/secure-sandbox/native-egress ]]; then
        [[ -d /var/lib/secure-sandbox/native-egress \
          && ! -L /var/lib/secure-sandbox/native-egress ]] || return 1
        rmdir /var/lib/secure-sandbox/native-egress || return 1
      fi
      ;;
    *) return 1 ;;
  esac
  case "$user_existed" in
    true) getent passwd native-tunnel >/dev/null || return 1 ;;
    false)
      if getent passwd native-tunnel >/dev/null; then
        ! pgrep -u native-tunnel >/dev/null 2>&1 || return 1
        userdel native-tunnel || return 1
      fi
      ;;
    *) return 1 ;;
  esac
  case "$group_existed" in
    true) getent group native-tunnel >/dev/null || return 1 ;;
    false)
      if getent group native-tunnel >/dev/null; then
        groupdel native-tunnel || return 1
      fi
      ;;
    *) return 1 ;;
  esac
}

resolve_pending_helper() {
  python3 - "$pending" <<'PY'
import hashlib,json,os,re,stat,sys
path=sys.argv[1]
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
opened=os.fstat(fd); raw=bytearray()
while len(raw)<=262144:
    block=os.read(fd,min(65536,262145-len(raw)))
    if not block: break
    raw.extend(block)
os.close(fd)
if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
        or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600
        or (before.st_dev,before.st_ino,before.st_size)!=(opened.st_dev,opened.st_ino,opened.st_size)
        or len(raw)!=opened.st_size or len(raw)>262144):
    raise SystemExit("native_pending_untrusted")
value=json.loads(raw)
helper=value.get("recovery_helper") if isinstance(value,dict) else None
name=helper.get("path") if isinstance(helper,dict) else None
expected=helper.get("sha256") if isinstance(helper,dict) else None
prefix="/usr/local/libexec/secure-sandbox/native-install-recovery/"
if (not isinstance(name,str)
        or not re.fullmatch(r"[0-9a-f]{64}",str(expected))
        or name != prefix+expected+"/native_install_transaction.py"):
    raise SystemExit("native_recovery_helper_reference_invalid")
hbefore=os.lstat(name)
hfd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
hopened=os.fstat(hfd); hraw=bytearray()
while len(hraw)<=16777216:
    block=os.read(hfd,min(65536,16777217-len(hraw)))
    if not block: break
    hraw.extend(block)
os.close(hfd)
if (not stat.S_ISREG(hopened.st_mode) or hopened.st_uid!=0 or hopened.st_gid!=0
        or hopened.st_nlink!=1 or stat.S_IMODE(hopened.st_mode)!=0o555
        or (hbefore.st_dev,hbefore.st_ino,hbefore.st_size)!=(hopened.st_dev,hopened.st_ino,hopened.st_size)
        or len(hraw)!=hopened.st_size or hashlib.sha256(hraw).hexdigest()!=expected):
    raise SystemExit("native_recovery_helper_untrusted")
print(name)
PY
}

metadata_get() {
  python3 -c 'import json,sys; value=json.load(sys.stdin); item=value["metadata"][sys.argv[1]]; print(str(item).lower() if isinstance(item,bool) else item)' "$1"
}

nft_semantic_sha256() {
  nft -j list ruleset | python3 -c '
import hashlib,json,sys
value=json.load(sys.stdin)
def clean(item):
    if isinstance(item,dict):
        result={}
        for key in sorted(item):
            if key in {"handle","index","position"}: continue
            if key in {"packets","bytes"}: continue
            if key=="metainfo": continue
            result[key]=clean(item[key])
        return result
    if isinstance(item,list): return [clean(v) for v in item]
    return item
raw=json.dumps(clean(value),sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
print(hashlib.sha256(raw).hexdigest())
'
}

install_emergency_barrier() {
  local native_uid
  if ! getent passwd native-tunnel >/dev/null; then return 0; fi
  native_uid="$(id -u native-tunnel)"
  if ! nft -j list table inet secure_sandbox_native_install_fence >/dev/null 2>&1; then
    nft -f - >/dev/null <<EOF
table inet secure_sandbox_native_install_fence {
  chain input {
    type filter hook input priority -300; policy accept;
    ct mark != 0 drop
  }
  chain output {
    type filter hook output priority -300; policy accept;
    meta skuid $native_uid drop
    ct mark != 0 drop
  }
}
EOF
  fi
  nft -j list table inet secure_sandbox_native_install_fence | python3 -c '
import json,sys
uid=int(sys.argv[1]); items=json.load(sys.stdin).get("nftables")
if not isinstance(items,list): raise SystemExit("native_install_fence_invalid")
tables=[item.get("table") for item in items if isinstance(item,dict) and isinstance(item.get("table"),dict)]
if len(tables)!=1 or tables[0].get("family")!="inet" or tables[0].get("name")!="secure_sandbox_native_install_fence":
    raise SystemExit("native_install_fence_invalid")
chains={item["chain"]["name"]:item["chain"] for item in items if isinstance(item,dict)
        and isinstance(item.get("chain"),dict)}
if set(chains)!={"input","output"}: raise SystemExit("native_install_fence_invalid")
for name in chains:
    chain=chains[name]
    if (chain.get("type")!="filter" or chain.get("hook")!=name
            or chain.get("prio")!=-300 or chain.get("policy")!="accept"):
        raise SystemExit("native_install_fence_invalid")
def match(expr,left,op,right):
    value=expr.get("match") if isinstance(expr,dict) else None
    return isinstance(value,dict) and value.get("left")==left and value.get("op")==op and value.get("right")==right
rules=[item.get("rule") for item in items if isinstance(item,dict) and isinstance(item.get("rule"),dict)]
owner=False; marks=set()
for rule in rules:
    expr=rule.get("expr"); expr=expr if isinstance(expr,list) else []
    drops=any(isinstance(value,dict) and set(value)=={"drop"} for value in expr)
    if not drops: raise SystemExit("native_install_fence_invalid")
    if any(match(value,{"meta":{"key":"skuid"}},"==",uid) for value in expr):
        if rule.get("chain")!="output": raise SystemExit("native_install_fence_invalid")
        owner=True
    if any(match(value,{"ct":{"key":"mark"}},"!=",0) for value in expr):
        marks.add(rule.get("chain"))
if not owner or marks!={"input","output"} or len(rules)!=3:
    raise SystemExit("native_install_fence_invalid")
' "$native_uid"
}

apply_restored_firewall() {
  local expected="$1" observed
  [[ -f /etc/nftables.conf && ! -L /etc/nftables.conf ]] || return 1
  nft -c -f /etc/nftables.conf >/dev/null
  nft -f /etc/nftables.conf >/dev/null
  observed="$(nft_semantic_sha256)" || return 1
  [[ "$observed" == "$expected" ]]
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
if len(tables)!=1 or tables[0].get("family")!="inet" or tables[0].get("name")!="filter":
    raise SystemExit("native_nft_table_set_invalid")
chains={c.get("name"):c for item in items if isinstance(item,dict)
        for c in [item.get("chain")] if isinstance(c,dict)
        and c.get("family")=="inet" and c.get("table")=="filter"}
if set(chains)!={"input","forward","output"}:
    raise SystemExit("native_nft_filter_chains_missing")
hooks={"input":"input","forward":"forward","output":"output"}
for name,hook in hooks.items():
    chain=chains[name]
    if (chain.get("type")!="filter" or chain.get("hook")!=hook
            or chain.get("prio") != 0 or chain.get("policy")!="drop"):
        raise SystemExit("native_nft_base_chain_invalid")
sets=[item.get("set",{}).get("name") for item in items if isinstance(item,dict)
      and isinstance(item.get("set"),dict)]
if "native_provider_ipv4" in sets:
    raise SystemExit("native_nft_open_set_present")
def verdict(expr,name): return isinstance(expr,dict) and set(expr)=={name}
def expressions(rule):
    value=rule.get("expr")
    return value if isinstance(value,list) else []
def exact_match(expr,left,op,right):
    match=expr.get("match") if isinstance(expr,dict) else None
    return (isinstance(match,dict) and match.get("op")==op
            and match.get("left")==left and match.get("right")==right)
uid_left={"meta":{"key":"skuid"}}
mark_left={"ct":{"key":"mark"}}
native_drop=False; native_accept=False
marked_drop={"input":False,"output":False}
accept_seen={"input":False,"output":False}
for item in items:
    rule=item.get("rule") if isinstance(item,dict) else None
    if not isinstance(rule,dict) or rule.get("family")!="inet" or rule.get("table")!="filter":
        continue
    expr=expressions(rule)
    if any(isinstance(e,dict) and ("jump" in e or "goto" in e) for e in expr):
        raise SystemExit("native_nft_control_transfer_present")
    owns=any(exact_match(e,uid_left,"==",uid) for e in expr)
    drops=any(verdict(e,"drop") for e in expr)
    accepts=any(verdict(e,"accept") for e in expr)
    chain=rule.get("chain")
    if chain in accept_seen and accepts:
        accept_seen[chain]=True
    if owns and drops:
        if chain!="output" or accept_seen["output"]:
            raise SystemExit("native_nft_owner_drop_order_invalid")
        native_drop=True
    if owns and accepts: native_accept=True
    if drops and any(exact_match(e,mark_left,"!=",0) for e in expr):
        if chain not in marked_drop or accept_seen[chain]:
            raise SystemExit("native_nft_mark_drop_order_invalid")
        marked_drop[chain]=True
if not native_drop:
    raise SystemExit("native_nft_owner_drop_missing")
if native_accept:
    raise SystemExit("native_nft_owner_accept_present")
if set(name for name,present in marked_drop.items() if present)!={"input","output"}:
    raise SystemExit("native_nft_mark_drop_missing")
' "$native_uid"
}

if [[ -e "$pending" || -L "$pending" ]]; then
  recovery_helper="$(resolve_pending_helper)"
  pending_info="$(python3 "$recovery_helper" inspect --pending "$pending")"
  decision="$(printf '%s' "$pending_info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["decision"] or "none")')"
  if [[ "$decision" == commit ]]; then
    python3 "$recovery_helper" commit --pending "$pending" >/dev/null
    echo "native-egress-gateway:commit-reconciled"
    exit 0
  fi
  pre_firewall="$(printf '%s' "$pending_info" | metadata_get pre_firewall_sha256)"
  pre_service_load="$(printf '%s' "$pending_info" | metadata_get pre_service_load)"
  pre_service_enabled="$(printf '%s' "$pending_info" | metadata_get pre_service_enabled)"
  pre_user="$(printf '%s' "$pending_info" | metadata_get native_user_existed)"
  pre_group="$(printf '%s' "$pending_info" | metadata_get native_group_existed)"
  pre_grant_dir="$(printf '%s' "$pending_info" | metadata_get grant_directory_existed)"
  install_emergency_barrier
  systemctl stop native-opaque-tunnel.service >/dev/null 2>&1 || :
  service_is_quiescent_or_absent || {
    echo "native recovery could not prove tunnel quiescence" >&2; exit 75;
  }
  python3 "$recovery_helper" recover --pending "$pending" >/dev/null
  systemctl daemon-reload
  apply_restored_firewall "$pre_firewall"
  restore_service_enablement "$pre_service_load" "$pre_service_enabled"
  verify_service_prestate "$pre_service_load" "$pre_service_enabled"
  restore_identity_prestate "$pre_user" "$pre_group" "$pre_grant_dir"
  python3 "$recovery_helper" finalize-recovery --pending "$pending" >/dev/null
  echo "native-egress-gateway:recovered; run deployment again" >&2
  exit 75
fi

# Snapshot every source from one held descriptor into a root-only bundle. From
# this point onward the installer never resolves the caller-supplied paths.
python3 - <<'PY'
import os,re,stat
root="/var/lib/secure-sandbox"; descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    retained=[name for name in os.listdir(descriptor)
              if re.fullmatch(r"native-install-sources\.[A-Za-z0-9]{8}",name)]
finally: os.close(descriptor)
if len(retained)>=64: raise SystemExit("native_source_snapshot_retention_limit")
PY
source_snapshot="$(mktemp -d /var/lib/secure-sandbox/native-install-sources.XXXXXXXX)"
chmod 700 "$source_snapshot"
trap 'rm -rf -- "$source_snapshot"' EXIT
source_manifest_json="$(python3 - "$source_snapshot" "${sources[@]}" <<'PY'
import hashlib,json,os,stat,sys
root=sys.argv[1]; manifest=[]; total_size=0
for index,name in enumerate(sys.argv[2:]):
    current=os.path.abspath(os.path.dirname(name) or ".")
    while True:
        value=os.lstat(current)
        safe=(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode)
              and value.st_uid==0
              and (not (value.st_mode & 0o022)
                   or (current in {"/tmp","/var/tmp"}
                       and value.st_mode & stat.S_ISVTX)))
        if not safe: raise SystemExit(f"native_source_ancestor_untrusted:{current}")
        if current=="/": break
        current=os.path.dirname(current)
    before=os.lstat(name)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    opened=os.fstat(fd); data=bytearray()
    while len(data)<=16777216:
        block=os.read(fd,min(65536,16777217-len(data)))
        if not block: break
        data.extend(block)
    after=os.fstat(fd); os.close(fd)
    identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid!=0 or opened.st_nlink!=1 or opened.st_mode & 0o022
            or identity(before)!=identity(opened) or identity(opened)!=identity(after)
            or len(data)!=opened.st_size or len(data)>16777216):
        raise SystemExit(f"native_source_untrusted:{name}")
    total_size+=len(data)
    if total_size>67108864: raise SystemExit("native_source_bundle_oversized")
    destination=os.path.join(root,f"source-{index:02d}")
    out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    view=memoryview(data)
    while view:
        view=view[os.write(out,view):]
    os.fchmod(out,stat.S_IMODE(opened.st_mode)); os.fsync(out); os.close(out)
    manifest.append({"index":index,"sha256":hashlib.sha256(data).hexdigest(),
                     "size":len(data),"mode":stat.S_IMODE(opened.st_mode)})
directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(directory); os.close(directory)
print(json.dumps(manifest,sort_keys=True,separators=(",",":")))
PY
)"
source_manifest_sha256="$(printf '%s\n' "$source_manifest_json" | sha256sum | awk '{print $1}')"
guest_control="$source_snapshot/source-00"
native_egress="$source_snapshot/source-01"
shared_init="$source_snapshot/source-02"
renderer="$source_snapshot/source-03"
tunnel="$source_snapshot/source-04"
unit="$source_snapshot/source-05"
policy_hash="$source_snapshot/source-06"
native_vendor_stack="$source_snapshot/source-07"
native_stack_binding="$source_snapshot/source-08"
model_stack_binding="$source_snapshot/source-09"
runtime_authority="$source_snapshot/source-10"
harness_binding="$source_snapshot/source-11"
session_binding="$source_snapshot/source-12"
install_transaction="$source_snapshot/source-13"

PYTHONPYCACHEPREFIX="$source_snapshot/pycache" python3 -m py_compile \
  "$guest_control" "$native_egress" "$renderer" "$tunnel" \
  "$native_vendor_stack" "$native_stack_binding" "$model_stack_binding" \
  "$runtime_authority" "$harness_binding" "$session_binding" \
  "$install_transaction"
systemd-analyze verify "$unit" >/dev/null
[[ -x "$policy_hash" ]] || { echo "native policy hash helper is not executable" >&2; exit 2; }

helper_sha="$(sha256sum "$install_transaction" | awk '{print $1}')"
helper_directory="/usr/local/libexec/secure-sandbox/native-install-recovery/$helper_sha"
recovery_helper="$helper_directory/native_install_transaction.py"
python3 - "$install_transaction" "$helper_sha" "$recovery_helper" <<'PY'
import hashlib,os,re,stat,sys
source,expected,destination=sys.argv[1:]
base="/usr/local/libexec/secure-sandbox/native-install-recovery"
base_info=os.lstat(base)
if (not stat.S_ISDIR(base_info.st_mode) or stat.S_ISLNK(base_info.st_mode)
        or base_info.st_uid!=0 or base_info.st_gid!=0
        or stat.S_IMODE(base_info.st_mode)!=0o755):
    raise SystemExit("native_recovery_store_untrusted")
with open(source,"rb") as handle: raw=handle.read(16777217)
if len(raw)>16777216 or hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit("native_recovery_source_invalid")
base_fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    retained=[name for name in os.listdir(base_fd) if re.fullmatch(r"[0-9a-f]{64}",name)]
    if expected not in retained and len(retained)>=64:
        raise SystemExit("native_recovery_helper_retention_limit")
    try:
        os.mkdir(expected,0o755,dir_fd=base_fd); os.fsync(base_fd)
    except FileExistsError:
        pass
    directory_fd=os.open(expected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                         dir_fd=base_fd)
    try:
        info=os.fstat(directory_fd)
        if (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o755):
            raise SystemExit("native_recovery_directory_untrusted")
        name="native_install_transaction.py"
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                       0o555,dir_fd=directory_fd)
        except FileExistsError:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory_fd)
            opened=os.fstat(fd); observed=bytearray()
            while len(observed)<=16777216:
                block=os.read(fd,min(65536,16777217-len(observed)))
                if not block: break
                observed.extend(block)
            os.close(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=0 or opened.st_gid!=0
                    or opened.st_nlink!=1 or stat.S_IMODE(opened.st_mode)!=0o555
                    or bytes(observed)!=raw):
                raise SystemExit("native_recovery_helper_collision")
        else:
            os.fchown(fd,0,0); os.fchmod(fd,0o555)
            view=memoryview(raw)
            while view: view=view[os.write(fd,view):]
            os.fsync(fd); os.close(fd); os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(base_fd)
PY

[[ ! -e /var/lib/secure-sandbox/native-egress/active.json \
  && ! -L /var/lib/secure-sandbox/native-egress/active.json ]] || {
  echo "An active native-egress grant blocks installation." >&2
  exit 1
}
if ! service_is_quiescent_or_absent; then
  echo "native tunnel unexpectedly active before installation" >&2
  exit 1
fi
if getent passwd native-tunnel >/dev/null; then
  ! pgrep -u native-tunnel >/dev/null 2>&1 || {
    echo "native tunnel identity still owns a live process" >&2; exit 1;
  }
fi

# Prove that every durable replay artifact is understood by both the version
# being installed and the rollback version.  The installer never guesses or
# silently migrates a ledger.
python3 - "$guest_control" "$tunnel" <<'PY'
import ast,hashlib,json,os,pwd,re,sqlite3,stat,sys,uuid
new_guest,new_tunnel=sys.argv[1:]
old_guest="/usr/local/libexec/secure-sandbox/native_guest_control.py"
old_tunnel="/usr/local/libexec/secure-sandbox/native_opaque_tunnel.py"
receipt_schema="secure-sandbox-native-guest-step-receipt-v1"
result_schema="secure-sandbox-native-stack-step-result-v1"
sha=re.compile(r"[0-9a-f]{64}")
receipt_name=re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[a-z][a-z-]{0,62}\.json"
)
def source_supports(path,needle):
    try: tree=ast.parse(open(path,"rb").read())
    except (OSError,SyntaxError): return False
    return any(isinstance(node,ast.Constant) and node.value==needle for node in ast.walk(tree))
def assigned_integer(path,name):
    try: tree=ast.parse(open(path,"rb").read())
    except (OSError,SyntaxError): return None
    for node in tree.body:
        if (isinstance(node,(ast.Assign,ast.AnnAssign))
                and isinstance(node.value,ast.Constant)
                and isinstance(node.value.value,int)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            if any(isinstance(target,ast.Name) and target.id==name for target in targets):
                return node.value.value
    return None
root="/var/lib/secure-sandbox/native-egress-control"
receipts=[]
entries=os.listdir(root)
if len(entries)>8192: raise SystemExit("native_install_state_entry_limit")
receipt_bytes=0
for name in entries:
    if not receipt_name.fullmatch(name): continue
    path=os.path.join(root,name); before=os.lstat(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC); opened=os.fstat(fd)
    raw=bytearray()
    while len(raw)<=262144:
        block=os.read(fd,min(65536,262145-len(raw)))
        if not block: break
        raw.extend(block)
    after=os.fstat(fd); os.close(fd)
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=0 or opened.st_gid!=0
            or opened.st_nlink!=1 or stat.S_IMODE(opened.st_mode)!=0o600
            or identity(before)!=identity(opened) or identity(opened)!=identity(after)
            or len(raw)!=opened.st_size or len(raw)>262144):
        raise SystemExit("native_install_guest_receipt_untrusted")
    receipt_bytes+=len(raw)
    if len(receipts)>=4096 or receipt_bytes>67108864:
        raise SystemExit("native_install_guest_receipt_limit")
    try: value=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError):
        raise SystemExit("native_install_guest_receipt_invalid")
    canonical=(json.dumps(value,allow_nan=False,ensure_ascii=True,
               separators=(",",":"),sort_keys=True)+"\n").encode("ascii")
    result=value.get("result") if isinstance(value,dict) else None
    if (not isinstance(value,dict) or set(value)!={"schema","request_sha256","result"}
            or value.get("schema")!=receipt_schema
            or sha.fullmatch(str(value.get("request_sha256"))) is None
            or canonical!=raw or not isinstance(result,dict)
            or set(result)!={"schema","action_id","plan_sha256","authorization_sha256",
                             "step","status","evidence_sha256"}
            or result.get("schema")!=result_schema or result.get("status")!="verified"
            or any(sha.fullmatch(str(result.get(key))) is None for key in
                   ("plan_sha256","authorization_sha256","evidence_sha256"))):
        raise SystemExit("native_install_guest_receipt_invalid")
    try: parsed=uuid.UUID(str(result.get("action_id")))
    except (ValueError,AttributeError):
        raise SystemExit("native_install_guest_receipt_invalid")
    if parsed.version!=4 or str(parsed)!=result.get("action_id"):
        raise SystemExit("native_install_guest_receipt_invalid")
    # The UUID occupies five hyphen-separated components; the rest is the step.
    parts=name[:-5].split("-"); encoded_action="-".join(parts[:5]); encoded_step="-".join(parts[5:])
    if encoded_action!=result.get("action_id") or encoded_step!=result.get("step"):
        raise SystemExit("native_install_guest_receipt_invalid")
    receipts.append(path)
if receipts and (not source_supports(new_guest,receipt_schema)
                 or not source_supports(old_guest,receipt_schema)):
    raise SystemExit("native_install_guest_receipts_incompatible")

ledger="/var/lib/native-opaque-tunnel/consumption.sqlite3"
if os.path.lexists(ledger):
    if any(os.path.lexists(ledger+suffix) for suffix in ("-journal","-wal","-shm")):
        raise SystemExit("native_install_tunnel_ledger_not_quiescent")
    if (assigned_integer(new_tunnel,"LEDGER_SCHEMA_VERSION")!=1
            or assigned_integer(old_tunnel,"LEDGER_SCHEMA_VERSION")!=1):
        raise SystemExit("native_install_tunnel_ledger_incompatible")
    info=os.lstat(ledger)
    try: expected_uid=pwd.getpwnam("native-tunnel").pw_uid
    except KeyError: raise SystemExit("native_install_tunnel_identity_missing")
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid!=expected_uid or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o600
            or not 1<=info.st_size<=67108864):
        raise SystemExit("native_install_tunnel_ledger_untrusted")
    database=sqlite3.connect(f"file:{ledger}?mode=ro&immutable=1",uri=True)
    try:
        tables={row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        version=database.execute(
            "SELECT schema_version FROM ledger_meta WHERE singleton=1").fetchall()
        active=database.execute("SELECT COALESCE(SUM(active_connections),0) FROM grants").fetchone()
        integrity=database.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error as error:
        raise SystemExit("native_install_tunnel_ledger_invalid") from error
    finally: database.close()
    if tables!={"ledger_meta","grants"} or version!=[(1,)] or active!=(0,) or integrity!=[("ok",)]:
        raise SystemExit("native_install_tunnel_ledger_incompatible")
PY

native_user_existed=false; native_group_existed=false; grant_directory_existed=false
getent passwd native-tunnel >/dev/null && native_user_existed=true
getent group native-tunnel >/dev/null && native_group_existed=true
[[ -d /var/lib/secure-sandbox/native-egress && ! -L /var/lib/secure-sandbox/native-egress ]] \
  && grant_directory_existed=true
if [[ "$native_group_existed" == true ]]; then
  group="$(getent group native-tunnel)"
  IFS=: read -r group_name _ group_gid group_members <<< "$group"
  [[ "$group_name" == native-tunnel && "$group_gid" -ne 0 \
    && -z "$group_members" ]] || {
    echo "native tunnel group prestate is incompatible" >&2; exit 2;
  }
fi
if [[ "$native_user_existed" == true ]]; then
  account="$(getent passwd native-tunnel)"
  IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell <<< "$account"
  [[ "$native_group_existed" == true && "$account_name" == native-tunnel \
    && "$account_uid" -ne 0 && "$account_gid" == "$group_gid" \
    && "$account_home" == /var/empty && "$account_shell" == /usr/sbin/nologin \
    && "$(id -G native-tunnel)" == "$group_gid" ]] || {
    echo "native tunnel identity prestate is incompatible" >&2; exit 2;
  }
fi
if [[ -e /var/lib/secure-sandbox/native-egress \
  || -L /var/lib/secure-sandbox/native-egress ]]; then
  [[ "$grant_directory_existed" == true && "$native_group_existed" == true \
    && "$(stat -c %U:%G:%a /var/lib/secure-sandbox/native-egress)" \
      == root:native-tunnel:750 ]] || {
    echo "native grant directory prestate is incompatible" >&2; exit 2;
  }
fi
pre_service_load="$(systemctl show native-opaque-tunnel.service --property=LoadState --value 2>/dev/null || true)"
[[ "$pre_service_load" == loaded || "$pre_service_load" == not-found ]] || {
  echo "native tunnel service prestate is unsupported" >&2; exit 2;
}
pre_service_enabled="$(service_enabled_state)"
if [[ "$pre_service_load:$pre_service_enabled" != not-found:not-found \
  && "$pre_service_load:$pre_service_enabled" != loaded:enabled \
  && "$pre_service_load:$pre_service_enabled" != loaded:disabled \
  && "$pre_service_load:$pre_service_enabled" != loaded:static ]]; then
  echo "native tunnel enablement prestate is inconsistent" >&2; exit 2
fi
python3 - <<'PY'
import os,stat
path="/etc/nftables.conf"; before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC); opened=os.fstat(fd); os.close(fd)
if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or opened.st_uid!=0 or opened.st_gid!=0 or opened.st_nlink!=1
        or opened.st_mode & 0o022 or not 1<=opened.st_size<=16777216
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)):
    raise SystemExit("native_firewall_prestate_untrusted")
PY
nft -c -f /etc/nftables.conf >/dev/null
pre_firewall_sha256="$(nft_semantic_sha256)"

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
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh
  /etc/systemd/system/native-opaque-tunnel.service
  /etc/secure-sandbox/native-egress-installed
  /etc/secure-sandbox/native-egress-role
  /etc/secure-sandbox/gateway-admin-source-ipv4
  /etc/secure-sandbox/policy.sha256
  /etc/nftables.conf
  /var/lib/secure-sandbox/policy-backups/native-egress-gateway-latest
)
backup_id="native-egress-gateway-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
python3 - <<'PY'
import os,re
root="/var/lib/secure-sandbox/policy-backups"
descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    retained=[name for name in os.listdir(descriptor) if re.fullmatch(
        r"native-egress-gateway-[0-9]{8}T[0-9]{6}Z-[0-9]+",name)]
finally: os.close(descriptor)
if len(retained)>=64: raise SystemExit("native_backup_retention_limit")
PY
metadata="$(python3 - "$pre_firewall_sha256" "$pre_service_load" "$pre_service_enabled" \
  "$native_user_existed" "$native_group_existed" "$grant_directory_existed" \
  "$source_manifest_sha256" "$source_manifest_json" <<'PY'
import json,sys
print(json.dumps({
 "pre_firewall_sha256":sys.argv[1],"pre_service_load":sys.argv[2],
 "pre_service_enabled":sys.argv[3],"native_user_existed":sys.argv[4]=="true",
 "native_group_existed":sys.argv[5]=="true","grant_directory_existed":sys.argv[6]=="true",
 "source_manifest_sha256":sys.argv[7],"source_manifest":json.loads(sys.argv[8]),
 "compatibility":"native-state-v1",
},sort_keys=True,separators=(",",":")))
PY
)"
python3 "$recovery_helper" begin --pending "$pending" --backup "$backup" \
  --recovery-helper "$recovery_helper" --metadata-json "$metadata" \
  "${destinations[@]}" >/dev/null

# On upgrades the identity already exists, so establish the independent live
# fence as the first post-journal mutation.  First installs repeat this
# immediately after creating the previously absent identity.
install_emergency_barrier
if [[ "$native_group_existed" == false ]]; then groupadd --system native-tunnel; fi
if [[ "$native_user_existed" == false ]]; then
  useradd --system --gid native-tunnel --home-dir /var/empty \
    --shell /usr/sbin/nologin native-tunnel
fi
account="$(getent passwd native-tunnel)"; group="$(getent group native-tunnel)"
IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell <<< "$account"
IFS=: read -r group_name _ group_gid group_members <<< "$group"
identity_groups="$(id -G native-tunnel)"
[[ "$account_name" == native-tunnel && "$group_name" == native-tunnel \
  && "$account_uid" -ne 0 && "$account_gid" == "$group_gid" && "$group_gid" -ne 0 \
  && "$account_home" == /var/empty && "$account_shell" == /usr/sbin/nologin \
  && -z "$group_members" && "$identity_groups" == "$group_gid" ]] || false
install_emergency_barrier
if [[ "$grant_directory_existed" == true ]]; then
  [[ "$(stat -c %U:%G:%a /var/lib/secure-sandbox/native-egress)" \
    == "root:native-tunnel:750" ]] || false
else
  mkdir /var/lib/secure-sandbox/native-egress
  chown root:native-tunnel /var/lib/secure-sandbox/native-egress
  chmod 750 /var/lib/secure-sandbox/native-egress
fi

rollback_install() {
  trap - ERR HUP INT TERM
  set +e
  local failed=0
  local info decision
  [[ -e "$pending" && ! -L "$pending" ]] || return 75
  info="$(python3 "$recovery_helper" inspect --pending "$pending" 2>/dev/null)" \
    || return 75
  decision="$(printf '%s' "$info" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["decision"] or "none")' 2>/dev/null)" \
    || return 75
  if [[ "$decision" == commit ]]; then
    python3 "$recovery_helper" commit --pending "$pending" >/dev/null || return 75
    return 0
  fi
  install_emergency_barrier || return 75
  systemctl stop native-opaque-tunnel.service >/dev/null 2>&1 || :
  service_is_quiescent_or_absent || failed=1
  if [[ "$failed" -eq 0 ]]; then
    python3 "$recovery_helper" recover --pending "$pending" >/dev/null || failed=1
  fi
  if [[ "$failed" -eq 0 ]]; then
    systemctl daemon-reload >/dev/null 2>&1 || failed=1
  fi
  if [[ "$failed" -eq 0 ]]; then
    apply_restored_firewall "$pre_firewall_sha256" || failed=1
  fi
  if [[ "$failed" -eq 0 ]]; then
    restore_service_enablement "$pre_service_load" "$pre_service_enabled" || failed=1
    verify_service_prestate "$pre_service_load" "$pre_service_enabled" || failed=1
    restore_identity_prestate "$native_user_existed" "$native_group_existed" \
      "$grant_directory_existed" || failed=1
  fi
  if [[ "$failed" -eq 0 ]]; then
    python3 "$recovery_helper" finalize-recovery --pending "$pending" >/dev/null || failed=1
  fi
  if [[ "$failed" -ne 0 ]]; then
    echo "native gateway rollback is fenced; durable recovery remains pending" >&2
    return 75
  fi
  return 0
}

policy_temporary=""
remove_policy_temporary() {
  if [[ -n "$policy_temporary" \
    && "$policy_temporary" == /etc/.nftables.conf.native.* ]]; then
    rm -f -- "$policy_temporary"
  fi
}
installation_failed() {
  local status=$?
  trap - ERR HUP INT TERM
  remove_policy_temporary
  if rollback_install; then exit "$status"; else exit 75; fi
}
installation_interrupted() {
  trap - ERR HUP INT TERM
  remove_policy_temporary
  if rollback_install; then exit 70; else exit 75; fi
}
trap installation_failed ERR
trap installation_interrupted HUP INT TERM

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
install -o root -g root -m 755 "$policy_hash" /usr/local/libexec/secure-sandbox/update-policy-hash.sh
install -o root -g root -m 644 "$unit" /etc/systemd/system/native-opaque-tunnel.service
install -o root -g root -m 600 /dev/null /etc/secure-sandbox/native-egress-role
printf '%s\n' gateway > /etc/secure-sandbox/native-egress-role
install -o root -g root -m 600 /dev/null /etc/secure-sandbox/native-egress-installed
printf '%s\n' secure-sandbox-native-egress-installed-v1 \
  > /etc/secure-sandbox/native-egress-installed

systemctl daemon-reload
systemctl disable native-opaque-tunnel.service >/dev/null
systemctl stop native-opaque-tunnel.service
service_is_exactly_stopped
[[ "$(service_enabled_state)" == disabled ]]

policy_temporary="$(mktemp /etc/.nftables.conf.native.XXXXXX)"
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
policy_temporary=""
python3 -c 'import os; fd=os.open("/etc",os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)'
nft -f /etc/nftables.conf
verify_closed_live_firewall
closed_firewall_sha256="$(nft_semantic_sha256)"
[[ "$(nft_semantic_sha256)" == "$closed_firewall_sha256" ]]

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
"$policy_hash" gateway >/dev/null
[[ "$(stat -c %U:%G:%a /etc/secure-sandbox/policy.sha256)" == root:root:644 ]]
grep -Eq '^[0-9a-f]{64}$' /etc/secure-sandbox/policy.sha256

installed_pairs=(
  "$guest_control|/usr/local/libexec/secure-sandbox/native_guest_control.py|755"
  "$native_egress|/usr/local/libexec/secure-sandbox/shared/native_egress.py|644"
  "$shared_init|/usr/local/libexec/secure-sandbox/shared/__init__.py|644"
  "$native_vendor_stack|/usr/local/libexec/secure-sandbox/shared/native_vendor_stack.py|644"
  "$native_stack_binding|/usr/local/libexec/secure-sandbox/shared/native_stack_runtime_binding.py|644"
  "$model_stack_binding|/usr/local/libexec/secure-sandbox/shared/model_stack_runtime_binding.py|644"
  "$runtime_authority|/usr/local/libexec/secure-sandbox/shared/runtime_authority.py|644"
  "$harness_binding|/usr/local/libexec/secure-sandbox/shared/harness_runtime_binding.py|644"
  "$session_binding|/usr/local/libexec/secure-sandbox/shared/session_context_binding.py|644"
  "$renderer|/usr/local/libexec/secure-sandbox/render_gateway_firewall.py|755"
  "$tunnel|/usr/local/libexec/secure-sandbox/native_opaque_tunnel.py|755"
  "$policy_hash|/usr/local/libexec/secure-sandbox/update-policy-hash.sh|755"
  "$unit|/etc/systemd/system/native-opaque-tunnel.service|644"
)
python3 - "${installed_pairs[@]}" <<'PY'
import ipaddress,os,stat,sys
for encoded in sys.argv[1:]:
    source,destination,mode_text=encoded.split("|"); expected_mode=int(mode_text,8)
    source_raw=open(source,"rb").read()
    before=os.lstat(destination)
    fd=os.open(destination,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    opened=os.fstat(fd); raw=bytearray()
    while len(raw)<=16777216:
        block=os.read(fd,min(65536,16777217-len(raw)))
        if not block: break
        raw.extend(block)
    after=os.fstat(fd); os.close(fd)
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid!=0 or opened.st_gid!=0 or opened.st_nlink!=1
            or stat.S_IMODE(opened.st_mode)!=expected_mode
            or identity(before)!=identity(opened) or identity(opened)!=identity(after)
            or bytes(raw)!=source_raw):
        raise SystemExit("native_installed_file_readback_failed:"+destination)
for path,mode,raw in (
    ("/etc/secure-sandbox/native-egress-role",0o600,b"gateway\n"),
    ("/etc/secure-sandbox/native-egress-installed",0o600,
     b"secure-sandbox-native-egress-installed-v1\n"),
):
    info=os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=mode or open(path,"rb").read()!=raw):
        raise SystemExit("native_installed_marker_readback_failed:"+path)
admin="/etc/secure-sandbox/gateway-admin-source-ipv4"; info=os.lstat(admin)
try: address=open(admin,"r",encoding="ascii").read(64).strip()
except (OSError,UnicodeError): raise SystemExit("native_admin_source_readback_failed")
try: parsed=ipaddress.ip_address(address)
except ValueError: raise SystemExit("native_admin_source_readback_failed")
if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1
        or stat.S_IMODE(info.st_mode)!=0o600 or parsed.version!=4):
    raise SystemExit("native_admin_source_readback_failed")
PY

latest=/var/lib/secure-sandbox/policy-backups/native-egress-gateway-latest
python3 - "$latest" "$backup_id" <<'PY'
import os,stat,sys,uuid
path,value=sys.argv[1:]; parent=os.path.dirname(path); name=os.path.basename(path)
parent_info=os.lstat(parent)
if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid!=0 or parent_info.st_gid!=0
        or stat.S_IMODE(parent_info.st_mode)!=0o700):
    raise SystemExit("native_latest_parent_untrusted")
directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
temporary=f".{name}.{uuid.uuid4()}.tmp"; raw=(value+"\n").encode("ascii")
try:
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
               0o600,dir_fd=directory)
    try:
        os.fchown(fd,0,0); os.fchmod(fd,0o600)
        view=memoryview(raw)
        while view: view=view[os.write(fd,view):]
        os.fsync(fd)
    finally: os.close(fd)
    os.rename(temporary,name,src_dir_fd=directory,dst_dir_fd=directory); os.fsync(directory)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
    try: info=os.fstat(fd); observed=os.read(fd,4096)
    finally: os.close(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
            or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or observed!=raw):
        raise SystemExit("native_latest_readback_failed")
finally:
    try: os.unlink(temporary,dir_fd=directory)
    except FileNotFoundError: pass
    os.close(directory)
PY

# The commit decision is the point of no return.  Once it is durable, recovery
# may only finish the commit, never restore the old installation.
trap - ERR HUP INT TERM
python3 "$recovery_helper" commit --pending "$pending" >/dev/null
echo "native-egress-gateway:installed:$backup_id"
