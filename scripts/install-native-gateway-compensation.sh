#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

[[ "$(id -u)" -eq 0 && "$(id -g)" -eq 0 && "$#" -eq 0 ]] || {
  echo native_gateway_compensation_authority_invalid >&2
  exit 64
}
for path in \
  /tmp/native_install_transaction.py \
  /tmp/native_deployment.py \
  /tmp/native_gateway_compensation.py \
  /tmp/native-deployment-plan.json \
  /tmp/install-native-egress-gateway.sh; do
  [[ -f "$path" && ! -L "$path" ]] || {
    echo native_gateway_compensation_payload_invalid >&2
    exit 2
  }
done

if [[ -z "${SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD:-}" \
  && -z "${SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD:-}" ]]; then
  exec python3 -I /tmp/native_gateway_compensation.py lock-exec
fi
[[ "${SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD:-}" == 9 \
  && "${SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD:-}" == 8 ]] || {
  echo native_gateway_compensation_lock_authority_invalid >&2
  exit 2
}
flock -x "$SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD"
flock -x "$SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD"
python3 - "$SECURE_SANDBOX_NATIVE_INSTALL_LOCK_FD" \
  "$SECURE_SANDBOX_NATIVE_GUEST_LOCK_FD" <<'PY'
import os,stat,sys
paths=("/var/lib/secure-sandbox/native-egress-control/install.lock",
       "/var/lib/secure-sandbox/native-egress-control/.lock")
for path,number in zip(paths,map(int,sys.argv[1:])):
    opened=os.fstat(number); current=os.lstat(path)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=0 or opened.st_gid!=0
            or opened.st_nlink!=1 or stat.S_IMODE(opened.st_mode)!=0o600
            or stat.S_ISLNK(current.st_mode)
            or (opened.st_dev,opened.st_ino)!=(current.st_dev,current.st_ino)):
        raise SystemExit("native_gateway_compensation_lock_untrusted")
PY

# Arm the retained exact preimage before the ordinary installer performs its
# already hardened, crash-replayable recovery path.
python3 -I /tmp/native_gateway_compensation.py
set +e
/bin/bash /tmp/install-native-egress-gateway.sh >/dev/null 2>&1
status=$?
set -e
[[ "$status" -eq 75 \
  && ! -e /var/lib/secure-sandbox/native-egress-control/gateway-install.pending.json \
  && ! -L /var/lib/secure-sandbox/native-egress-control/gateway-install.pending.json ]] || {
  echo native_gateway_compensation_incomplete >&2
  exit 75
}
printf '%s\n' '{"schema":"secure-sandbox-native-gateway-compensation-result-v1","status":"prior-restored"}'
