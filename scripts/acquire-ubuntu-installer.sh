#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
release_directory="$root_dir/artifacts/ubuntu-26.04.1"
artifact_name="ubuntu-26.04.1-live-server-arm64.iso"
artifact="$release_directory/$artifact_name"
partial="$release_directory/.$artifact_name.partial"
url="https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/$artifact_name"
verifier="/usr/local/libexec/secure-sandbox-host/current/installer_verifier"
requesting_agent="${SECURE_SANDBOX_REQUESTING_AGENT:-}"
requesting_session="${SECURE_SANDBOX_REQUESTING_SESSION:-}"
while (( $# )); do
  case "$1" in
    --requesting-agent) requesting_agent="${2:-}"; shift 2 ;;
    --requesting-session) requesting_session="${2:-}"; shift 2 ;;
    *) print -u2 "Usage: $0 --requesting-agent NAME --requesting-session ID"; exit 2 ;;
  esac
done
[[ -n "$requesting_agent" && -n "$requesting_session" ]] || {
  print -u2 "Installer publication requires --requesting-agent and --requesting-session."
  exit 2
}

[[ -x "$verifier" && ! -L "$verifier" ]] || {
  print -u2 "Root-owned installer verifier is unavailable."
  exit 1
}
[[ -d "$release_directory" && ! -L "$release_directory" ]] || {
  print -u2 "Installer release directory is unavailable or unsafe."
  exit 1
}

if [[ -e "$artifact" || -L "$artifact" ]]; then
  [[ -f "$artifact" && ! -L "$artifact" ]] || {
    print -u2 "Refusing unsafe installer artifact path."
    exit 1
  }
  "$verifier" --release-directory "$release_directory" >/dev/null || {
    print -u2 "Existing installer artifact is not authentic; refusing to overwrite it."
    exit 1
  }
else
  if [[ -e "$partial" || -L "$partial" ]]; then
    [[ -f "$partial" && ! -L "$partial" && "$(stat -f %u "$partial")" == "$EUID" \
      && "$(stat -f %l "$partial")" == 1 ]] || {
      print -u2 "Refusing unsafe partial installer path."
      exit 1
    }
  else
    (umask 077; : >"$partial")
  fi
  chmod 600 "$partial"
  print "Downloading the pinned Canonical installer (resumable, approximately 2.9 GiB)."
  /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
    --retry 5 --retry-all-errors --continue-at - --output "$partial" "$url"
  chmod 600 "$partial"
  mv "$partial" "$artifact"
  "$verifier" --release-directory "$release_directory" >/dev/null || {
    print -u2 "Downloaded installer failed Canonical signature or SHA-256 verification."
    exit 1
  }
fi

print "Installer bytes match the pinned Canonical signature and SHA-256."
"$root_dir/scripts/installer-operation.py" promote \
  --requesting-agent "$requesting_agent" --requesting-session "$requesting_session"
protected_path="$(/usr/bin/python3 -I "$verifier" \
  --release-directory "$release_directory" --use-promoted --path-only)"
[[ "$protected_path" == /Library/Application\ Support/SecureSandbox/installers/*.iso ]] || {
  print -u2 "Installer verifier returned an invalid protected path."
  exit 1
}
/usr/bin/python3 -I "$verifier" \
  --release-directory "$release_directory" --use-promoted --path-only >/dev/null
"$root_dir/scripts/build-autoinstall-installer.sh" \
  --requesting-agent "$requesting_agent" --requesting-session "$requesting_session"
rm -f "$artifact"
print "Protected installer verified at $protected_path"
print "Protected canonical and reviewed autoinstall images are verified."
print "Removed the redundant mutable workspace copy after protected verification."
