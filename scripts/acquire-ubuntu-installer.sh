#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
release_directory="$root_dir/artifacts/ubuntu-26.04.1"
artifact_name="ubuntu-26.04.1-live-server-arm64.iso"
artifact="$release_directory/$artifact_name"
partial="$release_directory/.$artifact_name.partial"
url="https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/$artifact_name"
signature_name="SHA256SUMS.gpg"
signature="$release_directory/$signature_name"
signature_url="https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/$signature_name"
signature_sha256="bfa9b6e8b87298c3dfed6310029e370c4bd5f553175fb2c57705cd11bfb84086"
keyring_name="ubuntu-archive-keyring.gpg"
keyring="$release_directory/$keyring_name"
keyring_url="https://archive.ubuntu.com/ubuntu/project/$keyring_name"
keyring_sha256="80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
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

acquire_verification_input() {
  # `path` is zsh's array tied to PATH.  Never use it as a local variable:
  # doing so silently replaces command lookup for the duration of this
  # function, which made clean-host acquisition fail before authorization.
  local destination_path="$1" input_url="$2" expected_sha256="$3" maximum_bytes="$4"
  local name="${destination_path:t}" actual size temporary
  if [[ -e "$destination_path" || -L "$destination_path" ]]; then
    [[ -f "$destination_path" && ! -L "$destination_path" \
      && "$(/usr/bin/stat -f %u "$destination_path")" == "$EUID" \
      && "$(/usr/bin/stat -f %l "$destination_path")" == 1 ]] || {
      print -u2 "Refusing unsafe existing verification input: $name"
      return 1
    }
    size="$(/usr/bin/stat -f %z "$destination_path")"
    (( size > 0 && size <= maximum_bytes )) || {
      print -u2 "Existing verification input has an invalid size: $name"
      return 1
    }
    actual="$(/usr/bin/shasum -a 256 "$destination_path" | /usr/bin/awk '{print $1}')"
    [[ "$actual" == "$expected_sha256" ]] || {
      print -u2 "Existing verification input differs from the reviewed bytes: $name"
      return 1
    }
    return 0
  fi

  temporary="$(/usr/bin/mktemp "$release_directory/.verification-input.XXXXXX")" || {
    print -u2 "Could not reserve a private verification-input download."
    return 1
  }
  /bin/chmod 600 "$temporary"
  print "Downloading reviewed public verification input: $name"
  /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
    --retry 5 --retry-all-errors --max-filesize "$maximum_bytes" \
    --output "$temporary" "$input_url" || {
    print -u2 "Verification-input download failed; retained private partial: ${temporary:t}"
    return 1
  }
  size="$(/usr/bin/stat -f %z "$temporary")"
  (( size > 0 && size <= maximum_bytes )) || {
    print -u2 "Downloaded verification input has an invalid size; retained private partial: ${temporary:t}"
    return 1
  }
  actual="$(/usr/bin/shasum -a 256 "$temporary" | /usr/bin/awk '{print $1}')"
  [[ "$actual" == "$expected_sha256" ]] || {
    print -u2 "Downloaded verification input differs from the reviewed bytes; retained private partial: ${temporary:t}"
    return 1
  }

  /usr/bin/python3 -I - "$temporary" "$destination_path" <<'PY'
import ctypes
import os
import stat
import sys

source, destination = sys.argv[1:]
opened = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(opened)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise SystemExit("verification_input_temporary_identity_invalid")
    os.fsync(opened)
finally:
    os.close(opened)

libc = ctypes.CDLL(None, use_errno=True)
renameatx_np = libc.renameatx_np
renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p,
                         ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameatx_np.restype = ctypes.c_int
AT_FDCWD = -2
RENAME_EXCL = 0x00000004
if renameatx_np(AT_FDCWD, os.fsencode(source), AT_FDCWD,
                os.fsencode(destination), RENAME_EXCL) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), destination)
directory = os.open(os.path.dirname(destination), os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  acquire_verification_input "$destination_path" "$input_url" "$expected_sha256" "$maximum_bytes"
}

# These are public trust inputs, not credentials. A clean public checkout
# deliberately does not carry ignored binary .gpg files, so acquire their exact
# reviewed bytes before asking the protected verifier to authenticate the
# tracked manifest and pinned Canonical installer.
acquire_verification_input "$signature" "$signature_url" "$signature_sha256" 65536
acquire_verification_input "$keyring" "$keyring_url" "$keyring_sha256" 1048576

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
    [[ -f "$partial" && ! -L "$partial" \
      && "$(/usr/bin/stat -f %u "$partial")" == "$EUID" \
      && "$(/usr/bin/stat -f %l "$partial")" == 1 ]] || {
      print -u2 "Refusing unsafe partial installer path."
      exit 1
    }
  else
    (umask 077; : >"$partial")
  fi
  /bin/chmod 600 "$partial"
  print "Downloading the pinned Canonical installer (resumable, approximately 2.9 GiB)."
  /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
    --retry 5 --retry-all-errors --continue-at - --output "$partial" "$url"
  /bin/chmod 600 "$partial"
  /bin/mv "$partial" "$artifact"
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
/bin/rm -f "$artifact"
print "Protected installer verified at $protected_path"
print "Protected canonical and reviewed autoinstall images are verified."
print "Removed the redundant mutable workspace copy after protected verification."
