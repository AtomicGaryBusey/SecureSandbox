# Build prerequisites and readiness

Run these checks from the repository root before choosing a workflow. They inspect
tools and configuration; they do not install software, build a product, start a
VM, or request authorization. A passing tool check does not establish a signed
release or disposable-Mac campaign verdict.

## 1. Source and public-release checks

| Need | Install or provide | Read-only check |
| --- | --- | --- |
| Git and a complete `public-release` checkout | Git, with this repository checked out at the reviewed commit | `git --version`; `git branch --show-current`; `git rev-parse --is-shallow-repository`; `git status --short` |
| Python 3.10 or newer and the macOS command-line shell tools | Put a compatible `python3` on `PATH` for source and release checks, and provide Bash and Zsh. This Neo's `/usr/bin/python3` is 3.9.6; its Homebrew Python 3.12 is available in a new login shell. | `command -v python3`; `python3 --version` (expect 3.10 or newer); `/bin/bash --version`; `/bin/zsh --version` |

`scripts/run-public-release-checks.sh` rejects older Python, then runs compilation, shell syntax
checks, unit tests, and deterministic source-package construction against the
exact checked-out commit. It is a validation run, not a prerequisite probe; it
creates temporary files and can take time. Remote CI and signed provenance are
separate publication gates in [the roadmap](TODO.md#public-release-controls).
The PKI tests invoke the first `openssl` on `PATH`; macOS's `/usr/bin/openssl`
is LibreSSL and fails their Ed25519 operations. Put the OpenSSL 3 installation
ahead of `/usr/bin` when running the checks. The harness acceptance tests
additionally enforce the MacPorts trust pin described below.

## 2. Local Control Center build

| Need | Install or provide | Read-only check |
| --- | --- | --- |
| macOS and Apple Silicon | A Mac capable of running the app's macOS 27.0 minimum | `/usr/bin/sw_vers -productVersion`; `/usr/bin/uname -m` (expect `arm64`) |
| Full Xcode and developer directory | Xcode with Swift 6.4 support and the macOS 27 SDK; select that Xcode with `xcode-select` or set `DEVELOPER_DIR` for each build command | `/usr/bin/xcode-select -p` shows the default; under the selected or explicitly set developer directory, check `/usr/bin/xcodebuild -version`, `/usr/bin/swift --version`, `/usr/bin/xcrun --find actool`, and `/usr/bin/xcrun --show-sdk-version --sdk macosx` |
| SwiftTerm package source | Network access for Swift Package Manager's first fetch, or an already populated compatible cache; the revision is pinned in `macos/ControlCenter/Package.swift` | Inspect `macos/ControlCenter/Package.swift` and `Package.resolved` for the pinned SwiftTerm revision |

The package declares Swift tools 6.4 and macOS 27. The build script uses
`/usr/bin/swift`, `xcrun actool`, and `codesign`. For a local unsigned release
workflow, it signs the app ad hoc. To build without opening the app, run
`macos/ControlCenter/script/build_and_run.sh --build-only` after the checks.
That command writes build output and may fetch the pinned dependency.
An installed Xcode is not ready if its license has not been accepted: `xcrun`
may refuse `actool` even when `xcodebuild -version` prints a version. Review
and accept the license in Terminal as the Mac's operator, then repeat the
tool checks. Selecting Xcode is a machine-wide developer-directory change;
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` can be used for an
individual diagnostic without changing that selection.

For a package-only compile check without creating `.build` or `dist` in the
checkout, use a fresh temporary scratch directory:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  /usr/bin/swift build --package-path macos/ControlCenter \
  --scratch-path /private/tmp/secure-sandbox-control-center-check -c debug
```

The first run may fetch the pinned Swift dependencies. A successful compile
checks the Swift toolchain and package source; the app-bundle builder must
still compile the icon and sign the bundle before installation readiness.
To verify that separate bundle step without launching the app, run:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  SECURE_SANDBOX_SWIFT_SCRATCH_PATH=/private/tmp/secure-sandbox-control-center-check \
  macos/ControlCenter/script/build_and_run.sh --build-only
```

This writes an ad hoc signed `.app` under `macos/ControlCenter/dist`; it does
not produce a Developer ID signed or notarized release.

## 3. Developer ID release build

This path is for the trusted release-build Mac. The disposable acceptance Mac
must not receive production signing or notarization credentials.

| Need | Install or provide | Read-only check |
| --- | --- | --- |
| Full Xcode toolchain | Xcode, including `xcodebuild`, `notarytool`, and `stapler` | `/usr/bin/xcodebuild -version`; `/usr/bin/xcrun --find notarytool`; `/usr/bin/xcrun --find stapler` |
| Exact Developer ID Application signing identity for the fixed project team | Install the intended certificate and private key in the release operator's Keychain; configure the SHA-1 pin required by the release build | `/usr/bin/security find-identity -v -p codesigning` (verify one matching Developer ID Application identity for team `389K3H8Y32`; do not paste the full output into public records) |
| Notarization profile and trusted Keychain | Configure the profile and Keychain expected by `scripts/build-native-host-products.sh` | Check that `SECURE_SANDBOX_DEVELOPER_ID`, `SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE`, and `SECURE_SANDBOX_NOTARY_KEYCHAIN` name the intended inputs. The build performs the authoritative identity, Keychain, and notarization checks. |

The native host build also invokes the Touch ID UI and native credential
component builders. Its release path performs signing and notarization; a
version print or certificate listing alone cannot prove those services will
accept the candidate. See [the release-build design](PROTECTED_RELEASE_BUILD_PRINCIPAL_SIGNING_CUSTODY_DESIGN.md)
before using release credentials.

## 4. Disposable-Mac harness acceptance

This is an installation and physical-evidence workflow, not a local source
build. Use a freshly erased dedicated Mac with a new local test account and no
production provider, 1Password, cloud, or research sign-in. The checkout must
be clean on `public-release` at the exact reviewed public GitHub tip. The
private Hobby Forgejo credential stays on the trusted publication Mac.

| Need | Install or provide | Read-only check |
| --- | --- | --- |
| Enough physical memory for the selected three-VM layout | The published `standard` layout allocates 2 GiB Gateway, 6 GiB Research, and 4 GiB Target, or 12 GiB before host overhead. An unqualified source candidate named `neo-8gb` allocates 5.5 GiB total. | `/usr/sbin/sysctl -n hw.memsize`; compare with `LAYOUTS` in `scripts/vm-maintenance.py` and [the Neo qualification design](MACBOOK_NEO_VM_LAYOUT_DESIGN.md). An 8 GB host rejects the standard layout; the Neo candidate remains unusable for an accepted install until physically qualified. |
| Enough disk space for guests and evidence | The current provisioning code requests 12 GiB Gateway, 50 GiB Research, and 40 GiB Target virtual disks, plus installer media, snapshots, build output, and evidence. | `df -h .`; inspect the actual VM storage location and budget for snapshots before provisioning. Virtual disk sizes are not a guaranteed physical free-space requirement. |
| Parallels Desktop and its CLI | Install and initialize Parallels Desktop. An empty inventory is accepted only by the pre-install Host bootstrap gate; the campaign gate requires Gateway, Research, and Target. | `command -v prlctl`; `prlctl list -a --json` must be readable with the GUI closed; after provisioning, verify all three expected VMs. |
| MacPorts OpenSSL 3 for harness signature verification | Install MacPorts for macOS 27 and its `openssl` shim port, which depends on `openssl3`. The verifier requires the root-owned `/opt/local/bin/openssl` link to resolve to `/opt/local/libexec/openssl3/bin/openssl`; Homebrew OpenSSL does not satisfy that trust pin. | `test -x /opt/local/bin/port`; `/opt/local/bin/port installed openssl openssl3`; `realpath /opt/local/bin/openssl` (expect `/opt/local/libexec/openssl3/bin/openssl`) |
| Host toolchain and Git | macOS system Git, Python 3.10 or newer for source checks, and the full Xcode toolchain needed by the exact protected release | Run the source and Xcode checks above; check `/usr/bin/git --version` and the selected `python3 --version` |
| No production material | No provider credential environment, production state paths, or Agents Keychain service credential | The enrollment and morning-preflight scripts perform the project-defined checks; a manual environment inspection is not a substitute |
| Exact protected acceptance release | Install only after the enrollment and morning preflight have established the exact next action | The morning preflight reports source and protected driver counts and the permitted next action; a checkout alone has zero physically available drivers |
| Transferable signed native-Host candidate | Export one v3 candidate directory from the trusted release Mac. It contains signed/notarized public artifacts, bounded Apple notarization evidence, the source archive, and Host-release preimage—not a Developer ID key, notarization credential, provider token, or 1Password credential. | Run `python3 scripts/deploy-host-controller.py stage-native-host-candidate /absolute/path/to/CANDIDATE_DIRECTORY`; require the verified transfer schema, then review the exact candidate bindings in the separate first-install bootstrap ceremony. |

Follow [the disposable-Mac operator queue](DISPOSABLE_MAC_OPERATOR_CEREMONY_QUEUE.md)
in order. Its enrollment command creates a private receipt. Its subsequent
morning preflight is read-only, but requires that receipt and performs a live
public-tip check. Do not run the installer, ask for a root password, or invoke
Touch ID until that gate names the corresponding next action. Installation,
campaign initialization, VM power changes, and the 11 Touch ID cases are
separate later steps. Physical acceptance still requires the complete ordered
campaign and independent off-machine evidence verification.

The gate requires a clean checkout. Uncommitted documentation changes also
make it fail; retain them outside the campaign checkout and use the exact
reviewed public commit. The production-material exclusion includes `.claude`,
`.gemini`, `.config/op`, and `.config/gh/hosts.yml` under the test account's
home. Do not delete or move an existing operator's data merely to pass this
check. Use the fresh disposable test account and machine state specified by
the acceptance design.

The current 8 GB MacBook Neo configuration cannot be declared ready for the
selected VM layout merely because Parallels is installed or disk space is
available. [The Neo candidate design](MACBOOK_NEO_VM_LAYOUT_DESIGN.md)
defines the physical qualification needed. The provisioning contract and
focused source tests now cover the candidate; measure memory pressure and complete
physical boundary acceptance before treating that layout as supported. Do not
silently reduce the three VM allocations to pass a preflight.

## Scope of this guide

The host tool checks above cover source validation, the native macOS build,
release signing, and the currently queued disposable-Mac campaign. Guest
provisioning and production operations have additional configuration and
external-service requirements in [the implementation overview](IMPLEMENTATION.md)
and their linked designs. A missing version or unavailable SDK should be
resolved against the package manifest and build script before installation;
this guide does not assert an unverified Xcode version number.
