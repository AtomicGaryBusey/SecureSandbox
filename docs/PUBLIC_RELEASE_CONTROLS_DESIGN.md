# Public Release Controls

## Status

Implemented for the `public-release` branch. Deployment-specific repository
identifiers and remote verification evidence remain outside tracked source.

## Objective

Publication must expose only a reviewed, exact Git commit without carrying
installation identifiers, secrets, private evidence, generated signed macOS
artifacts, or alternate Git history. A release artifact must be reproducible
from that commit and have independently verifiable provenance.

## Local fail-before-publication controls

The repository uses `.githooks/pre-commit` to inspect the exact staged index.
`.githooks/pre-push` accepts only a fast-forward update from
`public-release` to `public-release`, rejects deletion and every other ref, and
scans all objects reachable from the outgoing commit. The scanner rejects
private runtime roots, live identifiers, known credential formats, unsupported
blob types, non-placeholder signing identities, non-noreply commit identities,
and any installation-local deny pattern.

`scripts/run-public-release-checks.sh COMMIT` is the canonical exact-candidate
gate. It requires `COMMIT` to equal the clean checked-out `HEAD`, then runs:

1. non-ignored worktree and reachable-history publication scans;
2. Python and shell syntax checks using each tracked script's interpreter;
3. the complete automated unit-test suite; and
4. two independent source-bundle builds followed by byte comparison.

No network access is required by those checks.

## Remote controls

GitHub and the private Forgejo mirror use `public-release` as their sole branch
and default branch. The local pre-push hook is an early safeguard, not a remote
trust boundary. Because hosted CI is temporarily unavailable as an admission
gate, the public GitHub repository is frozen between reviewed publication
ceremonies: active branch and tag rulesets have no bypass actors and deny every
creation, update, and deletion. The branch ruleset also denies non-fast-forward
updates. `scripts/seal-public-github-release.py --apply` creates or updates
those rulesets, enables private vulnerability reporting, and then independently
reads back visibility, default branch, complete branch/tag inventories, exact
tip identity, reporting status, and both exact rulesets.

The repository remains private while controls are established. Changing
visibility is a separate operator decision made only after the exact remote
state and local exact-candidate gate are verified. Immediately after that
change, run the seal command and do not announce or otherwise treat the public
repository as released until its final record reports `status: verified`.
Future publication requires an explicit unseal, exact local gate, push, and
reseal ceremony; ordinary direct pushes are not an accepted public state.
`scripts/publish-public-github-release.py` implements that ceremony for one
fast-forward `public-release` update. It verifies the frozen repository and
remote parent, reruns the exact-candidate gate, disables only the branch
ruleset, pushes the exact reviewed SHA, and restores and verifies the immutable
ruleset in a `finally` path. A failed push still reseals the branch; an
ambiguous API or ref result stops without claiming publication. The tag
ruleset remains active throughout.

## Exact-candidate CI

`.github/workflows/public-release.yml` is explicitly dispatched. Automatic
push and pull-request triggers are intentionally disabled while GitHub-hosted
capacity is unavailable through 2026-11-01; restoring them requires a reviewed
source change. Every external action is pinned to an immutable commit. The
workflow checks that the checkout equals the dispatched commit and invokes the
same canonical local gate. It receives read-only repository contents authority.

After a successful push gate, a separate job builds the deterministic release,
uploads it with bounded retention, and requests GitHub artifact provenance.
Only that job receives the narrowly required OIDC and attestations permissions.
No repository write permission or long-lived signing key is provided.

## Reproducible source release

`scripts/build-public-release.py` resolves one commit, archives only its Git
tree under a fixed prefix, and applies deterministic gzip metadata. It emits:

- `SecureSandbox-source.tar.gz`;
- `SecureSandbox-source.provenance.json`; and
- `SHA256SUMS`.

The provenance document contains no wall-clock build time or host identity. It
binds the archive digest and size to the exact commit, tree, and commit-derived
`SOURCE_DATE_EPOCH`. Existing output is never overwritten. CI proves two builds
of the same commit are byte-identical before attesting the artifacts.

## Acceptance gates

1. The stale Secure Enclave roadmap and evidence text reflects completed live
   expiry and finalization.
2. Common credential formats and private publication material are rejected in
   the worktree, index, and reachable history.
3. The canonical gate passes from a clean exact-candidate checkout.
4. Two release builds from one commit are byte-identical and describe that
   commit and tree.
5. CI actions are commit-pinned and permissions are least-privilege by job.
6. Both remotes contain only `public-release` and name it as default; public
   GitHub has exact no-bypass branch/tag freeze rulesets and private
   vulnerability reporting enabled.
7. The first GitHub workflow run passes for an exact commit before attaching a
   public GitHub Release; hosted execution is deferred through 2026-11-01 and
   is not substituted for the local exact-candidate gate.

## Limitations

GitHub's provenance attestation proves the artifact was built by the identified
workflow from the identified repository event. It does not prove the source is
correct, that the runner was free of every platform compromise, or that a live
SecureSandbox deployment matches the source release. Branch protection also
does not replace local review, publication scanning, or deployment acceptance.
