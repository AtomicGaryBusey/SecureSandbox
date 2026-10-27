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
and default branch. Server-side branch protection denies force-push and branch
deletion while allowing the reviewed direct fast-forward workflow. Requiring a
post-push status as a precondition to the same direct push would be circular;
therefore the local pre-push hook is the admission gate and CI is an independent
post-publication verifier. If the project later adopts pull requests and remote
topic branches, required status checks can become a server-side merge gate.

The repository may remain private while controls are established. Changing
visibility is a separate operator decision made only after the exact remote
state and first successful CI run are verified.

## Exact-candidate CI

`.github/workflows/public-release.yml` runs on each `public-release` update and
on explicit dispatch. Every external action is pinned to an immutable commit.
The workflow checks that the checkout equals the event commit and invokes the
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
6. Both remotes contain only `public-release`, name it as default, and deny
   force-push and deletion.
7. The first GitHub workflow run passes for the exact pushed commit before any
   visibility expansion.

## Limitations

GitHub's provenance attestation proves the artifact was built by the identified
workflow from the identified repository event. It does not prove the source is
correct, that the runner was free of every platform compromise, or that a live
SecureSandbox deployment matches the source release. Branch protection also
does not replace local review, publication scanning, or deployment acceptance.
