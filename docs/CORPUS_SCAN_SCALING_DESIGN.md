# Large-corpus fixed-profile scan scaling

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## 1. Problem statement

The fixed `internal_hostnames` profile completed over a 10 MB OSWorld corpus
but reproducibly reached the existing 30-second fail-closed deadline over the
305 MB large documentation corpus corpus. The rejection was safe and explicit, but it
prevented an exhaustive result from an otherwise valid immutable index.

## 2. Measured cause

A production-path baseline stopped at exactly 30 seconds with
`query_timeout`. A bounded diagnostic run with the deadline raised only for
measurement completed all 52,170 documents and 305,377,443 bytes in 50.664
seconds, producing 639 matches and result digest
the pinned profile digest.

Individual rules completed in 4.286, 5.111, 20.049, and 7.513 seconds. This
rules out a single catastrophic expression. The dominant waste is invoking
all four expressions for every line even when their required fixed literals
are absent.

## 3. Decision

Keep the 30-second hard limit and add operator-owned literal prefilters for the
four `internal_hostnames` rules. Each prefilter is a conservative superset of
its regex:

- private IPv4: `10.`, `192.168.`, or `172.`;
- loopback: `localhost`, `127.`, or `::1`;
- internal DNS: `.corp`, `.internal`, `.intranet`, `.lan`, or `.local`;
- organization-specific development domains configured by a private profile.

A regex is skipped only when none of its required literals occurs on the line.
The caller cannot add or change prefilters. Regex definitions, flags, and
prefilters are bound into `PROFILE_VERSION`, and the engine version advances to
1.2.0 while retaining explicit read compatibility with 1.0.0 and 1.1.0
indexes.

This is preferable to increasing the global compute budget or adding a
long-lived asynchronous job surface. If later corpora still exceed the hard
limit after safe optimization, resumable root-owned scan jobs can receive a
separate design review.

## 4. Failure and telemetry behavior

Timeouts remain rejected and fail closed. A timeout response now includes only
safe operational progress:

- `exhaustive: false`;
- files and bytes examined;
- elapsed milliseconds;
- the fixed query budget.

It never includes partial matches, paths, snippets, or source content. The same
fields enter normalized telemetry so an operator can distinguish corpus growth
from a malfunction without treating a partial result as evidence.

Successful fixed-profile responses include elapsed time and the fixed budget,
alongside their existing exact counts and sealed result digest.

## 5. Security invariants

1. The 30-second deadline remains unchanged.
2. No shell, network, arbitrary path, custom regex, or source-execution surface
   is added.
3. Prefilters are immutable operator code and cannot create matches.
4. Every actual match is still produced by the original regex.
5. Tests prove a representative regex match necessarily passes each literal
   gate.
6. Timeout output is explicitly non-exhaustive and contains no candidate
   finding data.
7. Existing immutable indexes remain readable; newly built indexes record the
   new engine and profile versions.

## 6. Acceptance gates

- all Research unit tests pass;
- prefilter-superset and safe-timeout-response tests pass;
- the production large documentation corpus scan completes within 30 seconds;
- its 639 matches, category counts, and result digest equal the measured
  unoptimized exhaustive baseline;
- local and off-host telemetry contain timing/progress metadata but no content;
- the complete containment suite passes;
- the installer rollback bundle is verified before returning the environment
  to the agent.

## 7. Rollback

Use the rollback identifier emitted by `deploy-corpus-intelligence.sh` with
`/usr/local/libexec/secure-sandbox/rollback_corpus_intelligence.sh`. Rollback
restores the prior corpus engine, MCP adapter, telemetry normalizer, managed
policy, and MCP configuration. Immutable sources and indexes are retained.

## 8. Deployment evidence

Live corpus measurements, release generations, and recovery points are retained in ignored local records.
