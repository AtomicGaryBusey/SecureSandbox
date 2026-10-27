# Azure alert-semantics separation

Status: **implemented design**. Deployment state and acceptance evidence are private.
Decision owner: lab operator

## Decision

Replace the generic “any deny” Sev1 classification with two explicit rules:

1. Sev1 for missing Gateway/Research heartbeats and enumerated containment,
   policy, high-risk tool-intent, or evidence-pipeline failures.
2. Sev3 for sustained model-provider availability failure: at least three
   `upstream_failed` events in 15 minutes with no later `request_complete`.
3. Sev2 for Azure ingestion warnings or errors, including daily-cap and
   ingestion-rate events that can create an evidence gap.

Raw events and their normalized decisions are unchanged and remain queryable.
Only notification semantics change.

## Motivation

The combined query classified a recovered provider reset and safe
`corpus_query_rejected` events as Sev1 because both carried `Decision=deny`.
That conflated enforcement success, availability, and containment failure,
creating alert fatigue precisely where operator attention must remain sharp.

## Invariants

- Missing heartbeats remain Sev1 regardless of run identifier.
- The reserved `boundary-test` run remains excluded only from the explicit
  violation branch; its events remain retained.
- Security classification uses an exact event allowlist rather than substring
  matching or every normalized deny.
- Critical events remain Sev1 except the explicitly reclassified availability
  and bounded-query families.
- One recovered upstream failure does not page.
- Repeated unrecovered upstream failures page at Sev3.
- No telemetry is suppressed, deleted, or downgraded at ingestion.
- All three rules use the existing verified action group and email receiver.
- Alert freshness uses Azure ingestion time, with `TimeGenerated` retained as
  evidence. Guest-clock drift after host sleep cannot hide a fresh violation or
  manufacture a missing-heartbeat incident.
- Verification does not apply an API-level `timespan` filter, because Azure
  applies that filter to guest-supplied `TimeGenerated` before KQL can select by
  ingestion time.
- Denied Gateway IPv6 MLD control traffic to the exact link-local multicast
  tuple `ff02::16`/port zero remains retained but does not page. Cold-boot
  acceptance identified it as deterministic kernel control traffic. No other
  IPv6 destination, port, event type, or allow decision is excluded.

## Acceptance

- Bicep compiles without diagnostics.
- What-if shows one in-place Sev1 rule update and one new Sev3 rule, with no
  workspace, table, DCR, lock, role, or action-group replacement.
- Deployment completes in the intended subscription/resource group.
- Live resource inspection confirms names, severities, queries, schedules, and
  action-group binding.
- Synthetic KQL fixtures prove: explicit containment event fires Sev1;
  `boundary-test` does not; one recovered upstream failure does not fire;
  three unrecovered failures fire Sev3; a later success clears the condition.
- Existing fresh heartbeats remain visible and the complete local containment
  suite still passes.

## Rollback

Redeploy the preceding `azure/main.bicep` artifact or update the Sev1 query to
the prior combined expression and delete `${prefix}-availability`. Raw evidence
requires no migration because the table schema and ingestion path are unchanged.

## Deployment record

Deployment-specific subscription, resource-group, region, alert-resource,
query-result, incident, and revision details are retained in ignored local
records. Public acceptance requires the synthetic semantics above, a scoped
what-if, live resource inspection, fresh heartbeats, and a complete local
boundary pass without publishing those installation identifiers.
