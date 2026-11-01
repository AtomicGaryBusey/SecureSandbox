# Anthropic CVP Defense containment foundation

## Source and standing

SecureSandbox treats Anthropic's **“Agent containment best practices for CVP
participants”** as foundational primary guidance for the project:

<https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants>

The operator is enrolled in the Anthropic Cyber Vulnerability Program (CVP)
Defense tier and supplied a full-page copy of the guidance on 2026-10-31 after
the canonical support page was not accessible to the documentation agent. This
record retroactively repairs missing provenance in the original architecture
and later harness DDDs. It does not claim that Anthropic reviewed, certified,
or endorsed SecureSandbox.

The canonical Anthropic page remains the authority. The summary below records
the substantive contents that informed this project without republishing the
article verbatim. When Anthropic changes the guidance, the project must review
the new text, record the review date, and reconcile changed recommendations
before claiming continued alignment.

## Normative guidance captured from the source

The article distinguishes vulnerability-discovery and other local work from
pentesting/red-team work that needs broader target access. Across those work
classes, it recommends the following controls:

1. Run agentic work in a dedicated virtual machine or bare-metal environment,
   not in an ordinary credential-bearing workstation context.
2. Deny network access by default. For local work, permit only the required
   model API path; route that path through a proxy or broker outside the
   sandbox and keep the real API credential outside the agent environment.
3. Before live work, deliberately test the containment environment for escape,
   local-file exfiltration, privilege escalation, and unintended network
   access. Repeat this validation after meaningful sandbox, model, harness, or
   tool changes.
4. Retain model transcripts and sandbox/system logs for at least 30 days,
   monitor them for unexpected or dangerous behavior, and provide a route for
   review and escalation.
5. Use Claude Code's vendor-provided safe/restricted operating mode where it is
   applicable, while treating that mode as defense in depth rather than the
   containment boundary.
6. For pentesting and red-team work, enforce the authorized target scope at the
   network and credential layers, explicitly state the engagement scope to the
   model, and avoid relying on prompt text as the sole scope control.
7. Prefer scoped, pre-authorized test mechanisms and narrowly limited
   credentials. Do not give the agent ambient access to unrelated systems,
   networks, accounts, or secrets.
8. Keep a human actively supervising consequential work with the ability to
   stop it immediately. Human review is an additional control, not a substitute
   for technical confinement.
9. Segment the agent and target environment from unrelated infrastructure and
   prevent pivoting outside the engagement boundary.
10. Do not run autonomous agents against high-consequence production targets
    where an unintended action could cause material harm. Use representative,
    disposable, or otherwise safely isolated targets instead.

These are baseline requirements. SecureSandbox may impose stricter controls;
it may not weaken one of these controls merely because another layer appears
to compensate for it.

## SecureSandbox control mapping

| CVP Defense recommendation | SecureSandbox realization | Primary evidence |
|---|---|---|
| Dedicated isolated compute | Separate Gateway, Research, and Target VMs; disposable Target execution; powered-off goldens | `docs/DESIGN.md`, `docs/DISPOSABLE_EXECUTION_DESIGN.md`, `scripts/verify-boundaries.sh` |
| Default-deny networking and external model broker | Research and Target have no general Internet path; Gateway owns the fixed upstream route and credential | `docs/DESIGN.md`, `gateway/`, `research/claude_relay.py` |
| Credential exclusion | Provider secrets remain in the Gateway/secret-injection path and are denied from files, environment, process listings, errors, and logs in Research | `docs/DESIGN.md`, `docs/MODEL_PROFILE_CONFIGURATION_DESIGN.md`, boundary tests |
| Pre-engagement and post-change validation | Complete boundary verification, negative canaries, external-containment audit, fresh-VM restoration, and disposable-Mac acceptance gates | `scripts/verify-boundaries.sh`, `docs/EXTERNAL_CONTAINMENT_AUDIT_DESIGN.md`, `docs/FRESH_VM_CONTAINMENT_RESTORATION_DESIGN.md` |
| Transcript and system-log retention | Encrypted conversation capture plus a locked 30-day Azure archive and off-host telemetry/evidence | `README.md`, `docs/ARTIFACT_EVIDENCE_PIPELINE.md`, `docs/AZURE_EVIDENCE_ALERTING_PLANE_DESIGN.md` |
| Vendor restricted mode | Root-managed Claude policy and fixed restricted launcher; hooks, ambient MCP, marketplaces, memory, and side loading are disabled | `docs/AGENT_SELF_DEFINITION_DESIGN.md`, `research/managed-settings.proposed.json` |
| Technical engagement scope | Fixed VM routes, source identities, run/session leases, exact tool brokers, budgets, and Target-only execution prevent prompts from expanding authority | `docs/RUN_LEASE_DESIGN.md`, `docs/SOURCE_ACQUISITION_DESIGN.md`, `docs/REQUEST_BOUND_EXECUTION_APPROVAL_DESIGN.md` |
| Active human stop authority | Exact Touch ID ceremonies for consequential operations and host-side `labctl panic` independent of guest cooperation | `docs/TOUCH_ID_OPERATOR_AUTHORIZATION_DESIGN.md`, `docs/DESIGN.md` |
| Segmentation and anti-pivot controls | Separate control and lab networks; no Research/Target shared or bridged NIC; Target cannot reach Gateway or the Internet | `docs/DESIGN.md`, `scripts/verify-boundaries.sh` |
| No autonomous high-consequence production targeting | Scope is a disposable research lab; live production admission is not provided, and synthetic/disposable acceptance precedes candidate use | `docs/DESIGN.md`, harness admission and lifecycle DDDs |

## Consequences for future design

- Every new harness, model adapter, plugin-like capability, source path, and
  updater must preserve this baseline and prove it through negative tests.
- Harness conformance must include escape, exfiltration, privilege, network,
  credential, scope-expansion, and process-tree probes in a disposable fixture.
- A vendor safe mode, model refusal, prompt instruction, or approval dialog can
  supplement—but never replace—VM, network, identity, and credential controls.
- Any proposal for live production access or broader network reach is a new
  security boundary and requires a separate DDD, threat model, operator
  authorization, and CVP-guidance reconciliation.
- The project must retain this source in the reference set for architecture,
  containment audits, harness lifecycle, multi-harness admission, and any
  first-party harness evaluation.
