# Security Policy

## Supported version

Security fixes are made against the current `public-release` branch. Older
commits, generated release archives, local deployments, and forks are not
maintained as separate supported versions.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, pull request,
discussion, commit, review bundle, or tracked repository file.

After this repository becomes public, use GitHub's **Report a vulnerability**
button on the Security Advisories page. The public-release sealing ceremony
enables private vulnerability reporting and verifies that it is active.

Before that channel is active, contact the maintainer through an already
established private channel and include only enough information to arrange a
secure handoff. Do not transmit secrets, exploit details, private evidence, or
installation identifiers through a public channel.

A useful report identifies the affected commit, violated security invariant,
prerequisites, reproducible behavior, likely impact, and any safe remediation
ideas. Please avoid accessing data that is not yours, persisting in systems,
disrupting services, or testing against installations without authorization.

## Security scope

High-value security boundaries include:

- host authorization and protected-release integrity;
- guest privileged-control admission and role separation;
- Gateway credential, source, evidence, and network brokers;
- Research agent confinement and managed tool admission;
- request-bound disposable execution and Secure Enclave approval;
- Target container isolation and resource limits;
- encrypted evidence transport, retention, and alerting; and
- public-release confidentiality, exact-history scanning, and provenance.

Reports are especially useful when they demonstrate unauthorized privilege,
credential access, network reachability, execution, evidence modification,
approval bypass, replay, publication of private material, or a fail-open
condition at one of these boundaries.

Threats that require an already-authorized host administrator, physical device
control, or compromise of the hypervisor, operating-system kernel, firmware, or
an external cloud/provider control plane may fall outside the project's direct
implementation boundary. They are still welcome when SecureSandbox incorrectly
claims to contain them or materially worsens their impact.

## Disclosure and response

Maintainers will validate reports against the documented threat model and
current source. Valid findings will be fixed and verified before public
technical disclosure whenever practical. No response-time or bounty commitment
is made.

Good-faith research that follows this policy is welcome. This policy does not
grant access to systems, data, credentials, or accounts you do not own or have
explicit permission to test.
