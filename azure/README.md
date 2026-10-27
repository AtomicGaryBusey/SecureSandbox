# Azure evidence plane

`main.bicep` defines the metadata evidence deployment:

- one Log Analytics workspace capped at 0.1 GB/day;
- a 30-day Analytics custom table with metadata-only fields;
- a `kind: Direct` Data Collection Rule, so no DCE is required;
- an optional Monitoring Metrics Publisher assignment scoped only to the DCR;
- a cannot-delete lock on the workspace;
- one Sev1 scheduled query alert covering explicit containment/evidence
  violations and missing Gateway/Research heartbeats;
- one Sev3 scheduled query alert for sustained, unrecovered model-provider
  availability failures; and
- one Sev2 scheduled query alert for Azure ingestion warnings/errors,
  including the 0.1 GB/day safety cap;
- one USD 10 monthly resource-group budget with 80% actual and 100% forecast
  notifications; and
- an optional email action group.

`alerts.bicep` is the narrow operational template for changing only the two
scheduled-query rules against an existing workspace and action group. Use it
for alert-semantics revisions so provider-computed table properties are never
part of the deployment change set.

`conversation-archive.bicep` separately defines the full-content evidence
plane: a shared-key-disabled StorageV2 account, private container, locked
30-day time-based immutability policy, cannot-delete lock, create-only custom
uploader role, and read-only operator assignment. Only age ciphertext is
stored there; Log Analytics continues to receive metadata only.

The template does **not** create an Entra app or client secret. Creating that
identity is an explicit deployment ceremony: create a dedicated service
principal, pass only its object ID to the template, store its client secret as a
host-bound encrypted credential on Gateway, and grant no role other than the
DCR-scoped Monitoring Metrics Publisher role.

## Local deployment configuration

Subscription, tenant, principal, workspace, generated resource, endpoint-pin,
and notification-recipient values are deliberately excluded from version
control. Copy `config/external-containment.example.json` to the ignored
`config/external-containment.json`, then populate it from the trusted local
deployment outputs. The live conversation archive configuration likewise lives
in ignored `gateway/conversation-azure.json`; use
`gateway/conversation-azure.example.json` as its public template.

The dedicated service principal has only Monitoring Metrics Publisher at the
DCR resource scope. Its secret is stored as
`op://Agents/SecureSandbox-Azure-Ingestion/credential`; never resolve that
reference into a repository file or command-line argument. Non-secret resource
outputs are retained in `runs/azure-deployment-outputs.json`.

After activation, verify fresh off-host evidence with:

```sh
scripts/verify-azure-evidence.sh \
  '<subscription-id>' \
  '<workspace-customer-id>'
```

The acceptance check requires recent Gateway and Research heartbeats plus a
Research deny. It varies the query text on every run to avoid accepting a
briefly cached Log Analytics result.

The reviewed end-to-end deployment entry point is:

```sh
scripts/deploy-azure-evidence-alerting-ddd.sh
```

It performs a destructive-change-rejecting Azure what-if, incrementally
deploys the exact Bicep resources, verifies resource identities and synthetic
alert semantics, activates the pinned Gateway shipper with the Agents-vault
credential, waits for fresh off-host evidence, and then runs the complete
SecureSandbox boundary suite. The shared Azure support installer preserves an
already active metadata shipper during later encrypted-archive updates.

The Sev1 containment/heartbeat rule retains all `boundary-test` events in Log Analytics
but excludes that reserved run ID from the policy-violation branch. Missing
heartbeats remain actionable regardless of run ID. This prevents the deliberate
negative probes in `labctl start` and `labctl verify` from paging while keeping
them available as off-host evidence.

The same Sev1 rule treats Claude tool-intent events as actionable: sandbox bypass,
privilege escalation, security-policy change, network tunnel/proxy requests,
accepted risky-tool approvals, and any other critical-severity event. These
records contain classifications and hashes only, never prompt or command text.
It also treats conversation capture, forwarding, and archive upload failures
as critical. Successful lifecycle records contain only a run ID, ciphertext
SHA-256, and byte count.

The rule treats source-import rejection and manifest/archive evidence failures
as actionable. A source-fetch transport failure remains retained evidence but
is not automatically a containment violation. Successful source lifecycle
records contain only fixed event metadata, opaque IDs, hashes, counts, sizes,
and policy state; source bytes, filenames, repository URLs, and requested refs
do not enter Log Analytics. Exact encrypted provenance is retained in the
locked blob archive.

`upstream_failed` and ordinary bounded-tool rejection events remain in Log
Analytics but no longer inherit Sev1 merely because their normalized decision
is `deny`. The separate Sev3 availability rule requires at least three provider
failures within 15 minutes and no successful response after the most recent
failure. A single recovered reset therefore remains observable without paging
as a containment incident.

Denied Gateway MLD control traffic to the exact link-local multicast tuple
`ff02::16`/port zero is retained but excluded from Sev1. This deterministic
cold-boot kernel traffic is blocked by policy; every other firewall denial,
IPv6 destination, and port remains subject to the explicit containment rule.

Retrieve and verify a completed conversation with:

```sh
./scripts/labctl transcript RUN_ID
```

The operator's container-scoped Reader role cannot modify or delete blobs. The
Gateway uploader's custom role has only `blobs/add/action` and cannot list,
read, overwrite, or delete. The age identity is stored at
`op://Agents/SecureSandbox-Conversation-Archive/password`; do not resolve it to
disk. A locked policy cannot be shortened or removed, so test a new deployment
while its policy is unlocked and run `scripts/lock-conversation-retention.sh`
only after upload/download/decrypt acceptance succeeds.

For a separate environment, choose its subscription, resource group, region,
and alert recipient first. Example:

```sh
az deployment group create \
  --resource-group secure-sandbox-monitoring \
  --template-file azure/main.bicep \
  --parameters location=westus3 \
               ingestionPrincipalObjectId='<object-id>' \
               alertEmail='<recipient>'
```

After deployment, use the outputs `logsIngestionEndpoint`, `dcrImmutableId`,
and `streamName` to configure the Gateway shipper. Firewall rules must pin the
current IPv4 addresses for the exact DCR ingestion hostname and the tenant-
specific Entra token hostname; Research and Target never receive Azure
credentials or Azure routes.

Create `azure-shipper.json` from `gateway/azure-shipper.example.json`. Resolve
both names on the trusted Mac immediately before activation, record every
global A record, and do not include IPv6 or any CIDR. The shipper connects to
those numeric addresses while validating the original TLS names. Address drift
therefore fails closed and requires an operator to re-resolve, review, update,
and re-run the boundary suite. The client secret is accepted only on standard
input by `scripts/activate-azure-shipper.sh`, encrypted to the Gateway host by
`systemd-creds`, and never belongs in the JSON file or shell history.

After the dedicated service principal secret is stored as
`op://Agents/SecureSandbox-Azure-Ingestion/credential`, the host wrapper takes
the five non-secret deployment outputs/identity values, resolves and validates
the endpoint pins, installs the dormant shipper, streams both sudo and client
credentials from 1Password, activates it, and reruns verification:

```sh
scripts/activate-azure.sh TENANT_ID CLIENT_ID INGESTION_ENDPOINT \
  DCR_IMMUTABLE_ID Custom-SecureSandbox_CL
```

The generated ARM template in `runs/azure-main.arm.json` is a build artifact,
not an authority for deployment. Deploy the Bicep source, preserve deployment
outputs as non-secret run evidence, then test one synthetic deny and both
heartbeats before considering the off-host gate closed.

## Optional LiteLLM and Langfuse

Do not put either product in the first enforcement path. The custom broker is
smaller, rejects generic proxy methods, strips client headers, blocks remote web
tools, and has an auditable fixed destination. LiteLLM can be added later
behind that boundary for budgets and richer model accounting, but its own docs
warn that budgets are not enforced without PostgreSQL and that many limits are
unset by default.

Langfuse v4 is not a cheap single-container add-on: its documented minimum is
separate web and worker containers (2 CPU/4 GiB each), PostgreSQL (2 CPU/4
GiB), Redis/Valkey (1 CPU/1.5 GiB), ClickHouse (2 CPU/8 GiB), and blob storage.
The official Azure module is an AKS deployment. For this one-user lab, Azure
Monitor should be the durable evidence plane first. Revisit Langfuse only when
prompt/response tracing is explicitly desired and its substantially larger
attack surface and cost are justified.
