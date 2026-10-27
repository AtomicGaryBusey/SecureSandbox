# Azure Evidence and Alerting Plane

Status: **implemented design; deployment evidence remains installation-local**

## Objective

Export only normalized, content-free security metadata from Gateway to an
independently retained Azure Monitor workspace. Keep Research and Target
without Azure credentials or routes, prevent the ingestion identity from
querying or changing evidence, bound spend, and turn containment, evidence,
availability, and ingestion failures into deliberately separated alerts.

The encrypted conversation archive is a separate evidence path. It uploads
only age ciphertext to an add-only Blob container and does not replace the
searchable metadata plane described here.

## Trust and data flow

```text
Research telemetry identity --mTLS--> Gateway receiver
Gateway trusted local exporters ------> bounded JSONL spool
                                        |
                                        v
                               azure-shipper.service
                         pinned IPv4 + original TLS names
                         DCR-scoped ingest-only identity
                                        |
                                        v
                       Direct DCR -> SecureSandbox_CL
                                        |
                  containment / availability / ingestion alerts
```

The service principal has exactly `Monitoring Metrics Publisher` on the DCR.
It cannot query, alter, purge, or administer the workspace. Its secret moves
from the Agents vault directly into a host-bound `systemd-creds` credential on
Gateway and never enters a repository file or command-line argument.

## Resource and cost bounds

- 30-day Analytics retention and a metadata-only fixed table schema.
- A 0.1 GB/day workspace safety cap. This is a last-resort surge bound, not
  routine filtering; reaching it creates an ingestion-health alert because
  evidence collection then pauses until Azure's daily reset.
- A USD 10 monthly resource-group budget, notifying at 80% actual cost and
  100% forecast cost through the same reviewed action group.
- Batches are limited to 100 events and 900 KiB; individual records are at
  most 16 KiB, and local telemetry rotation remains bounded.
- Three five-minute scheduled-query rules avoid per-dimension fan-out.

## Alert separation

- **Sev1 posture:** missing Gateway/Research heartbeats, explicit containment
  violations, dangerous tool intent, policy tamper, and evidence-pipeline
  failures. Deliberate `boundary-test` events and exact blocked IPv6 MLD noise
  remain retained but do not page.
- **Sev3 availability:** at least three provider failures in 15 minutes with
  no later successful response.
- **Sev2 ingestion health:** Azure daily-cap, ingestion-rate, or other
  ingestion warnings/errors.

Synthetic live KQL acceptance proves the important positive and negative
classifications without injecting a real containment incident.

## Lifecycle correction

The metadata and encrypted-archive shippers share the pinned TLS support
module. Historically, installing that shared support unconditionally disabled
the metadata shipper. A later archive redeployment therefore left ciphertext
upload active while metadata ingestion stopped. The installer now snapshots
the metadata unit's enabled and active state before replacement and restores a
previously active service only after the protected configuration and encrypted
credential remain readable. A never-configured installation stays inactive.

The boundary verifier treats an enabled-but-inactive metadata shipper as a
failure. Only a deliberately unconfigured installation remains a `GATE`.

## Deployment and acceptance

`scripts/deploy-azure-evidence-alerting-ddd.sh`:

1. builds the reviewed Bicep source;
2. rejects destructive or unsupported Azure what-if changes;
3. incrementally deploys the exact workspace, table, DCR, role, lock, alerts,
   action group, and budget;
4. verifies every live resource and synthetic alert classification;
5. resolves and pins only the exact public IPv4 token/ingestion endpoints;
6. streams the secret from 1Password into Gateway's host-bound credential;
7. waits for fresh off-host Gateway heartbeat, Research heartbeat, and
   Research-denial evidence; and
8. runs the complete SecureSandbox boundary suite.

Subscription, tenant, principal, endpoints, recipient, workspace identifiers,
deployment outputs, query results, and live acceptance records stay in ignored
local state.

## Recovery

Endpoint-address drift fails closed. Re-run the deployment entry point to
resolve current global IPv4 records, regenerate the exact firewall allowlist,
rotate the host-bound configuration, and repeat off-host and complete-boundary
acceptance. Do not add DNS, CIDRs, generic HTTPS, or Azure credentials to
Research or Target as a recovery shortcut.
