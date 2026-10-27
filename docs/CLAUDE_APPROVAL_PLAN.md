# Claude Code hardening approval plan

Status: **implemented design**. Deployment state and acceptance evidence are private.

## Evolution principle

This is a firm initial posture, not a permanent static configuration. When
real research work conflicts with a control, capture the concrete blocked
workflow and discuss the smallest change that restores necessary functionality.
Each change should document its threat tradeoff, remain deny-by-default, add or
update a regression test, and be revalidated against the outer VM, network,
credential, and telemetry boundaries. Do not weaken controls merely for
convenience or silently widen them during troubleshooting.

The read-only `agent-safety-check` audit classified the empty Claude Code
configuration as Tier 2 while the intended offensive/reduced-safeguard workload
requires Tier 4. The outer VM, credential broker, no-route network, host kill
switch, and off-VM evidence design supply the Tier 4 containment controls. The
following two in-guest policy writes still require owner approval.

## Change 1: root-owned managed policy

Proposed source: `research/managed-settings.proposed.json`

Destination: `/etc/claude-code/managed-settings.json`, owned by root and mode
`0644`.

Effects:

- permanently disables bypass-permissions mode;
- forces Claude's Linux sandbox to fail closed;
- blocks all shell-command network access and local listening sockets;
- confines file access to the selected working directory and denies credential
  locations at both the tool and OS-sandbox layers;
- permits only the root-managed, networkless `source_integrity` and
  `corpus_intelligence` MCP servers and their exact `verify_source`,
  `search_corpus`, `scan_corpus`, and `explore_corpus` tools; corpus operations
  are UUID-scoped to root-built immutable indexes and expose no shell,
  arbitrary path, network, or index-management interface; hooks, plugins,
  WebFetch, WebSearch,
  subagents, agent teams, and background task creation remain unavailable;
- prevents project/user configuration from widening managed permissions,
  sandbox network domains, hooks, or MCP servers; and
- makes every shell command require an interactive approval.

Expected tradeoffs: package downloads, Git remotes, browser integrations,
plugins, MCP, subagents, and unattended operation will not work. This is
intentional for the initial high-risk profile.

## Change 2: root-owned launcher

Proposed source: `research/research-claude.proposed`

Destination: `/usr/local/bin/research-claude`, owned by root and mode `0755`.

Effects:

- starts with an empty environment and only a small explicit variable set;
- forces the working directory to `/home/agent/research-workspace` and rejects
  all caller-supplied CLI options except `--resume SESSION_UUID` (a plain
  initial prompt is still accepted), and requires resumed UUIDs to appear in a
  root-owned registry derived from Research-workspace Claude journals;
- sends API calls only to the loopback mTLS relay using a non-secret placeholder;
- pins Opus/Sonnet/Haiku aliases to Abliteration Large V2 with the `[1m]`
  Claude Code context annotation;
- disables updates, login/logout, nonessential traffic, telemetry/error-report
  paths, and credential inheritance into subprocesses; and
- preserves Claude Code's complete built-in command set, including `/compact`,
  `/clear`, and `/quit`, while starting with no Chrome and manual approval mode.
  The blanket `--disable-slash-commands` switch is deliberately absent because
  it also disables those built-in lifecycle and continuity controls. Custom
  commands and skills remain unavailable through restricted mode and the
  managed customization, hook, plugin, permission, and MCP controls.
  Root-owned `managed-mcp.json` is the exclusive MCP configuration. `--bare`
  and `--safe-mode` are deliberately absent because they suppress implicit MCP
  loading; an explicit `--mcp-config` is also absent because the enterprise
  `disableSideloadFlags` control correctly rejects that sideload path. The
  managed policy and scrubbed launcher environment supply the required
  customization restrictions. Claude Code also rejects combining enterprise
  managed MCP with `--strict-mcp-config`.

The provider credential remains only as a host-bound encrypted systemd
credential on Gateway and cannot be read from Research. Its password-manager
locator is supplied through ignored local configuration.

Rollback is available from the Mac as
`scripts/rollback-approved-claude-policy.sh`. It refuses to delete either file
if its hash has changed since this approved baseline, and it preserves the
research workspace.

## Verification after approval

1. Validate the JSON before installation and re-run `agent-safety-check`.
2. Confirm `claude --dangerously-skip-permissions` is refused.
3. Confirm Bash cannot read `/etc/secure-sandbox`, bind a socket, or connect to
   Gateway, Target, a public IP, or metadata; only Claude's own API client may
   reach the loopback relay.
4. Confirm file tools cannot read outside a dedicated workspace.
5. Confirm WebFetch, WebSearch, Agent/subagent, teams, MCP, hooks, and plugins
   are unavailable.
6. Run one mock-model call before enabling real provider egress.
