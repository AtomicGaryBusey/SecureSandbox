# Enterprise Security Recommendation: OSC 52 and AI Agent Terminals

Status: recommendation. Deployment state and acceptance evidence are private.
**Status:** Recommended security baseline  
**Scope:** Enterprise endpoints, terminal emulators, AI coding agents, SSH workflows, development VMs, containers, CI/CD consoles, and security-research environments

## Executive summary

Organizations should deny OSC 52 clipboard access by default across managed terminals, with narrowly approved and time-limited exceptions. Clipboard reads should be prohibited everywhere possible. Clipboard writes should also be denied by default, particularly in terminals used by AI agents or connected to untrusted systems.

OSC 52 is a terminal control sequence that lets terminal output interact with the workstation clipboard. In an AI-agent workflow, model- or tool-controlled output can therefore cross the boundary between an isolated process, SSH host, container, or VM and the user's endpoint clipboard. Publicly disclosed terminal vulnerabilities and agent-CLI research demonstrate both clipboard exfiltration and clipboard-poisoning risks.

Monitoring should complement this baseline, but it is not a substitute for disabling the feature. OSC 52 is commonly interpreted locally inside the terminal emulator and may be invisible to network monitoring and ordinary endpoint telemetry.

## Threat model

The relevant data path is:

```text
AI agent or untrusted process
    -> stdout / pseudo-terminal
    -> SSH, tmux, container, or VM console
    -> host terminal emulator
    -> workstation clipboard
```

This path can bypass otherwise effective isolation controls. For example, disabling hypervisor clipboard sharing does not prevent a terminal connected over SSH from interpreting OSC 52 on the host.

The principal attack patterns are:

1. **Clipboard poisoning:** Untrusted output causes the host terminal to replace clipboard contents with a command, URL, account identifier, or other attacker-controlled text. The payload takes effect when the operator subsequently pastes it. Embedded newlines or terminal paste-handling defects can increase the impact.
2. **Clipboard exfiltration:** An OSC 52 query causes a permissive terminal to read clipboard contents and return them through the terminal session. This can expose passwords, tokens, customer data, commands, or other recently copied material.
3. **Exploit composition:** OSC 52 is combined with ANSI injection, bracketed-paste weaknesses, or another terminal vulnerability to reduce or eliminate required operator interaction.

OSC 52 alone is not generally equivalent to arbitrary command execution or a hypervisor escape. It is nevertheless a host-facing trust-boundary crossing primitive that can form an important part of an escape chain.

## Recommended enterprise policy

| Capability | Enterprise baseline |
|---|---|
| OSC 52 clipboard read/query | Deny everywhere |
| OSC 52 clipboard write | Deny by default |
| Write-only exception | Permit only for documented business needs, preferably with explicit confirmation |
| Read/write exception | Avoid; require a specific security review and compensating controls |
| Terminal paste warnings | Enable, including multiline and newline warnings |
| VDI/RDP clipboard redirection | Disable in privileged and research environments |
| AI-agent terminals | Use a dedicated managed profile with OSC 52 disabled |

Clipboard reading presents the greater direct confidentiality risk. Clipboard writing remains material because poisoning may result in credential disclosure, incorrect financial or infrastructure operations, or execution of attacker-chosen commands.

## Default clipboard behavior in Claude Code and Codex CLI

Claude Code and Codex CLI both contain clipboard-reading functionality for image paste. Neither was found to poll or read the clipboard merely because the CLI is running. However, after the operator invokes the image-paste shortcut, both can read clipboard contents without displaying a separate CLI approval dialog.

| Behavior | Claude Code | Codex CLI |
|---|---|---|
| Reads the clipboard merely because the CLI starts | No evidence found | No evidence found |
| Polls the clipboard autonomously during ordinary chat | No evidence found | No evidence found |
| Reads clipboard contents after an image-paste shortcut | Yes | Yes |
| Displays a separate per-read CLI approval prompt | No | No |
| Ordinary text paste | Normally performed by the terminal, which sends the resulting text as terminal input | Normally performed by the terminal, which sends the resulting text as terminal input |
| Remote OSC 52 clipboard read | Public reports describe this for user-triggered Claude image paste over SSH | Current public source shows native clipboard and WSL image-read paths; its documented OSC 52 implementation is principally for clipboard writes |

This distinction matters when describing the risk:

- If "without explicit approval" means without a security confirmation dialog, both CLIs can read clipboard images without one after a paste shortcut. The shortcut is treated as the user's authorization.
- If it means silently reading the clipboard without a user action, no evidence was found that either default CLI does so during ordinary operation.
- Regular text paste generally does not require the CLI to call a clipboard API. The terminal reads the clipboard and delivers the pasted bytes to the CLI as input.
- A permissive terminal remains dangerous even if the CLI itself only reads on a shortcut. Any process capable of writing terminal output could issue an OSC 52 query; the terminal must enforce the security boundary.

### Claude Code

Claude Code supports native clipboard-image handling on macOS, Windows, and Linux. Public issue reports document local clipboard reads after the image-paste shortcut and an OSC 52 read path used for user-triggered image paste over SSH. On Windows, reported implementations invoke PowerShell clipboard APIs. These operations do not present a separate Claude Code approval prompt after the operator presses the paste shortcut.

Claude Code also contains separately permissioned clipboard interfaces associated with computer-use capabilities. Those interfaces should not be conflated with the ordinary terminal image-paste feature or treated as evidence that the model automatically receives general clipboard access.

### Codex CLI

Codex's public source shows that a `Ctrl+V` or `Alt+V` key event can produce a `PasteImage` action. The image-paste implementation creates a native clipboard handle, checks clipboard file entries, and calls `get_image()`. Under WSL, it can fall back to PowerShell `Get-Clipboard -Format Image`. No separate Codex approval dialog is interposed after the user invokes the shortcut.

Codex's distinct clipboard-copy implementation uses native clipboard access and, in applicable SSH or multiplexer environments, OSC 52 to copy responses out of the TUI. That write path should not be mistaken for evidence of background OSC 52 clipboard reads.

## Why prevention is more reliable than detection

OSC 52 activity may be:

- Local to the endpoint rather than network-visible.
- Carried inside encrypted SSH traffic.
- Interpreted only by the terminal emulator.
- Absent from shell command history.
- Missing from conventional EDR process and network telemetry.
- Wrapped or relayed through tmux, screen, or nested terminal sessions.

Searching network traffic for the literal `ESC ] 52 ;` sequence is therefore not a dependable control. Raw terminal transcript inspection can detect some uses, but only where collection preserves control characters and occurs before the terminal interprets them.

## Implementation guidance

### 1. Inventory terminal implementations

Inventory installed versions and configuration of at least:

- Windows Terminal
- Warp
- Ghostty
- iTerm2
- Apple Terminal
- VS Code and other IDE-integrated terminals
- WezTerm, Kitty, Alacritty, and other approved developer terminals
- tmux, screen, and other terminal multiplexers
- VDI, RDP, browser terminals, and embedded administrative consoles

Terminal emulators differ materially in their defaults, read/write capabilities, confirmation behavior, and administrative manageability.

### 2. Enforce terminal-specific controls

- **Windows Terminal:** Set `compatibility.allowOSC52` to `false` for every applicable profile. Microsoft documents this setting as defaulting to `true`, making explicit enforcement important.
- **Warp:** Enforce `osc52_clipboard_access = "deny"`. Warp now documents `deny` as the default following its 2026 clipboard-access vulnerability.
- **Ghostty:** Set both `clipboard-read = deny` and `clipboard-write = deny`. Its documented default asks before reads but allows writes.
- **iTerm2:** Disable terminal-application clipboard access rather than relying solely on per-event consent. iTerm2 supports both OSC 52 writes and queries.
- **Other terminals:** Verify both read and write behavior empirically. Absence of a documented feature is not sufficient evidence that it is unavailable in the deployed version.

Configuration should be managed through the organization's normal endpoint-management system where possible. Controls should be tested after terminal upgrades because defaults and option names may change.

### 3. Account for nested terminal layers

OSC 52 can be wrapped or passed through SSH sessions and terminal multiplexers. Disabling it inside a guest shell or tmux configuration does not guarantee that the outer terminal will reject the final sequence. The endpoint terminal must enforce the ultimate denial.

### 4. Establish a constrained exception process

Where developers have a genuine need for remote-copy functionality:

- Prefer write-only access.
- Require confirmation for each operation where supported.
- Prohibit clipboard queries.
- Exclude privileged administration, production access, and AI-agent terminals.
- Assign an accountable owner and expiration date.
- Revalidate the need periodically.

### 5. Validate behavior with benign canaries

For every supported terminal and version, verify that:

- OSC 52 cannot change clipboard contents under the managed baseline.
- Clipboard queries do not return clipboard data.
- Wrapped sequences cannot traverse SSH or tmux and reach the host clipboard.
- Policy persists after software updates.
- Non-administrative users cannot trivially override the configuration.

Testing actual behavior is more reliable than checking configuration alone.

## Monitoring recommendations

Monitoring should focus primarily on control coverage and drift:

- Inventory installed terminal emulators and versions.
- Audit terminal configuration through MDM, Intune, Jamf, osquery, or equivalent endpoint tooling.
- Monitor configuration files for unauthorized changes.
- Alert on installation or execution of unapproved terminal applications.
- Detect flags, environment variables, or profile changes that enable clipboard access.
- Use endpoint DLP clipboard telemetry where available and proportionate.
- Run periodic benign canary tests to verify effective behavior.
- Search agent transcripts for OSC 52 sequences where transcripts preserve raw terminal output.

Avoid collecting general clipboard contents solely for monitoring. Doing so creates an additional sensitive-data repository and may introduce privacy, legal, and access-control concerns.

## Recommended rollout

1. Immediately deny OSC 52 on security, infrastructure, production-access, and AI-agent endpoints.
2. Run an enterprise-wide terminal and configuration inventory.
3. Use a short audit period to identify legitimate dependencies.
4. Deploy organization-wide denial after compatibility testing.
5. Grant only write-only, owner-assigned, time-limited exceptions.
6. Continuously validate policy after terminal and agent-CLI upgrades.

## Evidence and references

- [Warp security advisory GHSA-wgqj-4c26-7c4g / CVE-2026-48725](https://github.com/warpdotdev/warp/security/advisories/GHSA-wgqj-4c26-7c4g) — public disclosure of terminal-output-driven clipboard read and write access through OSC 52; rated High.
- [Warp terminal settings](https://docs.warp.dev/terminal/settings/all-settings/) — documents `osc52_clipboard_access` modes and the current `deny` default.
- [Windows Terminal v1.22 release documentation](https://github.com/microsoft/terminal/discussions/18516) — documents `compatibility.allowOSC52`, including its `true` default.
- [Ghostty configuration reference](https://ghostty.org/docs/config/reference) — documents separate clipboard read and write policies and their defaults.
- [Ghostty OSC 52 protocol documentation](https://ghostty.org/docs/vt/osc/52) — describes clipboard modification and query behavior.
- [iTerm2 escape-code documentation](https://stage.iterm2.com/3.4/documentation-escape-codes.html) — documents OSC 52 clipboard writes and clipboard queries.
- [ANSI escape-code injection research involving OpenAI Codex CLI](https://engineered.at/articles/ansi-escape-code-injection-in-openai-s-codex-cli-leading-to-rce) — researcher-described clipboard-poisoning and terminal exploit chains.
- [Independent Codex CLI security audit](https://gist.github.com/ghuntley/7dd788d4528936c3fad1fd9b727bfe4c) — reports model-controlled content reaching raw terminal control paths and separately demonstrates bracketed-paste command execution.
- [Claude Code issue #41954](https://github.com/anthropics/claude-code/issues/41954) — reports repeated OSC 52 clipboard writes during selection and streaming.
- [Claude Code issue #76902](https://github.com/anthropics/claude-code/issues/76902) — documents the `sent N chars via OSC 52` behavior and an Apple Terminal compatibility report.
- [Claude Code issue #69330](https://github.com/anthropics/claude-code/issues/69330) — reports local clipboard-image reads and a user-triggered OSC 52 image-paste path over SSH.
- [Claude Code issue #32791](https://github.com/anthropics/claude-code/issues/32791) — documents PowerShell clipboard operations used by Claude Code's Windows image-paste path.
- [Codex CLI clipboard-paste source](https://github.com/openai/codex/blob/main/codex-rs/tui/src/clipboard_paste.rs) — implements native clipboard image reads and a WSL PowerShell fallback.
- [Codex CLI key-event handling](https://github.com/openai/codex/blob/main/codex-rs/tui/src/chatwidget/interaction.rs) — ties clipboard image reads to paste key events.
- [Codex CLI clipboard-copy source](https://github.com/openai/codex/blob/main/codex-rs/tui/src/clipboard_copy.rs) — documents native and OSC 52 clipboard-write behavior.

## Conclusion

OSC 52 is a convenience mechanism that crosses an important endpoint trust boundary. Public terminal vulnerabilities and agent-CLI research make denial a defensible enterprise hardening measure rather than a speculative precaution. Because reliable detection is difficult, the preferred control is an explicit terminal-level deny, supported by configuration monitoring, behavioral canaries, and tightly governed exceptions.
