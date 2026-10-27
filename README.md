# Build Your First AI Agent: Domain Audit Demo

3 AI security agents, plus a "Chief" agent that coordinates them, packaged as a Codex / Claude Code plugin. Point them at a domain you own and they will map what it exposes, check its HTTPS security and check its email and DNS protection, then write a detailed report for each agent.

```text
setup the plugin from https://github.com/rohasnagpal/demo-domain-audit and run a full domain audit against example.com
```

This is a teaching demo extracted from Cyber360, an agentic cybersecurity framework by Rohas Nagpal.

## What is an AI agent?

An AI agent is an AI model set up to pursue a goal across several steps on its own. It decides what to do next, runs tools, reads the results and keeps going until the job is done.

The agents here are not separate AI models. Each one is a **folder of instructions, tools and knowledge** that turns the model already running in Codex / Claude Code into a specialist.

## The agents

| Agent | What it checks | Commands it runs |
|---|---|---|
| **H1 Reconnaissance** | What the domain exposes: DNS records, registration, reachability, the HTTPS response, open web ports, and third-party services it reveals | `dig`, `host`, `whois`, `ping`, `traceroute`, `curl`, `nc` |
| **S11 TLS & Cryptography Security** | The website's certificate, trust chain, TLS versions, cipher suites and client compatibility | `openssl`, `testssl.sh` |
| **S18 Email & Domain Security** | Email spoofing protection (SPF, DKIM, DMARC), mail encryption (MTA-STS, TLS-RPT, STARTTLS), CAA, DNSSEC, nameservers, expiry and transfer lock | `dig`, `curl`, `openssl`, `whois` |
| **Chief** | Confirms scope and authority, picks the agents, runs the workflow and summarises the results | (coordinates the others) |

Every agent has the same 6 parts:

| Part | What it does | Where it lives (H1 example) |
|---|---|---|
| 1. Identity and instructions | Who the agent is, what it may and may not do | `agents/hacking/reconnaissance/agent.md` |
| 2. Tools | The exact commands it is allowed to run | `agents/hacking/reconnaissance/tools.yaml` |
| 3. Skills | Step-by-step procedure for its job | `agents/hacking/reconnaissance/skills/` |
| 4. Workflows | The order of steps for a task | `agents/hacking/reconnaissance/workflows/` |
| 5. Knowledge | What each result means and how to fix problems | `agents/hacking/reconnaissance/references/` |
| 6. Outputs | The shape of the report it produces | `agents/hacking/reconnaissance/outputs/` |

## Requirements

- [Claude Code](https://claude.com/claude-code) or [Codex](https://developers.openai.com/codex) (the CLI or the desktop app)
- Python 3.11 or newer (standard library only, nothing to `pip install`)
- macOS or Linux with Homebrew or `apt-get`
- **A domain you own or have written permission to test**

## Setup

**1. Get the folder** and open a terminal in it:

```bash
cd demo-domain-audit
```

**2. Install the command-line tools.** `dig`, `whois`, `curl`, `nc`, `ping`, `traceroute` and `openssl` usually come with macOS; `testssl.sh` usually needs installing. The script shows the exact install command and asks before changing anything:

```bash
./scripts/setup-tools.sh --check      # see what is missing
./scripts/setup-tools.sh --install    # install it
```

**3. Install the plugin** in Claude Code or Codex. The same folder works in both.

Claude Code:

```bash
claude plugin marketplace add "$(pwd)" --scope user
claude plugin install demo-domain-audit@demo-domain-audit --scope user
```

Codex:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add demo-domain-audit@demo-domain-audit
```

**4. Start a new session** so the plugin loads, in any folder where you want the reports saved:

```bash
mkdir -p ~/my-first-audit && cd ~/my-first-audit
claude        # or: codex
```

## The reports

Each agent writes its own report in the folder you started Claude Code or Codex from:

```text
cyber360-reports/
└── yourdomain.com/
    ├── H1-reconnaissance/   report.html · report.json · evidence/
    ├── S11-tls/             report.html · report.json · evidence/
    ├── S18-email-domain/    report.html · report.json · evidence/
    └── archive/<timestamp>/ the previous run, moved here automatically
```

Open any `report.html` in a browser. Each report has an executive summary, charts, and a detailed write-up of every finding: what was found, why it matters, how an attacker would use it, how to fix it for your actual DNS host and email provider, and how to verify the fix. Every finding links to the raw command output that proves it.

## How it works

```text
"Cyber360 full domain audit: yourdomain.com"
        │
        ▼
skills/full-domain-audit/SKILL.md      the Chief: confirm authority, check tools
        │
        ▼
engine/domain/full_audit.py            runs every registered command (no shell)
   ├── H1 commands ─┐                  shared commands run once
   ├── S18 commands ┤
   └── S11 (in parallel)
        │
        ▼
engine/domain/analysis.py              turns raw output into pass / finding / unknown
        │
        ▼
references/knowledge.json              explains each result and how to fix it
        │
        ▼
engine/reporting/                      one HTML + JSON report per agent
```

Three rules keep the agents honest:

1. **Allow-listed commands only.** Agents run only the commands in their `tools.yaml`; no free-form shell.
2. **Evidence first.** Every command's raw output is saved, and every finding links to it.
3. **Unknown is not a pass.** A blocked or failed check is reported as unknown, never as secure.

## Folder structure

```text
demo-domain-audit/
├── plugin.json             portable Agent Plugins manifest used by current Codex versions
├── .claude-plugin/        plugin and marketplace manifests for Claude Code
├── .codex-plugin/         Codex compatibility manifest for older hosts
├── .agents/plugins/       marketplace manifest for Codex
├── skills/                what you type: full-domain-audit, hi-cyber-360, setup-tools, one per agent
├── agents/
│   ├── chief-cyber360-officer.md
│   ├── hacking/reconnaissance/          H1
│   └── security/
│       ├── tls-security/                S11
│       └── email-domain-security/       S18
├── orchestrator/          the Chief's instructions, agent registry and workflow
├── engine/                Python that runs the commands and builds the reports
│   ├── domain/            H1 and S18 commands and analysis
│   ├── tls/               S11 assessment
│   └── reporting/         report pages, charts and themes
└── scripts/               tool setup and request routing
```

## Safety

Only test domains you own or have written permission to test. The agents make ordinary, low-volume requests (DNS lookups, one web request, a TLS scan of port 443 and one mail-server handshake per MX host) but some organisations treat any scan as hostile. Reports and evidence stay on your computer.

## Licence

Copyright 2026 Rohas Nagpal. Licensed under the [Apache License 2.0](LICENSE).
