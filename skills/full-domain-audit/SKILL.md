---
name: full-domain-audit
description: Run the Cyber360 full domain audit (H1 Reconnaissance, S11 TLS & Cryptography Security and S18 Email & Domain Security) against one explicitly authorised domain. Use when the user says "Cyber360 full domain audit: <domain>", asks for a full or complete domain audit, or wants DNS, TLS and email security checked together.
---

# Cyber360 full domain audit

Follow the [full domain audit workflow](../../orchestrator/workflows/full-domain-audit.yaml) as the [Chief Cyber360 Officer](../../orchestrator/chief-cyber360-officer.md).

1. Extract exactly one domain from the request, such as `vdpo.org` from `Cyber360 full domain audit: vdpo.org`. Strip any scheme or path the user included; if more than one domain is given, ask which one.
2. Confirm authority. If the user has not said that they own or are authorised to test the domain, ask once before any network activity. Record their words as the authority statement.
3. Run `../../scripts/setup-tools.sh --check`. If a tool is missing, tell the user which checks will be skipped or direct them to the `setup-tools` skill (`/demo-domain-audit:setup-tools` in Claude Code, `$demo-domain-audit:setup-tools` in Codex).
4. From the user's current working directory, run the engine at `../../engine/domain/full_audit.py` (relative to this skill file) once, passing the domain and authority as separate arguments and never interpolating user text into a shell string:

   ```bash
   python3 <plugin-root>/engine/domain/full_audit.py <domain> --authority "<authority statement>"
   ```

   Add `--dkim-selector <selector>` for each DKIM selector the user names (for example `google` for Google Workspace). Do not guess selectors. Add `--tls-profile extended` only when the user asks for deeper TLS checks.

   The engine needs outbound network access. In a sandboxed host such as Codex, request approval to run this command outside the sandbox (or with network access) rather than running it sandboxed; a run without network reports every check as unknown. If that happens, say so and rerun with network access instead of presenting the results.

   The engine writes one report per agent to `./cyber360-reports/<domain>/H1-reconnaissance/`, `S11-tls/` and `S18-email-domain/` in the current working directory, and moves any previous run to `./cyber360-reports/<domain>/archive/<timestamp>/`. There is no combined report. It typically takes three to five minutes because S11's testssl.sh scan runs alongside the DNS and email checks.
5. Read each agent's `report.json`, then reply with:
   - each agent's severity counts and the S11 evidence grade;
   - the most important findings across all three agents first, each with its agent, what was found and the fix;
   - unknowns that matter, such as SMTP checks blocked by the local network or DKIM not checked; and
   - the paths to the three `report.html` files.

Read the specialist instructions when interpreting their results: [H1](../../agents/hacking/reconnaissance/agent.md), [S11](../../agents/security/tls-security/agent.md) and [S18](../../agents/security/email-domain-security/agent.md).

Routing to this workflow does not authorise testing other domains, subdomains or ports, or making any change.
