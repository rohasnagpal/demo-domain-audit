---
name: email-domain-security
description: Run the Cyber360 S18 Email & Domain Security Agent against one explicitly authorised domain. Use for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, SMTP STARTTLS, CAA, DNSSEC, nameservers, domain expiry or transfer locks; not for sending email or testing relays.
---

# Cyber360 S18 — Email & Domain Security

This is the portable plugin entrypoint for the canonical S18 agent package.

1. Run `../../scripts/setup-tools.sh --check`.
2. Read and follow the [S18 identity and instructions](../../agents/security/email-domain-security/agent.md).
3. Read the canonical [email and domain assessment skill](../../agents/security/email-domain-security/skills/email-domain-assessment/SKILL.md) and the [baseline](../../agents/security/email-domain-security/references/baseline.json).
4. Use only registered invocations from the [tool registry](../../agents/security/email-domain-security/tools.yaml), preferably through `engine/domain/full_audit.py <domain> --authority "<statement>" --skip-tls`, adding `--dkim-selector` for each selector the user names. The engine needs outbound network access; in a sandboxed host such as Codex, request approval to run it with network access.
5. Follow the [assess workflow](../../agents/security/email-domain-security/workflows/assess.yaml).

Do not infer network authority from invocation of this skill. If the exact domain or authority is unclear, stop before making a connection. For DNS, TLS and email checks together, use the `full-domain-audit` skill (`/demo-domain-audit:full-domain-audit` in Claude Code, `$demo-domain-audit:full-domain-audit` in Codex).
