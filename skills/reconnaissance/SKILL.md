---
name: reconnaissance
description: Run the Cyber360 H1 Reconnaissance Agent to map the attack surface of one explicitly authorised domain from DNS, WHOIS, reachability and HTTPS evidence. Use for DNS records, delegation, registration, exposed web ports and recon; not for subdomain brute forcing, port scanning or exploitation.
---

# Cyber360 H1 — Reconnaissance

This is the portable plugin entrypoint for the canonical H1 agent package.

1. Run `../../scripts/setup-tools.sh --check`.
2. Read and follow the [H1 identity and instructions](../../agents/hacking/reconnaissance/agent.md).
3. Read the canonical [domain reconnaissance skill](../../agents/hacking/reconnaissance/skills/domain-reconnaissance/SKILL.md).
4. Use only registered invocations from the [tool registry](../../agents/hacking/reconnaissance/tools.yaml), preferably through `engine/domain/full_audit.py <domain> --authority "<statement>" --skip-tls`. The engine needs outbound network access; in a sandboxed host such as Codex, request approval to run it with network access.
5. Follow the [assess workflow](../../agents/hacking/reconnaissance/workflows/assess.yaml).

Do not infer network authority from invocation of this skill. If the exact domain or authority is unclear, stop before making a connection. For DNS, TLS and email checks together, use the `full-domain-audit` skill (`/demo-domain-audit:full-domain-audit` in Claude Code, `$demo-domain-audit:full-domain-audit` in Codex).
