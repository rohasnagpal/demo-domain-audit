---
name: tls-security
description: Run the Cyber360 S11 TLS & Cryptography Security Agent against an explicitly authorised endpoint or supplied TLS configuration. Use for certificates, hostname or IP identity, trust chains, TLS protocols, ciphers, OpenSSL evidence, remediation or fix verification; not for general web testing or network scanning.
---

# Cyber360 S11 — TLS Security

This is the portable plugin entrypoint for the canonical S11 agent package.

1. Run `../../scripts/setup-tools.sh --check`. For classroom use, stop if any declared S11 tool is missing and direct the user to the `setup-tools` skill (`/demo-domain-audit:setup-tools` in Claude Code, `$demo-domain-audit:setup-tools` in Codex).
2. Read and follow the [S11 identity and instructions](../../agents/security/tls-security/agent.md).
3. Read the canonical [TLS assessment skill](../../agents/security/tls-security/skills/tls-assessment/SKILL.md).
4. Use only registered invocations from the [tool registry](../../agents/security/tls-security/tools.yaml). Live checks need outbound network access; in a sandboxed host such as Codex, request approval to run them with network access.
5. Select the applicable workflow: [assess](../../agents/security/tls-security/workflows/assess.yaml), [remediate](../../agents/security/tls-security/workflows/remediate.yaml) or [verify](../../agents/security/tls-security/workflows/verify.yaml).
6. Load only the referenced baseline, authorities and output files required by that workflow.

Do not infer network or change authority from invocation of this skill. If the exact remote target or authority is unclear, stop before making a connection.
