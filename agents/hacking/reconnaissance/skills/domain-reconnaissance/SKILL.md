---
name: domain-reconnaissance
description: Build a passive, low-volume attack-surface inventory of one explicitly authorised domain from DNS, WHOIS, reachability and HTTPS evidence. Do not use for subdomain brute forcing, port scanning or exploitation.
---

# Domain Reconnaissance

Map what one expressly authorised domain exposes and preserve reproducible evidence for every observation.

## Prepare

1. Record the domain, authority, time window and exclusions.
2. Reject URLs, wildcards, IP ranges and lists of domains; ask for one domain.
3. Read `../../references/authorities.yaml` when explaining a record type.
4. Choose a unique report ID and run `../../../../../engine/reporting/output_store.py <report-id>`. Use only that directory.

## Collect evidence

Prefer the shared engine, which runs the registered argv lists without a shell and preserves evidence:

```bash
python3 engine/domain/full_audit.py <domain> --authority "<authority statement>" --skip-tls
```

When the engine is unavailable, run only the registered invocations in `../../tools.yaml`, substituting the authorised domain. Never interpolate user text into a shell string.

- Preserve the command, UTC start and end times, exit status, stdout and stderr for each invocation under `evidence/`.
- A failed, refused or timed-out command is evidence of that result, not of absence.

## Analyse

- Inventory A, AAAA, CNAME, MX, NS, SOA, TXT and CAA records, the delegation trace, registrar, creation and expiry dates and EPP status codes.
- Record the HTTPS redirect chain, final status, response time and remote IP, and the state of TCP 80 and 443.
- Note technology disclosures (`Server`, `X-Powered-By`, `Via`) as observations.
- Note third-party services revealed by records (mail provider, DNS host, verification tokens) without probing them.
- Assess only the H1 exposure controls. Pass security conclusions about TLS to S11 and about email authentication, DNSSEC and registration hygiene to S18.

## Report

Write the H1 report to `cyber360-reports/<domain>/H1-reconnaissance/`: the inventory with what each item reveals, the H1 controls (server banner, X-Powered-By, HTTP-to-HTTPS redirect, HSTS and third-party services) and detailed findings from `../../references/knowledge.json`.
