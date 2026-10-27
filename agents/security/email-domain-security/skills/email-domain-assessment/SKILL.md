---
name: email-domain-assessment
description: Assess an explicitly authorised domain for SPF, DMARC, DKIM, MTA-STS, TLS-RPT, SMTP STARTTLS, CAA, DNSSEC, nameserver and registration weaknesses. Do not use to send email, test relaying or enumerate mailboxes.
---

# Email & Domain Assessment

Assess one expressly authorised domain and produce reproducible, evidence-based control results.

## Prepare

1. Read `../../references/baseline.json` for the controls, authorities and remediation.
2. Read `../../references/authorities.yaml` when citing a source.
3. Record the domain, authority, any supplied DKIM selectors and exclusions.
4. Choose a unique report ID and run `../../../../../engine/reporting/output_store.py <report-id>`.

## Collect evidence

Prefer the shared engine:

```bash
python3 engine/domain/full_audit.py <domain> --authority "<authority statement>" [--dkim-selector <selector> ...] --skip-tls
```

Otherwise run only the registered invocations in `../../tools.yaml`:

- mail records: MX, TXT, `_dmarc`, `_smtp._tls`, `_mta-sts` and CAA, plus the MTA-STS policy fetch;
- DKIM only for supplied selectors;
- DNSSEC: DS, DNSKEY and `+dnssec` answers for A, AAAA, MX and TXT;
- delegation: NS, SOA and `+trace`;
- one `openssl s_client -starttls smtp` session per MX host with empty stdin; and
- WHOIS.

Preserve the command, UTC times, exit status, stdout and stderr of each invocation.

## Analyse

- **SPF:** exactly one `v=spf1` record; the final all-qualifier; the number of DNS-querying terms. Nested includes are not expanded, so a count of ten or fewer is `unknown` rather than a pass.
- **DMARC:** exactly one `v=DMARC1` record; `p=quarantine` or `p=reject`; `pct`; an `rua` address.
- **DKIM:** a non-empty `p=` key for each supplied selector.
- **MTA-STS and TLS-RPT:** record present, policy reachable over HTTPS, `mode: enforce`.
- **SMTP:** STARTTLS offered and `Verify return code: 0 (ok)`. An unreachable port 25 is `unknown`.
- **CAA:** at least one issuance restriction.
- **DNSSEC:** DS at the parent plus DNSKEY and RRSIG in the zone. DS without signatures is critical because validating resolvers will fail.
- **Nameservers:** at least two.
- **Registration:** expiry more than 30 days away and a transfer lock.

A control without conclusive evidence is `unknown`, never `pass`.

## Report

Write the S18 report to `cyber360-reports/<domain>/S18-email-domain/`. Every control is explained, and each finding uses `../../references/knowledge.json` for what was found, why it matters, the fix, rollback and verification.
