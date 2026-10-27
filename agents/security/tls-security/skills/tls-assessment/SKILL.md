---
name: tls-assessment
description: Assess an explicitly authorised TLS endpoint or TLS configuration for certificate identity, trust, validity, protocol and cryptographic weaknesses. Do not use for general web testing, network scanning or exploitation.
---

# TLS Assessment

Assess one expressly authorised TLS service at a time and produce reproducible, evidence-based findings.

## Prepare

1. Read `../../references/tls-baseline.yaml` and use only the controls relevant to the requested scope.
2. Read `../../references/authorities.yaml` when interpreting a control or citing its source.
3. Record the target, port, identifier type, authority, time window and exclusions.
4. Distinguish hostnames from IP addresses. A hostname is checked against DNS SAN entries; an IP address is checked against `iPAddress` SAN entries.
5. Discover the registered tool version before testing. If the required tool is unavailable, report the limitation and stop rather than substituting an unregistered command.
6. Choose a unique report ID and run `../../../../../engine/reporting/output_store.py <report-id>`. Use the returned directory for all files created by the assessment. Its layout is `cyber360-reports/<report-id>/report.json`, `report.html` and `evidence/`.

## Collect evidence

Use the registered templates in `../../tools.yaml`; do not construct an arbitrary shell command.

- Run the matching hostname or IP chain-retrieval invocation first, then run the separate identity and trust verification invocation. Strict verification can terminate a handshake before complete chain evidence is captured, so these are distinct evidence steps.
- Preserve the command arguments, UTC start and end times, tool version, exit status, stdout and stderr.
- Preserve every raw output directly under the managed report directory's `evidence/` folder.
- Extract the presented leaf certificate into that `evidence/` folder when certificate inspection is in scope, then run the registered inspection command.
- Test TLS 1.0, 1.1, 1.2 and 1.3 only when protocol coverage is requested. A client-side error is not conclusive unless the evidence distinguishes local lack of support from server rejection.
- Use optional `testssl.sh` only when installed, authorised and needed for broader cipher enumeration.

Do not treat a successful chain-retrieval connection as successful trust validation. Do not infer complete cipher, chain, revocation, HTTP-security-header or application coverage from a successful basic handshake.

## Analyse

- Evaluate each selected baseline rule as `pass`, `confirmed`, `unknown` or `not_applicable`.
- A confirmed finding must meet the rule's `evidence_required` fields.
- Keep certificate identity, validity and trust-chain conclusions separate.
- Treat policy thresholds as policy choices, not universal cryptographic facts.
- State when interception, a private trust store, TLS termination or a load balancer could change the conclusion.
- Do not convert tool labels directly into severity without analysing exposure and impact.

## Remediate and verify

Do not change configuration unless the user expressly authorises remediation. When authorised, identify the actual TLS terminator and make the smallest applicable change. Preserve the pre-change evidence.

Verify by rerunning the checks tied to each finding. Record exactly one outcome:

- `verified_fixed`
- `partially_fixed`
- `not_fixed`
- `not_reproducible`
- `verification_blocked`

Do not mark a finding fixed merely because configuration text changed.

## Report

Write JSON conforming to `../../outputs/report.schema.json` to the managed path `cyber360-reports/<report-id>/report.json`. Populate the structured `technical` fields for certificates, protocols, cipher suites, client simulations, server features and passed controls only where captured evidence supports them. Report untested and blocked controls as unknown or not tested.

Generate `cyber360-reports/<report-id>/report.html` with `../../../../../engine/reporting/render_tls_report.py`. The renderer rejects output paths outside `cyber360-reports/`. The deliverable is a self-contained HTML file, not Markdown. Assign a grade only when the report records a defensible scoring basis and sufficient evidence; otherwise use `N/A`.
