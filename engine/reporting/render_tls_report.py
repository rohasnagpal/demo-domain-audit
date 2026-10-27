#!/usr/bin/env python3
"""Render a Cyber360 S11 JSON report as a self-contained HTML report."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

try:
    from . import charts, report_charts, theme
    from . import components as ui
    from .output_store import create_report_directory, reports_root, require_managed_path
except ImportError:
    import charts
    import components as ui
    import report_charts
    import theme
    from output_store import create_report_directory, reports_root, require_managed_path


ROOT = Path(__file__).resolve().parents[2]


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def badge(value: Any, tone: str | None = None) -> str:
    label = str(value or "unknown")
    css = tone or label.lower().replace("_", "-").replace(" ", "-")
    return f'<span class="badge {esc(css)}">{esc(label.replace("_", " "))}</span>'


def rows(items: list[tuple[str, Any]]) -> str:
    rendered = []
    for label, value in items:
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        rendered.append(
            f'<div class="data-row"><dt>{esc(label)}</dt><dd>{esc(value)}</dd></div>'
        )
    return "".join(rendered) or '<p class="empty">No structured data recorded.</p>'


def section(title: str, body: str, subtitle: str = "") -> str:
    sub = f'<p class="section-subtitle">{esc(subtitle)}</p>' if subtitle else ""
    return f'<section class="panel"><header class="panel-head"><div><h2>{esc(title)}</h2>{sub}</div></header>{body}</section>'


def render_scores(technical: dict[str, Any], summary: dict[str, Any], external: dict[str, Any] | None = None) -> str:
    external = external or {}
    provider = external.get("provider")
    grade = technical.get("grade", "N/A")
    score = technical.get("score")
    score_text = f"{score}/100" if isinstance(score, (int, float)) else ("Provider grade" if provider else "Not scored")
    grade_class = str(grade).lower().replace("+", "-plus").replace("/", "-")
    components = technical.get("score_components", [])
    if components:
        bars = "".join(
            f'''<div class="score-row">
                <div><span>{esc(item.get("name", "Component"))}</span><strong>{esc(item.get("score", "N/A"))}</strong></div>
                <div class="track"><i style="width:{max(0, min(100, int(item.get('score', 0))))}%"></i></div>
            </div>'''
            for item in components
        )
    elif provider:
        evidence_sections = [
            ("Certificates", len(external.get("certificates", []))),
            ("Protocols", len(external.get("protocols", []))),
            ("Cipher suites", len(external.get("cipher_suites", []))),
            ("Handshake simulations", len(external.get("client_simulations", []))),
        ]
        bars = "".join(
            f'''<div class="evidence-row"><span>{esc(name)}</span><div class="track"><i class="{'available' if count else 'absent'}" style="width:{'100' if count else '0'}%"></i></div><strong>{count} record{'s' if count != 1 else ''}</strong></div>'''
            for name, count in evidence_sections
        )
        bars += '<p class="bar-note">Evidence availability only — these bars are not component security scores.</p>'
    else:
        bars = f'''<div class="metric-grid">
            <div><strong>{esc(summary.get("confirmed_findings", 0))}</strong><span>Confirmed findings</span></div>
            <div><strong>{esc(summary.get("unknown_controls", 0))}</strong><span>Unknown controls</span></div>
        </div>
        <p class="empty compact">{esc('SSL Labs does not expose Cyber360 component scores; no numeric score was inferred.' if provider else 'This report has no component scores. Cyber360 does not infer a grade from incomplete data.')}</p>'''
    basis = technical.get("grade_basis", "No grade was supplied by the assessment agent.")
    grade_label = f"{provider} grade" if provider else "Evidence grade"
    return f'''<div class="score-layout">
        <div class="grade grade-{esc(grade_class)}"><span>{esc(grade_label)}</span><strong>{esc(grade)}</strong><small>{esc(score_text)}</small></div>
        <div class="score-details">{bars}<p class="grade-basis">{esc(basis)}</p></div>
    </div>'''


def render_notices(report: dict[str, Any]) -> str:
    notices = []
    if report.get("external_assessment"):
        notices.extend([
            '<div class="notice info"><b>Remote scan</b><span>The TLS assessment was performed by Qualys SSL Labs servers, not locally by Cyber360.</span></div>',
            '<div class="notice success"><b>Data fidelity</b><span>Provider grades and original API values are preserved without recalculation.</span></div>',
            '<div class="notice caution"><b>Use terms</b><span>Results remain subject to the Qualys SSL Labs Terms of Use and the target owner’s permission.</span></div>',
        ])
        legacy = report["external_assessment"].get("legacy_warning")
        if legacy:
            notices.append(f'<div class="notice warning"><b>Legacy API</b><span>{esc(legacy)}</span></div>')
    for text in report.get("limitations", []):
        notices.append(f'<div class="notice warning"><b>Limitation</b><span>{esc(text)}</span></div>')
    for text in report.get("assumptions", []):
        notices.append(f'<div class="notice info"><b>Assumption</b><span>{esc(text)}</span></div>')
    return "".join(notices)


def render_findings(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    if any("what_we_found" in finding for finding in findings):
        return ui.render_findings(findings)
    if not findings:
        return '<div class="good-state"><span>✓</span><div><strong>No confirmed findings</strong><p>No finding met the selected baseline evidence threshold. Review unknowns and limitations before drawing assurance conclusions.</p></div></div>'
    cards = []
    for finding in findings:
        evidence = finding.get("evidence", [])
        evidence_links = "".join(
            f'<li>{ui.evidence_link(item)} {esc(item.get("path"))}</li>'
            for item in evidence
        )
        cards.append(f'''<article class="finding severity-{esc(finding.get('severity'))}">
            <div class="finding-title"><div>{badge(finding.get('severity'))}<code>{esc(finding.get('finding_id'))}</code></div><h3>{esc(finding.get('title'))}</h3></div>
            <p>{esc(finding.get('analysis'))}</p>
            <div class="finding-grid"><div><h4>Remediation</h4><p>{esc(finding.get('remediation'))}</p></div><div><h4>Verification</h4>{badge(finding.get('verification'))}</div></div>
            <details><summary>Evidence</summary><ul class="evidence-list">{evidence_links}</ul></details>
        </article>''')
    return "".join(cards)


def render_certificates(technical: dict[str, Any]) -> str:
    certificates = technical.get("certificates", [])
    if not certificates:
        return '<p class="empty">Certificate evidence was not supplied as structured report data.</p>'
    cards = []
    for index, cert in enumerate(certificates, 1):
        cards.append(f'''<article class="subpanel">
            <div class="subpanel-title"><h3>Certificate #{index}: {esc(cert.get('subject', 'Unnamed certificate'))}</h3>{badge(cert.get('status', 'observed'))}</div>
            <dl class="data-list">{rows([
                ('Position', cert.get('position')),
                ('Subject', cert.get('subject')),
                ('Issuer', cert.get('issuer')),
                ('Serial number', cert.get('serial_number')),
                ('DNS names / IP SANs', cert.get('subject_alternative_names')),
                ('Valid from', cert.get('not_before')),
                ('Valid until', cert.get('not_after')),
                ('Public key', cert.get('public_key')),
                ('Signature algorithm', cert.get('signature_algorithm')),
                ('SHA-256 fingerprint', cert.get('sha256_fingerprint')),
                ('Trust result', cert.get('trust_result')),
                ('Identity result', cert.get('identity_result')),
            ])}</dl>
        </article>''')
    return "".join(cards)


def render_table(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not items:
        return '<p class="empty">No structured results recorded.</p>'
    head = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
    body = []
    for item in items:
        cells = []
        for key, _ in columns:
            value = item.get(key, "")
            cells.append(f"<td>{badge(value) if key in {'status', 'result'} else esc(value)}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def render_unknowns(report: dict[str, Any]) -> str:
    unknowns = report.get("unknowns", [])
    if not unknowns:
        return '<div class="good-state small"><span>✓</span><div><strong>No unresolved controls recorded</strong></div></div>'
    return "".join(
        f'''<article class="unknown"><div><code>{esc(item.get('rule_id'))}</code>{badge('unknown')}</div>
        <p>{esc(item.get('reason'))}</p><p><strong>Evidence needed:</strong> {esc(item.get('evidence_needed'))}</p></article>'''
        for item in unknowns
    )


def pretty(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def render_api_table(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not items:
        return '<p class="empty">The API did not return this section.</p>'
    head = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
    body = []
    for item in items:
        cells = "".join(f'<td><code class="api-value">{esc(pretty(item.get(key)))}</code></td>' for key, _ in columns)
        body.append(f"<tr>{cells}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def render_original_certificate(item: dict[str, Any], index: int) -> str:
    original = item.get("original") or {}
    public_values = [(key, pretty(value)) for key, value in original.items() if key != "raw"]
    pem = original.get("raw")
    pem_html = f'<details class="raw-response"><summary>PEM certificate evidence</summary><pre class="json-block">{esc(pem)}</pre></details>' if pem else ""
    return f'<details class="subpanel disclosure" {"open" if index == 0 else ""}><summary>{esc(item.get("position"))}: {esc(item.get("subject"))}</summary><dl class="data-list padded">{rows(public_values)}</dl>{pem_html}</details>'


def render_chain_details(item: dict[str, Any], index: int) -> str:
    chain_cards = []
    for chain_number, chain in enumerate(item.get("chains") or [], 1):
        trust_paths = []
        for path_number, path in enumerate(chain.get("trustPaths") or [], 1):
            stores = ", ".join(
                f"{trust.get('rootStore', 'unknown')}: {'trusted' if trust.get('isTrusted') else 'not trusted'}"
                + (f" ({trust.get('trustErrorMessage')})" if trust.get('trustErrorMessage') else "")
                for trust in path.get("trust", [])
            ) or "not reported"
            trust_paths.append({
                "path": path_number,
                "certIds": path.get("certIds"),
                "stores": stores,
                "isPinned": path.get("isPinned"),
                "matchedPins": path.get("matchedPins"),
                "unmatchedPins": path.get("unmatchedPins"),
            })
        chain_cards.append(
            f'<article class="chain-card"><h4>Chain {chain_number}</h4><dl class="data-list">{rows([("Chain ID", chain.get("id")), ("Certificate IDs", chain.get("certIds")), ("Issue flags", chain.get("issues")), ("No SNI", chain.get("noSni"))])}</dl>{render_api_table(trust_paths, [("path", "Trust path"), ("certIds", "Certificate IDs"), ("stores", "Trust stores"), ("isPinned", "Pinned"), ("matchedPins", "Matched pins"), ("unmatchedPins", "Unmatched pins")])}</article>'
        )
    content = "".join(chain_cards) or '<p class="empty">No chain objects returned.</p>'
    return f'<details class="subpanel disclosure" {"open" if index == 0 else ""}><summary>Certification paths for endpoint {esc(item.get("endpoint"))}</summary>{content}</details>'


def render_external_assessment(external: dict[str, Any]) -> str:
    if not external:
        return ""
    endpoints = external.get("endpoints", [])
    endpoint_rows = [{
        "ipAddress": item.get("ipAddress"), "serverName": item.get("serverName"),
        "statusMessage": item.get("statusMessage"), "grade": item.get("grade"),
        "gradeTrustIgnored": item.get("gradeTrustIgnored"), "futureGrade": item.get("futureGrade"),
        "hasWarnings": item.get("hasWarnings"),
    } for item in endpoints]
    grade_tiles = "".join(
        f'<div class="endpoint-grade"><span>{esc(item.get("ipAddress", "endpoint"))}</span><strong>{esc(item.get("grade", "N/A"))}</strong><small>{esc(item.get("statusMessage", "not reported"))}</small></div>'
        for item in endpoints
    ) or '<p class="empty">No endpoint grades were returned.</p>'
    cipher_counts: dict[str, int] = {}
    for suite in external.get("cipher_suites", []):
        strength = suite.get("cipherStrength")
        label = f"{strength} bit" if strength is not None else "not reported"
        cipher_counts[label] = cipher_counts.get(label, 0) + 1
    maximum = max(cipher_counts.values(), default=1)
    cipher_chart = "".join(
        f'<div class="chart-row"><span>{esc(label)}</span><i style="width:{count / maximum * 100:.1f}%"></i><b>{count}</b></div>'
        for label, count in sorted(cipher_counts.items())
    ) or '<p class="empty">No cipher strength values were returned.</p>'
    simulations = []
    for item in external.get("client_simulations", []):
        client = item.get("client") or {}
        simulations.append({
            "endpoint": item.get("endpoint"),
            "client": " ".join(str(client.get(key, "")) for key in ("name", "version") if client.get(key)),
            "platform": client.get("platform"), "result": "success" if item.get("errorCode") == 0 else "failed",
            "errorMessage": item.get("errorMessage"), "protocolId": item.get("protocolId"),
            "suiteName": item.get("suiteName"), "kxType": item.get("kxType"),
            "kxStrength": item.get("kxStrength"), "namedGroupName": item.get("namedGroupName"),
        })
    metadata = rows([
        ("Provider", external.get("provider")), ("API", external.get("api_version")),
        ("Engine version", external.get("engine_version")), ("Criteria version", external.get("criteria_version")),
        ("Retrieval mode", external.get("mode")), ("Assessment status", external.get("status")),
        ("Provider status message", external.get("status_message")), ("Assessment start", external.get("start_time")),
        ("Assessment completion", external.get("test_time")), ("Cache expiry", external.get("cache_expiry_time")),
        ("Published by provider", external.get("is_public")), ("Raw response", external.get("raw_path")),
        ("Legacy API warning", external.get("legacy_warning")),
        ("Methodology", external.get("methodology")), ("Attribution", external.get("attribution")),
    ])
    messages = external.get("service_messages", [])
    message_html = "".join(f"<li>{esc(message)}</li>" for message in messages) or "<li>No service messages returned.</li>"
    endpoint_table = render_api_table(endpoint_rows, [
        ("ipAddress", "Endpoint"), ("serverName", "Server name"), ("statusMessage", "Status"),
        ("grade", "Grade"), ("gradeTrustIgnored", "Trust ignored"), ("futureGrade", "Future grade"), ("hasWarnings", "Warnings")
    ])
    protocol_table = render_api_table(external.get("protocols", []), [
        ("endpoint", "Endpoint"), ("name", "Name"), ("version", "Version"), ("id", "ID"),
        ("v2SuitesDisabled", "SSLv2 suites disabled"), ("q", "Quality flag")
    ])
    suite_table = render_api_table(external.get("cipher_suites", []), [
        ("endpoint", "Endpoint"), ("source", "Handshake"), ("protocol", "Protocol"), ("name", "Suite"), ("cipherStrength", "Cipher bits"),
        ("kxType", "Key exchange"), ("kxStrength", "KX bits"), ("namedGroupName", "Named group"),
        ("q", "Quality flag"), ("preference", "Server preference")
    ])
    simulation_table = render_api_table(simulations, [
        ("endpoint", "Endpoint"), ("client", "Client"), ("platform", "Platform"), ("result", "Handshake"),
        ("errorMessage", "Error"), ("protocolId", "Protocol ID"), ("suiteName", "Suite"),
        ("kxType", "KX"), ("kxStrength", "KX bits"), ("namedGroupName", "Named group")
    ])
    check_table = render_api_table(external.get("checks", []), [
        ("endpoint", "Endpoint"), ("field", "Original API field"), ("value", "Original API value")
    ])
    chain_html = "".join(render_chain_details(item, index) for index, item in enumerate(external.get("certificate_chains", []))) or '<p class="empty">The API did not return certificate-chain details.</p>'
    certificate_html = "".join(render_original_certificate(item, index) for index, item in enumerate(external.get("certificates", []))) or '<p class="empty">The API did not return certificate objects.</p>'
    transaction_html = "".join(
        f'<article class="subpanel"><h3>Endpoint {esc(item.get("endpoint"))}</h3><pre class="json-block">{esc(pretty(item.get("transactions")))}</pre></article>'
        for item in external.get("http_transactions", [])
    ) or '<p class="empty">The API did not return HTTP transactions.</p>'
    raw = external.get("raw_bundle")
    raw_html = f'<details class="raw-response"><summary>Complete preserved API response</summary><pre class="json-block">{esc(pretty(raw))}</pre></details>' if raw is not None else '<p class="empty">See the raw response file identified above.</p>'
    certificate_panel = section(
        "Certificates and trust chains",
        f'<div class="report-block"><h3>Certificate summary</h3><p>Identity, issuer, validity, names, algorithms and fingerprints.</p>{render_certificates({"certificates": external.get("certificates", [])})}</div><div class="report-block"><h3>Complete certificate objects</h3><p>Original identifiers, revocation, CAA, issue flags, fingerprints and key data.</p>{certificate_html}</div><div class="report-block"><h3>Certification paths</h3><p>Certificate IDs, trust paths, trust stores and original chain issue flags.</p>{chain_html}</div>',
        "Complete SSL Labs certificate evidence",
    )
    configuration_panel = section(
        "Configuration",
        "".join([
            f'<div class="report-block"><h3>Endpoints and grades</h3><p>Exact provider grades; Cyber360 does not recalculate them.</p><div class="provider-visuals"><div class="endpoint-grades">{grade_tiles}</div><div class="cipher-chart"><h3>Cipher strengths returned</h3>{cipher_chart}</div></div>{endpoint_table}</div>',
            f'<div class="report-block"><h3>Protocols</h3><p>Every protocol object returned by the API.</p>{protocol_table}</div>',
            f'<div class="report-block"><h3>Cipher suites</h3><p>SNI and no-SNI suites with original quality flags.</p>{suite_table}</div>',
            f'<div class="report-block"><h3>Browser and client simulations</h3><p>Negotiated protocol, suite, key exchange and any simulation error.</p>{simulation_table}</div>',
            f'<div class="report-block"><h3>Protocol details, vulnerabilities and security features</h3><p>All endpoint-detail fields outside the dedicated sections.</p>{check_table}</div>',
            f'<div class="report-block"><h3>HTTP requests and responses</h3><p>Redirects, response status and provider-observed transactions.</p>{transaction_html}</div>',
        ]),
        "Protocols, suites, compatibility, vulnerabilities, features and HTTP behavior",
    )
    metadata_panel = section(
        "Assessment details and methodology",
        f'<dl class="data-list padded">{metadata}</dl><div class="api-messages"><h3>SSL Labs service messages shown before assessment</h3><ul>{message_html}</ul></div>',
        "Provider versions, timing, cache state and attribution",
    )
    return certificate_panel + configuration_panel + metadata_panel + section("Original API evidence", raw_html, "Lossless provider data for audit and regeneration")


def render_report(report: dict[str, Any]) -> str:
    scope = report.get("scope", {})
    summary = report.get("summary", {})
    technical = report.get("technical", {})
    external = report.get("external_assessment", {})
    endpoint = f"{scope.get('target', 'unknown')}:{scope.get('port', '')}"
    tooling = "".join(
        f'<li><strong>{esc(tool.get("name"))}</strong><span>{esc(tool.get("version"))}</span></li>'
        for tool in report.get("tooling", [])
    )
    protocols = render_table(technical.get("protocols", []), [
        ("name", "Protocol"), ("status", "Status"), ("negotiated_cipher", "Negotiated cipher"), ("evidence_id", "Evidence")
    ])
    ciphers = render_table(technical.get("cipher_suites", []), [
        ("protocol", "Protocol"), ("name", "Cipher suite"), ("strength_bits", "Bits"), ("key_exchange", "Key exchange"), ("status", "Status")
    ])
    clients = render_table(technical.get("client_simulations", []), [
        ("client", "Client"), ("platform", "Platform"), ("result", "Result"), ("protocol", "Protocol"), ("cipher", "Cipher")
    ])
    features = render_table(technical.get("server_features", []), [
        ("name", "Feature"), ("status", "Status"), ("details", "Details")
    ])
    passed = technical.get("passed_controls", [])
    passed_body = "".join(
        f'<li><code>{esc(item.get("rule_id"))}</code><span>{esc(item.get("title"))}</span><small>{esc(", ".join(item.get("evidence_ids", [])))}</small></li>'
        for item in passed
    ) or '<li class="empty">No passed controls were supplied as structured data.</li>'

    css = theme.stylesheet()
    records = {item["evidence_id"]: item for item in report.get("evidence", [])}
    script = '''document.querySelectorAll('[data-print]').forEach(b=>b.addEventListener('click',()=>window.print()));''' + charts.TOOLTIP_JS
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber360 TLS Report — {esc(endpoint)}</title><style>{css}</style></head>
<body><header class="topbar"><div class="brand"><span class="brand-mark">360</span><div><strong>Cyber360</strong><small>TLS &amp; Cryptography Security</small></div></div><button data-print>Print / Save PDF</button></header>
<main>
  <section class="report-head"><div><p class="eyebrow">S11 SECURITY ASSESSMENT</p><h1>TLS report: {esc(endpoint)}</h1><p>Point-in-time, evidence-based assessment generated {esc(report.get('generated_at'))}</p></div><div class="report-id"><span>Report ID</span><code>{esc(report.get('report_id'))}</code></div></section>
  {section('Other reports from this run', '<ul class="toc">' + ''.join(f'<li><a href="{esc(item["href"])}" target="_blank" rel="noopener">{esc(item["label"])}</a></li>' for item in report.get('related_reports', [])) + '</ul>') if report.get('related_reports') else ''}
  {section('Executive summary', render_scores(technical, summary, external) + f'<div class="assessment"><h3>Assessment</h3><p>{esc(summary.get("overall_assessment"))}</p></div>' + render_notices(report), 'Observed posture and evidence coverage')}
  {section('At a glance', report_charts.build(report), 'Hover or focus any mark for detail; each chart has a data table') if not external else ''}
  {section('Confirmed findings', render_findings(report), 'Risks meeting the Cyber360 evidence threshold')}
  {'' if external else section('Certificate chain', render_certificates(technical), 'Identity, validity, trust and cryptographic properties')}
  {render_external_assessment(external)}
  {'' if external else section('Protocol configuration', protocols, 'Observed handshake results for explicitly tested protocol versions')}
  {'' if external else section('Cipher suites', ciphers, 'Observed or enumerated cipher configuration')}
  {'' if external else section('Client simulations', clients, 'Compatibility observations; absent results are not inferred')}
  {'' if external else section('Server features', features, 'TLS-related capabilities and defensive configuration')}
  {'' if external else section('Passed controls', f'<ul class="control-list">{passed_body}</ul>', 'Only controls actually tested and satisfied')}
  {section('Every control checked', ui.render_controls_table(report['controls'], records), 'Passes, findings and unknowns, each with what the control checks and its evidence') if report.get('controls') and isinstance(report['controls'][0], dict) and 'about' in report['controls'][0] else ''}
  {section('Unknowns and evidence gaps', ui.render_unknowns(report['unknowns'], records) if report.get('controls') else render_unknowns(report), 'Items that remain unresolved are not treated as passes')}
  {section('Methodology and evidence', ui.render_methodology(report['evidence'], report.get('command_purposes', {})), 'Every command run, why it was run and its raw output (opens in a new tab)') if report.get('evidence') else ''}
  {section('Glossary', ui.render_glossary(report['glossary']), 'Terms used in this report') if report.get('glossary') else ''}
  <section class="two-col">
    {section('Scope and authority', f'<dl class="data-list">{rows([("Target", scope.get("target")), ("Port", scope.get("port")), ("Identifier type", scope.get("identifier_type")), ("Authority", scope.get("authority")), ("Started", scope.get("started_at")), ("Completed", scope.get("completed_at")), ("Exclusions", scope.get("exclusions"))])}</dl>')}
    {section('Tools', f'<ul class="tool-list">{tooling}</ul>', 'Locally executed tooling recorded by the assessment')}
  </section>
</main>
<footer><strong>Cyber360</strong><span>Local-first evidence. Findings are limited to the stated scope, tests and assessment time.</span></footer>
<script>{script}</script></body></html>'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="S11 report JSON")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="HTML path below ./cyber360-reports/; defaults to <report-id>/report.html",
    )
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if args.output:
        candidate = args.output if args.output.is_absolute() else Path.cwd() / args.output
        try:
            output = require_managed_path(candidate)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        source = args.report.resolve()
        root = reports_root()
        try:
            source.relative_to(root)
            output = source.with_suffix(".html")
        except ValueError:
            output = create_report_directory(str(report.get("report_id", "tls-report"))) / "report.html"
    if output.suffix.lower() != ".html":
        parser.error("HTML report output must use the .html extension")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(report), encoding="utf-8")
    print(output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

