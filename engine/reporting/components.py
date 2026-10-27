#!/usr/bin/env python3
"""Shared HTML building blocks for Cyber360 agent reports: detailed findings, evidence links and reference sections."""

from __future__ import annotations

import html
from pathlib import PurePosixPath
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "informational")



def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def badge(value: Any) -> str:
    label = str(value or "unknown")
    css = label.lower().replace("_", "-").replace(" ", "-")
    return f'<span class="badge {esc(css)}">{esc(label.replace("_", " "))}</span>'


def section(title: str, body: str, subtitle: str = "", anchor: str = "") -> str:
    sub = f'<p class="section-subtitle">{esc(subtitle)}</p>' if subtitle else ""
    ident = f' id="{esc(anchor)}"' if anchor else ""
    return f'<section class="panel"{ident}><header class="panel-head"><div><h2>{esc(title)}</h2>{sub}</div></header>{body}</section>'


def evidence_href(record: dict[str, Any]) -> str:
    """Link relative to report.html so it works offline and in any copy of the report folder."""
    path = PurePosixPath(str(record.get("path", "")).replace("\\", "/"))
    return f"evidence/{path.name}" if path.name else "#"


def evidence_link(record: dict[str, Any], label: str | None = None) -> str:
    return (
        f'<a class="evidence-link" href="{esc(evidence_href(record))}" target="_blank" rel="noopener">'
        f'{esc(label or record.get("evidence_id"))} ↗</a>'
    )


def evidence_ids_links(ids: list[str], records: dict[str, dict[str, Any]]) -> str:
    return ", ".join(evidence_link(records[eid]) if eid in records else esc(eid) for eid in ids) or "—"


def render_evidence_items(evidence: list[dict[str, Any]]) -> str:
    items = []
    for record in evidence:
        command = " ".join(str(part) for part in record.get("command", []))
        excerpt = str(record.get("excerpt", "")).strip()
        excerpt_html = f'<pre class="excerpt">{esc(excerpt)}</pre>' if excerpt else ""
        sha = str(record.get("sha256", ""))
        items.append(
            f'<li>{evidence_link(record)} <code>{esc(command)}</code>'
            f'<div class="meta">exit {esc(record.get("exit_status"))} · captured {esc(record.get("captured_at"))} · sha256 {esc(sha[:16])}…</div>'
            f"{excerpt_html}</li>"
        )
    return f'<ul class="evidence-items">{"".join(items)}</ul>' if items else '<p class="empty">No evidence recorded.</p>'


def render_step(step: Any) -> str:
    if isinstance(step, dict):
        code = f'<pre class="code">{esc(step.get("code"))}</pre>' if step.get("code") else ""
        return f"<li>{esc(step.get('text', ''))}{code}</li>"
    return f"<li>{esc(step)}</li>"


def render_detailed_finding(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "informational"))
    meta = " · ".join(
        part
        for part in (
            f"Control {finding.get('rule_id')}" if finding.get("rule_id") else "",
            str(finding.get("category", "")),
            f"Authority {finding.get('authority')}" if finding.get("authority") else "",
        )
        if part
    )
    blocks = []
    if finding.get("about"):
        blocks.append(f"<h4>What this control checks</h4><p>{esc(finding['about'])}</p>")
    blocks.append(f'<h4>What we found</h4><div class="observed">{esc(finding.get("what_we_found") or finding.get("analysis"))}</div>')
    why = finding.get("why_it_matters") or []
    if why:
        blocks.append("<h4>Why it matters</h4>" + "".join(f"<p>{esc(paragraph)}</p>" for paragraph in why))
    if finding.get("attack_scenario"):
        blocks.append(f'<h4>How an attacker would use it</h4><p class="callout">{esc(finding["attack_scenario"])}</p>')
    if finding.get("severity_rationale"):
        blocks.append(f"<h4>Why {esc(severity)}</h4><p>{esc(finding['severity_rationale'])}</p>")
    steps = finding.get("fix_steps") or ([finding["remediation"]] if finding.get("remediation") else [])
    if steps:
        blocks.append(f'<h4>How to fix it</h4><ol class="fix-steps">{"".join(render_step(step) for step in steps)}</ol>')
    if finding.get("rollback"):
        blocks.append(f"<h4>Rollback</h4><p>{esc(finding['rollback'])}</p>")
    verify = finding.get("verify") or {}
    if verify:
        blocks.append(
            '<h4>How to verify the fix</h4><dl class="verify-grid">'
            f'<dt>Run</dt><dd><pre class="code">{esc(verify.get("command"))}</pre></dd>'
            f'<dt>Expect</dt><dd>{esc(verify.get("expected"))}</dd>'
            f'<dt>Status</dt><dd>{badge(finding.get("verification", "not_started"))}</dd></dl>'
        )
    references = finding.get("references") or []
    if references:
        links = "".join(
            f'<li><a href="{esc(ref.get("url"))}" target="_blank" rel="noopener">{esc(ref.get("title"))}</a></li>' for ref in references
        )
        blocks.append(f'<h4>References</h4><ul class="ref-list">{links}</ul>')
    blocks.append(f"<h4>Evidence</h4>{render_evidence_items(finding.get('evidence', []))}")
    return f'''<article class="finding-detail severity-{esc(severity)}" id="{esc(finding.get("finding_id"))}">
      <header><div class="row">{badge(severity)}<code>{esc(finding.get("finding_id"))}</code></div>
      <h3>{esc(finding.get("title"))}</h3><div class="finding-meta">{esc(meta)}</div></header>
      <div class="finding-body">{"".join(blocks)}</div></article>'''


def render_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<div class="good-state"><span>✓</span><div><strong>No confirmed findings</strong><p>No control met the evidence threshold for a finding. Review the unknowns and limitations before drawing assurance conclusions.</p></div></div>'
    index = "".join(
        f'<li><a href="#{esc(item.get("finding_id"))}">{esc(item.get("finding_id"))}</a> {badge(item.get("severity"))} {esc(item.get("title"))}</li>'
        for item in findings
    )
    return f'<ul class="toc">{index}</ul>' + "".join(render_detailed_finding(item) for item in findings)


def render_summary_tiles(counts: dict[str, int], passed: int, unknown: int, not_applicable: int = 0) -> str:
    tiles = "".join(
        f'<div class="tile-{level}"><strong>{esc(counts.get(level, 0))}</strong><span>{esc(level)}</span></div>' for level in SEVERITIES
    )
    tiles += f'<div class="tile-pass"><strong>{esc(passed)}</strong><span>passed</span></div>'
    tiles += f'<div><strong>{esc(unknown)}</strong><span>unknown</span></div>'
    tiles += f'<div><strong>{esc(not_applicable)}</strong><span>n/a</span></div>'
    return f'<div class="summary-tiles">{tiles}</div>'


def render_controls_table(controls: list[dict[str, Any]], records: dict[str, dict[str, Any]]) -> str:
    if not controls:
        return '<p class="empty">No controls were evaluated.</p>'
    rows = []
    for item in controls:
        status = "finding" if item.get("status") == "confirmed" else item.get("status")
        rows.append(
            "<tr>"
            f"<td><code>{esc(item.get('rule_id'))}</code></td>"
            f"<td>{esc(item.get('category'))}</td>"
            f"<td>{badge(status)}{(' ' + badge(item['severity'])) if item.get('severity') and status == 'finding' else ''}</td>"
            f"<td>{esc(item.get('explanation') or item.get('detail'))}<div class=\"about\">{esc(item.get('about'))}</div></td>"
            f"<td>{evidence_ids_links(item.get('evidence_ids', []), records)}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table class="control-table"><thead><tr><th>Control</th><th>Category</th><th>Result</th>'
        f'<th>Outcome and what the control checks</th><th>Evidence</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def render_methodology(records: list[dict[str, Any]], purposes: dict[str, str]) -> str:
    if not records:
        return '<p class="empty">No commands were recorded.</p>'
    rows = []
    for record in records:
        invocation = record.get("invocation") or ""
        purpose = purposes.get(invocation) or purposes.get(str(record.get("evidence_id", ""))[:3]) or ""
        command = " ".join(str(part) for part in record.get("command", []))
        rows.append(
            f"<tr><td>{evidence_link(record)}</td><td><code>{esc(command)}</code></td><td>{esc(purpose)}</td>"
            f"<td>{esc(record.get('exit_status'))}</td><td>{esc(record.get('captured_at'))}</td></tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>Evidence</th><th>Command</th><th>Purpose</th><th>Exit</th><th>Captured (UTC)</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def render_glossary(entries: list[list[str]]) -> str:
    if not entries:
        return ""
    return '<dl class="glossary">' + "".join(f"<dt>{esc(term)}</dt><dd>{esc(meaning)}</dd>" for term, meaning in entries) + "</dl>"


def render_unknowns(unknowns: list[dict[str, Any]], records: dict[str, dict[str, Any]]) -> str:
    if not unknowns:
        return '<div class="good-state small"><span>✓</span><div><strong>No unresolved controls</strong></div></div>'
    return "".join(
        f'''<article class="unknown"><div><code>{esc(item.get("rule_id"))}</code>{badge("unknown")}</div>
        <p><strong>Why it is unknown:</strong> {esc(item.get("detail") or item.get("reason"))}</p>
        <p><strong>How to resolve it:</strong> {esc(item.get("explanation") or item.get("evidence_needed") or "Collect conclusive evidence for this control.")}</p>
        <p class="finding-meta">Evidence: {evidence_ids_links(item.get("evidence_ids", []), records)}</p></article>'''
        for item in unknowns
    )


def render_fact_sections(sections: list[dict[str, Any]], records: dict[str, dict[str, Any]]) -> str:
    """Render agent-specific technical sections: facts with explanations, or tables."""
    out = []
    for block in sections:
        if block.get("kind") == "table":
            columns = block.get("columns", [])
            head = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
            body = "".join(
                "<tr>" + "".join(f"<td>{badge(row.get(key)) if key in ('status', 'state', 'result') else esc(row.get(key, ''))}</td>" for key, _ in columns) + "</tr>"
                for row in block.get("rows", [])
            ) or f'<tr><td colspan="{len(columns)}">No data recorded.</td></tr>'
            content = f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
        else:
            rows = []
            for item in block.get("items", []):
                value = item.get("value")
                if isinstance(value, list):
                    value = "\n".join(str(v) for v in value) or "none"
                rows.append(
                    f'<div class="data-row"><dt>{esc(item.get("label"))}</dt><dd><div class="observed">{esc(value if value not in (None, "") else "none")}</div>'
                    f'<div class="about">{esc(item.get("explanation", ""))}</div>'
                    f'<div class="finding-meta">Evidence: {evidence_ids_links(item.get("evidence_ids", []), records)}</div></dd></div>'
                )
            content = f'<dl class="data-list padded">{"".join(rows)}</dl>'
        intro = f'<p class="narrative">{esc(block["intro"])}</p>' if block.get("intro") else ""
        out.append(section(block.get("title", ""), intro + content, block.get("subtitle", "")))
    return "".join(out)
