#!/usr/bin/env python3
"""Render a Cyber360 H1 or S18 JSON report as a self-contained, detailed HTML report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from . import charts, report_charts, theme
    from . import components as ui
    from .output_store import require_managed_path
except ImportError:
    import charts  # type: ignore[no-redef]
    import components as ui  # type: ignore[no-redef]
    import report_charts  # type: ignore[no-redef]
    import theme  # type: ignore[no-redef]
    from output_store import require_managed_path  # type: ignore[no-redef]



def render(report: dict[str, Any]) -> str:
    scope = report.get("scope", {})
    summary = report.get("summary", {})
    records = {item["evidence_id"]: item for item in report.get("evidence", [])}
    target = scope.get("target", "unknown")
    title = report.get("agent_name", "Cyber360 agent report")
    code = str(report.get("agent_id", "")).upper()

    narrative = "".join(f"<p>{ui.esc(p)}</p>" for p in summary.get("narrative", []))
    facts = "".join(
        f'<div class="data-row"><dt>{ui.esc(label)}</dt><dd>{ui.esc(value)}</dd></div>' for label, value in summary.get("key_facts", [])
    )
    executive = (
        ui.render_summary_tiles(summary.get("severity_counts", {}), summary.get("passed", 0), summary.get("unknown", 0), summary.get("not_applicable", 0))
        + f'<div class="narrative">{narrative}</div>'
        + (f'<dl class="data-list padded">{facts}</dl>' if facts else "")
    )
    related = "".join(
        f'<li><a href="{ui.esc(item["href"])}" target="_blank" rel="noopener">{ui.esc(item["label"])}</a></li>' for item in report.get("related_reports", [])
    )
    limitations = "".join(f'<div class="notice warning"><b>Limitation</b><span>{ui.esc(text)}</span></div>' for text in report.get("limitations", []))
    assumptions = "".join(f'<div class="notice info"><b>Assumption</b><span>{ui.esc(text)}</span></div>' for text in report.get("assumptions", []))
    tooling = "".join(
        f'<li><strong>{ui.esc(tool.get("name"))}</strong><span>{ui.esc(tool.get("version"))}</span></li>' for tool in report.get("tooling", [])
    )
    scope_rows = [
        ("Target", target),
        ("Agent", f"{code} {title}"),
        ("Authority", scope.get("authority")),
        ("Started (UTC)", scope.get("started_at")),
        ("Completed (UTC)", scope.get("completed_at")),
        ("In scope", "; ".join(scope.get("in_scope", []))),
        ("Exclusions", "; ".join(scope.get("exclusions", []))),
    ]
    scope_html = "".join(f'<div class="data-row"><dt>{ui.esc(k)}</dt><dd>{ui.esc(v)}</dd></div>' for k, v in scope_rows if v)

    toc = "".join(
        f'<li><a href="#{anchor}">{ui.esc(name)}</a></li>'
        for anchor, name in (
            ("summary", "Executive summary"),
            ("glance", "At a glance (charts)"),
            ("findings", "Findings"),
            ("controls", "Every control checked"),
            ("technical", "Technical detail"),
            ("unknowns", "Unknowns"),
            ("methodology", "Methodology and evidence"),
            ("glossary", "Glossary"),
            ("scope", "Scope, tools and limitations"),
        )
    )
    css = theme.stylesheet()
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber360 {ui.esc(code)} — {ui.esc(target)}</title><style>{css}</style></head>
<body><header class="topbar"><div class="brand"><span class="brand-mark">360</span><div><strong>Cyber360</strong><small>{ui.esc(code)} {ui.esc(title)}</small></div></div><button data-print>Print / Save PDF</button></header>
<main>
  <section class="report-head"><div><p class="eyebrow">{ui.esc(code)} · {ui.esc(report.get("category", "").upper())}</p><h1>{ui.esc(title)}: {ui.esc(target)}</h1>
  <p>Point-in-time, evidence-based assessment generated {ui.esc(report.get("generated_at"))}</p></div>
  <div class="report-id"><span>Report ID</span><code>{ui.esc(report.get("report_id"))}</code></div></section>
  <section class="panel"><header class="panel-head"><div><h2>Contents</h2></div></header><ul class="toc">{toc}</ul>
  {f'<p class="related">Other reports from this run:</p><ul class="toc">{related}</ul>' if related else ''}</section>
  {ui.section("Executive summary", executive, "What this assessment found, in plain language", "summary")}
  {ui.section("At a glance", report_charts.build(report), "Hover or focus any mark for detail; each chart has a data table", "glance")}
  {ui.section("Findings", ui.render_findings(report.get("findings", [])), "Each finding explains the problem, why it matters, how to fix it and how to verify the fix", "findings")}
  {ui.section("Every control checked", ui.render_controls_table(report.get("controls", []), records), "Passes, findings, unknowns and not-applicable controls, each with its evidence", "controls")}
  <div id="technical">{ui.render_fact_sections(report.get("technical_sections", []), records)}</div>
  {ui.section("Unknowns and evidence gaps", ui.render_unknowns(report.get("unknowns", []), records), "Unresolved controls are never counted as passes", "unknowns")}
  {ui.section("Methodology and evidence", ui.render_methodology(report.get("evidence", []), report.get("command_purposes", {})), "Every command run, why it was run and its raw output (opens in a new tab)", "methodology")}
  {ui.section("Glossary", ui.render_glossary(report.get("glossary", [])), "Terms used in this report", "glossary")}
  <section id="scope" class="two-col">
    {ui.section("Scope and authority", f'<dl class="data-list padded">{scope_html}</dl>')}
    {ui.section("Tools", f'<ul class="tool-list">{tooling}</ul>', "Locally executed tooling")}
  </section>
  {ui.section("Limitations and assumptions", limitations + assumptions or '<p class="empty">None recorded.</p>')}
</main>
<footer><strong>Cyber360</strong><span>Local-first evidence. Findings are limited to the stated scope, tests and assessment time.</span></footer>
<script>document.querySelectorAll('[data-print]').forEach(b=>b.addEventListener('click',()=>window.print()));{charts.TOOLTIP_JS}</script></body></html>'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="H1 or S18 report JSON")
    args = parser.parse_args()
    source = args.report.resolve()
    try:
        output = require_managed_path(source.with_suffix(".html"))
    except ValueError as exc:
        parser.error(str(exc))
    output.write_text(render(json.loads(source.read_text(encoding="utf-8"))), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
