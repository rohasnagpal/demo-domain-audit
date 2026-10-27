#!/usr/bin/env python3
"""Choose and build the charts for each agent's report from its JSON."""

from __future__ import annotations

from typing import Any

try:
    from . import charts
except ImportError:
    import charts  # type: ignore[no-redef]


def summary_counts(report: dict[str, Any]) -> tuple[dict[str, int], int, int, int, int]:
    controls = report.get("controls", [])
    counts = {level: 0 for level in charts.SEVERITY_ORDER}
    for finding in report.get("findings", []):
        level = finding.get("severity", "informational")
        counts[level] = counts.get(level, 0) + 1
    passed = sum(1 for c in controls if c.get("status") == "pass")
    unknown = sum(1 for c in controls if c.get("status") == "unknown")
    na = sum(1 for c in controls if c.get("status") == "not_applicable")
    found = sum(1 for c in controls if c.get("status") == "confirmed")
    return counts, passed, found, unknown, na


def build(report: dict[str, Any]) -> str:
    agent = report.get("agent_id")
    data = report.get("chart_data", {})
    counts, passed, found, unknown, na = summary_counts(report)
    cards = [charts.severity_bars(counts), charts.control_donut(passed, found, unknown, na)]
    if agent == "h1":
        cards.append(charts.surface_map(report.get("scope", {}).get("target", ""), [tuple(n) for n in data.get("surface_nodes", [])]))
        cards.append(charts.network_path(data.get("hops", []), report.get("scope", {}).get("target", ""), data.get("destination_ip")))
    elif agent == "s18":
        controls = report.get("controls", [])
        cards.append(charts.protection_checklist(controls))
        cards.append(charts.dmarc_path(data.get("dmarc_policy"), data.get("dmarc_pct")))
        cards.append(charts.email_flow(report.get("scope", {}).get("target", ""), data.get("mail_provider", "your email provider"), data.get("mx_hosts", []), controls))
        cards.append(charts.timeline([tuple(item) for item in data.get("timeline", [])]))
    elif agent == "s11":
        technical = report.get("technical", {})
        cards.append(charts.protocol_matrix(technical))
        cards.append(charts.client_compatibility(technical.get("client_simulations", [])))
        cards.append(charts.timeline([tuple(item) for item in data.get("timeline", [])]))
    return charts.grid(cards)
