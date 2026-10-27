#!/usr/bin/env python3
"""Inline SVG/HTML charts for Cyber360 reports. Self-contained: no scripts or fonts are loaded from outside."""

from __future__ import annotations

import html
import math
import re
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}


TOOLTIP_JS = """(()=>{const t=document.createElement('div');t.className='viz-tip';t.setAttribute('role','tooltip');document.body.appendChild(t);
const show=(el,x,y)=>{const [a,b]=(el.getAttribute('data-tip')||'').split('|');t.textContent='';const s=document.createElement('strong');s.textContent=a||'';t.appendChild(s);
if(b){const d=document.createElement('span');d.textContent=b;t.appendChild(d)}t.style.display='block';const w=t.offsetWidth,h=t.offsetHeight;
t.style.left=Math.min(x+14,innerWidth-w-8)+'px';t.style.top=Math.max(8,y-h-10)+'px'};
document.querySelectorAll('[data-tip]').forEach(el=>{el.setAttribute('tabindex','0');
el.addEventListener('pointermove',e=>show(el,e.clientX,e.clientY));el.addEventListener('pointerleave',()=>t.style.display='none');
el.addEventListener('focus',()=>{const r=el.getBoundingClientRect();show(el,r.left+r.width/2,r.top)});el.addEventListener('blur',()=>t.style.display='none')})})();"""


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def tip(title: Any, detail: Any = "") -> str:
    """data-tip attribute; the tooltip script inserts it with textContent."""
    text = f"{title}|{detail}" if detail else str(title)
    return f' data-tip="{esc(text)}"'


def card(title: str, subtitle: str, body: str, table: str = "", wide: bool = False, legend: str = "") -> str:
    data = f'<details class="viz-table"><summary>Show data table</summary><div class="table-wrap">{table}</div></details>' if table else ""
    return (
        f'<figure class="viz-card{" wide" if wide else ""}" role="group" aria-label="{esc(title)}">'
        f'<h3>{esc(title)}</h3><p class="viz-sub">{esc(subtitle)}</p>{body}{legend}{data}</figure>'
    )


def simple_table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def legend(items: list[tuple[str, str]]) -> str:
    return '<ul class="viz-legend">' + "".join(f'<li><i style="background:{color}"></i>{esc(label)}</li>' for label, color in items) + "</ul>"


def sev_var(severity: str) -> str:
    return f"var(--sev-{severity if severity in SEVERITY_ORDER else 'informational'})"


# ---------------------------------------------------------------- 1. severity bars


def severity_bars(counts: dict[str, int]) -> str:
    peak = max([counts.get(level, 0) for level in SEVERITY_ORDER] + [1])
    row_h, label_w, width = 30, 92, 460
    plot = width - label_w - 40
    rows = []
    for i, level in enumerate(SEVERITY_ORDER):
        n = counts.get(level, 0)
        y = 8 + i * row_h
        w = max(n / peak * plot, 0)
        bar = (
            f'<path d="M{label_w},{y} h{max(w - 4, 0):.1f} a4,4 0 0 1 4,4 v6 a4,4 0 0 1 -4,4 h{-max(w - 4, 0):.1f} z" fill="{sev_var(level)}"/>'
            if n
            else f'<line x1="{label_w}" x2="{label_w + 2}" y1="{y + 7}" y2="{y + 7}" stroke="var(--viz-grid)" stroke-width="14"/>'
        )
        rows.append(
            f'<g{tip(f"{n} {SEVERITY_LABELS[level].lower()} finding" + ("s" if n != 1 else ""), "Severity: " + SEVERITY_LABELS[level])}>'
            f'<rect x="0" y="{y - 6}" width="{width}" height="{row_h - 2}" fill="transparent"/>'
            f'<text x="{label_w - 10}" y="{y + 11}" text-anchor="end" font-size="12" class="muted">{SEVERITY_LABELS[level]}</text>{bar}'
            f'<text x="{label_w + w + 8:.1f}" y="{y + 11}" font-size="12" font-weight="700">{n}</text></g>'
        )
    svg = f'<svg viewBox="0 0 {width} {8 + 5 * row_h}" role="img" aria-label="Findings by severity">{"".join(rows)}</svg>'
    table = simple_table(["Severity", "Findings"], [[SEVERITY_LABELS[l], counts.get(l, 0)] for l in SEVERITY_ORDER])
    total = sum(counts.get(l, 0) for l in SEVERITY_ORDER)
    return card("Findings by severity", f"{total} confirmed finding{'s' if total != 1 else ''}", svg, table)


# ---------------------------------------------------------------- 2. control donut


def control_donut(passed: int, findings: int, unknown: int, not_applicable: int) -> str:
    parts = [
        ("Passed", passed, "var(--st-good)"),
        ("Findings", findings, "var(--sev-high)"),
        ("Unknown", unknown, "var(--st-unknown)"),
        ("Not applicable", not_applicable, "var(--st-na)"),
    ]
    total = sum(n for _, n, _ in parts) or 1
    r, stroke, cx, cy = 54, 20, 80, 80
    circ = 2 * math.pi * r
    gap = 2 if sum(1 for _, n, _ in parts if n) > 1 else 0
    offset = 0.0
    arcs = []
    for label, n, color in parts:
        if not n:
            continue
        length = n / total * circ
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="{stroke}" '
            f'stroke-dasharray="{max(length - gap, 0.5):.2f} {circ:.2f}" stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"{tip(f"{n} {label.lower()}", f"{round(n / total * 100)}% of {total} controls")}/>'
        )
        offset += length
    labels = "".join(
        f'<text x="190" y="{40 + i * 24}" font-size="12"><tspan font-weight="700">{n}</tspan><tspan class="muted"> {esc(label)}</tspan></text>'
        f'<rect x="174" y="{30 + i * 24}" width="10" height="10" rx="2" fill="{color}"/>'
        for i, (label, n, color) in enumerate(parts)
    )
    svg = (
        f'<svg viewBox="0 0 340 160" role="img" aria-label="Control results">{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-size="26" font-weight="800">{sum(n for _, n, _ in parts)}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="11" class="muted">controls</text>{labels}</svg>'
    )
    table = simple_table(["Result", "Controls"], [[label, n] for label, n, _ in parts])
    return card("Control results", "Unknown controls are never counted as passes", svg, table)


# ---------------------------------------------------------------- 3. protection checklist

S18_GROUPS = [
    ("SPF", ("S18-SPF-001", "S18-SPF-002", "S18-SPF-003", "S18-SPF-004")),
    ("DKIM", ("S18-DKIM-001",)),
    ("DMARC", ("S18-DMARC-001", "S18-DMARC-002", "S18-DMARC-003", "S18-DMARC-004")),
    ("MTA-STS", ("S18-MTASTS-001",)),
    ("TLS-RPT", ("S18-TLSRPT-001",)),
    ("SMTP STARTTLS", ("S18-SMTP-001",)),
    ("DNSSEC", ("S18-DNSSEC-001", "S18-DNSSEC-002")),
    ("CAA", ("S18-CAA-001",)),
    ("Nameservers", ("S18-NS-001",)),
    ("Registration expiry", ("S18-REG-001",)),
    ("Transfer lock", ("S18-REG-002",)),
]
ICONS = {"good": "✓", "critical": "✕", "high": "✕", "medium": "!", "low": "!", "informational": "i", "unknown": "?", "na": "–"}


def group_state(controls: list[dict[str, Any]], rules: tuple[str, ...]) -> tuple[str, str]:
    items = [c for c in controls if c.get("rule_id") in rules]
    confirmed = [c for c in items if c.get("status") == "confirmed"]
    if confirmed:
        worst = min(confirmed, key=lambda c: SEVERITY_ORDER.index(c.get("severity", "informational")) if c.get("severity") in SEVERITY_ORDER else 9)
        sev = worst.get("severity", "informational")
        return sev, f"{SEVERITY_LABELS.get(sev, sev)} finding"
    if any(c.get("status") == "pass" for c in items):
        partial = any(c.get("status") == "unknown" for c in items)
        return "good", "In place" + (" (partly verified)" if partial else "")
    if items and all(c.get("status") == "not_applicable" for c in items):
        return "na", "Not applicable"
    return "unknown", "Not determined"


def protection_checklist(controls: list[dict[str, Any]]) -> str:
    tiles, rows = [], []
    for name, rules in S18_GROUPS:
        state, label = group_state(controls, rules)
        tiles.append(
            f'<div class="check-tile {esc(state)}"{tip(f"{name}: {label}", ", ".join(rules))}>'
            f'<span class="icon" aria-hidden="true">{ICONS.get(state, "?")}</span><strong>{esc(name)}</strong>'
            f'<span class="state">{esc(label)}</span></div>'
        )
        rows.append([name, label, ", ".join(rules)])
    body = f'<div class="checklist">{"".join(tiles)}</div>'
    return card("Domain protection checklist", "Each protection's state, from the controls that test it", body, simple_table(["Protection", "State", "Controls"], rows), wide=True)


# ---------------------------------------------------------------- 4. DMARC rollout path


def dmarc_path(policy: str | None, pct: int | None) -> str:
    steps = [("none", "No record"), ("p=none", "Monitor"), ("quarantine 25%", "Partial"), ("quarantine", "Quarantine"), ("reject", "Reject")]
    if not policy:
        current = 0
    elif policy == "none":
        current = 1
    elif policy == "quarantine":
        current = 2 if (pct or 100) < 100 else 3
    elif policy == "reject":
        current = 4 if (pct or 100) == 100 else 3
    else:
        current = 1
    width, gap = 900, 190
    nodes = []
    for i, (code, label) in enumerate(steps):
        x = 70 + i * gap
        done = i <= current
        fill = "var(--st-good)" if i == 4 and done else ("var(--series-1)" if done else "var(--viz-surface)")
        stroke = "var(--series-1)" if i < 4 or not done else "var(--st-good)"
        if i:
            nodes.append(f'<line x1="{x - gap + 14}" y1="40" x2="{x - 14}" y2="40" stroke="{"var(--series-1)" if done else "var(--viz-grid)"}" stroke-width="3" stroke-linecap="round"/>')
        nodes.append(
            f'<g{tip(label + (" — current policy" if i == current else ""), code)}><circle cx="{x}" cy="40" r="12" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
            f'<text x="{x}" y="72" text-anchor="middle" font-size="12" font-weight="{"800" if i == current else "500"}">{esc(label)}</text>'
            f'<text x="{x}" y="88" text-anchor="middle" font-size="10.5" class="faint">{esc(code)}</text></g>'
        )
    x = 70 + current * gap
    marker = (
        f'<path d="M{x - 6},6 h12 l-6,8 z" fill="var(--viz-ink)"/>'
        f'<text x="{x}" y="0" text-anchor="middle" font-size="11" font-weight="800">You are here</text>'
    )
    svg = f'<svg viewBox="0 -14 {width} 110" role="img" aria-label="DMARC rollout path">{"".join(nodes)}{marker}</svg>'
    table = simple_table(["Stage", "Policy", "Current"], [[label, code, "yes" if i == current else ""] for i, (code, label) in enumerate(steps)])
    return card("DMARC rollout path", "Move right one stage at a time, checking aggregate reports between stages", svg, table, wide=True)


# ---------------------------------------------------------------- 5. email flow


def email_flow(domain: str, mail_provider: str, mx_hosts: list[str], controls: list[dict[str, Any]]) -> str:
    def node(x: float, y: float, w: float, label: str, rules: tuple[str, ...]) -> str:
        state, text = group_state(controls, rules)
        color = "var(--st-good)" if state == "good" else ("var(--st-unknown)" if state in ("unknown", "na") else sev_var(state))
        return (
            f'<g{tip(f"{label}: {text}", ", ".join(rules))}><rect x="{x}" y="{y}" width="{w}" height="30" rx="15" fill="var(--viz-surface)" stroke="{color}" stroke-width="2.5"/>'
            f'<text x="{x + 16}" y="{y + 19.5}" font-size="12" font-weight="800" fill="{color}">{ICONS.get(state, "?")}</text>'
            f'<text x="{x + 32}" y="{y + 19.5}" font-size="11.5">{esc(label)}</text></g>'
        )

    def box(x: float, y: float, w: float, title: str, sub: str) -> str:
        return (
            f'<rect x="{x}" y="{y}" width="{w}" height="46" rx="6" fill="var(--chart-box)" stroke="var(--chart-box-line)"/>'
            f'<text x="{x + w / 2}" y="{y + 20}" text-anchor="middle" font-size="12" font-weight="700">{esc(title)}</text>'
            f'<text x="{x + w / 2}" y="{y + 36}" text-anchor="middle" font-size="10.5" class="muted">{esc(sub[:34])}</text>'
        )

    arrow = lambda x1, x2, y: f'<line x1="{x1}" y1="{y}" x2="{x2 - 6}" y2="{y}" stroke="var(--chart-arrow)" stroke-width="2"/><path d="M{x2 - 7},{y - 5} l7,5 l-7,5 z" fill="var(--chart-arrow)"/>'  # noqa: E731
    mx = mx_hosts[0] if mx_hosts else "no MX"
    parts = [
        '<text x="0" y="14" font-size="11" font-weight="800" class="muted">MAIL YOU SEND — checked by the recipient</text>',
        box(0, 26, 150, f"{mail_provider}", f"sending as @{domain}"),
        arrow(150, 196, 49),
        box(196, 26, 150, "Recipient server", "Gmail, Outlook, …"),
        node(372, 8, 104, "SPF", ("S18-SPF-001", "S18-SPF-002", "S18-SPF-003", "S18-SPF-004")),
        node(372, 42, 104, "DKIM", ("S18-DKIM-001",)),
        node(486, 25, 120, "DMARC policy", ("S18-DMARC-001", "S18-DMARC-002", "S18-DMARC-003")),
        arrow(346, 372, 49),
        arrow(606, 640, 49),
        box(640, 26, 120, "Inbox or spam", "decided by DMARC"),
        '<text x="0" y="112" font-size="11" font-weight="800" class="muted">MAIL YOU RECEIVE — protected in transit</text>',
        box(0, 150, 150, "Other mail servers", "delivering to you"),
        arrow(150, 196, 173),
        node(196, 132, 130, "MTA-STS", ("S18-MTASTS-001",)),
        node(196, 166, 130, "STARTTLS", ("S18-SMTP-001",)),
        node(340, 156, 120, "TLS-RPT", ("S18-TLSRPT-001",)),
        arrow(460, 520, 173),
        box(520, 150, 240, f"Your MX: {mx}", mail_provider),
    ]
    svg = f'<svg viewBox="-4 -4 772 212" role="img" aria-label="Email authentication and transport flow">{"".join(parts)}</svg>'
    rows = [[name, group_state(controls, rules)[1]] for name, rules in S18_GROUPS if name in ("SPF", "DKIM", "DMARC", "MTA-STS", "SMTP STARTTLS", "TLS-RPT")]
    return card("How your email is protected", "Where each control is checked; colours and icons show its state", f'<div class="scroll-x">{svg}</div>', simple_table(["Check", "State"], rows), wide=True)


# ---------------------------------------------------------------- 6. protocol × cipher matrix

FAMILIES = [
    ("AEAD (GCM, ChaCha20)", lambda n: "GCM" in n or "CHACHA20" in n or "CCM" in n, "ok"),
    ("CBC", lambda n: "_CBC_" in n, "weak"),
    ("Static RSA key exchange", lambda n: n.startswith("TLS_RSA_WITH"), "weak"),
    ("64-bit block (3DES, IDEA)", lambda n: "3DES" in n or "IDEA" in n, "bad"),
    ("NULL / EXPORT / RC4 / anon", lambda n: any(t in n for t in ("NULL", "EXPORT", "RC4", "_anon_", "_ANON_")), "bad"),
]
PROTOCOL_ROWS = [("SSL 2.0", "SSLv2"), ("SSL 3.0", "SSLv3"), ("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1.1"), ("TLS 1.2", "TLSv1.2"), ("TLS 1.3", "TLSv1.3")]


def protocol_matrix(technical: dict[str, Any]) -> str:
    status = {p.get("name"): p.get("status") for p in technical.get("protocols", [])}
    suites = technical.get("cipher_suites", [])
    head = "".join(f"<th>{esc(name)}</th>" for name, _, _ in FAMILIES)
    rows, data_rows = [], []
    for label, code in PROTOCOL_ROWS:
        state = status.get(label, "unknown")
        proto_cell = "ok" if (state == "supported" and label in ("TLS 1.2", "TLS 1.3")) else ("bad" if state == "supported" else "off")
        cells = [f'<td class="cell {proto_cell}"{tip(label, state.replace("_", " "))}>{esc("offered" if state == "supported" else state.replace("_", " "))}</td>']
        data = [label, state]
        for name, test, tone in FAMILIES:
            matched = [s["name"] for s in suites if str(s.get("protocol", "")).replace("TLSv1.0", "TLSv1") == code and test(str(s.get("name", "")).upper())]
            if state != "supported":
                cells.append('<td class="cell off">—</td>')
                data.append("—")
            elif matched:
                cells.append(f'<td class="cell {tone}"{tip(f"{len(matched)} {name} suite(s) on {label}", ", ".join(matched))}>{len(matched)} accepted</td>')
                data.append(f"{len(matched)} accepted")
            else:
                cells.append(f'<td class="cell {"off" if tone == "ok" else "ok"}">none</td>')
                data.append("none")
        rows.append(f"<tr><th>{esc(label)}</th>{''.join(cells)}</tr>")
        data_rows.append(data)
    body = (
        f'<div class="table-wrap" style="padding:0"><table class="matrix"><thead><tr><th>Protocol</th><th>Status</th>{head}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )
    lg = legend([("Recommended / not accepted", "var(--cell-ok-bg)"), ("Legacy, weaker", "var(--cell-weak-bg)"), ("Insecure", "var(--cell-bad-bg)"), ("Not offered", "var(--cell-off-bg)")])
    return card("Protocols and cipher families", "Which cipher families each protocol version accepts; hover a cell for the suite names", body, simple_table(["Protocol", "Status"] + [n for n, _, _ in FAMILIES], data_rows), wide=True, legend=lg)


# ---------------------------------------------------------------- 7. client compatibility


def client_compatibility(clients: list[dict[str, Any]]) -> str:
    if not clients:
        return card("Client compatibility", "No client simulation data was captured", '<p class="empty">Not tested.</p>')
    groups = {"TLS 1.3": [], "TLS 1.2": [], "Older protocol": [], "Failed": []}
    for c in clients:
        proto = str(c.get("protocol", ""))
        if c.get("result") != "success":
            groups["Failed"].append(c)
        elif "1.3" in proto or "1_3" in proto:
            groups["TLS 1.3"].append(c)
        elif "1.2" in proto or "1_2" in proto:
            groups["TLS 1.2"].append(c)
        else:
            groups["Older protocol"].append(c)
    colors = {"TLS 1.3": "var(--st-good)", "TLS 1.2": "var(--series-1)", "Older protocol": "var(--sev-medium)", "Failed": "var(--sev-critical)"}
    total, width, x = len(clients), 600, 0.0
    segs = []
    for name, items in groups.items():
        if not items:
            continue
        w = len(items) / total * width
        segs.append(
            f'<rect x="{x:.1f}" y="0" width="{max(w - 2, 1):.1f}" height="22" rx="3" fill="{colors[name]}"{tip(f"{len(items)} clients: {name}", ", ".join(i.get("client", "") for i in items[:12]))}/>'
            + (f'<text x="{x + w:.1f}" y="40" font-size="11.5" text-anchor="end">' if x > width - 140 else f'<text x="{x + 2:.1f}" y="40" font-size="11.5">')
            + f'<tspan font-weight="700">{len(items)}</tspan><tspan class="muted"> {esc(name)}</tspan></text>'
        )
        x += w
    svg = f'<svg viewBox="0 0 {width} 46" role="img" aria-label="Client compatibility">{"".join(segs)}</svg>'
    chips = "".join(
        f'<span class="{"fail" if c.get("result") != "success" else ""}"{tip(c.get("client"), (c.get("protocol", "") + " " + c.get("cipher", "")).strip() or "no connection")}>'
        f'{esc(c.get("client"))} <b>{esc(c.get("protocol") or "✕")}</b></span>'
        for c in clients
    )
    table = simple_table(["Client", "Result", "Protocol", "Cipher"], [[c.get("client"), c.get("result"), c.get("protocol", ""), c.get("cipher", "")] for c in clients])
    return card("Client compatibility", f"{total} simulated browsers and devices; which protocol each negotiates", svg + f'<div class="client-chips">{chips}</div>', table, wide=True)


# ---------------------------------------------------------------- 8. timeline


def parse_when(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            parsed = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text[: len(datetime(2000, 1, 1).strftime(fmt))], fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def timeline(intervals: list[tuple[str, Any, Any]], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    parsed = [(label, parse_when(a), parse_when(b)) for label, a, b in intervals]
    parsed = [(label, a, b) for label, a, b in parsed if b]
    if not parsed:
        return card("Expiry timeline", "No validity dates were captured", '<p class="empty">No dates available.</p>')
    starts = [a or now for _, a, _ in parsed]
    lo = min(starts + [now])
    hi = max([b for _, _, b in parsed] + [now])
    span = (hi - lo).total_seconds() or 1
    width, left, row_h = 900, 170, 46
    plot = width - left - 20
    xpos = lambda d: left + (d - lo).total_seconds() / span * plot  # noqa: E731
    rows = []
    for i, (label, a, b) in enumerate(parsed):
        y = 22 + i * row_h
        x1, x2 = xpos(a or lo), xpos(b)
        warn = max(xpos(b) - 30 * 86400 / span * plot, x1)
        days = (b - now).days
        state = "expired" if days < 0 else (f"{days} days left")
        rows.append(
            f'<g{tip(f"{label}: {state}", f"{(a or lo).date()} → {b.date()}")}>'
            f'<text x="{left - 10}" y="{y + 12}" text-anchor="end" font-size="12">{esc(label)}</text>'
            f'<rect x="{x1:.1f}" y="{y}" width="{max(x2 - x1, 2):.1f}" height="16" rx="4" fill="var(--series-1)" opacity=".85"/>'
            f'<rect x="{warn:.1f}" y="{y}" width="{max(x2 - warn, 0):.1f}" height="16" rx="4" fill="var(--sev-medium)"/>'
            f'<text x="{x2:.1f}" y="{y + 30}" font-size="11" text-anchor="end" class="muted">{esc(b.date())} · {esc(state)}</text></g>'
        )
    tx = xpos(now)
    height = 22 + len(parsed) * row_h + 14
    axis = (
        f'<line x1="{tx:.1f}" x2="{tx:.1f}" y1="8" y2="{height - 14}" stroke="var(--viz-ink)" stroke-width="2" stroke-dasharray="3 3"/>'
        f'<text x="{tx:.1f}" y="4" text-anchor="middle" font-size="11" font-weight="800">Today {now.date()}</text>'
        f'<text x="{left}" y="{height}" font-size="10.5" class="faint">{lo.date()}</text>'
        f'<text x="{width - 20}" y="{height}" font-size="10.5" class="faint" text-anchor="end">{hi.date()}</text>'
    )
    svg = f'<svg viewBox="0 -8 {width} {height + 12}" role="img" aria-label="Expiry timeline">{axis}{"".join(rows)}</svg>'
    lg = legend([("Valid period", "var(--series-1)"), ("Final 30 days (renew before this)", "var(--sev-medium)")])
    table = simple_table(["Item", "From", "Until", "Days left"], [[l, (a.date() if a else ""), b.date(), (b - now).days] for l, a, b in parsed])
    return card("Expiry timeline", "Certificate and registration validity against today", svg, table, wide=True, legend=lg)


# ---------------------------------------------------------------- 9. attack-surface map


def surface_map(domain: str, nodes: list[tuple[str, str]]) -> str:
    nodes = nodes[:12]
    width, height = 760, 420
    cx, cy, rx, ry = width / 2, height / 2, 290, 160
    parts = []
    for i, (kind, value) in enumerate(nodes):
        angle = -math.pi / 2 + i * 2 * math.pi / max(len(nodes), 1)
        x, y = cx + rx * math.cos(angle), cy + ry * math.sin(angle)
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="var(--chart-line)" stroke-width="1.5"/>')
        label = value if len(value) <= 26 else value[:25] + "…"
        anchor = "middle"
        parts.append(
            f'<g{tip(kind, value)}><rect x="{x - 88:.1f}" y="{y - 20:.1f}" width="176" height="40" rx="6" fill="var(--paper)" stroke="var(--chart-arrow)"/>'
            f'<text x="{x:.1f}" y="{y - 4:.1f}" text-anchor="{anchor}" font-size="10" class="muted" letter-spacing=".06em">{esc(kind.upper())}</text>'
            f'<text x="{x:.1f}" y="{y + 11:.1f}" text-anchor="{anchor}" font-size="11.5" font-weight="700">{esc(label)}</text></g>'
        )
    parts.append(
        f'<circle cx="{cx}" cy="{cy}" r="48" fill="var(--navy)"/><text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="13" font-weight="800" class="on-dark">{esc(domain)}</text>'
    )
    svg = f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Attack-surface map">{"".join(parts)}</svg>'
    return card("Attack-surface map", "What an attacker learns about the domain from public sources", f'<div class="scroll-x">{svg}</div>', simple_table(["Type", "Value"], [[k, v] for k, v in nodes]), wide=True)


# ---------------------------------------------------------------- 10. network path


def parse_hops(stdout: str) -> list[dict[str, Any]]:
    hops = []
    for line in stdout.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        rest = match.group(2).strip()
        if rest.startswith("*"):
            hops.append({"hop": int(match.group(1)), "host": None, "ip": None, "rtt_ms": None})
            continue
        host = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", rest)
        rtt = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({"hop": int(match.group(1)), "host": host.group(1) if host else rest, "ip": host.group(2) if host and host.group(2) else None, "rtt_ms": float(rtt.group(1)) if rtt else None})
    return hops


def network_path(hops: list[dict[str, Any]], destination: str, destination_ip: str | None) -> str:
    if not hops:
        return card("Network path", "No traceroute data was captured", '<p class="empty">Not available.</p>', wide=True)
    gap = max(30, min(64, 820 / len(hops)))
    width = len(hops) * gap + 140
    parts = []
    for i, hop in enumerate(hops):
        x = 30 + i * gap
        replied = hop["host"] is not None
        dash = "" if replied else ' stroke-dasharray="4 4"'
        ring = "" if replied else ' stroke-dasharray="3 2"'
        if i:
            parts.append(f'<line x1="{x - gap + 10}" y1="50" x2="{x - 10}" y2="50" stroke="var(--chart-line)" stroke-width="2"{dash}/>')
        title = f"Hop {hop['hop']}: " + (hop["host"] or "no reply")
        detail = f"{hop['ip'] or ''} {hop['rtt_ms']} ms".strip() if replied else "This router did not answer the probe; common and not an error."
        rtt = f"{hop['rtt_ms']:.0f} ms" if hop["rtt_ms"] is not None else "*"
        fill = "var(--series-1)" if replied else "var(--viz-surface)"
        parts.append(
            f'<g{tip(title, detail)}><circle cx="{x}" cy="50" r="9" fill="{fill}" stroke="var(--series-1)" stroke-width="2"{ring}/>'
            f'<text x="{x}" y="78" text-anchor="middle" font-size="10.5" class="muted">{hop["hop"]}</text>'
            f'<text x="{x}" y="30" text-anchor="middle" font-size="10" class="faint">{esc(rtt)}</text></g>'
        )
    x = 30 + len(hops) * gap + 40
    parts.append(f'<line x1="{x - gap - 30}" y1="50" x2="{x - 30}" y2="50" stroke="var(--chart-line)" stroke-width="2" stroke-dasharray="4 4"/>')
    parts.append(
        f'<g{tip(destination, destination_ip or "")}><rect x="{x - 30}" y="36" width="96" height="28" rx="6" fill="var(--navy)"/>'
        f'<text x="{x + 18}" y="54" text-anchor="middle" font-size="11" font-weight="700" class="on-dark">{esc(destination[:14])}</text></g>'
    )
    svg = f'<svg viewBox="0 0 {width + 40} 92" role="img" aria-label="Network path" style="min-width:{min(width, 900):.0f}px">{"".join(parts)}</svg>'
    replied = sum(1 for h in hops if h["host"])
    table = simple_table(["Hop", "Host", "IP", "RTT (ms)"], [[h["hop"], h["host"] or "*", h["ip"] or "", h["rtt_ms"] if h["rtt_ms"] is not None else ""] for h in hops])
    lg = legend([("Router replied", "var(--series-1)"), ("No reply (filtered)", "var(--paper)")])
    return card("Network path", f"{len(hops)} hops traced, {replied} replied; hollow nodes did not answer probes", f'<div class="scroll-x">{svg}</div>', table, wide=True, legend=lg)


def grid(cards: list[str]) -> str:
    return f'<div class="viz-root viz-grid">{"".join(c for c in cards if c)}</div>'
