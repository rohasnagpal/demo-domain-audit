#!/usr/bin/env python3
"""Expand an S11 report's controls and findings with the S11 knowledge base and observed TLS values."""

from __future__ import annotations

from typing import Any

try:
    from ..reporting import knowledge as kb
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from engine.reporting import knowledge as kb


def _bullets(items: list[str]) -> str:
    return "\n".join(f"• {item}" for item in items) if items else "none"


def s11_context(report: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    scope = report.get("scope", {})
    technical = report.get("technical", {})
    cert = (technical.get("certificates") or [{}])[0]
    protocols = technical.get("protocols", [])
    suites = technical.get("cipher_suites", [])
    cbc = [s for s in suites if "_CBC_" in str(s.get("name", "")).upper() or ("-CBC" in str(s.get("name", "")).upper())]
    static_rsa = [s for s in suites if str(s.get("name", "")).upper().startswith("TLS_RSA_WITH")]
    ctx = {
        "domain": scope.get("target", ""),
        "port": scope.get("port", 443),
        "cert_subject": cert.get("subject"),
        "cert_issuer": cert.get("issuer"),
        "cert_not_before": cert.get("not_before"),
        "cert_not_after": cert.get("not_after"),
        "cert_sans": ", ".join(cert.get("subject_alternative_names", [])),
        "cert_key": cert.get("public_key"),
        "cert_sig": cert.get("signature_algorithm"),
        "cert_trust": cert.get("trust_result"),
        "deprecated_protocols": ", ".join(p["name"] for p in protocols if p.get("name") in ("TLS 1.0", "TLS 1.1") and p.get("status") == "supported") or "none",
        "modern_protocols": ", ".join(p["name"] for p in protocols if p.get("name") in ("TLS 1.2", "TLS 1.3") and p.get("status") == "supported") or "none",
        "cbc_count": len(cbc),
        "cbc_suites": _bullets([f"{s['name']} ({s.get('protocol')}, {s.get('key_exchange')}, {s.get('strength_bits')}-bit)" for s in cbc]),
        "cbc_protocols": ", ".join(sorted({str(s.get("protocol")) for s in cbc})) or "none",
        "static_rsa_count": len(static_rsa),
        "static_rsa_suites": _bullets([f"{s['name']} ({s.get('protocol')})" for s in static_rsa]),
        "server_product": "the web server",
        "hosting_provider": "your hosting provider",
    }
    ctx.update({key: value for key, value in (extra or {}).items() if value})
    return ctx


def enrich_s11_report(report: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    knowledge = kb.load("s11")
    ctx = s11_context(report, extra)
    raw_controls = report.get("raw_controls") or report.get("controls") or []
    controls = [kb.explain_control(knowledge, item, ctx) for item in raw_controls]
    by_rule = {item["rule_id"]: item for item in raw_controls}
    findings = []
    for finding in report.get("findings", []):
        item = by_rule.get(finding.get("rule_id"), {"rule_id": finding.get("rule_id"), "detail": finding.get("analysis", ""), "severity": finding.get("severity")})
        item = {**item, "severity": finding.get("severity")}
        rich = kb.build_finding(
            knowledge, item, ctx, finding["finding_id"], finding.get("evidence", []),
            title=finding.get("title"), authority=finding.get("authority"),
        )
        rich["verification"] = finding.get("verification", "not_started")
        findings.append(rich)
    explained = {item["rule_id"]: item for item in controls}
    unknowns = []
    for unknown in report.get("unknowns", []):
        control = explained.get(unknown.get("rule_id"), {})
        unknowns.append({**unknown, "detail": unknown.get("reason"), "explanation": control.get("about") or unknown.get("evidence_needed"), "evidence_ids": control.get("evidence_ids", [])})
    report.update(
        {
            "raw_controls": raw_controls,
            "controls": controls,
            "findings": findings,
            "unknowns": unknowns,
            "command_purposes": kb.command_purposes(knowledge),
            "glossary": kb.glossary(knowledge),
        }
    )
    return report
