#!/usr/bin/env python3
"""Run the Cyber360 full domain audit: H1 Reconnaissance, S11 TLS and S18 Email & Domain Security.

Each agent writes its own detailed report under cyber360-reports/<domain>/<agent>/.
A previous run for the same domain is moved to cyber360-reports/<domain>/archive/<timestamp>/.
"""

from __future__ import annotations

import argparse
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from ..reporting import charts
    from ..reporting import knowledge as kb
    from ..reporting.output_store import reports_root, safe_report_id
    from ..reporting.render_agent_report import render as render_agent_report
    from ..reporting.render_tls_report import render_report as render_tls_report
    from ..tls.assessment import finding_evidence, run_assessment, utc_now
    from ..tls.enrichment import enrich_s11_report
    from . import analysis, providers
    from .commands import AGENT_INVOCATIONS, S18_DKIM_INVOCATION, S18_SMTP_INVOCATION, DomainEvidence, render_argv, validate_domain, validate_selector
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from engine.domain import analysis, providers
    from engine.domain.commands import AGENT_INVOCATIONS, S18_DKIM_INVOCATION, S18_SMTP_INVOCATION, DomainEvidence, render_argv, validate_domain, validate_selector
    from engine.reporting import charts
    from engine.reporting import knowledge as kb
    from engine.reporting.output_store import reports_root, safe_report_id
    from engine.reporting.render_agent_report import render as render_agent_report
    from engine.reporting.render_tls_report import render_report as render_tls_report
    from engine.tls.assessment import finding_evidence, run_assessment, utc_now
    from engine.tls.enrichment import enrich_s11_report


ROOT = Path(__file__).resolve().parents[2]
S18_BASELINE = ROOT / "agents" / "security" / "email-domain-security" / "references" / "baseline.json"
MAX_MX_HOSTS = 10
AGENT_FOLDERS = {"h1": "H1-reconnaissance", "s11": "S11-tls", "s18": "S18-email-domain"}
AGENT_NAMES = {
    "h1": "Reconnaissance",
    "s11": "TLS & Cryptography Security",
    "s18": "Email & Domain Security",
}
H1_TITLES = {
    "H1-WEB-001": "Server header discloses web server software",
    "H1-WEB-002": "X-Powered-By header discloses application technology",
    "H1-WEB-003": "Plain HTTP does not redirect to HTTPS",
    "H1-WEB-004": "HTTP Strict Transport Security (HSTS) not enforced",
    "H1-DNS-001": "Public DNS reveals third-party services",
}
VERSION_PROBES = {"dig": ["dig", "-v"], "curl": ["curl", "--version"], "openssl": ["openssl", "version"]}


# ---------------------------------------------------------------- folders and evidence


def prepare_domain_folder(domain: str) -> tuple[Path, list[str]]:
    """Create cyber360-reports/<domain>/ and archive any previous run's agent folders."""
    root = reports_root()
    folder = (root / safe_report_id(domain)).resolve()
    folder.relative_to(root)
    folder.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    existing = [folder / name for name in AGENT_FOLDERS.values() if (folder / name).exists()]
    if existing:
        stamp = previous_run_stamp(existing)
        archive = folder / "archive" / stamp
        archive.mkdir(parents=True, exist_ok=True)
        for path in existing:
            shutil.move(str(path), str(archive / path.name))
        notes.append(f"The previous run's reports were moved to {archive.relative_to(root.parent).as_posix()}/.")
    staging = folder / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    return folder, notes


def previous_run_stamp(paths: list[Path]) -> str:
    for path in paths:
        report = path / "report.json"
        if report.is_file():
            try:
                generated = json.loads(report.read_text(encoding="utf-8")).get("generated_at", "")
                if generated:
                    return generated.replace(":", "").replace("-", "")
            except (OSError, json.JSONDecodeError):
                pass
    return datetime.fromtimestamp(paths[0].stat().st_mtime, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def agent_evidence(evidence: DomainEvidence, agent: str, destination: Path) -> list[dict[str, Any]]:
    """Copy the evidence files an agent used into its own report folder and return its records."""
    target = destination / "evidence"
    target.mkdir(parents=True, exist_ok=True)
    records = []
    for record in evidence.store.records:
        used = record.get("used_by", {})
        if agent not in used and "tooling" not in used:
            continue
        for key in ("path", "json_path"):
            path = Path(record[key]) if Path(record[key]).is_absolute() else Path.cwd() / record[key]
            if path.is_file():
                shutil.copy2(path, target / path.name)
        copied = dict(record)
        copied["path"] = f"evidence/{Path(record['path']).name}"
        copied["json_path"] = f"evidence/{Path(record['json_path']).name}"
        copied["invocation"] = used.get(agent) or used.get("tooling", "")
        records.append(copied)
    return records


def tool_inventory(evidence: DomainEvidence) -> list[dict[str, str]]:
    tooling = []
    executables = sorted({argv[0] for invocations in AGENT_INVOCATIONS.values() for _, argv, _ in invocations} | {"openssl"})
    for name in executables:
        location = shutil.which(name)
        entry = {"name": name, "version": location or "not installed"}
        if location and name in VERSION_PROBES:
            entry["evidence_id"] = evidence.plan("tooling", f"{name}_version", VERSION_PROBES[name], 15).evidence_id
        tooling.append(entry)
    return tooling


def plan_agent(evidence: DomainEvidence, agent: str, domain: str, skipped: list[str]) -> None:
    for invocation_id, template, timeout in AGENT_INVOCATIONS[agent]:
        argv = render_argv(template, {"domain": domain})
        if shutil.which(argv[0]) is None:
            skipped.append(f"{agent.upper()} {invocation_id}: `{argv[0]}` is not installed, so this check was not run.")
            continue
        evidence.plan(agent, invocation_id, argv, timeout)


# ---------------------------------------------------------------- shared context


def build_context(domain: str, inventory: dict[str, Any], s11_report: dict[str, Any] | None) -> dict[str, Any]:
    data = providers.load_providers()
    dns = inventory["dns"]
    mx_hosts = [item["host"] for item in dns["mx"]]
    dns_provider = providers.dns_provider(dns["ns"], data)
    mail = providers.mail_provider(mx_hosts, data)
    registration = inventory.get("registration", {})
    registrar = providers.registrar(registration.get("registrar"), data)
    server = inventory["http"]["final_headers"].get("server", "")
    hosting = dns_provider["name"] if dns_provider["id"] in ("dreamhost", "godaddy", "digitalocean") else "your hosting provider"
    issuer = None
    if s11_report:
        issuer = ((s11_report.get("technical", {}).get("certificates") or [{}])[0]).get("issuer")
    issuer_domain = providers.ca_domain(issuer, data)
    spf_record = next((value for value in dns["txt"] if value.lower().startswith("v=spf1")), "")
    spf_senders = [
        data["spf_include_services"].get(term.split(":", 1)[1].lower(), term.split(":", 1)[1])
        for term in spf_record.split()
        if term.lower().startswith("include:")
    ]
    suggested_include = mail.get("spf_include") or "mx"
    return {
        "domain": domain,
        "today_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
        "mx_hosts": ", ".join(mx_hosts) or "none",
        "mx_policy_lines": "\n".join(f"mx: {host}" for host in mx_hosts) or "mx: <your mail host>",
        "dns_provider": dns_provider["name"],
        "dns_edit": dns_provider["edit_dns"],
        "dns_dnssec": dns_provider["dnssec"],
        "mail_provider": mail["name"],
        "dkim_steps": mail["dkim_steps"].replace("{domain}", domain),
        "dkim_selector_hint": " or ".join(f"\"{s}\"" for s in mail.get("dkim_selectors", [])) or "shown in the s= tag",
        "registrar": registrar["name"],
        "registrar_lock": registrar["lock"],
        "registrar_renew": registrar["renew"],
        "registrar_ds": registrar["ds"],
        "server_product": server or "the web server",
        "server_header": server,
        "hosting_provider": hosting,
        "caa_issuer": issuer or "your current certificate authority",
        "caa_issuer_domain": issuer_domain or "<your CA's CAA domain, for example letsencrypt.org>",
        "spf_record": spf_record,
        "spf_suggested": f"v=spf1 {suggested_include} ~all",
        "spf_senders": ", ".join(spf_senders) or "none listed",
    }


def dmarc_context(controls: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    record = next((c["facts"].get("dmarc_record") for c in controls if c["rule_id"] == "S18-DMARC-001" and c["facts"].get("dmarc_record")), "")
    if not record:
        return {}
    tags = analysis.parse_dmarc_tags(record)
    rua = tags.get("rua", "")
    domain = context["domain"]

    def variant(policy: str, pct: str | None = None) -> str:
        parts = ["v=DMARC1", f"p={policy}"] + ([f"pct={pct}"] if pct else [])
        parts += [f"{key}={value}" for key, value in tags.items() if key not in ("v", "p", "pct")]
        if not rua:
            parts.append(f"rua=mailto:dmarc-reports@{domain}")
        return "; ".join(parts)

    with_rua = record.rstrip("; ") + f"; rua=mailto:dmarc-reports@{domain}"
    dkim_prereq = (
        f"Turn on DKIM signing for {context['mail_provider']} first, so mail still passes DMARC when SPF breaks (for example when it is forwarded): {context['dkim_steps']}"
    )
    return {
        "dmarc_rua_note": (
            f"Reports are already being sent to {rua}, so you can see who sends mail as {domain}. That is what makes enforcement safe."
            if rua
            else "No rua= address is set, so you are not receiving reports and cannot see who sends mail as the domain."
        ),
        "dmarc_rua_suffix": f" sent to {rua}" if rua else " (add a rua= address first)",
        "dmarc_reporting_state": f"being collected at {rua}" if rua else "not yet being collected",
        "dmarc_quarantine_25": variant("quarantine", "25"),
        "dmarc_quarantine_100": variant("quarantine"),
        "dmarc_reject": variant("reject"),
        "dmarc_with_rua": with_rua,
        "dkim_prereq": dkim_prereq,
    }


# ---------------------------------------------------------------- report assembly


def explain_and_find(
    agent: str, controls: list[dict[str, Any]], context: dict[str, Any], records: dict[str, dict[str, Any]], titles: dict[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    knowledge = kb.load(agent)
    explained = [kb.explain_control(knowledge, item, context) for item in controls]
    confirmed = [item for item in controls if item["status"] == "confirmed"]
    confirmed.sort(key=lambda item: analysis.SEVERITY_ORDER.get(item.get("severity", "informational"), 9))
    findings = []
    for index, item in enumerate(confirmed, 1):
        evidence = [finding_evidence(records[eid]) for eid in item["evidence_ids"] if eid in records]
        findings.append(
            kb.build_finding(knowledge, item, context, f"{agent.upper()}-{index:03d}", evidence, title=titles.get(item["rule_id"]), authority=titles.get(item["rule_id"] + ":authority"))
        )
    unknowns = [item for item in explained if item["status"] == "unknown"]
    return explained, findings, unknowns


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in analysis.SEVERITY_ORDER}
    for finding in findings:
        counts[finding.get("severity", "informational")] = counts.get(finding.get("severity", "informational"), 0) + 1
    return counts


def narrative(agent_label: str, domain: str, controls: list[dict[str, Any]], findings: list[dict[str, Any]], strengths: list[str]) -> list[str]:
    passed = sum(1 for c in controls if c["status"] == "pass")
    unknown = sum(1 for c in controls if c["status"] == "unknown")
    counts = severity_counts(findings)
    parts = ", ".join(f"{n} {level}" for level, n in counts.items() if n)
    text = [f"{agent_label} evaluated {len(controls)} controls for {domain}: {passed} passed, {len(findings)} produced findings{f' ({parts})' if parts else ''} and {unknown} could not be determined."]
    if findings:
        top = findings[0]
        text.append(f"The most significant issue is {top['finding_id']} “{top['title']}” ({top['severity']}). {top['analysis']}")
        if len(findings) > 1:
            others = "; ".join(f"{f['finding_id']} “{f['title']}” ({f['severity']})" for f in findings[1:])
            text.append(f"Other findings: {others}.")
    else:
        text.append("No control met the threshold for a finding.")
    if strengths:
        text.append("Controls in good shape: " + " ".join(s if s.rstrip().endswith(".") else s.rstrip() + "." for s in strengths))
    if unknown:
        text.append("Unknown controls are listed with what is needed to resolve them; they are not treated as passes.")
    return text


def base_report(agent: str, domain: str, authority: str, started_at: str, records: list[dict[str, Any]], tooling: list[dict[str, str]], related: list[dict[str, str]]) -> dict[str, Any]:
    knowledge = kb.load(agent)
    return {
        "report_id": f"{agent.upper()}-{domain}-{started_at.replace(':', '').replace('-', '')}",
        "agent_id": agent,
        "agent_name": f"{AGENT_NAMES[agent]} report",
        "category": {"h1": "hacking", "s18": "security"}[agent],
        "generated_at": utc_now(),
        "scope": {"target": domain, "authority": authority, "started_at": started_at, "completed_at": utc_now()},
        "evidence": records,
        "tooling": tooling,
        "command_purposes": kb.command_purposes(knowledge),
        "glossary": kb.glossary(knowledge),
        "related_reports": related,
    }


def h1_report(domain: str, inventory: dict[str, Any], services: list[str], controls: list[dict[str, Any]], context: dict[str, Any], records: list[dict[str, Any]], base: dict[str, Any], limitations: list[str]) -> dict[str, Any]:
    by_id = {r["evidence_id"]: r for r in records}
    inv_id = {r["invocation"]: r["evidence_id"] for r in records}
    knowledge = kb.load("h1")
    explain = knowledge["inventory_explanations"]
    explained, findings, unknowns = explain_and_find("h1", controls, context, by_id, H1_TITLES)
    dns = inventory["dns"]
    reg = inventory.get("registration", {})
    http = inventory["http"]
    reach = inventory["reachability"]
    ev = lambda *names: [inv_id[n] for n in names if n in inv_id]  # noqa: E731
    sections = [
        {
            "title": "DNS footprint",
            "subtitle": "What public DNS reveals about the domain",
            "intro": "Each record type is listed with what it tells an attacker. Values are exactly as returned by dig.",
            "items": [
                {"label": "A (IPv4)", "value": dns["a"], "explanation": explain["a"], "evidence_ids": ev("dig_a")},
                {"label": "AAAA (IPv6)", "value": dns["aaaa"], "explanation": explain["aaaa"], "evidence_ids": ev("dig_aaaa")},
                {"label": "CNAME", "value": dns["cname"], "explanation": explain["cname"], "evidence_ids": ev("dig_cname")},
                {"label": "MX", "value": [f"{m['preference']} {m['host']}" for m in dns["mx"]], "explanation": explain["mx"], "evidence_ids": ev("dig_mx")},
                {"label": "NS", "value": dns["ns"], "explanation": explain["ns"], "evidence_ids": ev("dig_ns")},
                {"label": "SOA", "value": dns["soa"], "explanation": explain["soa"], "evidence_ids": ev("dig_soa")},
                {"label": "TXT", "value": dns["txt"], "explanation": explain["txt"], "evidence_ids": ev("dig_txt")},
                {"label": "CAA", "value": dns["caa"], "explanation": explain["caa"], "evidence_ids": ev("dig_caa")},
                {"label": "Delegation trace", "value": "completed from the root to the domain's nameservers" if dns["delegation_traced"] else "did not complete", "explanation": explain["delegation"], "evidence_ids": ev("dig_trace")},
                {"label": "host cross-check", "value": inventory.get("host", []), "explanation": "A second resolver client confirming the address and mail records.", "evidence_ids": ev("host")},
            ],
        },
        {
            "title": "Registration",
            "subtitle": "WHOIS data for the domain",
            "items": [
                {"label": "Registrar", "value": reg.get("registrar"), "explanation": "The company the domain is registered through. Its account controls the domain's nameservers.", "evidence_ids": ev("whois")},
                {"label": "Created", "value": reg.get("created"), "explanation": "Registration date.", "evidence_ids": ev("whois")},
                {"label": "Expires", "value": reg.get("expires"), "explanation": "If this date passes without renewal, the domain can be lost.", "evidence_ids": ev("whois")},
                {"label": "Last updated", "value": reg.get("updated"), "explanation": "Last change to the registration record.", "evidence_ids": ev("whois")},
                {"label": "EPP status", "value": reg.get("statuses", []), "explanation": "Registry locks. clientTransferProhibited blocks unauthorised transfers.", "evidence_ids": ev("whois")},
            ],
        },
        {
            "kind": "table",
            "title": "HTTPS response chain",
            "subtitle": "curl -IL https://" + domain,
            "columns": [("status", "Status"), ("location", "Redirect to"), ("server", "Server header")],
            "rows": http["chain"],
        },
        {
            "kind": "table",
            "title": "HTTPS response headers",
            "subtitle": "Final response headers; security headers are explained by the web application agent when implemented",
            "columns": [("name", "Header"), ("value", "Value")],
            "rows": [{"name": k, "value": v} for k, v in http["final_headers"].items()],
        },
        {
            "title": "Reachability and exposure",
            "subtitle": "Ports 80 and 443, ICMP and the network path",
            "items": [
                {"label": "TCP 80 (HTTP)", "value": next((p["state"] for p in inventory["ports"] if p["port"] == 80), "unknown"), "explanation": explain["ports"], "evidence_ids": ev("nc_port_80")},
                {"label": "TCP 443 (HTTPS)", "value": next((p["state"] for p in inventory["ports"] if p["port"] == 443), "unknown"), "explanation": explain["ports"], "evidence_ids": ev("nc_port_443")},
                {"label": "HTTPS result", "value": f"HTTP {http['timing'].get('status', '?')} in {http['timing'].get('time', '?')} from {http['timing'].get('remote_ip', '?')}", "explanation": "Final status, total response time and the IP address actually connected to.", "evidence_ids": ev("curl_timing")},
                {"label": "Ping", "value": f"{reach['ping'].get('status')}; loss {reach['ping'].get('packet_loss_percent')}%; average {reach['ping'].get('average_rtt_ms')} ms", "explanation": explain["reachability"], "evidence_ids": ev("ping")},
                {"label": "Traceroute", "value": f"{reach['traceroute'].get('status')}; {reach['traceroute'].get('hops')} hops; last: {reach['traceroute'].get('last_hop')}", "explanation": "Hops showing * did not reply to probes; this is common and does not mean the path is broken.", "evidence_ids": ev("traceroute")},
            ],
        },
        {
            "kind": "table",
            "title": "Third-party services",
            "subtitle": "Providers identified from MX, NS, SPF and TXT records",
            "columns": [("service", "Service")],
            "rows": [{"service": item} for item in services],
        },
    ]
    strengths = [c["explanation"] for c in explained if c["status"] == "pass"][:4]
    ports_text = "; ".join(f"TCP {p['port']} is {p['state'].replace('_', ' ')}" for p in inventory["ports"])
    counts = severity_counts(findings)
    report = {
        **base,
        "scope": {
            **base["scope"],
            "in_scope": [f"Public DNS records of {domain}", "WHOIS registration data", f"ICMP and traceroute to {domain}", f"HTTP and HTTPS requests to {domain}", "TCP 80 and 443 connection tests"],
            "exclusions": ["Subdomain enumeration or brute forcing", "Any other port or host", "Vulnerability scanning, exploitation and credential testing", "Configuration changes"],
        },
        "summary": {
            "severity_counts": counts,
            "passed": sum(1 for c in explained if c["status"] == "pass"),
            "unknown": len(unknowns),
            "not_applicable": sum(1 for c in explained if c["status"] == "not_applicable"),
            "narrative": [
                f"H1 mapped what {domain} exposes to the internet. It resolves to {', '.join(dns['a']) or 'no IPv4 address'}, DNS is hosted by {context['dns_provider']}, email is handled by {context['mail_provider']} and the domain is registered with {context['registrar']}.",
                f"The HTTPS site returns HTTP {http['timing'].get('status', '?')} from {context['server_product']}; {ports_text}.",
            ] + narrative("H1", domain, explained, findings, strengths)[1:],
            "key_facts": [
                ("IPv4 / IPv6", ", ".join(dns["a"] + dns["aaaa"]) or "none"),
                ("DNS host", context["dns_provider"]),
                ("Email provider", context["mail_provider"]),
                ("Registrar", context["registrar"]),
                ("Web server", context["server_product"]),
                ("Third-party services found", str(len(services))),
            ],
        },
        "findings": findings,
        "controls": explained,
        "unknowns": unknowns,
        "technical_sections": sections,
        "inventory": inventory,
        "chart_data": {
            "surface_nodes": surface_nodes(domain, inventory, services, context),
            "hops": context.get("hops", []),
            "destination_ip": http["timing"].get("remote_ip") or (dns["a"][0] if dns["a"] else None),
        },
        "limitations": limitations + [
            "Point-in-time observation from one resolver and network path.",
            "Only the apex domain was examined; subdomains were not enumerated.",
        ],
        "assumptions": ["The domain's public DNS answers seen from this network are the same ones other internet users receive."],
    }
    return report


def surface_nodes(domain: str, inventory: dict[str, Any], services: list[str], context: dict[str, Any]) -> list[tuple[str, str]]:
    dns = inventory["dns"]
    nodes = [("IP address", ip) for ip in (dns["a"] + dns["aaaa"])[:3]]
    nodes += [
        ("DNS host", context["dns_provider"]),
        ("Email provider", context["mail_provider"]),
        ("Registrar", context["registrar"]),
        ("Web server", context["server_product"]),
    ]
    if context.get("caa_issuer") and not context["caa_issuer"].startswith("your"):
        nodes.append(("Certificate authority", context["caa_issuer"]))
    for item in services:
        if item.startswith(("Email:", "DNS hosting:")):
            continue
        label, _, rest = item.partition(" (")
        kind = "Email sender" if label.startswith("Authorised email sender") else "SaaS / verification"
        nodes.append((kind, label.replace("Authorised email sender: ", "")))
    return nodes[:12]


def spf_rows(record: str, data: dict[str, Any]) -> list[dict[str, str]]:
    meaning = {
        "v=spf1": "Identifies the record as SPF version 1.",
        "~all": "Soft fail: unlisted servers are suspicious; DMARC decides the outcome.",
        "-all": "Hard fail: mail from unlisted servers should be rejected.",
        "?all": "Neutral: no statement about unlisted servers.",
        "+all": "Pass: every server is authorised (dangerous).",
        "mx": "Servers in the domain's MX records may send.",
        "a": "The domain's A/AAAA addresses may send.",
    }
    rows = []
    for term in record.split():
        lowered = term.lower()
        if lowered.startswith("include:"):
            target = term.split(":", 1)[1]
            rows.append({"term": term, "meaning": f"Authorises the servers listed by {target}: {data['spf_include_services'].get(target.lower(), 'service not recognised by Cyber360')}. Costs at least one DNS lookup."})
        elif lowered.startswith(("ip4:", "ip6:")):
            rows.append({"term": term, "meaning": "Authorises this address or range directly (no DNS lookup)."})
        else:
            rows.append({"term": term, "meaning": meaning.get(lowered.lstrip("+"), "See RFC 7208.")})
    return rows


def dmarc_rows(record: str) -> list[dict[str, str]]:
    meaning = {
        "v": "Record version; must be DMARC1.",
        "p": "Policy for the domain: none (monitor), quarantine (spam folder) or reject (block).",
        "sp": "Policy for subdomains; defaults to p.",
        "pct": "Percentage of failing mail the policy applies to; defaults to 100.",
        "rua": "Where receivers send daily aggregate reports.",
        "ruf": "Where receivers send per-message failure reports (few receivers send these).",
        "adkim": "DKIM alignment: r (relaxed, default) or s (strict).",
        "aspf": "SPF alignment: r (relaxed, default) or s (strict).",
        "fo": "Which failures trigger failure reports.",
        "ri": "Requested report interval in seconds.",
    }
    return [{"tag": key, "value": value, "meaning": meaning.get(key, "")} for key, value in analysis.parse_dmarc_tags(record).items()]


def s18_report(domain: str, inventory: dict[str, Any], controls: list[dict[str, Any]], context: dict[str, Any], records: list[dict[str, Any]], base: dict[str, Any], limitations: list[str], selectors: list[str]) -> dict[str, Any]:
    by_id = {r["evidence_id"]: r for r in records}
    baseline = json.loads(S18_BASELINE.read_text(encoding="utf-8"))["controls"]
    titles = {rule: meta["title"] for rule, meta in baseline.items()} | {f"{rule}:authority": meta["authority"] for rule, meta in baseline.items()}
    explained, findings, unknowns = explain_and_find("s18", controls, context, by_id, titles)
    data = providers.load_providers()
    dns = inventory["dns"]
    spf_record = context.get("spf_record", "")
    dmarc_record = next((c["facts"].get("dmarc_record") for c in controls if c["facts"].get("dmarc_record")), "")
    smtp = {c["facts"].get("mx_host"): c for c in controls if c["rule_id"] == "S18-SMTP-001"}
    dnssec = next((c for c in explained if c["rule_id"].startswith("S18-DNSSEC")), {})
    sections = [
        {
            "kind": "table",
            "title": "Mail exchangers and transport encryption",
            "subtitle": "Each MX host was tested with STARTTLS on port 25",
            "columns": [("preference", "Preference"), ("host", "MX host"), ("status", "STARTTLS"), ("detail", "Result")],
            "rows": [
                {"preference": m["preference"], "host": m["host"], "status": smtp.get(m["host"], {}).get("status", "not_run"), "detail": smtp.get(m["host"], {}).get("detail", "")}
                for m in dns["mx"]
            ],
        },
        {
            "kind": "table",
            "title": "SPF record, term by term",
            "subtitle": spf_record or "No SPF record published",
            "columns": [("term", "Term"), ("meaning", "What it does")],
            "rows": spf_rows(spf_record, data) if spf_record else [],
        },
        {
            "kind": "table",
            "title": "DMARC record, tag by tag",
            "subtitle": dmarc_record or "No DMARC record published",
            "columns": [("tag", "Tag"), ("value", "Value"), ("meaning", "Meaning")],
            "rows": dmarc_rows(dmarc_record) if dmarc_record else [],
        },
        {
            "title": "Domain protection summary",
            "subtitle": "Providers detected and the state of each protection",
            "items": [
                {"label": "Email provider", "value": context["mail_provider"], "explanation": "Detected from the MX hosts. Fix instructions in this report are tailored to it.", "evidence_ids": [r["evidence_id"] for r in records if r["invocation"] == "dig_mx"]},
                {"label": "DNS host", "value": context["dns_provider"], "explanation": "Detected from the NS records. DNS changes in this report are made here.", "evidence_ids": [r["evidence_id"] for r in records if r["invocation"] == "dig_ns"]},
                {"label": "Registrar", "value": context["registrar"], "explanation": "From WHOIS. Locks, renewal and DS records are managed here.", "evidence_ids": [r["evidence_id"] for r in records if r["invocation"] == "whois"]},
                {"label": "DKIM selectors checked", "value": selectors or "none supplied", "explanation": f"Selectors cannot be listed from DNS. For {context['mail_provider']} the usual selector is {context['dkim_selector_hint']}.", "evidence_ids": [r["evidence_id"] for r in records if r["invocation"] == "dig_dkim"]},
                {"label": "DNSSEC", "value": dnssec.get("explanation", "unknown"), "explanation": "DS at the parent, DNSKEY and RRSIG in the zone, and the resolver's AD flag.", "evidence_ids": dnssec.get("evidence_ids", [])},
                {"label": "CAA", "value": dns["caa"] or "none", "explanation": "Certificate authorities allowed to issue for the domain.", "evidence_ids": [r["evidence_id"] for r in records if r["invocation"] == "dig_caa"]},
            ],
        },
    ]
    strengths = [c["explanation"] for c in explained if c["status"] == "pass"][:5]
    return {
        **base,
        "scope": {
            **base["scope"],
            "dkim_selectors": selectors,
            "in_scope": [f"Public DNS records of {domain} and its _dmarc, _mta-sts, _smtp._tls and DKIM selector names", "WHOIS registration data", f"HTTPS fetch of https://mta-sts.{domain}/.well-known/mta-sts.txt", "One STARTTLS handshake per published MX host on TCP 25"],
            "exclusions": ["Sending email or testing relaying", "Mailbox enumeration", "DKIM selectors not supplied by the user", "Configuration changes"],
        },
        "summary": {
            "severity_counts": severity_counts(findings),
            "passed": sum(1 for c in explained if c["status"] == "pass"),
            "unknown": len(unknowns),
            "not_applicable": sum(1 for c in explained if c["status"] == "not_applicable"),
            "narrative": narrative("S18", domain, explained, findings, strengths),
            "key_facts": [
                ("Email provider", context["mail_provider"]),
                ("DNS host", context["dns_provider"]),
                ("Registrar", context["registrar"]),
                ("SPF", spf_record or "none"),
                ("DMARC", dmarc_record or "none"),
            ],
        },
        "findings": findings,
        "controls": explained,
        "unknowns": unknowns,
        "technical_sections": sections,
        "chart_data": {
            "dmarc_policy": analysis.parse_dmarc_tags(dmarc_record).get("p", "").lower() if dmarc_record else None,
            "dmarc_pct": int(analysis.parse_dmarc_tags(dmarc_record).get("pct", "100")) if dmarc_record and analysis.parse_dmarc_tags(dmarc_record).get("pct", "100").isdigit() else 100,
            "mail_provider": context["mail_provider"],
            "mx_hosts": [m["host"] for m in dns["mx"]],
            "timeline": context.get("timeline", []),
        },
        "limitations": limitations + [
            "Point-in-time observation from one resolver and network path.",
            "Nested SPF include: records were not expanded.",
            "DKIM was checked only for selectors supplied by the user.",
        ],
        "assumptions": ["Outbound TCP 25 results reflect the network the assessment ran from; blocked connections are recorded as unknown."],
    }


# ---------------------------------------------------------------- workflow


def run_full_audit(
    domain: str,
    authority: str,
    dkim_selectors: list[str] | None = None,
    include_tls: bool = True,
    tls_profile: str = "standard",
) -> dict[str, Path]:
    domain = validate_domain(domain)
    if not authority.strip():
        raise ValueError("an explicit authority statement is required before any network activity")
    authority = authority.strip()
    selectors = [validate_selector(value) for value in (dkim_selectors or [])]

    folder, notes = prepare_domain_folder(domain)
    staging = folder / ".staging"
    (staging / "evidence").mkdir(parents=True)
    started_at = utc_now()
    evidence = DomainEvidence(staging)
    limitations: list[str] = []
    s11_dir = folder / AGENT_FOLDERS["s11"]

    with ThreadPoolExecutor(max_workers=1) as tls_pool:
        tls_future = tls_pool.submit(run_assessment, domain, 443, authority, tls_profile, 600, s11_dir) if include_tls else None
        tooling = tool_inventory(evidence)
        plan_agent(evidence, "h1", domain, limitations)
        plan_agent(evidence, "s18", domain, limitations)
        evidence.run_pending()
        mx_hosts = [item["host"] for item in analysis.parse_mx(evidence.output("s18", "dig_mx"))]
        if len(mx_hosts) > MAX_MX_HOSTS:
            limitations.append(f"Only the first {MAX_MX_HOSTS} of {len(mx_hosts)} MX hosts were tested for STARTTLS.")
        smtp_id, smtp_template, smtp_timeout = S18_SMTP_INVOCATION
        for host in mx_hosts[:MAX_MX_HOSTS]:
            if host and host != ".":
                evidence.plan("s18", smtp_id, render_argv(smtp_template, {"mx_host": host}), smtp_timeout)
        dkim_id, dkim_template, dkim_timeout = S18_DKIM_INVOCATION
        for selector in selectors:
            evidence.plan("s18", dkim_id, render_argv(dkim_template, {"domain": domain, "selector": selector}), dkim_timeout)
        evidence.run_pending()
        tls_error: Exception | None = None
        tls_paths: tuple[Path, Path] | None = None
        if tls_future is not None:
            try:
                tls_paths = tls_future.result()
            except (RuntimeError, ValueError, OSError) as exc:
                tls_error = exc

    for entry in tooling:
        result = evidence.results.get(entry.get("evidence_id", ""))
        if result:
            text = (result["stdout"] + "\n" + result["stderr"]).strip()
            entry["version"] = text.splitlines()[0] if text else entry["version"]

    inventory = analysis.build_inventory(lambda name: evidence.output("h1", name))
    s11_report = json.loads(tls_paths[0].read_text(encoding="utf-8")) if tls_paths else None
    context = build_context(domain, inventory, s11_report)
    dns = inventory["dns"]
    services = providers.third_party_services(dns["txt"], [m["host"] for m in dns["mx"]], dns["ns"])
    context["services_list"] = "\n".join(f"• {item}" for item in services)
    traceroute = evidence.output("h1", "traceroute")
    context["hops"] = charts.parse_hops(traceroute["stdout"]) if traceroute else []
    registration = inventory.get("registration", {})
    certificate = ((s11_report or {}).get("technical", {}).get("certificates") or [{}])[0]
    context["timeline"] = [
        item for item in (
            ["Domain registration", registration.get("created"), registration.get("expires")],
            ["TLS certificate", certificate.get("not_before"), certificate.get("not_after")],
        ) if item[2]
    ]

    h1_controls = analysis.h1_controls(lambda name: evidence.output("h1", name), services)
    s18_controls = analysis.build_email_controls(
        lambda name: evidence.output("s18", name), evidence.outputs("s18", "dig_dkim"), evidence.outputs("s18", "smtp_starttls")
    )
    s18_context = {**context, **dmarc_context(s18_controls, context)}

    agents = ["h1", "s11", "s18"] if include_tls else ["h1", "s18"]
    related_all = {agent: {"label": f"{agent.upper()} {AGENT_NAMES[agent]} report", "href": f"../{AGENT_FOLDERS[agent]}/report.html"} for agent in agents}
    outputs: dict[str, Path] = {}
    if include_tls and tls_error:
        limitations.append(f"S11 TLS assessment did not run: {tls_error}")

    for agent, builder in (("h1", "h1"), ("s18", "s18")):
        destination = folder / AGENT_FOLDERS[agent]
        records = agent_evidence(evidence, agent, destination)
        related = [item for key, item in related_all.items() if key != agent and not (key == "s11" and tls_error)]
        base = base_report(agent, domain, authority, started_at, records, tooling, related)
        if builder == "h1":
            report = h1_report(domain, inventory, services, h1_controls, context, records, base, notes + limitations)
        else:
            report = s18_report(domain, inventory, s18_controls, s18_context, records, base, notes + limitations, selectors)
        (destination / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (destination / "report.html").write_text(render_agent_report(report), encoding="utf-8")
        outputs[agent] = destination / "report.html"

    if s11_report is not None and tls_paths:
        for record in s11_report.get("evidence", []):
            record["path"] = f"evidence/{Path(record['path']).name}"
        enrich_s11_report(s11_report, {"server_product": context["server_product"], "hosting_provider": context["hosting_provider"]})
        s11_report["chart_data"] = {"timeline": context["timeline"]}
        s11_report["related_reports"] = [item for key, item in related_all.items() if key != "s11"]
        tls_paths[0].write_text(json.dumps(s11_report, indent=2), encoding="utf-8")
        tls_paths[1].write_text(render_tls_report(s11_report), encoding="utf-8")
        outputs["s11"] = tls_paths[1]

    shutil.rmtree(staging, ignore_errors=True)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="One authorised DNS domain, such as example.org")
    parser.add_argument("--authority", required=True, help="User-provided authority statement recorded in each report")
    parser.add_argument("--dkim-selector", action="append", default=[], help="Known DKIM selector; repeat for several")
    parser.add_argument("--skip-tls", action="store_true", help="Do not run the S11 TLS assessment")
    parser.add_argument("--tls-profile", choices=("standard", "extended"), default="standard")
    args = parser.parse_args()
    try:
        outputs = run_full_audit(args.domain, args.authority, args.dkim_selector, not args.skip_tls, args.tls_profile)
    except ValueError as exc:
        parser.error(str(exc))
    for agent in ("h1", "s11", "s18"):
        if agent in outputs:
            print(f"{agent.upper()}: {outputs[agent].resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
