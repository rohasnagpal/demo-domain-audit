#!/usr/bin/env python3
"""Turn preserved H1 and S18 command output into inventory facts and baseline control results.

Every control result is one of pass, confirmed, unknown or not_applicable. A
failed, blocked or timed-out command produces unknown, never pass.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

Output = dict[str, Any] | None

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def ok(result: Output) -> bool:
    return bool(result) and result["exit_status"] == 0


def lines(result: Output) -> list[str]:
    if not result:
        return []
    return [line.strip() for line in result["stdout"].splitlines() if line.strip() and not line.startswith(";")]


def txt_values(result: Output) -> list[str]:
    """Join dig +short TXT output, where long records are split into quoted chunks."""
    values = []
    for line in lines(result):
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        values.append("".join(chunks) if chunks else line)
    return values


def answer_records(result: Output, rrtype: str) -> list[str]:
    """Return ANSWER-section records of one type from full (non +short) dig output."""
    if not result:
        return []
    records, in_answer = [], False
    for line in result["stdout"].splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue
        if in_answer and (not line.strip() or line.startswith(";;")):
            in_answer = False
        if in_answer:
            parts = line.split()
            if len(parts) >= 5 and parts[3].upper() == rrtype.upper():
                records.append(" ".join(parts[4:]))
    return records


def dig_status(result: Output) -> str | None:
    if not result:
        return None
    match = re.search(r"status: ([A-Z]+)", result["stdout"])
    return match.group(1) if match else None


def dig_flags(result: Output) -> set[str]:
    if not result:
        return set()
    match = re.search(r";; flags: ([a-z ]+);", result["stdout"])
    return set(match.group(1).split()) if match else set()


def evidence_ids(*results: Output) -> list[str]:
    return [result["evidence_id"] for result in results if result]


# ---------------------------------------------------------------- H1 inventory


def parse_mx(result: Output) -> list[dict[str, Any]]:
    records = []
    for line in lines(result):
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            records.append({"preference": int(parts[0]), "host": parts[1].rstrip(".").lower()})
    return sorted(records, key=lambda item: (item["preference"], item["host"]))


def parse_http_chain(result: Output) -> list[dict[str, Any]]:
    """Split curl -IL output into one entry per response in the redirect chain."""
    if not result:
        return []
    responses, current = [], None
    for raw in result["stdout"].splitlines():
        line = raw.strip()
        status = re.match(r"HTTP/[\d.]+\s+(\d{3})", line)
        if status:
            current = {"status": int(status.group(1)), "headers": {}}
            responses.append(current)
        elif current is not None and ":" in line:
            name, value = line.split(":", 1)
            current["headers"].setdefault(name.strip().lower(), value.strip())
    return responses


def parse_curl_timing(result: Output) -> dict[str, str]:
    facts = {}
    for line in lines(result):
        if ":" in line:
            name, value = line.split(":", 1)
            facts[name.strip().lower().replace(" ", "_")] = value.strip()
    return facts


def parse_port(port: int, result: Output) -> dict[str, Any]:
    if not result:
        return {"port": port, "state": "not_run"}
    text = result["stdout"] + "\n" + result["stderr"]
    if result["exit_status"] == 0 and re.search(r"succeeded|open", text, re.I):
        state = "open"
    elif re.search(r"refused", text, re.I):
        state = "closed"
    elif re.search(r"timed out|timeout", text, re.I) or result["exit_status"] == 124:
        state = "filtered_or_unreachable"
    else:
        state = "unknown"
    return {"port": port, "state": state}


def parse_ping(result: Output) -> dict[str, Any]:
    if not result:
        return {"status": "not_run"}
    text = result["stdout"]
    loss = re.search(r"([\d.]+)% packet loss", text)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", text)
    return {
        "status": "replied" if result["exit_status"] == 0 else "no_reply_or_blocked",
        "packet_loss_percent": float(loss.group(1)) if loss else None,
        "average_rtt_ms": float(rtt.group(1)) if rtt else None,
    }


def parse_traceroute(result: Output) -> dict[str, Any]:
    if not result:
        return {"status": "not_run", "hops": 0}
    hops = [line for line in result["stdout"].splitlines() if re.match(r"\s*\d+\s", line)]
    if result["exit_status"] == 124:
        status = "timed_out_partial"
    elif result["exit_status"] != 0:
        status = "failed"
    elif hops and hops[-1].strip().endswith("*"):
        status = "destination_not_reached"
    else:
        status = "completed"
    return {
        "status": status,
        "hops": len(hops),
        "last_hop": hops[-1].strip() if hops else None,
    }


WHOIS_FIELDS = {
    "registrar": [r"^\s*Registrar:\s*(.+)$"],
    "created": [r"^\s*Creation Date:\s*(.+)$", r"^\s*created:\s*(.+)$"],
    "expires": [r"^\s*Registry Expiry Date:\s*(.+)$", r"^\s*Registrar Registration Expiration Date:\s*(.+)$", r"^\s*Expir\w* Date:\s*(.+)$", r"^\s*paid-till:\s*(.+)$"],
    "updated": [r"^\s*Updated Date:\s*(.+)$"],
}


def parse_whois(result: Output) -> dict[str, Any]:
    if not result:
        return {}
    text = result["stdout"]
    facts: dict[str, Any] = {}
    for name, patterns in WHOIS_FIELDS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.I | re.M)
            if match and match.group(1).strip():
                facts[name] = match.group(1).strip()
                break
    statuses = sorted({match.split()[0] for match in re.findall(r"^\s*(?:Domain )?Status:\s*(\S+)", text, re.I | re.M)})
    if statuses:
        facts["statuses"] = statuses
    return facts


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip().replace("Z", "+00:00")
    for parser in (
        lambda v: datetime.fromisoformat(v),
        lambda v: datetime.strptime(v[:10], "%Y-%m-%d"),
        lambda v: datetime.strptime(v[:11], "%d-%b-%Y"),
    ):
        try:
            parsed = parser(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def build_inventory(outputs: Callable[[str], Output]) -> dict[str, Any]:
    """H1 attack-surface inventory. Observations only; H1 does not assign severity."""
    a, aaaa = outputs("dig_a"), outputs("dig_aaaa")
    http = outputs("curl_headers")
    chain = parse_http_chain(http)
    return {
        "dns": {
            "a": lines(a),
            "aaaa": lines(aaaa),
            "cname": lines(outputs("dig_cname")),
            "mx": parse_mx(outputs("dig_mx")),
            "ns": sorted(line.rstrip(".").lower() for line in lines(outputs("dig_ns"))),
            "soa": lines(outputs("dig_soa")),
            "txt": txt_values(outputs("dig_txt")),
            "caa": lines(outputs("dig_caa")),
            "delegation_traced": ok(outputs("dig_trace")),
        },
        "host": lines(outputs("host")),
        "registration": parse_whois(outputs("whois")),
        "http": {
            "chain": [{"status": item["status"], "location": item["headers"].get("location"), "server": item["headers"].get("server")} for item in chain],
            "final_headers": chain[-1]["headers"] if chain else {},
            "timing": parse_curl_timing(outputs("curl_timing")),
        },
        "ports": [parse_port(80, outputs("nc_port_80")), parse_port(443, outputs("nc_port_443"))],
        "reachability": {"ping": parse_ping(outputs("ping")), "traceroute": parse_traceroute(outputs("traceroute"))},
    }


# ---------------------------------------------------------------- H1 controls


def control(
    rule_id: str,
    status: str,
    detail: str,
    evidence: list[str],
    severity: str | None = None,
    variant: str = "default",
    **facts: Any,
) -> dict[str, Any]:
    """One baseline control result. `variant` selects the knowledge-base text; `facts` fill its placeholders."""
    item = {"rule_id": rule_id, "status": status, "detail": detail, "evidence_ids": evidence, "variant": variant, "facts": facts}
    if severity:
        item["severity"] = severity
    return item


def http_status_and_location(result: Output) -> tuple[int | None, str | None]:
    chain = parse_http_chain(result)
    if not chain:
        return None, None
    return chain[0]["status"], chain[0]["headers"].get("location")


def h1_controls(outputs: Callable[[str], Output], services: list[str]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    https = outputs("curl_headers")
    chain = parse_http_chain(https)
    headers = chain[-1]["headers"] if chain else {}
    ev = evidence_ids(https)

    if not chain:
        controls.append(control("H1-WEB-001", "unknown", "No HTTPS response was captured, so response headers could not be inspected.", ev))
        controls.append(control("H1-WEB-002", "unknown", "No HTTPS response was captured.", ev))
        controls.append(control("H1-WEB-004", "unknown", "No HTTPS response was captured.", ev))
    else:
        server = headers.get("server")
        if not server:
            controls.append(control("H1-WEB-001", "pass", "No Server header is returned.", ev))
        elif re.search(r"\d", server):
            controls.append(control("H1-WEB-001", "confirmed", f"Server: {server} discloses the product and version.", ev, "low", "with_version", server_header=server))
        else:
            controls.append(control("H1-WEB-001", "confirmed", f"Server: {server} discloses the product but not its version.", ev, "informational", "product_only", server_header=server))
        powered = headers.get("x-powered-by")
        if powered:
            controls.append(control("H1-WEB-002", "confirmed", f"X-Powered-By: {powered}", ev, "low", powered_by=powered))
        else:
            controls.append(control("H1-WEB-002", "pass", "No X-Powered-By header is returned.", ev))
        hsts = headers.get("strict-transport-security")
        if not hsts:
            controls.append(control("H1-WEB-004", "confirmed", "No Strict-Transport-Security header on the HTTPS response.", ev, "low", "missing"))
        else:
            age = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if age and int(age.group(1)) < 15768000:
                controls.append(control("H1-WEB-004", "confirmed", f"HSTS max-age is {age.group(1)} seconds (under six months).", ev, "low", "short_max_age", hsts=hsts))
            else:
                controls.append(control("H1-WEB-004", "pass", f"Strict-Transport-Security: {hsts}", ev, hsts=hsts))

    http = outputs("curl_http")
    port80 = parse_port(80, outputs("nc_port_80"))
    status, location = http_status_and_location(http)
    hev = evidence_ids(http, outputs("nc_port_80"))
    if port80["state"] in ("closed", "filtered_or_unreachable") and status is None:
        controls.append(control("H1-WEB-003", "not_applicable", "TCP 80 does not accept connections, so there is no plain-HTTP site to redirect.", hev))
    elif status is None:
        controls.append(control("H1-WEB-003", "unknown", "The plain-HTTP request did not return a response.", hev))
    elif status in (301, 302, 303, 307, 308) and location and location.lower().startswith("https://"):
        controls.append(control("H1-WEB-003", "pass", f"http:// returns {status} to {location}.", hev, http_status=status, http_location=location))
    elif status in (301, 302, 303, 307, 308):
        controls.append(control("H1-WEB-003", "confirmed", f"http:// redirects ({status}) to {location}, which is not HTTPS.", hev, "medium", "redirect_not_https", http_status=status, http_location=location))
    else:
        controls.append(control("H1-WEB-003", "confirmed", f"http:// returns {status} without redirecting to HTTPS.", hev, "medium", "no_redirect", http_status=status))

    dns_ev = evidence_ids(outputs("dig_txt"), outputs("dig_mx"), outputs("dig_ns"))
    if services:
        controls.append(control("H1-DNS-001", "confirmed", f"{len(services)} third-party services identified from public DNS.", dns_ev, "informational", services_list="\n".join(f"• {item}" for item in services)))
    else:
        controls.append(control("H1-DNS-001", "pass", "No third-party services identified.", dns_ev))
    return controls


# ---------------------------------------------------------------- S18 controls


def parse_spf(txt: Output) -> list[str]:
    return [value for value in txt_values(txt) if value.lower().startswith("v=spf1")]


def parse_dmarc_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def spf_controls(txt: Output, has_mx: bool) -> list[dict[str, Any]]:
    ev = evidence_ids(txt)
    if not ok(txt):
        return [control("S18-SPF-001", "unknown", "The TXT lookup failed, so SPF could not be evaluated.", ev)]
    spf = parse_spf(txt)
    if not spf:
        return [control("S18-SPF-001", "confirmed", "No SPF record (TXT beginning v=spf1) is published.", ev, "high" if has_mx else "medium")]
    record = spf[0]
    results = [control("S18-SPF-001", "pass", f"SPF record published: {record}", ev, spf_record=record)]
    if len(spf) > 1:
        results.append(control("S18-SPF-002", "confirmed", f"{len(spf)} SPF records are published; receivers must return permerror.", ev, "high", spf_count=len(spf), spf_records="\n".join(spf)))
    else:
        results.append(control("S18-SPF-002", "pass", "Exactly one SPF record is published.", ev))
    terms = record.split()
    lowered = [term.lower() for term in terms]
    qualifier = next((term for term in reversed(lowered) if term.endswith("all")), None)
    base = [term for term in terms if not term.lower().endswith("all")]
    fixed = " ".join(base + ["~all"])
    if qualifier in ("+all", "all"):
        results.append(control("S18-SPF-003", "confirmed", f"SPF ends with {qualifier}, which authorises every sender.", ev, "critical", "plus_all", spf_qualifier=qualifier, spf_record=record, spf_fixed=fixed))
    elif qualifier == "?all":
        results.append(control("S18-SPF-003", "confirmed", "SPF ends with ?all (neutral), which gives receivers no rejection signal.", ev, "medium", "neutral", spf_qualifier=qualifier, spf_record=record, spf_fixed=fixed))
    elif qualifier in ("~all", "-all"):
        note = (
            "-all (hard fail) tells receivers to reject mail from unlisted servers."
            if qualifier == "-all"
            else "~all (soft fail) asks receivers to accept but mark mail from unlisted servers; it is the common recommendation when paired with an enforcing DMARC policy, which makes the final decision."
        )
        results.append(control("S18-SPF-003", "pass", f"SPF ends with {qualifier}.", ev, spf_qualifier=qualifier, spf_qualifier_note=note))
    elif any(term.startswith("redirect=") for term in lowered):
        results.append(control("S18-SPF-003", "unknown", "SPF uses redirect=; the effective all-qualifier is in the redirected record.", ev))
    else:
        results.append(control("S18-SPF-003", "confirmed", "SPF has no all mechanism, so unmatched senders default to neutral.", ev, "medium", "no_all", spf_qualifier="(none)", spf_record=record, spf_fixed=fixed))
    lookups = sum(1 for term in lowered if re.match(r"[+~?-]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", term))
    if lookups > 10:
        results.append(control("S18-SPF-004", "confirmed", f"The top-level record alone has {lookups} DNS-querying terms (limit 10).", ev, "high", spf_lookups=lookups, spf_record=record))
    else:
        results.append(control("S18-SPF-004", "unknown", f"The top-level record has {lookups} DNS-querying terms; nested include: records were not expanded.", ev, spf_lookups=lookups))
    return results


def dmarc_controls(dmarc: Output) -> list[dict[str, Any]]:
    ev = evidence_ids(dmarc)
    if not ok(dmarc):
        return [control("S18-DMARC-001", "unknown", "The _dmarc TXT lookup failed.", ev)]
    records = [value for value in txt_values(dmarc) if value.lower().startswith("v=dmarc1")]
    if not records:
        return [control("S18-DMARC-001", "confirmed", "No DMARC record is published at _dmarc.", ev, "high", "missing")]
    if len(records) > 1:
        return [control("S18-DMARC-001", "confirmed", f"{len(records)} DMARC records are published; receivers must ignore DMARC.", ev, "high", "multiple", dmarc_count=len(records), dmarc_records="\n".join(records))]
    record = records[0]
    tags = parse_dmarc_tags(record)
    policy = tags.get("p", "").lower()
    facts = {"dmarc_record": record, "dmarc_policy": policy or "missing", "dmarc_rua": tags.get("rua", "")}
    results = [control("S18-DMARC-001", "pass", f"DMARC record published: {record}", ev, **facts)]
    if policy in ("quarantine", "reject"):
        effect = "quarantine (send to spam)" if policy == "quarantine" else "reject"
        results.append(control("S18-DMARC-002", "pass", f"DMARC policy is p={policy}.", ev, dmarc_policy_effect=effect, **facts))
    else:
        results.append(control("S18-DMARC-002", "confirmed", f"DMARC policy is p={policy or 'missing'}, which does not instruct receivers to act on spoofed mail.", ev, "medium", **facts))
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        full = "; ".join(part.strip() for part in record.split(";") if part.strip() and not part.strip().lower().startswith("pct="))
        results.append(control("S18-DMARC-003", "confirmed", f"DMARC enforcement applies to only pct={pct}% of failing mail.", ev, "low", dmarc_pct=pct, dmarc_pct_remaining=100 - int(pct), dmarc_full_pct=full, **facts))
    elif policy in ("quarantine", "reject"):
        results.append(control("S18-DMARC-003", "pass", "The policy applies to all failing mail.", ev))
    if "rua" in tags:
        results.append(control("S18-DMARC-004", "pass", f"Aggregate reports requested: {tags['rua']}", ev, **facts))
    else:
        results.append(control("S18-DMARC-004", "confirmed", "No rua= tag; the domain owner receives no aggregate DMARC reports.", ev, "low", **facts))
    return results


def dkim_controls(dkim_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not dkim_results:
        return [control("S18-DKIM-001", "unknown", "No DKIM selector was supplied; selectors cannot be enumerated from DNS and were not guessed.", [])]
    results = []
    for result in dkim_results:
        selector = result["argv"][1].split("._domainkey.", 1)[0]
        values = txt_values(result)
        record = next((value for value in values if "p=" in value), None)
        ev = [result["evidence_id"]]
        if not ok(result):
            results.append(control("S18-DKIM-001", "unknown", f"Lookup for selector {selector} failed.", ev, selector=selector))
        elif record is None:
            results.append(control("S18-DKIM-001", "confirmed", f"No DKIM key is published for supplied selector {selector}.", ev, "medium", "missing_key", selector=selector))
        elif re.search(r"(?:^|;)\s*p=\s*(?:;|$)", record):
            results.append(control("S18-DKIM-001", "confirmed", f"Selector {selector} publishes an empty p= (revoked key).", ev, "medium", "revoked", selector=selector))
        else:
            results.append(control("S18-DKIM-001", "pass", f"DKIM key published for selector {selector}.", ev, selector=selector))
    return results


def mta_sts_controls(record: Output, policy: Output, has_mx: bool) -> list[dict[str, Any]]:
    ev = evidence_ids(record, policy)
    if not has_mx:
        return [control("S18-MTASTS-001", "not_applicable", "The domain publishes no MX records.", ev)]
    if not ok(record):
        return [control("S18-MTASTS-001", "unknown", "The _mta-sts TXT lookup failed.", ev)]
    if not any(value.lower().startswith("v=stsv1") for value in txt_values(record)):
        return [control("S18-MTASTS-001", "confirmed", "No MTA-STS record is published; inbound SMTP TLS can be downgraded.", ev, "low", "missing")]
    if not ok(policy):
        return [control("S18-MTASTS-001", "confirmed", "An MTA-STS record exists but the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt could not be fetched.", ev, "medium", "policy_unreachable")]
    mode = re.search(r"^\s*mode:\s*(\S+)", policy["stdout"], re.M | re.I)
    mode_value = mode.group(1).lower() if mode else "missing"
    if mode_value == "enforce":
        return [control("S18-MTASTS-001", "pass", "MTA-STS policy is published in enforce mode.", ev)]
    return [control("S18-MTASTS-001", "confirmed", f"MTA-STS policy mode is {mode_value}, so receivers do not enforce TLS.", ev, "low", "not_enforce", mta_sts_mode=mode_value)]


def tlsrpt_controls(result: Output, has_mx: bool) -> list[dict[str, Any]]:
    ev = evidence_ids(result)
    if not has_mx:
        return [control("S18-TLSRPT-001", "not_applicable", "The domain publishes no MX records.", ev)]
    if not ok(result):
        return [control("S18-TLSRPT-001", "unknown", "The _smtp._tls TXT lookup failed.", ev)]
    if any(value.lower().startswith("v=tlsrptv1") for value in txt_values(result)):
        return [control("S18-TLSRPT-001", "pass", "SMTP TLS reporting (TLS-RPT) is configured.", ev)]
    return [control("S18-TLSRPT-001", "confirmed", "No TLS-RPT record; SMTP TLS delivery failures are not reported to the owner.", ev, "informational")]


def caa_controls(result: Output) -> list[dict[str, Any]]:
    ev = evidence_ids(result)
    if not ok(result):
        return [control("S18-CAA-001", "unknown", "The CAA lookup failed.", ev)]
    records = lines(result)
    if records:
        return [control("S18-CAA-001", "pass", f"CAA restricts certificate issuance: {'; '.join(records)}", ev, caa_records="; ".join(records))]
    return [control("S18-CAA-001", "confirmed", "No CAA record; any public CA may issue certificates for the domain.", ev, "low")]


def dnssec_controls(ds: Output, dnskey: Output, signed_answers: list[Output]) -> list[dict[str, Any]]:
    ev = evidence_ids(ds, dnskey, *signed_answers)
    if not ok(ds) or dig_status(ds) not in ("NOERROR", "NXDOMAIN"):
        return [control("S18-DNSSEC-001", "unknown", "The DS lookup did not complete.", ev)]
    has_ds = bool(answer_records(ds, "DS"))
    has_dnskey = bool(answer_records(dnskey, "DNSKEY"))
    has_rrsig = any(answer_records(answer, "RRSIG") for answer in signed_answers)
    validated = any("ad" in dig_flags(answer) for answer in signed_answers)
    if not has_ds and not has_dnskey:
        return [control("S18-DNSSEC-001", "confirmed", "The zone is not DNSSEC-signed (no DS at the parent, no DNSKEY).", ev, "medium", "unsigned")]
    if has_ds and not (has_dnskey and has_rrsig):
        return [control("S18-DNSSEC-002", "confirmed", "A DS record exists at the parent but the zone does not serve DNSKEY and RRSIG records; validating resolvers will fail.", ev, "critical")]
    if has_dnskey and not has_ds:
        return [control("S18-DNSSEC-001", "confirmed", "The zone is signed (DNSKEY present) but no DS record is published at the parent, so the chain of trust is incomplete.", ev, "medium", "no_ds")]
    note = " The resolver set the AD (authenticated data) flag." if validated else " The local resolver did not set the AD flag; validation was not confirmed by this resolver."
    return [control("S18-DNSSEC-001", "pass", "DS, DNSKEY and RRSIG records are present." + note, ev, dnssec_ad_note=note)]


def ns_controls(ns: Output) -> list[dict[str, Any]]:
    ev = evidence_ids(ns)
    if not ok(ns):
        return [control("S18-NS-001", "unknown", "The NS lookup failed.", ev)]
    servers = [line.rstrip(".") for line in lines(ns)]
    facts = {"ns_count": len(servers), "ns_list": ", ".join(servers)}
    if len(servers) >= 2:
        return [control("S18-NS-001", "pass", f"{len(servers)} authoritative nameservers are delegated.", ev, **facts)]
    return [control("S18-NS-001", "confirmed", f"Only {len(servers)} nameserver is delegated; DNS has a single point of failure.", ev, "medium", **facts)]


def registration_controls(whois: Output, now: datetime) -> list[dict[str, Any]]:
    ev = evidence_ids(whois)
    facts = parse_whois(whois)
    if not facts:
        return [control("S18-REG-001", "unknown", "WHOIS returned no parsable registration data.", ev)]
    results = []
    expires = parse_date(facts.get("expires"))
    if expires is None:
        results.append(control("S18-REG-001", "unknown", "The registration expiry date could not be parsed.", ev))
    else:
        days = (expires - now).days
        values = {"expires": facts["expires"], "days_left": days}
        if days < 0:
            results.append(control("S18-REG-001", "confirmed", f"The registration expired on {facts['expires']}.", ev, "critical", "expired", **values))
        elif days <= 30:
            results.append(control("S18-REG-001", "confirmed", f"The registration expires in {days} days ({facts['expires']}).", ev, "high", "expiring", **values))
        else:
            results.append(control("S18-REG-001", "pass", f"The registration is valid for {days} more days ({facts['expires']}).", ev, **values))
    statuses = facts.get("statuses", [])
    lowered = [status.lower() for status in statuses]
    epp = ", ".join(statuses) or "none listed"
    if not statuses:
        results.append(control("S18-REG-002", "unknown", "No EPP status codes were present in the WHOIS output.", ev))
    elif "clienttransferprohibited" in lowered or "servertransferprohibited" in lowered:
        results.append(control("S18-REG-002", "pass", "A transfer lock (transferProhibited) is set.", ev, epp_statuses=epp))
    else:
        results.append(control("S18-REG-002", "confirmed", "No transfer lock is set; the domain is easier to hijack through an unauthorised transfer.", ev, "medium", epp_statuses=epp))
    return results


def smtp_controls(results: list[dict[str, Any]], has_mx: bool) -> list[dict[str, Any]]:
    if not has_mx:
        return [control("S18-SMTP-001", "not_applicable", "The domain publishes no MX records.", [])]
    controls = []
    for result in results:
        host = result["argv"][5].rsplit(":", 1)[0]
        text = result["stdout"] + "\n" + result["stderr"]
        ev = [result["evidence_id"]]
        unreachable = re.search(r"(connect:|Connection refused|timed out|No route|errno|BIO_connect)", text, re.I)
        handshake_seen = "BEGIN CERTIFICATE" in text or "Verify return code" in text
        if result["exit_status"] == 124 or (unreachable and not handshake_seen):
            controls.append(control("S18-SMTP-001", "unknown", f"{host}:25 could not be reached from this network (outbound port 25 is often blocked).", ev, mx_host=host))
        elif re.search(r"didn't find starttls|STARTTLS not supported", text, re.I):
            controls.append(control("S18-SMTP-001", "confirmed", f"{host} does not offer STARTTLS; mail to it travels unencrypted.", ev, "high", "no_starttls", mx_host=host))
        else:
            code = re.search(r"Verify return code: (\d+) \(([^)]*)\)", text)
            if code and code.group(1) == "0":
                controls.append(control("S18-SMTP-001", "pass", f"{host} offers STARTTLS with a certificate that verifies.", ev, mx_host=host))
            elif code:
                controls.append(control("S18-SMTP-001", "confirmed", f"{host} offers STARTTLS but certificate verification failed: {code.group(2)}.", ev, "medium", "cert_invalid", mx_host=host, verify_error=code.group(2)))
            else:
                controls.append(control("S18-SMTP-001", "unknown", f"The STARTTLS result for {host} was inconclusive.", ev, mx_host=host))
    return controls


def build_email_controls(
    outputs: Callable[[str], Output],
    dkim_results: list[dict[str, Any]],
    smtp_results: list[dict[str, Any]],
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    mx = outputs("dig_mx")
    mx_records = parse_mx(mx)
    has_mx = bool(mx_records)
    controls: list[dict[str, Any]] = []
    if ok(mx) and not has_mx:
        controls.append(control("S18-MX-001", "confirmed", "No MX records are published. If the domain sends no mail, publish a null MX (0 .) and v=spf1 -all.", evidence_ids(mx), "informational"))
    elif has_mx:
        controls.append(control("S18-MX-001", "pass", f"{len(mx_records)} MX record(s) published.", evidence_ids(mx)))
    else:
        controls.append(control("S18-MX-001", "unknown", "The MX lookup failed.", evidence_ids(mx)))
    controls += spf_controls(outputs("dig_txt"), has_mx)
    controls += dmarc_controls(outputs("dig_dmarc"))
    controls += dkim_controls(dkim_results)
    controls += mta_sts_controls(outputs("dig_mta_sts"), outputs("curl_mta_sts_policy"), has_mx)
    controls += tlsrpt_controls(outputs("dig_tlsrpt"), has_mx)
    controls += smtp_controls(smtp_results, has_mx)
    controls += caa_controls(outputs("dig_caa"))
    controls += dnssec_controls(
        outputs("dig_ds"),
        outputs("dig_dnskey"),
        [outputs(name) for name in ("dig_a_dnssec", "dig_aaaa_dnssec", "dig_mx_dnssec", "dig_txt_dnssec")],
    )
    controls += ns_controls(outputs("dig_ns"))
    controls += registration_controls(outputs("whois"), now)
    return controls
