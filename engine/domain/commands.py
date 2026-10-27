#!/usr/bin/env python3
"""Registered H1 and S18 command invocations and a deduplicating evidence runner.

The argv lists here must stay identical to the invocations declared in each
agent's tools.yaml; tests/test_domain_engine.py enforces that.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from ..tls.assessment import EvidenceStore
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from engine.tls.assessment import EvidenceStore


HTTP_WRITE_OUT = "Status: %{http_code}\\nTime: %{time_total}s\\nRemote IP: %{remote_ip}\\n"

# (invocation id, argv template, timeout seconds)
H1_INVOCATIONS: list[tuple[str, list[str], int]] = [
    ("dig_a", ["dig", "{{domain}}", "A", "+short"], 15),
    ("dig_aaaa", ["dig", "{{domain}}", "AAAA", "+short"], 15),
    ("dig_cname", ["dig", "{{domain}}", "CNAME", "+short"], 15),
    ("dig_mx", ["dig", "{{domain}}", "MX", "+short"], 15),
    ("dig_txt", ["dig", "{{domain}}", "TXT", "+short"], 15),
    ("dig_ns", ["dig", "{{domain}}", "NS", "+short"], 15),
    ("dig_soa", ["dig", "{{domain}}", "SOA", "+short"], 15),
    ("dig_caa", ["dig", "{{domain}}", "CAA", "+short"], 15),
    ("dig_trace", ["dig", "{{domain}}", "+trace"], 45),
    ("host", ["host", "{{domain}}"], 15),
    ("whois", ["whois", "{{domain}}"], 30),
    ("ping", ["ping", "-c", "4", "{{domain}}"], 20),
    ("traceroute", ["traceroute", "-q", "1", "-w", "2", "-m", "20", "{{domain}}"], 60),
    ("curl_headers", ["curl", "-IL", "https://{{domain}}"], 30),
    ("curl_timing", ["curl", "-sS", "-o", "/dev/null", "-w", HTTP_WRITE_OUT, "https://{{domain}}"], 30),
    ("curl_http", ["curl", "-sSI", "http://{{domain}}"], 20),
    # One port per nc call: macOS nc reports only the first port of a list.
    ("nc_port_80", ["nc", "-zv", "-w", "2", "{{domain}}", "80"], 15),
    ("nc_port_443", ["nc", "-zv", "-w", "2", "{{domain}}", "443"], 15),
]

S18_INVOCATIONS: list[tuple[str, list[str], int]] = [
    ("dig_mx", ["dig", "{{domain}}", "MX", "+short"], 15),
    ("dig_txt", ["dig", "{{domain}}", "TXT", "+short"], 15),
    ("dig_dmarc", ["dig", "_dmarc.{{domain}}", "TXT", "+short"], 15),
    ("dig_tlsrpt", ["dig", "_smtp._tls.{{domain}}", "TXT", "+short"], 15),
    ("dig_caa", ["dig", "{{domain}}", "CAA", "+short"], 15),
    ("dig_ds", ["dig", "{{domain}}", "DS", "+dnssec"], 15),
    ("dig_dnskey", ["dig", "{{domain}}", "DNSKEY", "+dnssec"], 15),
    ("dig_a_dnssec", ["dig", "{{domain}}", "A", "+dnssec"], 15),
    ("dig_aaaa_dnssec", ["dig", "{{domain}}", "AAAA", "+dnssec"], 15),
    ("dig_mx_dnssec", ["dig", "{{domain}}", "MX", "+dnssec"], 15),
    ("dig_txt_dnssec", ["dig", "{{domain}}", "TXT", "+dnssec"], 15),
    ("dig_ns", ["dig", "{{domain}}", "NS", "+short"], 15),
    ("dig_soa_full", ["dig", "{{domain}}", "SOA"], 15),
    ("dig_trace", ["dig", "{{domain}}", "+trace"], 45),
    ("dig_mta_sts", ["dig", "_mta-sts.{{domain}}", "TXT", "+short"], 15),
    ("curl_mta_sts_policy", ["curl", "-fsSL", "https://mta-sts.{{domain}}/.well-known/mta-sts.txt"], 20),
    ("whois", ["whois", "{{domain}}"], 30),
]

# Run only for selectors the user supplies; selectors are never guessed.
S18_DKIM_INVOCATION: tuple[str, list[str], int] = (
    "dig_dkim", ["dig", "{{selector}}._domainkey.{{domain}}", "TXT", "+short"], 15
)

# Run once per MX hostname returned by dig_mx.
S18_SMTP_INVOCATION: tuple[str, list[str], int] = (
    "smtp_starttls",
    ["openssl", "s_client", "-starttls", "smtp", "-connect", "{{mx_host}}:25", "-servername", "{{mx_host}}"],
    20,
)

AGENT_INVOCATIONS = {"h1": H1_INVOCATIONS, "s18": S18_INVOCATIONS}

LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"


def validate_domain(value: str) -> str:
    """Return a normalised registrable-style DNS name or raise ValueError."""
    domain = value.strip().rstrip(".").lower()
    if not domain or "://" in domain or "/" in domain or ":" in domain:
        raise ValueError("target must be one DNS domain name, not a URL, port or range")
    domain = domain.encode("idna").decode("ascii")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or not all(re.fullmatch(LABEL, label) for label in labels):
        raise ValueError("target is not a valid DNS domain name")
    return domain


def validate_selector(value: str) -> str:
    selector = value.strip()
    if not re.fullmatch(r"(?!-)[A-Za-z0-9._-]{1,63}", selector):
        raise ValueError(f"invalid DKIM selector: {value!r}")
    return selector


def render_argv(template: list[str], variables: dict[str, str]) -> list[str]:
    rendered = []
    for part in template:
        for key, value in variables.items():
            part = part.replace("{{" + key + "}}", value)
        if "{{" in part:
            raise ValueError(f"unresolved variable in argv: {part}")
        rendered.append(part)
    return rendered


@dataclass
class Planned:
    evidence_id: str
    argv: list[str]
    timeout: int
    invocation_ids: dict[str, str] = field(default_factory=dict)  # agent -> invocation id


class DomainEvidence:
    """Run each unique registered command once and share its evidence across agents."""

    def __init__(self, report_directory: Path, workers: int = 6):
        self.store = EvidenceStore(report_directory)
        self.workers = workers
        self.planned: dict[tuple[str, ...], Planned] = {}
        self.results: dict[str, dict[str, Any]] = {}

    def plan(self, agent: str, invocation_id: str, argv: list[str], timeout: int) -> Planned:
        key = tuple(argv)
        if key not in self.planned:
            number = len(self.planned) + 1
            slug = re.sub(r"[^a-z0-9]+", "-", invocation_id.lower()).strip("-")
            self.planned[key] = Planned(f"D{number:02d}-{slug}", argv, timeout)
        item = self.planned[key]
        item.invocation_ids.setdefault(agent, invocation_id)
        return item

    def run_pending(self) -> None:
        pending = [item for item in self.planned.values() if item.evidence_id not in self.results]

        def execute(item: Planned) -> None:
            completed, record = self.store.run(item.evidence_id, item.argv, item.timeout)
            record["used_by"] = dict(item.invocation_ids)
            self.results[item.evidence_id] = {
                "record": record,
                "exit_status": completed.returncode,
                "stdout": completed.stdout.decode("utf-8", errors="replace"),
                "stderr": completed.stderr.decode("utf-8", errors="replace"),
            }

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            list(pool.map(execute, pending))
        self.store.records.sort(key=lambda record: record["evidence_id"])

    def output(self, agent: str, invocation_id: str) -> dict[str, Any] | None:
        for item in self.planned.values():
            if item.invocation_ids.get(agent) == invocation_id and item.evidence_id in self.results:
                return {"evidence_id": item.evidence_id, **self.results[item.evidence_id]}
        return None

    def outputs(self, agent: str, invocation_id: str) -> list[dict[str, Any]]:
        """Return every result for a per-item invocation such as DKIM or SMTP checks."""
        found = []
        for item in self.planned.values():
            if item.invocation_ids.get(agent) == invocation_id and item.evidence_id in self.results:
                found.append({"evidence_id": item.evidence_id, "argv": item.argv, **self.results[item.evidence_id]})
        return found
